"""SDK ``chat_completion`` + ``chat_completion_stream`` go through the
egress path (persistent ``_egress_dpop_key``), not the bearer-DPoP
wrapper ``_authed_request``.

Why: Mastio's ``/v1/llm/chat`` and ``/v1/chat/completions`` are gated by
``get_agent_from_dpop_client_cert`` which verifies the DPoP proof's
JWK thumbprint against ``internal_agents.dpop_jkt`` pinned at
enrollment time. The ephemeral DPoP key that ``login_via_proxy*``
generates does NOT match the pinned thumbprint, so the bearer-DPoP
path always 401s on the chat routes. The egress path signs with the
persistent ``identity/dpop.jwk`` key whose thumbprint matches.

These tests pin the contract:

* ``chat_completion`` delegates to ``_egress_http`` (with a real
  Connector identity so ``_egress_dpop_key`` is populated).
* ``chat_completion_stream`` builds the DPoP proof from the same
  egress key and replays the request once on a 401 with the
  ``use_dpop_nonce`` marker, picking up the rotated nonce.
* A plain 401 with no marker propagates as ``HTTPStatusError`` so
  downstream forensic / dashboard layers see the upstream body.
"""
from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from cullis_sdk.client import CullisClient
from tests._mtls_helpers import mint_agent_cert


def _build_connector_client(tmp_path: Path, *, site_url: str = "https://mastio.test") -> CullisClient:
    identity_dir = tmp_path / "identity"
    identity_dir.mkdir(parents=True, exist_ok=True)
    cert_pem, key_pem = mint_agent_cert(org_id="demo-org", agent_name="alice")
    (identity_dir / "agent.crt").write_text(cert_pem)
    (identity_dir / "agent.key").write_text(key_pem)
    (identity_dir / "metadata.json").write_text(json.dumps({
        "agent_id": "demo-org::alice",
        "capabilities": [],
        "site_url": site_url,
        "issued_at": "2026-05-15T00:00:00+00:00",
    }))
    return CullisClient.from_connector(config_dir=tmp_path)


# ── chat_completion goes through _egress_http (not _authed_request) ─


def test_chat_completion_uses_egress_path(tmp_path, monkeypatch):
    """Pre-fix the SDK called _authed_request which signs with the
    ephemeral bearer DPoP key. This test pins the post-fix routing:
    _egress_http is called with the egress (persistent) DPoP signing.
    """
    client = _build_connector_client(tmp_path)
    egress_calls: list[tuple] = []

    fake_response = httpx.Response(
        200,
        json={"id": "ok", "choices": []},
        request=httpx.Request("POST", f"{client.base}/v1/llm/chat"),
    )

    def _fake_egress(method: str, path: str, **kwargs):
        egress_calls.append((method, path, kwargs))
        return fake_response

    monkeypatch.setattr(client, "_egress_http", _fake_egress)
    # Guard against any code path slipping into the bearer wrapper.
    def _explode(*a, **kw):
        raise AssertionError(
            "chat_completion must not call _authed_request (bearer path); "
            "use _egress_http (persistent DPoP) instead"
        )
    monkeypatch.setattr(client, "_authed_request", _explode)

    body = {
        "model": "claude-haiku-4-5",
        "messages": [{"role": "user", "content": "ping"}],
        "max_tokens": 5,
    }
    result = client.chat_completion(body)
    assert result == {"id": "ok", "choices": []}

    assert len(egress_calls) == 1
    method, path, kwargs = egress_calls[0]
    assert method == "post"
    assert path == "/v1/llm/chat"
    assert kwargs.get("json") == body


# ── chat_completion_stream signs with egress key + retries on nonce ─


class _StreamCM:
    """Hand-rolled httpx.stream() context manager double.

    Records the headers each ``__enter__`` saw so the test can assert
    the DPoP proof rotated to the fresh nonce on the retry path.
    """

    def __init__(self, plan):
        self._plan = list(plan)
        self.entered_headers: list[dict] = []
        self._current = None

    def __call__(self, method: str, url: str, headers=None, json=None):
        self._pending_headers = dict(headers or {})
        self._pending_url = url
        return self

    def __enter__(self):
        self.entered_headers.append(self._pending_headers)
        spec = self._plan.pop(0)
        self._current = spec
        return spec["response"]

    def __exit__(self, exc_type, exc, tb):
        self._current = None
        return False


def _streaming_response(*, status: int, body_bytes: bytes = b"",
                       text_frames: list[str] | None = None,
                       headers: dict | None = None) -> httpx.Response:
    """Build a minimal httpx.Response with iter_bytes + iter_text stubs.

    httpx.Response in stream mode reads from the transport on demand;
    we replace the iterators directly because the test never has a
    real socket. ``text_frames`` is yielded as SSE-shaped text on
    iter_text; ``body_bytes`` is yielded on iter_bytes (used for the
    401 branch where we drain the body to detect the marker).
    """
    req = httpx.Request("POST", "https://mastio.test/v1/llm/chat")
    resp = httpx.Response(status, request=req, headers=headers or {})

    def _iter_bytes(chunk_size=None):
        if body_bytes:
            yield body_bytes

    def _iter_text(chunk_size=None):
        for f in (text_frames or []):
            yield f

    resp.iter_bytes = _iter_bytes  # type: ignore[assignment]
    resp.iter_text = _iter_text    # type: ignore[assignment]
    return resp


def test_chat_completion_stream_signs_with_egress_dpop_key(tmp_path, monkeypatch):
    """Happy path: chat_completion_stream issues exactly one
    ``self._http.stream`` call, with a DPoP header signed by the
    egress (persistent) key, and yields the upstream frames."""
    client = _build_connector_client(tmp_path)
    assert client._egress_dpop_key is not None, (
        "egress DPoP key must load from identity/dpop.jwk for the egress "
        "path to sign; from_connector should auto-generate one"
    )
    expected_jkt = client._egress_dpop_key.thumbprint()

    stub = _StreamCM([{
        "response": _streaming_response(
            status=200,
            text_frames=[
                'data: {"choices":[{"index":0,"delta":{"content":"hi"}}]}\n\n',
                'data: [DONE]\n\n',
            ],
            headers={"dpop-nonce": "fresh-nonce-after-success"},
        ),
    }])
    monkeypatch.setattr(client._http, "stream", stub)

    # Pre-set the egress nonce to a known value so we can confirm it
    # rotates to the post-success value.
    client._egress_dpop_nonce = "old-nonce"

    frames = list(client.chat_completion_stream({
        "model": "claude-haiku-4-5",
        "messages": [{"role": "user", "content": "ping"}],
    }))

    assert len(stub.entered_headers) == 1
    dpop = stub.entered_headers[0].get("DPoP")
    assert dpop, "DPoP header must be set by proxy_headers()"
    # The DPoP header is a JWT; decode its protected header and pull
    # the JWK to confirm the signing key was the egress one.
    import base64, json as _json
    header_b64, payload_b64, _sig = dpop.split(".")
    header_b64 += "=" * (-len(header_b64) % 4)
    header = _json.loads(base64.urlsafe_b64decode(header_b64))
    # JWK thumbprint of the proof must match the persistent egress key.
    jwk = header["jwk"]
    canon = _json.dumps(
        {k: jwk[k] for k in ("crv", "kty", "x", "y") if k in jwk},
        separators=(",", ":"), sort_keys=True,
    ).encode()
    import hashlib
    proof_jkt = base64.urlsafe_b64encode(
        hashlib.sha256(canon).digest(),
    ).decode().rstrip("=")
    assert proof_jkt == expected_jkt

    assert any('"content":"hi"' in f for f in frames)
    assert any("[DONE]" in f for f in frames)
    # Success nonce rotated.
    assert client._egress_dpop_nonce == "fresh-nonce-after-success"


def test_chat_completion_stream_retries_on_use_dpop_nonce(tmp_path, monkeypatch):
    """A 401 with ``use_dpop_nonce`` in the body must trigger one re-open
    with the fresh nonce. Subsequent stream proceeds normally."""
    client = _build_connector_client(tmp_path)

    stub = _StreamCM([
        {
            "response": _streaming_response(
                status=401,
                body_bytes=b'{"detail":"use_dpop_nonce"}',
                headers={"dpop-nonce": "rotated-by-server"},
            ),
        },
        {
            "response": _streaming_response(
                status=200,
                text_frames=[
                    'data: {"choices":[{"index":0,"delta":{"content":"ok"}}]}\n\n',
                    'data: [DONE]\n\n',
                ],
            ),
        },
    ])
    monkeypatch.setattr(client._http, "stream", stub)

    frames = list(client.chat_completion_stream({
        "model": "claude-haiku-4-5",
        "messages": [{"role": "user", "content": "x"}],
    }))

    # Two opens: first 401, second 200.
    assert len(stub.entered_headers) == 2
    # Second call used the rotated nonce.
    assert client._egress_dpop_nonce == "rotated-by-server"
    # Stream content from the second response reached the caller.
    assert any('"content":"ok"' in f for f in frames)


def test_chat_completion_stream_401_without_marker_raises(tmp_path, monkeypatch):
    """A 401 that is NOT a DPoP nonce challenge must propagate as
    HTTPStatusError carrying the upstream detail (e.g. cert pinning
    mismatch, expired auth)."""
    client = _build_connector_client(tmp_path)

    stub = _StreamCM([{
        "response": _streaming_response(
            status=401,
            body_bytes=(
                b'{"detail":"DPoP proof was signed by a key not registered '
                b'for this agent."}'
            ),
            headers={},
        ),
    }])
    monkeypatch.setattr(client._http, "stream", stub)

    with pytest.raises(httpx.HTTPStatusError) as ei:
        list(client.chat_completion_stream({
            "model": "claude-haiku-4-5",
            "messages": [{"role": "user", "content": "x"}],
        }))
    assert ei.value.response.status_code == 401
    assert b"not registered for this agent" in ei.value.response.content
