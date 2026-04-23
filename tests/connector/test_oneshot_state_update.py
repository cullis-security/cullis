"""Receive_oneshot side-effects on the intent-tool state.

After a successful decrypt, the connector remembers the sender as
the active peer and the msg_id as reply_to so that subsequent
`reply()` / `chat()` tool calls Just Work without asking the user
to repeat themselves. This contract is the bridge between the
oneshot module (low-level wire format) and the intent module
(natural-language UX).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from cullis_connector.config import ConnectorConfig
from cullis_connector.state import get_state, reset_state
from cullis_connector.tools import oneshot


class _FakeFastMCP:
    def __init__(self) -> None:
        self.tools: dict[str, object] = {}

    def tool(self):
        def decorator(fn):
            self.tools[fn.__name__] = fn
            return fn
        return decorator


class _FakeClient:
    def __init__(
        self,
        rows: list[dict],
        decoder=None,
        signing_key: str = "PEM",
    ) -> None:
        self._rows = rows
        self._decoder = decoder or (lambda r: {"payload": {"text": "decoded"}})
        self._signing_key_pem = signing_key
        self._pubkey_cache: dict = {}

    def receive_oneshot(self) -> list[dict]:
        return list(self._rows)

    def decrypt_oneshot(self, row: dict, *, pubkey_fetcher=None) -> dict:
        # The real SDK accepts the fetcher kwarg; the fake swallows it.
        # These tests exercise state-cursor bookkeeping, not pubkey
        # lookup — the fetcher just needs to be a no-op.
        return self._decoder(row)

    def get_agent_public_key_via_egress(
        self, agent_id: str, force_refresh: bool = False,
    ) -> str:
        """Stub fetcher — the real one hits the proxy; for these
        cursor-bookkeeping tests we just need a value the caller can
        pass around."""
        return "PEM"


@pytest.fixture(autouse=True)
def _isolate_state(tmp_path: Path):
    reset_state()
    get_state().config = ConnectorConfig(
        site_url="https://mastio.test",
        config_dir=tmp_path,
        verify_tls=False,
        request_timeout_s=2.0,
    )
    yield
    reset_state()


@pytest.fixture
def receive_tool():
    mcp = _FakeFastMCP()
    oneshot.register(mcp)
    return mcp.tools["receive_oneshot"]


def _install_client(rows, decoder=None) -> _FakeClient:
    import time as _time

    client = _FakeClient(rows=rows, decoder=decoder)
    # Pre-seed the cache so prime() short-circuits on the TTL-fresh
    # branch. The timestamp must be current — a 0.0 seed is always
    # stale and would trigger the _egress_http refetch path (which
    # returns 404 in this fixture → PubkeyPrimeError on purpose).
    now = _time.time()
    for r in rows:
        client._pubkey_cache[r["sender_agent_id"]] = ("PEM", now)
    get_state().client = client
    return client


def test_receive_updates_last_peer_and_reply_to(receive_tool):
    rows = [{
        "sender_agent_id": "acme::mario",
        "msg_id": "msg-XYZ",
        "correlation_id": "corr-1",
        "reply_to": None,
        "payload_ciphertext": "{}",
    }]
    _install_client(rows)
    out = receive_tool()
    assert "1 one-shot" in out
    assert get_state().last_peer_resolved == "acme::mario"
    assert get_state().last_reply_to == "msg-XYZ"


def test_receive_canonicalizes_bare_sender(receive_tool):
    """Older inbox rows can carry the bare agent name; ensure we
    canonicalize it before storing in last_peer_resolved so reply()
    speaks the form /v1/egress/* expects."""
    # No identity loaded → canonical_recipient returns the input
    # unchanged. Set up state.extra["identity"] with a fake cert
    # whose org name is "acme".
    from unittest.mock import MagicMock
    fake_attr = MagicMock()
    fake_attr.value = "acme"
    fake_cert = MagicMock()
    fake_cert.subject.get_attributes_for_oid.return_value = [fake_attr]
    fake_identity = MagicMock()
    fake_identity.cert = fake_cert
    get_state().extra["identity"] = fake_identity

    rows = [{
        "sender_agent_id": "mario",
        "msg_id": "msg-A",
        "correlation_id": "corr-A",
        "reply_to": None,
        "payload_ciphertext": "{}",
    }]
    _install_client(rows)
    receive_tool()
    assert get_state().last_peer_resolved == "acme::mario"
    assert get_state().last_reply_to == "msg-A"


def test_receive_only_updates_on_decode_success(receive_tool):
    """If decrypt fails we don't pollute last_peer_resolved with a
    sender we couldn't actually verify."""
    def _broken(_row): raise RuntimeError("bad sig")
    rows = [{
        "sender_agent_id": "acme::mallory",
        "msg_id": "msg-bad",
        "correlation_id": "corr-bad",
        "reply_to": None,
        "payload_ciphertext": "{}",
    }]
    _install_client(rows, decoder=_broken)
    out = receive_tool()
    assert "decrypt failed" in out
    assert get_state().last_peer_resolved is None
    assert get_state().last_reply_to is None


def test_bad_signature_does_not_update_last_peer_resolved(receive_tool):
    """Explicit contract test (security audit NEW #3): when
    ``decrypt_oneshot`` raises for a signature-verification failure,
    ``state.last_peer_resolved`` MUST NOT be touched.

    The invariant protects the ``reply()`` tool: if we updated the
    cursor on an unverified row, a reply would be addressed to an
    attacker-controlled sender string. The existing test above covers
    a generic RuntimeError; this one pins the specific failure mode
    the SDK surfaces when signature verification (inner or outer)
    doesn't match, so regressions that re-order the bookkeeping
    around the except clause fail loudly.
    """
    # Seed a known-good prior state. If the bad-signature branch
    # leaks into last_peer_resolved, this value will be overwritten
    # and the assertion below will fire.
    state = get_state()
    state.last_peer_resolved = "acme::prior-known-good"
    state.last_reply_to = "msg-prior"

    def _sig_verify_fail(_row):
        # Mirrors what cullis_sdk.client.decrypt_oneshot raises when
        # the envelope signature chain fails to verify against the
        # primed pubkey cache.
        raise ValueError("envelope signature verification failed")

    rows = [{
        "sender_agent_id": "acme::mallory",
        "msg_id": "msg-forged",
        "correlation_id": "corr-forged",
        "reply_to": None,
        "payload_ciphertext": "{}",
    }]
    _install_client(rows, decoder=_sig_verify_fail)
    out = receive_tool()

    # User-visible failure trail is preserved.
    assert "decrypt failed" in out
    assert "signature verification failed" in out
    # State is unchanged from before the call — NOT updated to the
    # unverified sender.
    assert state.last_peer_resolved == "acme::prior-known-good"
    assert state.last_reply_to == "msg-prior"


def test_receive_picks_last_decoded_row_when_multiple(receive_tool):
    """Multiple rows decoded → the LAST decoded one wins. That's the
    one the user just read, so it's the most plausible reply target."""
    rows = [
        {
            "sender_agent_id": "acme::alice",
            "msg_id": "msg-1",
            "correlation_id": "corr-1",
            "reply_to": None,
            "payload_ciphertext": "{}",
        },
        {
            "sender_agent_id": "acme::bob",
            "msg_id": "msg-2",
            "correlation_id": "corr-2",
            "reply_to": None,
            "payload_ciphertext": "{}",
        },
    ]
    _install_client(rows)
    receive_tool()
    assert get_state().last_peer_resolved == "acme::bob"
    assert get_state().last_reply_to == "msg-2"


def test_receive_no_messages_leaves_state_alone(receive_tool):
    """Empty inbox = no state change (a previous reply context stays
    valid until something replaces it)."""
    state = get_state()
    state.last_peer_resolved = "acme::previous"
    state.last_reply_to = "msg-prev"
    _install_client([])
    out = receive_tool()
    assert "No one-shot messages" in out
    assert state.last_peer_resolved == "acme::previous"
    assert state.last_reply_to == "msg-prev"
