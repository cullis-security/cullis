"""Lazy CullisClient cache for the Ambassador.

In single-user mode there is exactly one identity, so we keep one
CullisClient alive for the lifetime of the dashboard process. The
client is recreated when its access token nears expiry (re-login) or
when an SDK call raises an auth error (defensive recreate).

Multi-tenant mode (Step 3) replaces this singleton with a per-agent
LRU cache keyed by ``agent_id``.
"""
from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Any

_log = logging.getLogger("cullis_connector.ambassador.client")

# Re-login this much before the access token expires. The SDK exposes
# token expiry on the client object; v0.1 keeps it simple by recreating
# every N seconds since last login. Fine-grained expiry handling is a
# v0.2 polish.
_RELOGIN_INTERVAL_S = 10 * 60  # 10 minutes


class AmbassadorClient:
    """Thread-safe singleton holder of an authenticated CullisClient.

    The Ambassador reads ``site_url``, ``cert_path``, ``key_path``,
    ``agent_id``, ``org_id`` from the Connector config and re-uses the
    same SDK client across requests.
    """

    def __init__(
        self,
        *,
        site_url: str,
        agent_id: str,
        org_id: str,
        cert_pem: str,
        key_pem: str,
        verify_tls: bool | str = True,
        dpop_key_path: Path | None = None,
    ) -> None:
        self._site_url = site_url
        self._agent_id = agent_id
        self._org_id = org_id
        self._cert_pem = cert_pem
        self._key_pem = key_pem
        self._verify_tls = verify_tls
        # ``dpop_key_path`` is the on-disk persistent egress DPoP key
        # (``<config_dir>/identity/dpop.jwk``) whose thumbprint is
        # pinned in ``internal_agents.dpop_jkt`` at enrollment time.
        # The SDK's chat completion path (PR #724) signs with this key
        # via ``_egress_dpop_key`` so the cert-pinned route on the
        # Mastio accepts the call. ``None`` falls back to the legacy
        # behaviour (bearer-DPoP path only) which 401s on chat.
        self._dpop_key_path = dpop_key_path
        self._client: Any = None
        self._created_at: float = 0.0
        self._lock = threading.Lock()

    def _build(self) -> Any:
        """Create + login a fresh CullisClient. Caller holds the lock."""
        from cullis_sdk import CullisClient
        import os
        import time

        # CullisClient default timeout is 10 s which kills any chain-
        # of-thought local Ollama model (qwen3.5, deepseek-r1 routinely
        # take 20-60 s). Read the same env the rest of the Connector
        # uses so the SDK and the operator's expectation match.
        try:
            req_timeout = float(os.environ.get("CULLIS_REQUEST_TIMEOUT_S", "10"))
        except ValueError:
            req_timeout = 10.0
        client = CullisClient(
            self._site_url,
            verify_tls=self._verify_tls,
            timeout=req_timeout,
        )
        client.login_from_pem(
            self._agent_id, self._org_id, self._cert_pem, self._key_pem,
        )
        # PR #724 follow-up — populate the egress DPoP key the chat
        # completion path now requires. ``login_from_pem`` only sets
        # the ephemeral ``_dpop_privkey`` for the bearer-DPoP wrapper;
        # ``_egress_dpop_key`` stays ``None`` on the basic constructor
        # path, so a Mastio call to ``/v1/llm/chat`` would arrive
        # without a DPoP header and be refused. Load the persistent
        # key from disk so its thumbprint matches the pinned
        # ``internal_agents.dpop_jkt``.
        if self._dpop_key_path is not None:
            try:
                from cullis_sdk.dpop import DpopKey
                # Mirror ``from_connector`` (cullis_sdk/client.py:1100-1107):
                # load when the file exists, generate + persist on
                # cold-start. ``DpopKey.load_or_generate`` takes an
                # ``agent_id`` + ``base_dir`` form which doesn't match the
                # Connector-laid-out ``identity/dpop.jwk`` path, so we
                # use the explicit load/generate pair here.
                if self._dpop_key_path.exists():
                    client._egress_dpop_key = DpopKey.load(self._dpop_key_path)
                else:
                    client._egress_dpop_key = DpopKey.generate(
                        path=self._dpop_key_path,
                    )
                _log.info(
                    "ambassador egress DPoP key loaded "
                    "(jkt=%s…)",
                    client._egress_dpop_key.thumbprint()[:16],
                )
            except Exception as exc:
                # Cert-pinned routes will 401 if this fails. Log loudly
                # but don't refuse to build — bearer-DPoP routes like
                # ``/v1/mcp`` still work, and a clear runtime error on
                # the chat path is easier to diagnose than a silent
                # build-time refusal.
                _log.warning(
                    "ambassador egress DPoP key load failed (%s): %s. "
                    "Chat completions through this client will 401 on "
                    "Mastio's cert-pinned path until the file is "
                    "readable at %s.",
                    type(exc).__name__, exc, self._dpop_key_path,
                )
        self._client = client
        self._created_at = time.monotonic()
        _log.info(
            "ambassador SDK login ok agent=%s org=%s site=%s",
            self._agent_id, self._org_id, self._site_url,
        )
        return client

    def get(self) -> Any:
        """Return a logged-in CullisClient, building or refreshing as needed."""
        import time

        with self._lock:
            now = time.monotonic()
            if self._client is None or (now - self._created_at) > _RELOGIN_INTERVAL_S:
                self._build()
            return self._client

    def invalidate(self) -> None:
        """Drop the cached client so the next ``get()`` re-logs in.

        Called by the router on a 401 from the SDK so a stale token
        does not break a long-running process.
        """
        with self._lock:
            self._client = None
            self._created_at = 0.0
            _log.info("ambassador client cache invalidated")

    @property
    def agent_id(self) -> str:
        return self._agent_id

    @property
    def org_id(self) -> str:
        return self._org_id
