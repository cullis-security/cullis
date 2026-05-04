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
    ) -> None:
        self._site_url = site_url
        self._agent_id = agent_id
        self._org_id = org_id
        self._cert_pem = cert_pem
        self._key_pem = key_pem
        self._verify_tls = verify_tls
        self._client: Any = None
        self._created_at: float = 0.0
        self._lock = threading.Lock()

    def _build(self) -> Any:
        """Create + login a fresh CullisClient. Caller holds the lock."""
        from cullis_sdk import CullisClient
        import time

        client = CullisClient(self._site_url, verify_tls=self._verify_tls)
        client.login_from_pem(
            self._agent_id, self._org_id, self._cert_pem, self._key_pem,
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
