"""Per-user credential cache for Cullis Frontdesk shared mode.

Holds the (cert_pem, KMS-bound private-key handle, expiry) for each
provisioned user principal. Bounded LRU + TTL eviction so a busy
deployment cannot grow the cache without bound and a stale cert
cannot live longer than its issuance window.

The private key never leaves the KMS — this cache holds only:
  - the principal_id
  - the cert PEM (public material)
  - the KMS key_handle (opaque reference for log correlation)
  - the cert expiry timestamp

A miss triggers ``UserProvisioner.provision()`` which generates a
fresh keypair via the KMS, builds a CSR, ships it to Mastio for
signing, attaches the cert in the KMS, and populates the cache.
"""
from __future__ import annotations

import asyncio
import logging
import time
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

_log = logging.getLogger("cullis_connector.ambassador.shared.credentials")

DEFAULT_CACHE_SIZE = 1024
DEFAULT_TTL_SECONDS = 3600  # 1h, matches USER_CERT_TTL on the Mastio side


@dataclass(frozen=True)
class UserCredentials:
    """Snapshot of a provisioned user principal.

    The Ambassador uses ``cert_pem`` to assert identity to Mastio
    (x5c JWT header) and ``key_pem`` to sign the JWT + DPoP proofs.

    v0.1 limitation: the private key lives in process memory for
    the duration of the cache TTL (1h). v0.2 will move signing to
    the KMS via a signer-callable refactor of ``CullisClient`` so
    private key material never leaves the KMS boundary. Documented
    in ADR-021 §5 as the embedded-backend trade-off.
    """

    principal_id: str
    cert_pem: str
    key_pem: str
    cert_not_after: datetime

    def expired(self, *, now: Optional[float] = None) -> bool:
        cur = now if now is not None else time.time()
        return cur >= self.cert_not_after.timestamp()


class UserCredentialCache:
    """LRU + TTL cache keyed by ``principal_id``.

    Async-safe: every read/write goes through ``self._lock`` so
    concurrent provisioning attempts do not corrupt the OrderedDict.
    Provisioning itself happens outside the cache lock; the cache
    only serialises the in-memory map.
    """

    def __init__(
        self,
        *,
        max_size: int = DEFAULT_CACHE_SIZE,
    ) -> None:
        if max_size <= 0:
            raise ValueError("max_size must be > 0")
        self._max_size = max_size
        self._items: "OrderedDict[str, UserCredentials]" = OrderedDict()
        self._lock = asyncio.Lock()

    async def get(self, principal_id: str) -> Optional[UserCredentials]:
        """Return the cached credentials, or ``None`` on miss / expiry."""
        async with self._lock:
            cred = self._items.get(principal_id)
            if cred is None:
                return None
            if cred.expired():
                # Lazy expiry: evict on read so the next provision()
                # call repopulates with a fresh cert.
                del self._items[principal_id]
                return None
            self._items.move_to_end(principal_id)
            return cred

    async def put(self, cred: UserCredentials) -> None:
        async with self._lock:
            self._items[cred.principal_id] = cred
            self._items.move_to_end(cred.principal_id)
            while len(self._items) > self._max_size:
                evicted_id, _ = self._items.popitem(last=False)
                _log.debug("ambassador credentials cache evicted %s", evicted_id)

    async def invalidate(self, principal_id: str) -> bool:
        """Drop the entry. Returns True if something was removed."""
        async with self._lock:
            return self._items.pop(principal_id, None) is not None

    async def size(self) -> int:
        async with self._lock:
            return len(self._items)


__all__ = [
    "DEFAULT_CACHE_SIZE",
    "DEFAULT_TTL_SECONDS",
    "UserCredentialCache",
    "UserCredentials",
]
