"""Strip X-Cullis-* headers from incoming client requests (P1.3).

Mastio's auth dependencies derive trust state from the DPoP token's
claim set and the verified principal cert chain; no handler reads
``X-Cullis-*`` off an inbound request. This middleware makes that
contract explicit at the request boundary: any ``X-Cullis-*``
header on an inbound HTTP request is dropped from the ASGI scope
before any downstream handler — including the auth dep — can
observe it. A future refactor that accidentally splices in
``request.headers["X-Cullis-Trust"]`` can therefore not be tricked
into believing a forged value.

Out of scope for the strip:

* Response headers. Mastio sets ``x-cullis-mode`` and a handful of
  ``x-cullis-shed-reason`` shedding annotations on its own
  responses; those flow server → client and the strip lives at the
  request entry, so they are unaffected.
* Outgoing requests Mastio originates (egress to upstream LLM,
  federation publisher to Court, MCP resource forwarder). Those
  build their own header dicts and are governed by their own
  allow-lists / deny-lists (e.g. ``_strip_dangerous_upstream_headers``).
* Inter-Mastio / Mastio→Court trust headers like
  ``X-Cullis-Mastio-Signature`` arriving at the Court. Those are
  Court business — this middleware lives on the Mastio side.

Logging is opt-in via ``CULLIS_LOG_STRIPPED_HEADERS=1``. The
default is silent because a noisy client that always sets a custom
``X-Cullis-*`` header would otherwise generate an entry per
request.

The strip is a pure ASGI op — modifying ``scope["headers"]`` —
rather than a ``BaseHTTPMiddleware`` so the rewrite lands before
any header-reading dep runs. Same rationale as
``global_rate_limit.py``.
"""
from __future__ import annotations

import logging
import os


_log = logging.getLogger("mcp_proxy")

# Lower-cased bytes for fast prefix compare on the ASGI raw header
# tuples (the wire is bytes and case-insensitive per RFC 9110 §5.1).
_PREFIX = b"x-cullis-"

# ADR-032 Layer 2 — the Connector legitimately propagates user identity
# via X-Cullis-Session-Token + X-Cullis-On-Behalf-Of-User and (R2) the
# device-posture envelope via X-Cullis-Device-Attestation. These three
# are the only client → proxy ``X-Cullis-*`` headers the Mastio reads
# from an inbound request; every other ``X-Cullis-*`` stays stripped so
# the blanket defence ("no handler trusts a forged trust header") still
# holds for the rest of the namespace.
#
# R2 NOTE: the Mastio passes the attestation header through to the
# policy / audit layer untouched. Verification of the claim (manufacturer
# whitelist, stale-window, effective_tier recompute) lands in F5; this
# allowlist is the wire-side prerequisite.
_ALLOWLIST: frozenset[bytes] = frozenset({
    b"x-cullis-session-token",
    b"x-cullis-on-behalf-of-user",
    b"x-cullis-device-attestation",
})


def _should_log_stripped() -> bool:
    return os.environ.get("CULLIS_LOG_STRIPPED_HEADERS", "0").strip() in {
        "1", "true", "yes", "on",
    }


class StripXCullisHeadersMiddleware:
    """Pure ASGI middleware. Wired via ``app.add_middleware(...)``."""

    def __init__(self, app):
        self.app = app
        # Snapshot at construction: tests can flip the env before
        # mounting the app and see the change without an os.environ
        # read on every request hot path.
        self._log_stripped = _should_log_stripped()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        stripped: list[bytes] = []
        kept: list[tuple[bytes, bytes]] = []
        for name, value in scope["headers"]:
            lowered = name.lower()
            if lowered.startswith(_PREFIX) and lowered not in _ALLOWLIST:
                stripped.append(name)
                continue
            kept.append((name, value))

        if stripped:
            # Shallow copy: ASGI scope is shared with the rest of the
            # stack, and mutating it in place would leak a no-X-Cullis
            # view of the same request to siblings.
            scope = dict(scope)
            scope["headers"] = kept
            if self._log_stripped:
                _log.info(
                    "stripped %d X-Cullis-* request header(s): %s "
                    "method=%s path=%s",
                    len(stripped),
                    [n.decode("ascii", "replace") for n in stripped],
                    scope.get("method"),
                    scope.get("path"),
                )

        await self.app(scope, receive, send)
