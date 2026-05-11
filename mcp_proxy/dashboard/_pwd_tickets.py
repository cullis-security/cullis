"""One-shot temp-password ticket store (Wave B G2 fix).

Audit ref: imp/audits/2026-05-11-track-6-ai-frontdesk.md H-1.

Pre-fix the dashboard create-user / reset-password handlers redirected
to ``/proxy/users/<pid>?new_pw=<cleartext>`` so the receiving page
could render the temp password in a banner. The cleartext landed in
nginx access logs, the admin's browser history, and Referer headers
sent to any external link the dashboard contains.

Post-fix the redirect carries an opaque ticket id; this module mints
the ticket + stores the cleartext server-side with a short TTL +
single-consume semantics. The detail page reads the ticket once, the
store deletes it. Process-local dict is sufficient: Mastio runs
single-process per container in the documented deployment shape; a
future Frontdesk shared-mode deploy with workers > 1 would need to
move this to Redis (the same store the DPoP JTI cache uses).
"""
from __future__ import annotations

import secrets
import time
from dataclasses import dataclass


# Time-to-live for a minted ticket. 90 seconds is comfortable for
# admin "click create → read banner" UX without giving a stolen ticket
# a long replay window. Tickets are also single-consume — the dict
# pop on read makes a second GET impossible.
TICKET_TTL_SECONDS = 90.0


@dataclass(frozen=True)
class _StoredTicket:
    cleartext: str
    expires_at: float


_store: dict[str, _StoredTicket] = {}


def mint_password_ticket(cleartext: str) -> str:
    """Return an opaque ticket id bound to ``cleartext`` for ``TICKET_TTL_SECONDS``.

    Caller (mint flow) embeds the returned id in the redirect URL
    instead of the cleartext password. The detail-page handler then
    calls :func:`consume_password_ticket` to recover + render the
    cleartext, and the store drops the ticket on read.
    """
    _evict_expired()
    ticket = secrets.token_urlsafe(24)
    _store[ticket] = _StoredTicket(
        cleartext=cleartext,
        expires_at=time.monotonic() + TICKET_TTL_SECONDS,
    )
    return ticket


def consume_password_ticket(ticket: str | None) -> str | None:
    """Pop + return the cleartext bound to ``ticket``, or None on miss.

    Single-consume: the second call with the same ticket returns None.
    Expired tickets also return None (and are dropped from the store
    in the same call).
    """
    if not ticket:
        return None
    _evict_expired()
    stored = _store.pop(ticket, None)
    if stored is None:
        return None
    if stored.expires_at < time.monotonic():
        return None
    return stored.cleartext


def _evict_expired() -> None:
    """Drop entries past their TTL. Kept simple — O(n) in the size of
    the store; in practice the store has at most a handful of entries
    at any time."""
    now = time.monotonic()
    expired = [k for k, v in _store.items() if v.expires_at < now]
    for k in expired:
        _store.pop(k, None)
