"""``culk_*`` user API token resolver (ADR-027 Phase 1, PR 2).

Short-circuit auth path for ``/v1/*`` egress endpoints. When the request
carries ``Authorization: Bearer culk_<...>`` and the token is active in
``user_api_tokens``, this module resolves it to an ``InternalAgent``
envelope and the downstream handlers attribute the request to the
underlying ``user`` principal — same as the LOCAL_TOKEN typed-principal
path in :mod:`mcp_proxy.auth.local_agent_dep`.

The resolver is intentionally side-by-side with (not instead of) the
DPoP-bound client-cert path. ADR-027 documents that an API token IS the
proof of identity for the OpenAI-compat protocol — there is no second
proof-of-possession layer the way DPoP gives one for cert-based auth.
The caller wrote ``Authorization: Bearer culk_X``, and we trust that
header because (a) the token cannot be guessed (256-bit entropy) and
(b) the token is hashed at rest so a DB leak does not recover it. TLS
is the transport security boundary.

The integration in ``mcp_proxy.auth.dpop_client_cert.get_agent_from_dpop_client_cert``
runs this resolver FIRST: if it returns an ``InternalAgent``, we return
it directly and skip the cert + DPoP chain entirely. The downstream
handler does not need to know which auth class minted the agent — the
``InternalAgent.principal_type=="user"`` is the signal that downstream
audit code uses to attribute correctly.

Touch tracking:
    Every successful auth updates ``last_used_at`` + ``last_used_ip`` on
    the token row via ``touch_user_api_token``. Best-effort: failures in
    the touch are logged but do not break the auth path (the row is
    valid even if we cannot stat-track).

Audit:
    Successful auth is recorded by the downstream handler's audit row
    (``agent_id=<user_principal>``). The resolver itself does not emit
    an audit entry per request — that would double-log every successful
    call. A failed auth attempt that supplied a malformed or unknown
    ``culk_*`` token is silent at this layer; the caller receives 401
    only when the rest of the auth chain also fails to identify them.
    Audit of failed tokens is left to the operator: ``last_used_at``
    stays NULL for unknown tokens, distinguishing them from "minted but
    never used".
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone

from fastapi import HTTPException, Request, status

from mcp_proxy.db import (
    touch_user_api_token,
    verify_user_api_token,
)
from mcp_proxy.models import InternalAgent

_log = logging.getLogger("mcp_proxy.auth.api_token")


def _path_matches_globs(request_path: str, patterns: list[str]) -> bool:
    """True if ``request_path`` matches any glob in ``patterns``.

    Glob semantics: ``*`` matches any character including ``/`` (so
    ``/v1/*`` matches the entire ``/v1/...`` subtree). This is the
    permissive shape operators expect when they mint a token "for the
    OpenAI-compat surface" — a stricter ``no-slash`` glob would force
    them to enumerate every nested route.

    Empty ``patterns`` is treated as "unscoped" (caller should have
    short-circuited that case before calling this helper).
    """
    if not patterns:
        return True
    for pattern in patterns:
        # Translate glob → regex: escape every literal char, then
        # replace the escaped ``\*`` with ``.*``. Anchor full match.
        regex = "^" + re.escape(pattern).replace(r"\*", ".*") + "$"
        if re.fullmatch(regex, request_path):
            return True
    return False

# Header name + scheme — case-insensitive parse below. ``culk_`` is the
# stable prefix documented in ADR-027 §wire format.
_AUTH_HEADER = "authorization"
_BEARER_PREFIX = "bearer "
_TOKEN_PREFIX = "culk_"


def _extract_bearer_token(request: Request) -> str | None:
    """Return the cleartext Bearer value if it looks like a culk_ token.

    Returns ``None`` for any of:
      * Missing ``Authorization`` header
      * Wrong scheme (not ``Bearer``)
      * Empty token after the scheme
      * Value that does not start with ``culk_`` (lets the LOCAL_TOKEN
        and other Bearer flavours pass through to their own resolvers
        untouched)
    """
    raw = request.headers.get(_AUTH_HEADER, "")
    if not raw:
        return None
    # Case-insensitive scheme match. ``startswith`` on lower-case avoids
    # allocating a full ``.lower()`` of the whole header for the path
    # where the header is also not a culk_ token (most requests today).
    if not raw[: len(_BEARER_PREFIX)].lower() == _BEARER_PREFIX:
        return None
    token = raw[len(_BEARER_PREFIX):].strip()
    if not token or not token.startswith(_TOKEN_PREFIX):
        return None
    return token


def _principal_type_for(principal_id: str) -> str:
    """Derive the principal_type from the principal_id shape.

    ADR-020 SPIFFE-style id format ``<org>::user::<name>`` or
    ``<org>::workload::<name>`` lets us infer the type without a second
    DB query. Default ``user`` if the id does not contain a typed
    segment — the token table is currently only minted for user
    principals (ADR-027 Phase 1 scope), but the resolver is robust to
    future expansion.
    """
    if "::workload::" in principal_id:
        return "workload"
    if "::agent::" in principal_id:
        return "agent"
    return "user"


def _display_name_for(principal_id: str) -> str:
    """Strip the org + type prefix to yield a human-readable display name.

    Mirrors :mod:`mcp_proxy.auth.local_agent_dep` so the audit / log /
    UI surface sees the same shape for the same identity regardless of
    whether the user authed via cookie sessione, LOCAL_TOKEN, or API
    token. Falls back to the full id if the split fails.
    """
    if "::" in principal_id:
        return principal_id.split("::", 2)[-1]
    return principal_id


def _client_ip(request: Request) -> str | None:
    """Best-effort client IP for the touch row.

    Mastio sits behind nginx in every realistic deployment, so the
    request's TCP peer is the proxy. The forwarded chain is in
    ``X-Forwarded-For`` — take the leftmost entry, that is the
    closest-to-original client IP added by the trusted reverse proxy.
    Reverse-proxy spoof scenarios are out of scope for this audit field
    (it is informational, not load-bearing). Falls back to the TCP peer.
    """
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        first = xff.split(",")[0].strip()
        if first:
            return first
    return request.client.host if request.client else None


async def _maybe_api_token_principal(request: Request) -> InternalAgent | None:
    """Resolve a ``culk_*`` API token to its user principal envelope.

    Returns ``None`` if the request does not carry a culk_ token, the
    token is malformed, or the token is unknown / revoked / expired.
    Returns the populated ``InternalAgent`` on success. Never raises:
    a missing or wrong token simply means "I don't handle this auth",
    not "auth failed" — that decision belongs to the resolver chain
    further down the pipeline.
    """
    token = _extract_bearer_token(request)
    if token is None:
        return None

    row = await verify_user_api_token(token)
    if row is None:
        # Bounded-time miss (see ``verify_user_api_token`` docstring).
        # We silently decline so the next resolver gets a shot, instead
        # of 401-ing here on what might be a perfectly valid LOCAL_TOKEN
        # that happens to share the Bearer scheme.
        return None

    # Wave A PR3 (audit 2026-05-11 Tema A) — enforce ``scope_paths``
    # at the resolver. Pre-fix the field was stored at mint time and
    # never read; a token "scoped" to ``/v1/chat/completions`` worked
    # on every endpoint guarded by ``get_agent_from_dpop_client_cert``,
    # i.e. the entire egress + A2A surface. Now: if the token has
    # non-empty ``scope_paths``, the request path MUST match at least
    # one glob, else 403. Default mint sets ``["/v1/*"]`` so any
    # non-OpenAI-compat call from a culk_-only client is refused.
    scope_paths = row.get("scope_paths") or []
    if scope_paths and not _path_matches_globs(request.url.path, scope_paths):
        _log.warning(
            "culk_ token denied: path %r not in scope_paths %r "
            "(token id=%s, principal=%s)",
            request.url.path, scope_paths,
            row.get("id"), row.get("principal_id"),
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "API token scope_paths does not allow this request path"
            ),
        )

    # Best-effort last_used touch. Never raises (see helper docstring).
    await touch_user_api_token(row["id"], client_ip=_client_ip(request))

    principal_id = row["principal_id"]
    return InternalAgent(
        agent_id=principal_id,
        display_name=_display_name_for(principal_id),
        capabilities=[],
        created_at=row.get("created_at") or datetime.now(timezone.utc).isoformat(),
        is_active=True,
        cert_pem=None,
        dpop_jkt=None,
        # ADR-027 tokens are minted for user principals using OpenAI-compat
        # clients to call ``/v1/chat/completions`` and friends — that is
        # local egress, not A2A. ``reach="both"`` keeps the door open
        # without forcing scope here; egress paths don't enforce reach.
        reach="both",
        principal_type=_principal_type_for(principal_id),
        # Pass scope down to the AI gateway dispatcher (PR3) so it can
        # enforce scope_providers on /v1/chat/completions. Other auth
        # paths (cert+DPoP, LOCAL_TOKEN) leave these as None.
        scope_providers=row.get("scope_providers") or [],
        scope_paths=scope_paths,
    )
