"""ADR-012 §3 — JWKS endpoint for the Mastio local issuer.

Exposes the Mastio public keys as a JWKS document so intra-org
validators (Mastio-side middleware, MCP aggregator, local session
store) can verify tokens without a remote round-trip.

The endpoint is served unauthenticated by design — it publishes public
key material only, mirrors the /.well-known/jwks.json pattern used
by the broker, and is read by internal components sharing the same
FastAPI process.

Phase 2.2 shift: the endpoint now enumerates every key the keystore
still accepts for verification (active + deprecated-but-within-grace),
not just the single active signer. During a rotation grace window this
lets an in-flight consumer that has cached the old ``kid`` re-fetch
the JWKS and still find the old key — without this, a rotate immediately
invalidates every token already in flight even though the keystore
would happily verify them internally.

Hardening (#282):
- 60-second edge cache via ``Cache-Control: public, max-age=60,
  stale-while-revalidate=60``. The key list turns over on
  grace-window scales (days by default), so 60s staleness is
  negligible and lets a CDN / reverse-proxy absorb the broadcast
  load instead of hammering the DB on every GET.
- ``ETag`` over the sorted JWK set; ``If-None-Match`` → 304 so
  well-behaved clients skip the body entirely after their first
  warm fetch.
- Per-IP rate-limit (30/min) — unauthenticated endpoints need this
  even when cached, because cache poisoning / cache-busting query
  strings can still reach the handler.
"""
from __future__ import annotations

import hashlib
import json

from fastapi import APIRouter, HTTPException, Request, Response, status

from mcp_proxy.auth.rate_limit import get_agent_rate_limiter

router = APIRouter(tags=["auth"])

# Budget matches the cache max-age: a well-behaved client polling
# once per minute never touches the limiter. A bare client polling
# every 2 seconds still gets in for the first half-minute of any
# burst window; only sustained traffic from one IP is throttled.
_JWKS_RATE_LIMIT_PER_MINUTE = 30


def _client_ip(request: Request) -> str:
    """Return the rate-limit subject for this request.

    H-xff audit fix: the previous implementation read the first
    entry from ``X-Forwarded-For`` directly, which is fully
    attacker-controlled when nginx is bypassed (host port exposed,
    misconfigured deploy) or when nginx forwards the upstream XFF
    as-is. An attacker could spray ``X-Forwarded-For: 1.2.3.4`` with
    a different value per request and never trip the JWKS limiter.

    The deployed shape runs uvicorn behind nginx with
    ``--proxy-headers --forwarded-allow-ips=<nginx>`` so
    ``ProxyHeadersMiddleware`` rewrites ``request.client`` from the
    last trusted XFF hop. Using ``request.client.host`` directly
    matches ``app.rate_limit.limiter.get_client_ip`` and the
    post-H9 dashboard login handler.
    """
    client = request.client
    return client.host if client is not None else "unknown"


def _compute_etag(keys: list[dict]) -> str:
    """Strong ETag over the JWK list.

    Hashes the full serialised JWK set (not just the kids) so any
    change to pubkey material busts caches even in the pathological
    kid-reuse case. Output is the quoted-string form per RFC 7232.
    """
    digest = hashlib.sha256(
        json.dumps(keys, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return f'"{digest[:32]}"'


def _etag_matches(header: str, etag: str) -> bool:
    """RFC 7232 §3.2 ``If-None-Match`` evaluation.

    A client may send ``*`` to match any tag, or a comma-separated
    list. Weak-ETag prefix ``W/`` is tolerated on the request side —
    our server-emitted tags are strong but clients in the wild
    sometimes weak-ify them.
    """
    value = header.strip()
    if value == "*":
        return True
    for candidate in value.split(","):
        token = candidate.strip()
        if token.startswith("W/"):
            token = token[2:]
        if token == etag:
            return True
    return False


@router.get(
    "/.well-known/jwks-local.json",
    summary="JWKS for the Mastio local issuer (intra-org tokens)",
)
async def jwks_local(request: Request, response: Response):
    # Namespace the rate-limit subject with ``ip:`` so it cannot
    # collide with any ``agent_id`` value using the same limiter. The
    # prefix is deliberate — a future refactor that sees
    # ``get_agent_rate_limiter`` and assumes the subject is an
    # agent_id would be wrong; the mcp_proxy limiter is
    # subject-agnostic despite the name (see its module docstring).
    # Do NOT drop the prefix.
    client_ip = _client_ip(request)
    if not await get_agent_rate_limiter().check(
        f"ip:{client_ip}", _JWKS_RATE_LIMIT_PER_MINUTE,
    ):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="jwks-local rate limit exceeded",
        )

    keystore = getattr(request.app.state, "local_keystore", None)
    if keystore is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="local keystore not initialized",
        )
    keys = await keystore.all_valid_keys()
    if not keys:
        # Empty keystore means Mastio identity hasn't been ensured yet
        # (lifespan didn't complete or migration ran but no row exists).
        # 503 is more actionable than `{"keys": []}` for the caller.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="no mastio signing keys available",
        )

    # Sort by ``kid`` before serialising (#282). The DB query already
    # orders by kid ASC (see ``db.get_mastio_keys_valid``) — re-sorting
    # here is defence-in-depth so this handler stays deterministic
    # even if the underlying keystore changes its ordering policy.
    # Kid-sorted output also closes the rotation-timing oracle where
    # ``keys[-1]`` used to always be the newest signer.
    sorted_keys = sorted(keys, key=lambda k: k.kid)
    jwk_list = [k.jwk() for k in sorted_keys]
    etag = _compute_etag(jwk_list)

    # Cache the public JWK set — grace window is measured in days,
    # 60s edge staleness is negligible in that context, and a CDN /
    # reverse-proxy absorbing the broadcast load is a real win.
    response.headers["Cache-Control"] = (
        "public, max-age=60, stale-while-revalidate=60"
    )
    response.headers["ETag"] = etag

    if_none_match = request.headers.get("if-none-match")
    if if_none_match and _etag_matches(if_none_match, etag):
        # 304 Not Modified — no body. The caller already has an
        # equivalent copy; they keep using it.
        return Response(status_code=status.HTTP_304_NOT_MODIFIED,
                        headers=dict(response.headers))

    return {"keys": jwk_list}
