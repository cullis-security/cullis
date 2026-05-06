"""Tech-debt #2 — challenge-response login for device-code Connectors.

Companion to :mod:`mcp_proxy.auth.sign_assertion`. The legacy path signs
a ``client_assertion`` **on the agent's behalf** using the private key
stored in Vault / ``proxy_config`` — which only works when the key
actually lives on the proxy (BYOCA / Vault-held-key enrollments).
Device-code Connectors hold the key on the user's machine and get a
404 ``agent credentials not available on proxy``.

This module adds two endpoints for the client-holds-the-key case:

  POST /v1/auth/login-challenge           → issue a nonce
  POST /v1/auth/sign-challenged-assertion → verify a client-signed
                                             assertion + counter-sign

Flow (see imp/connector_login_challenge_response_design.md for the full
picture):

  1. Client posts ``/v1/auth/login-challenge`` authenticated by
     mTLS client cert (ADR-014). The Mastio mints a 32-byte random
     nonce, stores it under ``login_challenge:{agent_id}:{nonce}``
     with TTL 120s, and returns it.

  2. Client builds a standard broker ``client_assertion`` JWT
     (:func:`cullis_sdk.auth.build_client_assertion`) signed locally
     with its on-device key. The nonce is embedded as a claim so the
     signature covers it.

  3. Client posts ``/v1/auth/sign-challenged-assertion`` with the
     assertion + nonce. The Mastio:

       - consumes the nonce atomically (replay → 401);
       - extracts and verifies the x5c chain against the Org CA
         (reuses the primitives from :mod:`mcp_proxy.auth.local_token`);
       - pins the leaf against ``internal_agents.cert_pem``;
       - decodes + signature-verifies the assertion with the cert's
         public key;
       - cross-checks ``sub == agent.agent_id`` and
         ``decoded["nonce"] == nonce``;
       - counter-signs the assertion bytes with the Mastio leaf
         (ADR-009 Phase 2 primitive, unchanged).

  4. Client forwards the echoed assertion + counter-signature to
     ``/v1/auth/token`` — identical to the BYOCA path from there.

Anti-replay defences (layered):

  1. Nonce single-use (consumed on first valid call).
  2. Nonce bound to caller's ``agent_id`` via store key.
  3. Nonce is inside the signed assertion; tampering invalidates sig.
  4. Short assertion window (``exp - iat ≤ 300``).
  5. Cert pin against ``internal_agents.cert_pem``.
"""
from __future__ import annotations

import base64
import logging
import secrets
import time

import jwt as jose_jwt
from cryptography import x509
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from mcp_proxy.auth.challenge_store import get_challenge_store
from mcp_proxy.auth.client_cert import get_agent_from_client_cert
from mcp_proxy.models import InternalAgent

_log = logging.getLogger("mcp_proxy.auth.challenge_response")

router = APIRouter(tags=["auth"])

_NONCE_BYTES = 32
_NONCE_TTL_SECONDS = 120
_MAX_ASSERTION_LIFETIME_SECONDS = 300
_JWT_LEEWAY_SECONDS = 30


# ── Request / response models ───────────────────────────────────────


class LoginChallengeResponse(BaseModel):
    nonce: str = Field(
        ..., description="base64url-encoded 32-byte random nonce",
    )
    expires_in: int = Field(
        ..., description="seconds the nonce remains redeemable",
    )
    agent_id: str = Field(
        ..., description="the agent_id the nonce is bound to (caller's)",
    )


class SignChallengedAssertionRequest(BaseModel):
    client_assertion: str = Field(
        ..., description="JWT signed locally by the agent with x5c header",
    )
    nonce: str = Field(
        ..., description="nonce previously issued by /v1/auth/login-challenge",
    )


class SignChallengedAssertionResponse(BaseModel):
    client_assertion: str = Field(
        ..., description="echo of the input assertion — Mastio never re-signs",
    )
    agent_id: str
    mastio_signature: str | None = Field(
        None,
        description="ES256 signature over the assertion bytes, base64url — "
                    "None when ADR-009 Phase 2 isn't initialised yet",
    )


# ── Helpers (internal) ──────────────────────────────────────────────


def _issue_nonce() -> str:
    raw = secrets.token_bytes(_NONCE_BYTES)
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _get_agent_manager(request: Request):
    mgr = getattr(request.app.state, "agent_manager", None)
    if mgr is None:
        bridge = getattr(request.app.state, "broker_bridge", None)
        mgr = getattr(bridge, "_agent_manager", None) if bridge else None
    if mgr is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="agent manager not initialized",
        )
    return mgr


async def _load_org_ca():
    from mcp_proxy.db import get_config
    pem = await get_config("org_ca_cert")
    if not pem:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Org CA not loaded",
        )
    return x509.load_pem_x509_certificate(pem.encode())


def _log_clock_skew_hint(exc: jose_jwt.PyJWTError, agent_id: str) -> None:
    """If the JWT error looks clock-skew-adjacent and the skew is
    material (> 10s), emit a WARNING with an NTP hint — see note (3) in
    the orchestrator's brief. Otherwise return quietly."""
    msg = str(exc)
    if "expired" not in msg.lower() and "not yet valid" not in msg.lower():
        return
    # Pull the assertion's iat/exp back out (unverified) so we can reason
    # about skew. We're already about to reject the call — no risk.
    # PyJWTError doesn't carry the claims; caller hands them in via an
    # attribute set on the exception context we create.
    claims = getattr(exc, "_skew_claims", None)
    if not isinstance(claims, dict):
        return
    iat = claims.get("iat")
    exp = claims.get("exp")
    now = int(time.time())
    if isinstance(iat, (int, float)) and iat - now > 10:
        _log.warning(
            "login challenge assertion rejected for %s: iat %ds in the "
            "future — possible clock skew between Connector and Mastio, "
            "check NTP on both ends.",
            agent_id, int(iat - now),
        )
    elif isinstance(exp, (int, float)) and now - exp > 10:
        _log.warning(
            "login challenge assertion rejected for %s: expired %ds ago — "
            "clock skew suspect if the Connector clock trails; check NTP.",
            agent_id, int(now - exp),
        )


# ── Endpoints ───────────────────────────────────────────────────────


@router.post(
    "/v1/auth/login-challenge",
    response_model=LoginChallengeResponse,
    summary="Issue a single-use nonce for client-signed login",
)
async def login_challenge(
    request: Request,
    agent: InternalAgent = Depends(get_agent_from_client_cert),
) -> LoginChallengeResponse:
    """Mint a nonce bound to the authenticated agent.

    The nonce is stored with TTL 120s; the client must redeem it at
    ``/v1/auth/sign-challenged-assertion`` by embedding it in a signed
    ``client_assertion``. Replay of a consumed nonce returns 401.
    """
    store = get_challenge_store()
    # Tiny retry loop for the astronomically unlikely nonce collision —
    # 32 random bytes makes this ~0 in practice.
    nonce: str | None = None
    for _ in range(3):
        candidate = _issue_nonce()
        if await store.issue(agent.agent_id, candidate, _NONCE_TTL_SECONDS):
            nonce = candidate
            break
    if nonce is None:
        _log.error(
            "login challenge: nonce generator failed to produce a fresh "
            "nonce for %s after 3 tries", agent.agent_id,
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="unable to allocate login challenge nonce",
        )
    _log.info("login challenge issued for %s", agent.agent_id)
    return LoginChallengeResponse(
        nonce=nonce,
        expires_in=_NONCE_TTL_SECONDS,
        agent_id=agent.agent_id,
    )


@router.post(
    "/v1/auth/sign-challenged-assertion",
    response_model=SignChallengedAssertionResponse,
    summary="Verify a client-signed assertion + mastio counter-sign it",
)
async def sign_challenged_assertion(
    body: SignChallengedAssertionRequest,
    request: Request,
    agent: InternalAgent = Depends(get_agent_from_client_cert),
) -> SignChallengedAssertionResponse:
    """Verify a client-signed assertion + counter-sign it.

    The nonce is consumed atomically at the top of the handler — any
    failure after that point still leaves the nonce consumed, which is
    the desired property: one nonce = one attempt (successful or not).
    """
    # Local imports keep the module import-clean for the test harness
    # and avoid a cycle with mcp_proxy.auth.local_token.
    from mcp_proxy.auth.local_token import (
        _decode_assertion,
        _extract_x5c,
        _load_chain,
        _verify_chain,
    )
    from mcp_proxy.db import get_agent as db_get_agent

    store = get_challenge_store()
    if not await store.consume(agent.agent_id, body.nonce):
        _log.info(
            "login challenge rejected for %s: nonce invalid or already "
            "consumed", agent.agent_id,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="challenge nonce invalid, expired, or already consumed",
        )

    ca_cert = await _load_org_ca()

    # Pull the x5c chain, verify against the Org CA, then verify the
    # JWT signature with the leaf's public key — exactly the same chain
    # the broker will walk again at /v1/auth/token. Doing it here gives
    # fast-feedback + matching-failure-mode on bad certs.
    try:
        x5c_der = _extract_x5c(body.client_assertion)
        chain = _load_chain(x5c_der)
        _verify_chain(chain, ca_cert)
    except ValueError as exc:
        _log.info(
            "login challenge rejected for %s: x509 chain invalid: %s",
            agent.agent_id, exc,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"x509 chain: {exc}",
        ) from exc

    leaf = chain[0]
    try:
        claims = _decode_assertion(body.client_assertion, leaf)
    except jose_jwt.PyJWTError as exc:
        # Attach the unverified claims so _log_clock_skew_hint can read
        # them without re-parsing; safe because we're about to reject.
        try:
            exc._skew_claims = jose_jwt.decode(  # type: ignore[attr-defined]
                body.client_assertion, options={"verify_signature": False},
            )
        except Exception:
            pass
        _log_clock_skew_hint(exc, agent.agent_id)
        _log.info(
            "login challenge rejected for %s: assertion invalid: %s",
            agent.agent_id, exc,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"assertion: {exc}",
        ) from exc

    # sub must match the cert holder — prevents agent A from using
    # its own client cert to get B's assertion endorsed.
    if claims.get("sub") != agent.agent_id:
        _log.info(
            "login challenge rejected: assertion sub=%r, caller agent_id=%r",
            claims.get("sub"), agent.agent_id,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="assertion sub does not match authenticated agent",
        )

    # nonce claim binding — the nonce we just consumed must also be the
    # one the client signed over. If the client re-used a captured
    # assertion with a fresh nonce from the body, the assertion's
    # signed nonce won't match; we catch that here.
    if claims.get("nonce") != body.nonce:
        _log.info(
            "login challenge rejected for %s: assertion nonce mismatch",
            agent.agent_id,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="assertion nonce claim does not match request nonce",
        )

    # Cap assertion lifetime — defence against a legitimate-but-too-long
    # assertion being stockpiled offline. The SDK produces 5-minute
    # assertions by default (cullis_sdk/auth.py), matching this cap.
    iat = claims.get("iat")
    exp = claims.get("exp")
    if (
        not isinstance(iat, (int, float))
        or not isinstance(exp, (int, float))
        or exp - iat > _MAX_ASSERTION_LIFETIME_SECONDS
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"assertion lifetime must be ≤ "
                f"{_MAX_ASSERTION_LIFETIME_SECONDS}s"
            ),
        )

    # ADR-020 — typed principals (user / workload) skip the cert pin
    # check (see the matching branch in ``client_cert.py``): their certs
    # rotate every ~1h via ``/v1/principals/csr`` and the registry never
    # writes a pinned ``cert_pem`` for them. The chain walk + SPIFFE SAN
    # match enforced upstream by nginx ``ssl_verify_client`` is the
    # security gate; pinning a one-hour leaf would just force every
    # fresh login through a registry write the provisioner doesn't issue.
    is_typed_principal = (
        "::user::" in agent.agent_id or "::workload::" in agent.agent_id
    )
    if not is_typed_principal:
        # Cert pin — ``internal_agents.cert_pem`` is the row the operator
        # enrolled. A valid chain-of-trust cert that doesn't match the
        # pinned one is rejected (defence against silent re-issuance).
        db_row = await db_get_agent(agent.agent_id)
        if db_row is None or not db_row.get("is_active", True):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="agent not registered or deactivated",
            )
        pinned_pem = db_row.get("cert_pem")
        if not pinned_pem:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="agent has no pinned cert_pem on record",
            )
        try:
            pinned_cert = x509.load_pem_x509_certificate(pinned_pem.encode())
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="pinned cert_pem is malformed",
            ) from exc
        from cryptography.hazmat.primitives import serialization as _ser
        pinned_der = pinned_cert.public_bytes(_ser.Encoding.DER)
        leaf_der = leaf.public_bytes(_ser.Encoding.DER)
        if pinned_der != leaf_der:
            _log.info(
                "login challenge rejected for %s: leaf cert != pinned",
                agent.agent_id,
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="leaf certificate does not match pinned internal_agents.cert_pem",
            )

    # Counter-sign — reuse the ADR-009 Phase 2 primitive. When the
    # mastio identity isn't loaded yet (legacy deploys pre-ADR-009),
    # return None and the SDK will skip the X-Cullis-Mastio-Signature
    # header just like the legacy sign-assertion path does.
    mgr = _get_agent_manager(request)
    mastio_signature: str | None = None
    if getattr(mgr, "mastio_loaded", False):
        try:
            mastio_signature = mgr.countersign(body.client_assertion.encode())
        except Exception as exc:
            _log.warning(
                "mastio countersign failed for %s: %s",
                agent.agent_id, exc,
            )

    _log.info("login challenge endorsed for %s", agent.agent_id)
    return SignChallengedAssertionResponse(
        client_assertion=body.client_assertion,
        agent_id=agent.agent_id,
        mastio_signature=mastio_signature,
    )
