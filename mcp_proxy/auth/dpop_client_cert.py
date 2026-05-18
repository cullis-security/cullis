"""DPoP-bound client-cert auth for ``/v1/egress/*`` (ADR-014 PR-B).

The egress surface previously combined ``X-API-Key`` (identity) with a
DPoP proof (per-request signature) — see ``mcp_proxy.auth.dpop_api_key``.
PR-A moved the wire to TLS with mTLS-required on egress; PR-B replaces
api_key with the client cert as the identity carrier (see
``mcp_proxy.auth.client_cert``). The DPoP proof stays — mTLS gives
identity at TLS-handshake granularity, DPoP gives proof-of-possession
at request granularity, and replay protection comes from the per-proof
``jti`` consumed atomically.

What changed vs. ``dpop_api_key``:
  * Identity comes from ``get_agent_from_client_cert`` instead of
    ``get_agent_from_api_key`` — the cert is the credential.
  * The proof's ``ath`` claim is no longer required. Previously it
    bound the proof to the api_key (sha256 hash). Without an api_key
    there is no token to bind; the proof binds to the request's
    ``htm`` + ``htu`` + ``jti`` + ``iat``, and the cert binds the
    *identity*. Combined, the threat model is unchanged: an attacker
    who steals the agent's private key + cert can issue valid proofs
    *and* mTLS handshake — that's the same exposure as today's
    "steals api_key + DPoP key".
  * Per-agent ``jkt`` pinning against ``internal_agents.dpop_jkt`` is
    preserved. A cryptographically-valid proof signed by a key the
    agent never registered is still rejected.

The ADR-012 LOCAL_TOKEN short-circuit (cross-org via BrokerBridge)
runs first — when the request bears a valid Bearer LOCAL_TOKEN the
cert path is bypassed, same as the api_key path bypassed it before.
"""
from __future__ import annotations

import hmac
import logging

from fastapi import HTTPException, Request, status

from mcp_proxy.auth.client_cert import get_agent_from_client_cert
from mcp_proxy.config import get_settings
from mcp_proxy.models import InternalAgent

_log = logging.getLogger("mcp_proxy")

_REQUIRE_NONCE_DEFAULT = True
_MODES = frozenset({"off", "optional", "required"})


def _build_htu(request: Request) -> str:
    """Mirror ``dpop_api_key._build_htu`` — same htu construction so a
    deploy that flips between the two during a transition window has
    consistent proof binding."""
    settings = get_settings()
    base = (settings.proxy_public_url or "").rstrip("/")
    if base:
        return base + request.url.path
    return str(request.url)


def _resolve_mode() -> str:
    mode = (get_settings().egress_dpop_mode or "off").strip().lower()
    if mode not in _MODES:
        _log.warning(
            "Unknown CULLIS_EGRESS_DPOP_MODE=%r — falling back to 'off'. "
            "Valid values: off | optional | required.",
            mode,
        )
        return "off"
    return mode


async def get_agent_from_dpop_client_cert(request: Request) -> InternalAgent:
    """Egress agent auth: client cert + optional DPoP proof.

    Order:
      0. ADR-027 ``culk_*`` user API token short-circuit. Token is
         hash-verified against ``user_api_tokens``; if present, the
         resolved user principal is returned without going through
         cert + DPoP. The Bearer token IS the proof of identity for
         OpenAI-compat clients (LibreChat, Cursor, Cherry Studio, ...).
      1. ADR-012 LOCAL_TOKEN short-circuit (cross-org Bearer JWT).
      2. ``get_agent_from_client_cert`` — identity from TLS-layer cert,
         pinned against ``internal_agents.cert_pem``, rate-limited.
      3. When ``CULLIS_EGRESS_DPOP_MODE`` is ``optional`` or
         ``required``, verify a DPoP proof from the ``DPoP`` header:
         htm/htu match, jti consumed once, iat in window, jkt matches
         the agent's registered ``dpop_jkt`` (when stored).

    ``off`` mode is a thin pass-through that returns the cert-auth'd
    agent — useful during the PR-B → PR-C → flip window.
    """
    # Step 0 — ADR-027 culk_ token. Returns None on miss so step 1+ run.
    from mcp_proxy.auth.api_token import _maybe_api_token_principal
    api_token_principal = await _maybe_api_token_principal(request)
    if api_token_principal is not None:
        return api_token_principal

    from mcp_proxy.auth.local_agent_dep import _maybe_local_internal_agent
    local_agent = await _maybe_local_internal_agent(request)
    if local_agent is not None:
        return local_agent

    agent = await get_agent_from_client_cert(request)

    mode = _resolve_mode()
    if mode == "off":
        return agent

    dpop_header = request.headers.get("DPoP")
    if not dpop_header:
        if mode == "required":
            _log.warning(
                "DPoP proof required but missing on egress request "
                "(agent=%s, path=%s)",
                agent.agent_id, request.url.path,
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="DPoP proof required — set "
                       "MCP_PROXY_EGRESS_DPOP_MODE=optional or upgrade "
                       "the client SDK to emit DPoP proofs.",
                headers={
                    "WWW-Authenticate":
                        'DPoP realm="egress", algs="ES256 PS256"',
                },
            )
        # optional mode — cert alone is acceptable during transition.
        return agent

    htu = _build_htu(request)
    htm = request.method

    # ``access_token=None`` — ADR-014 drops the ath binding (there's no
    # token to hash now that the cert is the credential). ``verify_dpop_proof``
    # treats ``access_token=None`` as "skip ath check".
    from mcp_proxy.auth.dpop import verify_dpop_proof  # local import: avoid cycle
    proof_jkt = await verify_dpop_proof(
        dpop_header,
        htm=htm,
        htu=htu,
        access_token=None,
        require_nonce=_REQUIRE_NONCE_DEFAULT,
    )

    stored_jkt = getattr(agent, "dpop_jkt", None)
    if stored_jkt:
        if not hmac.compare_digest(proof_jkt, stored_jkt):
            # Wave 2 fix 7+8 — fall back to ``previous_dpop_jkt`` when
            # the row carries an active grace window. Pre-fix, the
            # admin DPoP rotation endpoint (or the re-enrollment flow)
            # swapped ``dpop_jkt`` in place and every mid-flight proof
            # signed by the OLD key 401'd against the fresh jkt. With
            # grace, proofs signed by the previous key keep working
            # until ``previous_grace_period_expires_at`` passes.
            from mcp_proxy.auth.cert_grace import is_grace_active
            prev_jkt = getattr(agent, "previous_dpop_jkt", None)
            grace_expires = getattr(
                agent, "previous_grace_period_expires_at", None,
            )
            if (
                prev_jkt
                and is_grace_active(grace_expires)
                and hmac.compare_digest(proof_jkt, prev_jkt)
            ):
                _log.warning(
                    "DPoP proof jkt grace match (agent=%s, proof_jkt=%s, "
                    "previous_jkt=%s, grace_expires=%s) — Connector "
                    "should re-issue its DPoP keypair before the grace "
                    "window closes.",
                    agent.agent_id, proof_jkt, prev_jkt, grace_expires,
                )
                try:
                    from mcp_proxy.db import log_audit
                    await log_audit(
                        agent_id=agent.agent_id,
                        action="agent.dpop_pinning_grace_match",
                        status="success",
                        detail=(
                            f"grace_expires_at={grace_expires} "
                            f"presented_jkt={proof_jkt}"
                        ),
                    )
                except Exception as exc:  # noqa: BLE001 — best-effort
                    _log.debug(
                        "agent.dpop_pinning_grace_match audit emit failed: %s",
                        exc,
                    )
                # Fall through: same shape as a current-jkt match.
            else:
                _log.warning(
                    "DPoP proof jkt mismatch (agent=%s, proof_jkt=%s, "
                    "stored_jkt=%s)",
                    agent.agent_id, proof_jkt, stored_jkt,
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="DPoP proof was signed by a key not registered "
                           "for this agent.",
                )
    elif mode == "required":
        _log.warning(
            "DPoP required but agent %s has no registered dpop_jkt — "
            "re-enrollment needed to populate it.",
            agent.agent_id,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Agent has no DPoP key registered. Re-enroll the "
                   "Connector so it can publish its JWK thumbprint.",
        )

    # P1.2 — stamp the verified jkt into the per-request contextvar so
    # ``log_audit()`` downstream picks it up for the ``audit_log.dpop_jkt``
    # column without each call site forwarding it. Only stamps on the
    # success path (after pinning passed); a 401 above must not
    # correlate the audit row to a thumbprint the verifier just rejected.
    # Counterpart to the same wiring in ``dependencies.py`` (Bearer-DPoP)
    # and ``local_agent_dep.py`` (LOCAL_TOKEN): without this branch every
    # ``/v1/chat/completions``, ``/v1/llm/chat``, and ``/v1/egress/*`` row
    # left the column NULL even though the proof key is the agent's
    # pinned identity — exactly the lookup forensic queries need.
    from mcp_proxy.auth.dpop_context import set_dpop_jkt
    set_dpop_jkt(proof_jkt)

    # ADR-032 Layer 2 — best-effort. If the Connector caller carries a
    # valid user session in X-Cullis-Session-Token + X-Cullis-On-Behalf-Of-User
    # headers, stamp the per-request "on behalf of user" contextvar so
    # ``audit_log.on_behalf_of_user_id`` populates. Absent / invalid
    # session is silently logged and does NOT block the request — the
    # agent identity stays the primary credential.
    #
    # Thread the verified cert thumbprint (registered + pinned at the
    # ``get_agent_from_client_cert`` step above) into the verifier so
    # the docstring-claimed "session bound to a different device"
    # check actually runs — closes the dead pinning gap.
    from mcp_proxy.auth.user_session import maybe_stamp_user_session
    caller_thumb: str | None = None
    if agent.cert_pem:
        from mcp_proxy.auth.client_cert import _pem_der_digest
        digest = _pem_der_digest(agent.cert_pem)
        if digest is not None:
            caller_thumb = digest.hex()
    await maybe_stamp_user_session(
        request,
        caller_agent_id=agent.agent_id,
        caller_cert_thumbprint=caller_thumb,
    )

    _log.debug(
        "Egress mTLS+DPoP accepted (agent=%s, jkt=%s, mode=%s, bound=%s)",
        agent.agent_id, proof_jkt, mode, bool(stored_jkt),
    )
    return agent
