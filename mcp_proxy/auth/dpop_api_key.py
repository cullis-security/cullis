"""DPoP-bound X-API-Key authentication for the egress surface (F-B-11 Phase 1).

Mastio today authenticates ``/v1/egress/*`` agents with a plain bearer
``X-API-Key`` header (see ``mcp_proxy.auth.api_key.get_agent_from_api_key``).
A leaked ``.env`` = full impersonation toward the Connector, asymmetric to
the ingress surface which already enforces DPoP-bound JWT (RFC 9449) on
every authenticated request. Audit F-B-11 (#181).

This module introduces the dep that will replace the bearer path in
``/v1/egress/*``: ``get_agent_from_dpop_api_key``. It delegates the
API-key lookup and rate-limit enforcement to the legacy helper, then —
when the ``CULLIS_EGRESS_DPOP_MODE`` flag is ``optional`` or
``required`` — also verifies a DPoP proof carried in the ``DPoP``
header. The proof is bound to the API-key via the ``ath`` claim
(``base64url(sha256(api_key))``) and validated against the request's
method + URL + a one-shot ``jti``.

Phase 1 contract (this PR):
  * New dep exists and is importable.
  * Default flag ``off`` keeps runtime unchanged — no handler wired yet.
  * ``optional`` accepts legacy-only AND DPoP-bound requests.
  * ``required`` rejects legacy-only requests (bare bearer).
  * Per-agent JWK thumbprint binding (``cnf.jkt`` ↔ stored ``dpop_jkt``)
    is deferred to Phase 2 — the column does not yet exist and Agent B's
    parallel device_info migration owns the next slot.

Phase 2 will:
  * Add ``internal_agents.dpop_jkt`` via its own migration.
  * Populate it in the enrollment flow.
  * Extend this dep to compare the proof's ``jkt`` with the stored value
    — refusing requests whose proof is valid but signed by a key the
    agent never registered.

Phase 5 will swap the 12 ``/v1/egress/*`` handlers to ``Depends(...)``
this dep, still with ``off`` as the default until Phase 6 flips it.
"""
from __future__ import annotations

import hashlib
import hmac
import logging

from fastapi import HTTPException, Request, status

from mcp_proxy.auth.api_key import get_agent_from_api_key
from mcp_proxy.config import get_settings
from mcp_proxy.models import InternalAgent

_log = logging.getLogger("mcp_proxy")

# The ingress ``get_authenticated_agent`` uses RFC 9449 server nonces
# (``require_nonce=True``). Mirror that here for parity once the flag is
# flipped. Phase 3 SDK picks up the ``DPoP-Nonce`` header and retries.
_REQUIRE_NONCE_DEFAULT = True

# Recognised values for CULLIS_EGRESS_DPOP_MODE.
_MODES = frozenset({"off", "optional", "required"})


def _build_htu(request: Request) -> str:
    """Build the canonical HTU the SDK would have signed against.

    When ``proxy_public_url`` is set, every SDK builds proof htu from
    that base + the request path (regardless of whether the proxy sits
    behind a reverse proxy). Fall back to the request URL as uvicorn
    reconstructs it otherwise — the DPoP verifier normalises
    http/ws scheme pairs and strips queries/fragments so the two shapes
    are equivalent for request-path matching.
    """
    settings = get_settings()
    base = (settings.proxy_public_url or "").rstrip("/")
    if base:
        return base + request.url.path
    return str(request.url)


def _resolve_mode() -> str:
    """Read the CULLIS_EGRESS_DPOP_MODE flag and normalise.

    Unknown values fall back to ``off`` with a warning — we never want a
    typo in ``.env`` to unexpectedly enforce (``required``) or silently
    drop (``optional``) DPoP. Operators who flip the flag see the
    effect only when it matches one of the three canonical values.
    """
    mode = (get_settings().egress_dpop_mode or "off").strip().lower()
    if mode not in _MODES:
        _log.warning(
            "Unknown CULLIS_EGRESS_DPOP_MODE=%r — falling back to 'off'. "
            "Valid values: off | optional | required.",
            mode,
        )
        return "off"
    return mode


async def get_agent_from_dpop_api_key(request: Request) -> InternalAgent:
    """Egress agent auth with optional DPoP-bound proof (F-B-11).

    Always runs the legacy bearer lookup first so:
      * the API-key format is sanity-checked and bcrypt-verified,
      * rate-limiting accounts for every request regardless of mode,
      * the returned ``InternalAgent`` record drives downstream
        handlers exactly as before.

    When the mode flag is ``off`` the function is a thin wrapper and
    runtime is indistinguishable from the legacy dep. When it is
    ``optional`` or ``required``, a DPoP proof from the ``DPoP`` header
    is validated — htm/htu match the concrete request, jti is consumed
    atomically via the shared JTI store, iat is within the acceptance
    window, and ``ath`` must match ``base64url(sha256(api_key))`` so
    the proof is bound to *this* API-key and not a different one that
    the same attacker might also control.

    ADR-012 Phase 5: when ``local_auth_enabled`` is on and the request
    carries a Bearer LOCAL_TOKEN issued by this Mastio, return an
    ``InternalAgent`` synthesized from the token claims + DB record and
    skip the X-API-Key path entirely. Cross-org work downstream goes
    through ``BrokerBridge`` which performs its own per-agent login
    against the Court, so the LOCAL_TOKEN never leaves the Mastio.
    """
    from mcp_proxy.auth.local_agent_dep import _maybe_local_internal_agent
    local_agent = await _maybe_local_internal_agent(request)
    if local_agent is not None:
        return local_agent

    agent = await get_agent_from_api_key(request)

    mode = _resolve_mode()
    if mode == "off":
        return agent

    dpop_header = request.headers.get("DPoP")
    if not dpop_header:
        if mode == "required":
            _log.warning(
                "DPoP proof required but missing on egress request "
                "(agent=%s, path=%s)",
                agent.agent_id,
                request.url.path,
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="DPoP proof required — set MCP_PROXY_EGRESS_DPOP_MODE=optional "
                       "or upgrade the client SDK to emit DPoP proofs.",
                headers={"WWW-Authenticate": 'DPoP realm="egress", algs="ES256 PS256"'},
            )
        # optional mode, legacy bearer accepted — grace period.
        return agent

    # Verify the DPoP proof. ``verify_dpop_proof`` raises 401 on every
    # failure; we let it propagate.
    api_key = request.headers.get("X-API-Key") or ""
    htu = _build_htu(request)
    htm = request.method

    from mcp_proxy.auth.dpop import verify_dpop_proof  # local import: avoid cycle
    proof_jkt = await verify_dpop_proof(
        dpop_header,
        htm=htm,
        htu=htu,
        access_token=api_key,
        require_nonce=_REQUIRE_NONCE_DEFAULT,
    )

    # F-B-11 Phase 2 — pin the proof to the agent's registered JWK.
    # A cryptographically-valid proof is not sufficient on its own: the
    # keypair that signed it must be the one the agent registered at
    # enrollment. Without this pin, an attacker who steals an API-key
    # but not the agent's private key could still synthesise a valid
    # proof with their own keypair. The jkt comparison closes that.
    stored_jkt = getattr(agent, "dpop_jkt", None)
    if stored_jkt:
        if not hmac.compare_digest(proof_jkt, stored_jkt):
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
        # ``required`` mode with no stored jkt = agent has not been
        # re-enrolled via the Phase 3 flow. Refuse so operators who
        # flipped the flag see the gap surface instead of silently
        # accepting every proof. Phase 3 teaches the SDK to push a
        # JWK during enrollment; existing agents must re-enroll before
        # the operator flips to ``required``.
        _log.warning(
            "DPoP required but agent %s has no registered dpop_jkt — "
            "re-enrollment needed to populate it (see F-B-11 Phase 3).",
            agent.agent_id,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Agent has no DPoP key registered. Re-enroll the "
                   "Connector so it can publish its JWK thumbprint.",
        )

    _log.debug(
        "Egress DPoP proof accepted (agent=%s, jkt=%s, mode=%s, bound=%s)",
        agent.agent_id, proof_jkt, mode, bool(stored_jkt),
    )
    return agent


def compute_api_key_ath(api_key: str) -> str:
    """Helper: compute the ``ath`` claim a DPoP proof must carry for
    this API-key. Exported for SDK reuse and for tests — the server
    side delegates to ``verify_dpop_proof`` which computes it inline.
    """
    import base64
    digest = hashlib.sha256(api_key.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
