"""ADR-010 Phase 2 — Mastio-side authoritative agent registry admin API.

This is the endpoint a Mastio admin (or automation like the sandbox
bootstrap after Phase 4) calls to register an agent **on the Mastio**.
Crucially, registering here does **not** automatically publish to the
Court — the ``federated`` flag controls that. Setting ``federated=true``
(either at create or via PATCH) enqueues a push that the federation
publisher loop (Phase 3) will carry to the Court via ADR-009
counter-signed ``POST /v1/federation/publish-agent``.

Auth: ``X-Admin-Secret`` (same contract as ``/v1/admin/mastio-pubkey``
and the MCP resources admin API). These operations are in-house admin
surface — the Connector dashboard can use the ADR-009 session flow,
scripts just pass the admin secret.

Register vs update:
- POST  ``/v1/admin/agents``                   — create new agent row
                                                (emits cert signed by
                                                Agent CA / Org CA and
                                                API key if enrolling)
- PATCH ``/v1/admin/agents/{id}/federated``    — flip the federate flag
- DELETE ``/v1/admin/agents/{id}``             — deactivate (revoke-at-
                                                Court follows if the
                                                agent was federated).

Cert issuance reuses ``AgentManager._generate_agent_cert`` so the
chain stays Org CA → Agent CA → leaf (or Org CA → leaf in the
pre-Agent-CA sandbox). No new PKI logic here.
"""
from __future__ import annotations

import bcrypt
import hmac
import json
import logging
import secrets
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from mcp_proxy.config import get_settings
from mcp_proxy.db import get_db, log_audit


_log = logging.getLogger("mcp_proxy.admin.agents")

router = APIRouter(prefix="/v1/admin/agents", tags=["admin"])


# ── auth ────────────────────────────────────────────────────────────────

def _require_admin_secret(
    x_admin_secret: str = Header(..., alias="X-Admin-Secret"),
) -> None:
    settings = get_settings()
    if not hmac.compare_digest(x_admin_secret, settings.admin_secret):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="invalid admin secret",
        )


# ── models ──────────────────────────────────────────────────────────────

class AgentCreateRequest(BaseModel):
    # Short name only; the mastio scopes it to its own org_id.
    agent_name: str = Field(..., pattern=r"^[a-zA-Z0-9._-]{1,64}$")
    display_name: str = Field("", max_length=256)
    capabilities: list[str] = Field(default_factory=list)
    federated: bool = False
    # Optional pre-generated cert+key pair, used by the sandbox bootstrap
    # that owns the same Org CA and wants to share the private key with
    # an out-of-Mastio agent container via a volume mount. When both are
    # provided the Mastio skips its own ``_generate_agent_cert`` call
    # and stores the inbound material as-is (Org CA chain is still the
    # trust anchor; re-emitting would invalidate the volume-shared key).
    cert_pem: str | None = None
    private_key_pem: str | None = None


class AgentCreateResponse(BaseModel):
    agent_id: str
    display_name: str
    capabilities: list[str]
    federated: bool
    api_key: str  # plaintext — shown exactly once
    cert_pem: str


class AgentOut(BaseModel):
    agent_id: str
    display_name: str
    capabilities: list[str]
    federated: bool
    federated_at: str | None
    federation_revision: int
    is_active: bool
    created_at: str


class FederatedPatch(BaseModel):
    federated: bool


# ── helpers ─────────────────────────────────────────────────────────────

def _api_key_for(agent_name: str) -> str:
    """Cryptographically-strong local API key. 32 random hex chars + prefix
    so it's recognizable in logs and can be revoked without re-scanning."""
    return f"sk_local_{agent_name}_{secrets.token_hex(16)}"


def _bcrypt_hash(raw: str) -> str:
    return bcrypt.hashpw(raw.encode(), bcrypt.gensalt(rounds=12)).decode()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _require_agent_mgr(request: Request):
    mgr = getattr(request.app.state, "agent_manager", None)
    if mgr is None or not getattr(mgr, "ca_loaded", False):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="agent manager not initialized — Org CA not loaded",
        )
    return mgr


# ── endpoints ───────────────────────────────────────────────────────────

@router.post(
    "",
    response_model=AgentCreateResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(_require_admin_secret)],
)
async def create_agent(
    body: AgentCreateRequest,
    request: Request,
) -> AgentCreateResponse:
    """Register a new agent on the Mastio.

    Emits an Org-CA-signed x509 cert + a local API key. Writes the row
    to ``internal_agents`` with ``federated`` set per the request. The
    Phase 3 publisher picks it up if federated=True.
    """
    mgr = await _require_agent_mgr(request)
    agent_name = body.agent_name
    agent_id = f"{mgr.org_id}::{agent_name}"

    # If both cert_pem + private_key_pem arrived in the body, trust the
    # caller (e.g. the sandbox bootstrap that owns the same Org CA and
    # has already shared the private key with an agent container over a
    # volume mount). Otherwise mint a fresh pair via the Org CA.
    if body.cert_pem and body.private_key_pem:
        cert_pem = body.cert_pem
        key_pem = body.private_key_pem
    elif body.cert_pem or body.private_key_pem:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="cert_pem and private_key_pem must be provided together",
        )
    else:
        cert_pem, key_pem = mgr._generate_agent_cert(agent_name)

    # Persist the private key. Store in Vault if configured, otherwise
    # fall back to proxy_config (same pattern as AgentManager.create_agent).
    try:
        await mgr._store_key_vault(agent_id, key_pem)
    except Exception as exc:
        from mcp_proxy.db import set_config
        _log.info("Vault unavailable for %s (%s) — stashing key in proxy_config",
                  agent_id, exc)
        await set_config(f"agent_key:{agent_id}", key_pem)

    api_key = _api_key_for(agent_name)
    api_key_hash = _bcrypt_hash(api_key)

    ts = _now_iso()
    try:
        async with get_db() as conn:
            await conn.execute(
                text(
                    """
                    INSERT INTO internal_agents (
                        agent_id, display_name, capabilities, api_key_hash,
                        cert_pem, created_at, is_active,
                        federated, federated_at, federation_revision,
                        enrollment_method, enrolled_at
                    ) VALUES (
                        :aid, :name, :caps, :hash,
                        :cert, :now, 1,
                        :federated, NULL, 1,
                        'admin', :now
                    )
                    """
                ),
                {
                    "aid": agent_id,
                    "name": body.display_name or agent_name,
                    "caps": json.dumps(body.capabilities),
                    "hash": api_key_hash,
                    "cert": cert_pem,
                    "now": ts,
                    # Bind a Python bool so SQLAlchemy + asyncpg write a
                    # real BOOLEAN on Postgres (integer binds raise
                    # "column is of type boolean but expression is of type
                    # integer"). SQLite accepts the bool as 0/1.
                    "federated": bool(body.federated),
                },
            )
    except IntegrityError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"agent {agent_id!r} already registered",
        ) from exc

    await log_audit(
        agent_id="admin",
        action="agent.create",
        status="success",
        detail=f"agent_id={agent_id} federated={body.federated}",
    )

    return AgentCreateResponse(
        agent_id=agent_id,
        display_name=body.display_name or agent_name,
        capabilities=body.capabilities,
        federated=body.federated,
        api_key=api_key,
        cert_pem=cert_pem,
    )


@router.get(
    "",
    response_model=list[AgentOut],
    dependencies=[Depends(_require_admin_secret)],
)
async def list_agents_endpoint() -> list[AgentOut]:
    async with get_db() as conn:
        rows = (await conn.execute(
            text(
                """
                SELECT agent_id, display_name, capabilities, is_active,
                       federated, federated_at, federation_revision,
                       created_at
                  FROM internal_agents
                 ORDER BY created_at DESC
                """
            )
        )).mappings().all()
    return [
        AgentOut(
            agent_id=r["agent_id"],
            display_name=r["display_name"],
            capabilities=json.loads(r["capabilities"] or "[]"),
            federated=bool(r["federated"]),
            federated_at=str(r["federated_at"]) if r["federated_at"] else None,
            federation_revision=int(r["federation_revision"]),
            is_active=bool(r["is_active"]),
            created_at=str(r["created_at"]),
        )
        for r in rows
    ]


@router.patch(
    "/{agent_id}/federated",
    response_model=AgentOut,
    dependencies=[Depends(_require_admin_secret)],
)
async def patch_federated(agent_id: str, body: FederatedPatch) -> AgentOut:
    """Toggle the federate flag. Phase 3 publisher will pick up the
    change on its next pass and PUT/revoke the agent at the Court."""
    async with get_db() as conn:
        row = (await conn.execute(
            text("SELECT 1 FROM internal_agents WHERE agent_id = :aid"),
            {"aid": agent_id},
        )).first()
        if row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="agent not found",
            )

        await conn.execute(
            text(
                """
                UPDATE internal_agents
                   SET federated = :fed,
                       federation_revision = federation_revision + 1
                 WHERE agent_id = :aid
                """
            ),
            {"fed": bool(body.federated), "aid": agent_id},
        )

        updated = (await conn.execute(
            text(
                """
                SELECT agent_id, display_name, capabilities, is_active,
                       federated, federated_at, federation_revision, created_at
                  FROM internal_agents WHERE agent_id = :aid
                """
            ),
            {"aid": agent_id},
        )).mappings().first()

    await log_audit(
        agent_id="admin",
        action="agent.federated_patched",
        status="success",
        detail=f"agent_id={agent_id} federated={body.federated}",
    )

    return AgentOut(
        agent_id=updated["agent_id"],
        display_name=updated["display_name"],
        capabilities=json.loads(updated["capabilities"] or "[]"),
        federated=bool(updated["federated"]),
        federated_at=str(updated["federated_at"]) if updated["federated_at"] else None,
        federation_revision=int(updated["federation_revision"]),
        is_active=bool(updated["is_active"]),
        created_at=str(updated["created_at"]),
    )


@router.delete(
    "/{agent_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    dependencies=[Depends(_require_admin_secret)],
)
async def deactivate_agent_endpoint(agent_id: str):
    """Soft-delete: ``is_active=0``. If the agent was federated, Phase 3
    publisher will follow up with a revoke push to the Court."""
    async with get_db() as conn:
        result = await conn.execute(
            text(
                """
                UPDATE internal_agents
                   SET is_active = 0,
                       federation_revision = federation_revision + 1
                 WHERE agent_id = :aid AND is_active = 1
                """
            ),
            {"aid": agent_id},
        )
        if result.rowcount == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="agent not found or already inactive",
            )

    await log_audit(
        agent_id="admin",
        action="agent.deactivated",
        status="success",
        detail=f"agent_id={agent_id}",
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ── F-B-11 Phase 3a — DPoP JWK registration ─────────────────────────

class DpopJwkRequest(BaseModel):
    """Public JWK the agent will use to sign DPoP proofs.

    Must be a PUBLIC key — presence of the ``d`` (private component)
    field is a hard reject. The server stores only the RFC 7638
    thumbprint; the JWK itself is not retained.
    """
    jwk: dict = Field(
        ...,
        description="Public JWK (EC P-256 or RSA). ``d`` field rejected.",
    )


class DpopJwkResponse(BaseModel):
    agent_id: str
    dpop_jkt: str


@router.post(
    "/{agent_id}/dpop-jwk",
    response_model=DpopJwkResponse,
    dependencies=[Depends(_require_admin_secret)],
)
async def register_agent_dpop_jwk(
    agent_id: str,
    body: DpopJwkRequest,
) -> DpopJwkResponse:
    """Register or rotate the DPoP JWK bound to an existing agent.

    Audit F-B-11 Phase 3a (#181). Populates ``internal_agents.dpop_jkt``
    so the egress DPoP dep (#199 + #204) can enforce key-possession
    proofs against this agent specifically. Before the Phase 3b SDK
    lands, this endpoint is how operators bind agents: the agent (or
    the operator on its behalf) generates a keypair, POSTs the public
    JWK here, and from then on proofs signed by the matching private
    key are accepted.

    Input validation:
      * ``d`` field must be absent — we never accept a private JWK.
      * ``kty`` must be ``EC`` (P-256) or ``RSA``; the verifier only
        supports those curves today.
      * The thumbprint must be computable. A malformed JWK is rejected
        as 400 — the caller can pinpoint the field from the message.

    Effect:
      * UPDATE ``internal_agents.dpop_jkt`` where ``agent_id`` matches
        and the row is active.
      * No federation impact — ``dpop_jkt`` is Mastio-local and does
        not flow through the Court push loop.
    """
    from mcp_proxy.auth.dpop import compute_jkt

    jwk = body.jwk or {}
    if not isinstance(jwk, dict) or not jwk:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="jwk must be a non-empty object",
        )
    if "d" in jwk:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="private key material ('d') rejected — send the "
                   "public JWK only",
        )
    kty = jwk.get("kty")
    if kty not in ("EC", "RSA"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"unsupported kty {kty!r} — expected 'EC' (P-256) or 'RSA'",
        )

    try:
        jkt = compute_jkt(jwk)
    except (ValueError, KeyError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"malformed JWK: {exc}",
        ) from exc

    async with get_db() as conn:
        result = await conn.execute(
            text(
                """
                UPDATE internal_agents
                   SET dpop_jkt = :jkt
                 WHERE agent_id = :aid AND is_active = 1
                """
            ),
            {"jkt": jkt, "aid": agent_id},
        )
        if result.rowcount == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="agent not found or inactive",
            )

    await log_audit(
        agent_id="admin",
        action="agent.dpop_jwk_set",
        status="success",
        detail=f"agent_id={agent_id} jkt={jkt}",
    )
    return DpopJwkResponse(agent_id=agent_id, dpop_jkt=jkt)
