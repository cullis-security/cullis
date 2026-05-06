"""
MCP Proxy Pydantic models — request/response schemas, token payloads, audit entries.
"""
import uuid
from typing import Any, Literal

from pydantic import BaseModel, Field


class ToolExecuteRequest(BaseModel):
    """Request to execute a tool through the proxy."""
    tool: str = Field(..., max_length=128, pattern=r"^[a-z][a-z0-9_]*$")
    parameters: dict[str, Any] = Field(default_factory=dict)
    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))


class ToolExecuteResponse(BaseModel):
    """Response from a tool execution."""
    request_id: str
    tool: str
    status: Literal["success", "error"]
    result: Any = None
    error: str | None = None
    execution_time_ms: float


class ToolInfo(BaseModel):
    """Metadata about an available tool."""
    name: str
    description: str
    required_capability: str
    parameters_schema: dict | None = None


class TokenPayload(BaseModel):
    """Decoded JWT token payload from the broker."""
    sub: str           # SPIFFE ID
    agent_id: str      # org::agent (or org::user::name / org::workload::name)
    org: str
    exp: int
    iat: int
    jti: str
    scope: list[str] = []
    cnf: dict | None = None
    # ADR-020 — typed principal. ``"agent"`` is the legacy default and
    # the only value emitted by pre-ADR-020 brokers, so the field stays
    # optional with a fallback. The aggregator + audit chain key on this
    # so a user named "daniele" never collides with an agent named
    # "daniele" when looking up bindings or writing audit rows.
    principal_type: str = "agent"


class InternalAgent(BaseModel):
    """An agent registered locally in the proxy for egress access."""
    agent_id: str
    display_name: str
    capabilities: list[str]
    created_at: str
    is_active: bool = True
    cert_pem: str | None = None
    # F-B-11 Phase 2 (#181) — JWK thumbprint (RFC 7638) of the DPoP
    # keypair this agent registered during enrollment. ``None`` during
    # the grace period for pre-Phase-3 agents; the dep treats NULL and
    # the flag mode asymmetrically — see ``dpop_api_key``.
    dpop_jkt: str | None = None
    # Migration 0017 — scope of A2A communication allowed for this
    # agent: ``intra`` (same-org only), ``cross`` (other orgs only),
    # ``both``. Consulted by ``mcp_proxy.egress.reach_guard`` before
    # any forwarding; defaults to ``both`` so rows without the column
    # (pre-migration fixtures, legacy inserts) stay permissive.
    reach: str = "both"
    # ADR-020 — typed principal mirrored from the client certificate /
    # token claim. ``"agent"`` is the legacy default; ``"user"`` and
    # ``"workload"`` widen the model to Frontdesk shared-mode users
    # and SPIFFE workloads. Audit rows + per-principal aggregation
    # key on this so a user named "daniele" never collides with an
    # agent named "daniele".
    principal_type: str = "agent"


class AuditEntry(BaseModel):
    """Immutable audit log entry."""
    id: int
    timestamp: str
    agent_id: str
    action: str  # "tool_execute", "session_open", "egress_send", etc.
    tool_name: str | None = None
    status: str  # "success", "error", "denied"
    detail: str | None = None
    request_id: str | None = None
    duration_ms: float | None = None
