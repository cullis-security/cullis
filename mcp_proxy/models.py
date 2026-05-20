"""
MCP Proxy Pydantic models — request/response schemas, token payloads, audit entries.
"""
import json
import uuid
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

# F-A-303 (audit 2026-05-20) — bound the serialised size of a tool
# call's ``parameters`` dict. 128 KiB is generous for the call sites
# we ship today (builtin tools take small JSON bodies, the MCP
# resource forwarder builds its own envelope) while a single
# oversized abuse request gets rejected before the executor's
# 30-second handler window even starts. CWE-770.
MAX_TOOL_PARAMETERS_BYTES = 128 * 1024


class ToolExecuteRequest(BaseModel):
    """Request to execute a tool through the proxy."""
    tool: str = Field(..., max_length=128, pattern=r"^[a-z][a-z0-9_]*$")
    parameters: dict[str, Any] = Field(default_factory=dict)
    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))

    @field_validator("parameters")
    @classmethod
    def _bound_parameters_size(cls, value: dict[str, Any]) -> dict[str, Any]:
        """Reject parameter payloads above the tool-call size ceiling.

        F-A-303 — a caller could otherwise submit a tool/call with an
        ``arguments`` blob of arbitrary size; the executor would then
        buffer it for the full 30-second handler timeout (and, for
        builtins that enqueue to ``local_messages``, persist it to
        SQLite, filling the WAL faster than the sweeper drains).
        Measuring the serialised JSON length rather than ``len(dict)``
        catches the dominant abuse shape (one giant string in a
        single key).
        """
        try:
            serialised = json.dumps(
                value, separators=(",", ":"), default=str,
            )
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "parameters must be JSON-serialisable"
            ) from exc
        size = len(serialised.encode("utf-8"))
        if size > MAX_TOOL_PARAMETERS_BYTES:
            raise ValueError(
                f"parameters payload exceeds the per-call limit of "
                f"{MAX_TOOL_PARAMETERS_BYTES} bytes (got {size})"
            )
        return value


class ToolExecuteResponse(BaseModel):
    """Response from a tool execution."""
    request_id: str
    tool: str
    status: Literal["success", "error"]
    result: Any = None
    error: str | None = None
    execution_time_ms: float
    # Machine-readable token for failure dispatch. Stable identifier from
    # ``mcp_proxy.policy.denied_reason_codes``; SDK consumers branch on
    # this instead of substring-matching ``error``. Set on every non-
    # success path; ``None`` only on ``status="success"``. (F5 follow-up
    # tracker #4.)
    denied_reason_code: str | None = None


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
    # Wave A PR3 (audit 2026-05-11 Tema A) — culk_ token scope.
    # ``None`` = caller did not auth via a culk_ token (cert / DPoP
    # path); these scope fields don't apply. Empty list ``[]`` from a
    # culk_ token = "no providers explicitly listed", interpreted as
    # "no AI provider gate". A non-empty list of provider names (e.g.
    # ``["anthropic"]``) restricts /v1/chat/completions to those
    # providers. ``scope_paths`` defaults to ``["/v1/*"]`` at mint
    # time so the OpenAI-compat surface is the only allowed reach
    # unless the operator widens it explicitly.
    scope_providers: list[str] | None = None
    scope_paths: list[str] | None = None
    # Wave 2 fix 7+8 — rotation grace period. Populated by the
    # rotation writers (re-enrollment, admin DPoP) when the previous
    # cert / jkt is still inside the configured grace window. Pinning
    # verifiers in ``mcp_proxy/auth/client_cert.py`` and
    # ``mcp_proxy/auth/dpop_client_cert.py`` fall back to these when
    # the current pin mismatches and ``previous_grace_period_expires_at``
    # is in the future. Cleaned by
    # ``mcp_proxy/lifespan/agent_cert_grace_cleanup.py`` on expiry.
    previous_cert_pem: str | None = None
    previous_dpop_jkt: str | None = None
    previous_grace_period_expires_at: str | None = None


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
