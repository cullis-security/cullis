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
    agent_id: str      # org::agent
    org: str
    exp: int
    iat: int
    jti: str
    scope: list[str] = []
    cnf: dict | None = None


class InternalAgent(BaseModel):
    """An agent registered locally in the proxy for egress access."""
    agent_id: str
    display_name: str
    capabilities: list[str]
    created_at: str
    is_active: bool = True
    cert_pem: str | None = None


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
