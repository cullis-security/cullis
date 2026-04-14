from datetime import datetime
from enum import Enum
from pydantic import BaseModel, Field, field_validator


class InboxMessage(BaseModel):
    seq: int
    sender_agent_id: str
    payload: dict
    nonce: str
    timestamp: datetime
    signature: str | None = None
    client_seq: int | None = None


class SessionStatus(str, Enum):
    pending = "pending"
    active = "active"
    closed = "closed"
    denied = "denied"


class SessionCloseReason(str, Enum):
    """Why a session was terminated. Attached to session.closed events (M1.3)."""
    normal = "normal"                # explicit close() by a peer
    idle_timeout = "idle_timeout"    # no activity within SESSION_IDLE_TIMEOUT
    ttl_expired = "ttl_expired"      # hard TTL reached (expires_at)
    peer_lost = "peer_lost"          # peer disconnected beyond grace (reserved for M2)
    policy_revoked = "policy_revoked"  # binding/policy revocation
    pending_timeout = "pending_timeout"  # accept not received within pending window
    rejected = "rejected"            # explicit reject() by target


class SessionRequest(BaseModel):
    target_agent_id: str = Field(..., description="ID of the target agent")
    target_org_id: str = Field(..., description="Target org — cross-checked against the registered org")
    requested_capabilities: list[str] = Field(
        default_factory=list,
        description="Capabilities the requester wants to use on the target"
    )
    context: dict = Field(default_factory=dict, description="Optional metadata about the request")

    @field_validator("context")
    @classmethod
    def validate_context(cls, v: dict) -> dict:
        import json

        def _check_depth(obj: object, depth: int = 0) -> None:
            if depth > 4:
                raise ValueError("context nesting exceeds maximum depth of 4")
            if isinstance(obj, dict):
                for key, val in obj.items():
                    if not isinstance(key, str):
                        raise ValueError("context keys must be strings")
                    _check_depth(val, depth + 1)
            elif isinstance(obj, list):
                for item in obj:
                    _check_depth(item, depth + 1)

        _check_depth(v)
        if len(json.dumps(v, default=str)) > 16384:
            raise ValueError("context exceeds 16 KB limit")
        return v


class SessionResponse(BaseModel):
    session_id: str
    status: SessionStatus
    initiator_agent_id: str
    target_agent_id: str
    created_at: datetime
    expires_at: datetime | None = None
    message: str | None = None


class MessageEnvelope(BaseModel):
    """
    Signed envelope used by agents to send messages through the broker.
    The broker validates session_id and agent_id before forwarding.
    """
    session_id: str
    sender_agent_id: str
    payload: dict
    nonce: str = Field(..., max_length=128, description="UUID to prevent message-level replay attacks")
    timestamp: int = Field(..., description="Unix timestamp (seconds UTC) of when the message was signed")
    signature: str = Field(..., max_length=2048, description="RSA-PSS-SHA256 signature of the canonical message")
    client_seq: int | None = Field(None, ge=0, description="Client-side monotonic sequence number for E2E ordering integrity")

    @field_validator("payload")
    @classmethod
    def limit_payload_size(cls, v: dict) -> dict:
        import json
        serialized = json.dumps(v, default=str)
        if len(serialized) > 1_048_576:  # 1 MB
            raise ValueError("payload exceeds 1 MB limit")
        return v


# ─────────────────────────────────────────────────────────────────────────────
# RFQ (Request for Quote) models
# ─────────────────────────────────────────────────────────────────────────────

class RfqRequest(BaseModel):
    """Broadcast a request for quote to all matching agents."""
    capability_filter: list[str] = Field(
        ..., min_length=1, description="Target agents must have ALL these capabilities",
    )
    payload: dict = Field(..., description="The RFQ payload (e.g., item, quantity)")
    timeout_seconds: int = Field(default=30, ge=5, le=120)
    context: dict = Field(default_factory=dict)

    @field_validator("payload")
    @classmethod
    def limit_rfq_payload(cls, v: dict) -> dict:
        import json
        if len(json.dumps(v, default=str)) > 65536:  # 64 KB
            raise ValueError("RFQ payload exceeds 64 KB limit")
        return v


class RfqRespondRequest(BaseModel):
    """A supplier's response to an RFQ."""
    payload: dict = Field(..., description="The quote response (e.g., price, lead time)")

    @field_validator("payload")
    @classmethod
    def limit_response_payload(cls, v: dict) -> dict:
        import json
        if len(json.dumps(v, default=str)) > 65536:
            raise ValueError("RFQ response payload exceeds 64 KB limit")
        return v


class RfqQuote(BaseModel):
    responder_agent_id: str
    responder_org_id: str
    payload: dict
    received_at: datetime


class RfqResponse(BaseModel):
    rfq_id: str
    status: str
    matched_agents: list[str]
    quotes: list[RfqQuote]
    created_at: datetime
    closed_at: datetime | None = None
