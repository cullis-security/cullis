from datetime import datetime
from pydantic import BaseModel, Field, field_validator


class AgentRegisterRequest(BaseModel):
    agent_id: str = Field(
        ..., max_length=256,
        pattern=r"^[a-z0-9][a-z0-9._-]{0,127}::[a-z0-9][a-z0-9._-]{0,127}$",
        description="Unique agent ID, e.g. 'banca-x::kyc-agent-v1'",
    )
    org_id: str = Field(..., max_length=128, description="Organization ID, e.g. 'banca-x'")
    display_name: str = Field(..., max_length=256)
    secret: str | None = Field(None, description="Optional shared secret — not used with x509 authentication")
    capabilities: list[str] = Field(default_factory=list, max_length=50, description="e.g. ['kyc.read', 'kyc.write']")
    description: str = Field("", max_length=1024, description="What this agent does — used for discovery")
    metadata: dict = Field(default_factory=dict)

    @field_validator("metadata")
    @classmethod
    def limit_metadata_size(cls, v: dict) -> dict:
        import json
        if len(json.dumps(v, default=str)) > 16384:
            raise ValueError("metadata exceeds 16 KB limit")
        return v


class AgentResponse(BaseModel):
    agent_id: str
    org_id: str
    display_name: str
    description: str = ""
    capabilities: list[str]
    is_active: bool
    registered_at: datetime
    metadata: dict
    agent_uri: str              # SPIFFE ID — spiffe://trust-domain/org/agent

    model_config = {"from_attributes": True}


class AgentListResponse(BaseModel):
    agents: list[AgentResponse]
    total: int


class AgentPublicKeyResponse(BaseModel):
    agent_id: str
    public_key_pem: str
