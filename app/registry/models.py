from datetime import datetime
from pydantic import BaseModel, Field


class AgentRegisterRequest(BaseModel):
    agent_id: str = Field(..., description="Unique agent ID, e.g. 'banca-x::kyc-agent-v1'")
    org_id: str = Field(..., description="Organization ID, e.g. 'banca-x'")
    display_name: str
    secret: str | None = Field(None, description="Optional shared secret — not used with x509 authentication")
    capabilities: list[str] = Field(default_factory=list, description="e.g. ['kyc.read', 'kyc.write']")
    metadata: dict = Field(default_factory=dict)


class AgentResponse(BaseModel):
    agent_id: str
    org_id: str
    display_name: str
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


class RotateCertRequest(BaseModel):
    new_certificate: str = Field(..., description="New agent certificate in PEM format")


class RotateCertResponse(BaseModel):
    agent_id: str
    thumbprint: str = Field(..., description="SHA-256 thumbprint of the new certificate")
