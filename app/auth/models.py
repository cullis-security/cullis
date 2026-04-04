from pydantic import BaseModel, Field


class TokenRequest(BaseModel):
    client_assertion: str = Field(
        ...,
        description="JWT RS256 firmato con la chiave privata dell'agente; header x5c contiene il certificato",
    )


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "DPoP"
    expires_in: int  # seconds


class TokenPayload(BaseModel):
    sub: str                    # SPIFFE ID — spiffe://trust-domain/org/agent (external/standard identity)
    agent_id: str               # internal ID — org::agent (DB primary key)
    org: str                    # org_id
    exp: int                    # unix timestamp expiry
    iat: int                    # unix timestamp issued-at
    jti: str                    # JWT ID — replay protection
    scope: list[str] = []       # capability scope from approved binding
    cnf: dict | None = None     # DPoP confirmation: {"jkt": "<jwk-thumbprint>"}
