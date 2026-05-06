from pydantic import BaseModel, Field


class TokenRequest(BaseModel):
    client_assertion: str = Field(
        ...,
        description="JWT RS256 signed with the agent's private key; x5c header contains the certificate",
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
    # Transaction token fields (optional — only present for token_type="transaction")
    token_type: str = "access"          # "access" or "transaction"
    act: dict | None = None             # RFC 8693 actor claim: {"sub": "human@org.com"}
    txn_type: str | None = None         # e.g. "CREATE_ORDER"
    resource_id: str | None = None      # bound resource (e.g. rfq_id)
    payload_hash: str | None = None     # SHA-256 of authorized payload
    parent_jti: str | None = None       # links to originating access token
    # ADR-020 typed principal. ``agent`` is the legacy default; ``user``
    # / ``workload`` arrive on tokens minted for Frontdesk shared-mode
    # users and SPIFFE workloads. Audit rows + per-principal aggregation
    # key on this so a user and an agent with the same local name don't
    # collide. Optional for back-compat with tokens issued by pre-ADR-020
    # brokers in the upgrade window.
    principal_type: str = "agent"
