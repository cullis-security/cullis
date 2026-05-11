# Integrations — point your OpenAI-compat client at Cullis Mastio

Cullis Mastio exposes an OpenAI-compatible API surface at
`https://<mastio-host>:9443/v1/*`. Any client that speaks the
OpenAI HTTP protocol can talk to Cullis as if it were
`api.openai.com` or `api.anthropic.com`, and get back:

- per-user identity attribution in the Mastio audit chain
- centralised provider credentials (no API key stored on the client)
- policy enforcement at the PDP layer
- cross-org federation when paired with a Court deployment

The contract: every request carries `Authorization: Bearer culk_<…>`
where `culk_<…>` is a Cullis user API token (ADR-027). The token
identifies which **user principal** is making the call; the underlying
provider call (Anthropic / OpenAI / Gemini / Bedrock / Vertex / Ollama)
is made by the Mastio with the org-wide credentials managed in the
dashboard.

## Integration guides

| Client | Type | Guide |
|---|---|---|
| LibreChat | self-hosted web, multi-user | [librechat.md](librechat.md) |
| Cherry Studio | desktop, MCP-native | [cherry-studio.md](cherry-studio.md) |
| Cursor | IDE, agentic | [cursor.md](cursor.md) |

All three guides assume:

1. A Mastio is reachable at a known URL (e.g.
   `https://mastio.acme.local:9443` for dev, or your VPS hostname for
   production).
2. The admin has configured at least one AI provider in the dashboard
   at `/proxy/ai-providers` (or via
   `PUT /v1/admin/ai-providers/{provider}` REST).
3. A user principal exists in the Mastio (created via Frontdesk SSO
   first login, or pre-provisioned via `POST /v1/admin/users`).

## Minting a token

### Via dashboard (browser)

1. Sign in to the Mastio dashboard at `https://<mastio-host>:9443/proxy/login`.
2. Navigate to **Users** → click the target user.
3. Switch to the **API Tokens** tab.
4. Fill in **Label** (e.g. `Cursor laptop daniele`, `LibreChat staging`),
   optionally pick scope providers and expiry, click **Mint token**.
5. The cleartext token appears in an amber banner once. Copy it now —
   it is never shown again.

### Via curl (CI / Terraform)

```bash
ADMIN_SECRET="<from MCP_PROXY_ADMIN_SECRET in proxy.env>"
MASTIO_URL="https://mastio.acme.local:9443"

curl -X POST "${MASTIO_URL}/v1/admin/api-tokens" \
  -H "X-Admin-Secret: ${ADMIN_SECRET}" \
  -H "Content-Type: application/json" \
  -d '{
    "principal_id": "acme::user::daniele@acme.local",
    "label": "Cursor laptop daniele"
  }'
# Response: {"id":"...","token":"culk_x7q3...j9k2","token_last4":"j9k2",...}
```

The `token` field is the cleartext credential. Stash it in your password
manager or pipe it straight to the client config. Subsequent GETs on
the same row return only `token_last4`.

## Revocation

Both surfaces revoke the same way:

- Dashboard: per-row **Revoke** button in the API Tokens tab.
- REST: `DELETE /v1/admin/api-tokens/{token_id}` with `X-Admin-Secret`.

Revoke is immediate. Clients holding the revoked token start getting
`401 Unauthorized` on the next request. Recovery: mint a fresh token,
distribute it, the client picks up the new credential on its next
config load.

## What ends up in the audit log

Every `/v1/*` request authenticated with a `culk_*` token writes a
hash-chained row with:

- `agent_id` = the user principal id (e.g.
  `acme::user::daniele@acme.local`)
- `action` = e.g. `egress_llm_chat`
- `details.principal_type` = `user`
- `details.model`, `details.provider`, `details.upstream_request_id`

The provider's own API key never appears in the chain. The Cullis
token id does not appear in egress audit rows (it appears only in
`api_token.mint` / `api_token.revoke` audit rows, with `details.source`
distinguishing dashboard from REST provenance).

## Security model recap

- `culk_*` tokens are 256-bit Bearer credentials. Treat them like an
  Anthropic / OpenAI API key: store in a password manager, never paste
  into shared chats, rotate periodically.
- The Mastio stores only a bcrypt hash. A DB leak does not recover
  the token; revoke + re-mint is the recovery path either way.
- Tokens are bound to a single user principal. Per-client labels make
  forensics easy when a client is compromised (revoke that token,
  others keep working).
- For higher-assurance clients (workload agents, server-to-server),
  the cert-based mTLS + DPoP path is still the right choice. API
  tokens are the OpenAI-compat convenience layer, not a replacement
  for cert auth.

## See also

- ADR-027 (local: `imp/adrs/adr-027-unified-user-credentials.md`) —
  formal model and rationale.
- ADR-025 (`imp/adrs/0025-frontdesk-dual-mode-auth.md`) — dual-mode
  Frontdesk auth (password local + OIDC). Tokens here are the third
  credential form alongside those two.
- ADR-020 (`imp/adrs/adr-020-user-principal-and-quadrants.md`) — user
  principal first-class.
