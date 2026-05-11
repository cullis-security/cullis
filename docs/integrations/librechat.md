# LibreChat → Cullis Mastio

[LibreChat](https://github.com/danny-avila/LibreChat) is a self-hosted
multi-user web app that speaks the OpenAI HTTP protocol. Pointing it at
Cullis Mastio gives every LibreChat conversation a verifiable user
principal in the Mastio audit chain, with zero changes to the LibreChat
UX your users already know.

Topology:

```
┌──────────────────┐   /v1/chat/completions    ┌──────────────────┐
│   LibreChat      │ ───────────────────────►  │   Cullis Mastio  │
│ (web, multi-user)│   Authorization:          │  (yours)          │
│                  │   Bearer culk_<...>       │                   │
└──────────────────┘                            └────────┬─────────┘
                                                         │
                                                         │ org-wide provider creds
                                                         ▼
                                              ┌──────────────────┐
                                              │  Anthropic / ... │
                                              └──────────────────┘
```

Two integration modes, pick one:

- **Per-user API key** (no LibreChat modifications): each LibreChat
  user pastes their own Cullis token in their profile. Recommended
  for the first deployment — keeps the LibreChat user list and the
  Cullis user list independent.
- **Single shared key + X-Forwarded-User** (advanced): one Cullis
  token for the whole LibreChat instance, with per-request user
  attribution via the proxy header. Requires a Cullis-side flag not
  yet shipped (planned). Skip for now.

## Per-user API key (recommended)

### 1. Mint a token per LibreChat user

For each LibreChat user that should be a Cullis principal, mint a
token associated with the corresponding user principal:

```bash
ADMIN_SECRET="<MCP_PROXY_ADMIN_SECRET from proxy.env>"
MASTIO_URL="https://mastio.acme.local:9443"

curl -X POST "${MASTIO_URL}/v1/admin/api-tokens" \
  -H "X-Admin-Secret: ${ADMIN_SECRET}" \
  -H "Content-Type: application/json" \
  -d '{
    "principal_id": "acme::user::alice@acme.local",
    "label": "LibreChat — alice"
  }'
# {"token":"culk_x7q3...j9k2", ...}
```

Save the cleartext `token` value. You will paste it into LibreChat
under Alice's profile.

If you prefer the dashboard, see the
[README mint section](README.md#minting-a-token).

### 2. Add the Cullis endpoint to `librechat.yaml`

In your LibreChat config (`librechat.yaml`), add a custom OpenAI
endpoint pointing at the Mastio. The right `baseURL` depends on your
topology:

**A. Production / VPS** — Mastio behind a real CA at a public hostname:

```yaml
version: 1.2.1
cache: true

endpoints:
  custom:
    - name: "Cullis"
      apiKey: "${OPENAI_API_KEY}"
      # User-supplied key: each LibreChat user pastes their own
      # culk_ token in their profile. The literal "${OPENAI_API_KEY}"
      # tells LibreChat to use the request-time per-user key instead
      # of a server-wide env var.
      baseURL: "https://mastio.acme.local:9443/v1"
      models:
        default: ["claude-haiku-4-5"]
        # Live discovery: LibreChat hits /v1/models on the Mastio
        # and shows whatever the org has configured + enabled.
        fetch: true
      titleConvo: true
      titleModel: "claude-haiku-4-5"
```

**B. Dev / same docker host** — LibreChat joins
``cullis-mastio_proxy_net`` so it can resolve the Mastio via docker
DNS:

```yaml
version: 1.2.1
cache: true

endpoints:
  custom:
    - name: "Cullis"
      apiKey: "${OPENAI_API_KEY}"
      # Same-host docker compose: speak HTTPS to the nginx sidecar by
      # its container name. Requires the cert to have ``mastio-nginx``
      # in its SAN list — the bundle ships this by default (proxy.env
      # ``MCP_PROXY_NGINX_SAN``). If you're on an older bundle that
      # doesn't include it, either regenerate proxy.env with the new
      # default or fall back to plain HTTP on the in-network mcp-proxy
      # port: ``baseURL: "http://mcp-proxy:9100/v1"``. HTTP plain is
      # acceptable here because the bridge network is the trust
      # boundary; never expose port 9100 outside the host.
      baseURL: "https://mastio-nginx:9443/v1"
      models:
        default: ["claude-haiku-4-5"]
        fetch: true
      titleConvo: false
      # Mount the org CA into the LibreChat container so Node trusts
      # the self-signed leaf:
      #   volumes:
      #     - ./cullis-mastio-bundle/certs/org-ca.pem:/app/certs/org-ca.pem:ro
      #   environment:
      #     - NODE_EXTRA_CA_CERTS=/app/certs/org-ca.pem
```

To put LibreChat on the same network as the Mastio bundle, in your
LibreChat `docker-compose.yml`:

```yaml
services:
  api:
    # ... existing config ...
    networks:
      - librechat
      - mastio

networks:
  librechat:
    driver: bridge
  mastio:
    external: true
    name: cullis-mastio_proxy_net
```

Restart LibreChat. If you use the docker-compose bundle, that is
`docker compose restart api`.

### 3. Each user pastes their token

Each LibreChat user logs in to LibreChat and:

1. Click their avatar → **Settings**.
2. Open the **Models** or **Account** tab (location varies by
   LibreChat version).
3. Find the **Cullis** custom endpoint they just configured.
4. Paste their `culk_*` token under **API Key**.
5. Save and refresh the chat page.

The model dropdown now shows whatever the Mastio admin has
configured + enabled in `/proxy/ai-providers` — Claude, GPT-4,
Gemini, Bedrock, Vertex, Ollama. Pick one, chat, audit chain attributes
the request to that user.

## Verify

A successful first chat should produce:

- LibreChat: regular conversation response.
- Mastio audit log (browser at `/proxy/audit` or `tail` the container
  stderr): one row per request with `agent_id=acme::user::alice@acme.local`,
  `action=egress_llm_chat`, `details.model=<the model you picked>`.
- Mastio dashboard → Users → Alice → API Tokens tab: the
  `last_used_at` column shows the timestamp of the call.

## Troubleshooting

### 401 on every chat

The token is wrong, revoked, or expired. Check:

- `curl -i -H "Authorization: Bearer ${TOKEN}" "${MASTIO_URL}/v1/models"`.
  - If `401`, the token is not valid. Re-mint from the dashboard.
  - If `200` but LibreChat still 401, LibreChat is sending the wrong
    `Authorization` header. Inspect LibreChat logs: `docker compose
    logs api | grep -i auth`.

### `connect ECONNREFUSED` or `unable to verify the first certificate`

Mastio is reachable on the address but TLS verification fails. In
production, mount your org's CA bundle into the LibreChat container
and set `NODE_EXTRA_CA_CERTS=/path/to/org-ca.pem`. In dev, the
bundle's self-signed cert needs explicit trust — see the
``volumes`` + ``NODE_EXTRA_CA_CERTS`` snippet in section 2B.

### `Host: mastio-nginx is not in the cert's altnames`

You're hitting `https://mastio-nginx:9443/v1` from a LibreChat
container on the bundle's docker network, but the Mastio's TLS leaf
was minted before ``mastio-nginx`` was added to ``MCP_PROXY_NGINX_SAN``
(default added in the 2026-05-11 bundle update).

Two fixes:

1. **Regenerate the cert with the updated SAN**:
   ```bash
   cd cullis-mastio-bundle/
   # Edit proxy.env to add mastio-nginx,mcp-proxy to MCP_PROXY_NGINX_SAN
   # then restart — the Mastio regenerates the cert on next boot.
   ./deploy.sh --down && ./deploy.sh
   ```

2. **Switch the LibreChat baseURL to plain HTTP on the in-network
   mcp-proxy port**: ``baseURL: "http://mcp-proxy:9100/v1"``. This
   bypasses TLS entirely, which is acceptable because the docker
   bridge network is itself the trust boundary. Never expose port
   9100 outside the host.

### Wrong model list

LibreChat shows fewer/different models than expected:

- Confirm the Mastio's `/v1/models` returns what you expect:
  `curl -H "Authorization: Bearer ${TOKEN}" "${MASTIO_URL}/v1/models"`.
- The list comes from `ai_provider_credentials` rows with `enabled=true`.
  Toggle providers in `/proxy/ai-providers` if needed.

### Tool calls behave inconsistently

LibreChat agents v2 emit OpenAI-flavoured tool calls. The Mastio's
embedded LiteLLM normalises them to the upstream provider's format
(Anthropic / Bedrock / etc). Some edge cases (parallel tool calls
against Claude) may not round-trip cleanly today. Workaround: pick a
provider whose native tool-call format matches what LibreChat emits
(OpenAI native is the safest), or disable agents v2 and use single-shot
chat for that conversation.

## Rotation

To rotate Alice's token without disrupting other users:

1. Mastio dashboard → Users → Alice → API Tokens → **Revoke** the
   active row.
2. **Mint token** new row with the same label.
3. Send Alice the new value out-of-band.
4. Alice pastes it in LibreChat **API Key** field. Old chats are
   preserved, new requests use the new token.

Or via REST:

```bash
curl -X DELETE "${MASTIO_URL}/v1/admin/api-tokens/${OLD_TOKEN_ID}" \
  -H "X-Admin-Secret: ${ADMIN_SECRET}"
curl -X POST "${MASTIO_URL}/v1/admin/api-tokens" \
  -H "X-Admin-Secret: ${ADMIN_SECRET}" \
  -H "Content-Type: application/json" \
  -d '{"principal_id":"acme::user::alice@acme.local","label":"LibreChat — alice (rotated)"}'
```
