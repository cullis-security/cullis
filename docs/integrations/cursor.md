# Cursor → Cullis Mastio

[Cursor](https://cursor.com) is an AI-first IDE based on VSCode. It
supports OpenAI-compatible custom endpoints, so you can route Cursor's
chat, edit, and agent operations through Cullis Mastio. Every model
call is attributed to your Cullis user principal in the audit chain.

Topology:

```
┌──────────────────┐   /v1/chat/completions    ┌──────────────────┐
│      Cursor      │ ───────────────────────►  │   Cullis Mastio  │
│  (Mac/Win IDE)   │   Authorization:          │  (yours)         │
│                  │   Bearer culk_<...>       │                  │
└──────────────────┘                            └──────────────────┘
```

## Important caveat up front

Cursor's **agentic** features (Composer, Agents, multi-step edits)
make heavy use of provider-specific extensions to the chat completion
API — tool-call streaming patterns, system prompt injection,
context-window stuffing. The Mastio's embedded LiteLLM normalises
the common subset, but some agentic operations may degrade or fail
when routed through a custom endpoint.

What works reliably today:

- Chat panel (`Cmd+L` / `Ctrl+L`) — standard chat with any model
  the Mastio has configured.
- Inline edit (`Cmd+K` / `Ctrl+K`) — works with OpenAI-format models
  and with Claude via the Anthropic-compatible normaliser.

What may misbehave:

- Composer multi-step agents on Claude 4.x with tool calls — known
  edge cases around parallel tool calls. Fall back to OpenAI models
  for now, or use the native Anthropic provider in Cursor (bypassing
  Cullis) for those flows.
- Cursor Tab and code autocompletion — these use Cursor's own models
  on Cursor's infrastructure regardless of your custom endpoint
  setting. Cullis cannot intercept them.

## 1. Mint a token

Either via the dashboard or via curl. See the
[README mint section](README.md#minting-a-token) for both.

Example via curl:

```bash
ADMIN_SECRET="<MCP_PROXY_ADMIN_SECRET>"
MASTIO_URL="https://mastio.acme.local:9443"

curl -X POST "${MASTIO_URL}/v1/admin/api-tokens" \
  -H "X-Admin-Secret: ${ADMIN_SECRET}" \
  -H "Content-Type: application/json" \
  -d '{
    "principal_id": "acme::user::daniele@acme.local",
    "label": "Cursor laptop daniele"
  }'
```

## 2. Configure Cursor

1. Open Cursor → **Cursor Settings** (`Cmd+,` on Mac).
2. Navigate to **Models**.
3. Toggle off all built-in providers if you want all traffic through
   Cullis. (You can also keep them on and add Cullis as one provider
   among many.)
4. Scroll down to **OpenAI API Key** section → click **Override OpenAI
   Base URL**.
5. Fill in:
   - **API Base URL**: `https://mastio.acme.local:9443/v1`
   - **API Key**: paste your `culk_*` token
6. In **Models**, type the model name you want to use (e.g.
   `claude-sonnet-4-6`) and click **Add Model**. Cursor doesn't auto-
   discover from `/v1/models`; you have to type each model id
   explicitly. This is a Cursor limitation, not a Cullis one.
7. **Verify** — Cursor pings the endpoint with the listed models;
   green checkmark on success.

If you want to use Anthropic-style models with Cursor's Claude path
(more reliable for tool-heavy agentic flows), the Mastio also serves
`/v1/messages` natively. Cursor doesn't expose an Anthropic-style
custom endpoint in the OSS-builds UI, but if you have an
Anthropic-flavoured Pro plan integration, point its base URL at the
same Mastio host (no `/v1` suffix).

## 3. TLS for self-signed dev cert

In production, front the Mastio with a real CA (Let's Encrypt via
Caddy or nginx). In dev with the bundle's self-signed cert, install
the bundle's Org CA into the Mac keychain:

```bash
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain \
  /path/to/cullis-mastio-bundle/certs/org-ca.pem
```

Then restart Cursor. The connection should succeed.

## 4. Verify

In Cursor:

1. Open the chat panel (`Cmd+L`).
2. Pick a Cullis-routed model from the model dropdown.
3. Ask `say hi`.

Cross-check on the Mastio dashboard at `/proxy/users` → your user →
**API Tokens** tab. The `last_used_at` column for the Cursor token
should show the timestamp of your chat. If it doesn't update, the
request either never left Cursor (check Network in Cursor's developer
tools) or the Mastio rejected it before the resolver touched the row
(check the Mastio logs).

## 5. Audit chain

Every Cursor chat lands a hash-chained audit row with:

- `agent_id`: your user principal id
- `action`: `egress_llm_chat`
- `details.model`: the model you picked
- `details.provider`: which upstream the Mastio routed to
  (Anthropic / OpenAI / etc — managed in `/proxy/ai-providers`)
- `details.cost_usd`: when the upstream returns it (usage tokens × pricing)

Browse the chain at `/proxy/audit` in the Mastio dashboard, or query
via SQL on the proxy DB. The hash chain means an admin trying to
selectively delete a row breaks the chain — full integrity guarantee
out of the box.

## Troubleshooting

### "Verify" button red, no error message

Cursor verifies models one-by-one by sending a minimal request. The
failure could be:

- TLS: see section 3.
- Model not configured in the Mastio: the model id you typed
  (`claude-sonnet-4-6`) must match exactly what an enabled provider
  in `/proxy/ai-providers` exposes. Inspect: `curl -H "Authorization:
  Bearer ${TOKEN}" "${MASTIO_URL}/v1/models" | jq '.data[].id'`.

### Chat works but Composer / Agents fails

Known limitation. The agentic surface uses provider-specific extensions
that don't always round-trip through normalisation. Workarounds:

- Use simpler models (Haiku-4.5 instead of Opus-4.7) for Composer
  flows. Less tool-call complexity tends to survive.
- Fall back to Cursor's native Anthropic / OpenAI providers for
  agentic flows (loses audit attribution for those calls, but the
  feature works).
- File an issue on the Cullis repo with the failing payload — we
  can extend the LiteLLM normaliser for common Cursor patterns.

### Cursor Tab (inline autocomplete) doesn't use Cullis

By design. Cursor Tab is a separate service on Cursor's own
infrastructure. It is not exposed via the custom endpoint mechanism.
Only chat + inline edit + Composer use the custom endpoint setting.

## Multi-machine setup

If you use Cursor on multiple machines (laptop + desktop), mint
**two** tokens with distinct labels:

```bash
# Laptop
curl ... -d '{"principal_id":"...","label":"Cursor — laptop"}'
# Desktop
curl ... -d '{"principal_id":"...","label":"Cursor — desktop"}'
```

This way `last_used_ip` audit metadata tells you which machine made
each call, and you can revoke one without disrupting the other (e.g.
laptop stolen → revoke the laptop token, desktop keeps working).
