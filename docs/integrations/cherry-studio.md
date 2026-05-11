# Cherry Studio → Cullis Mastio

[Cherry Studio](https://github.com/CherryHQ/cherry-studio) is a
desktop chat client for macOS / Windows / Linux. It speaks both the
OpenAI HTTP protocol and the Anthropic Messages protocol, and has
first-class MCP server integration. Pointing it at Cullis Mastio
gives a single Mac user a Cullis-attributed agentic surface without
spinning up a self-hosted web app.

Topology (desktop single-user):

```
┌─────────────────┐   /v1/chat/completions    ┌──────────────────┐
│  Cherry Studio  │ ───────────────────────►  │   Cullis Mastio  │
│  (Mac desktop)  │   Authorization:          │  (yours, VPS or │
│                 │   Bearer culk_<...>       │   localhost)     │
└─────────────────┘                            └──────────────────┘
```

## 1. Mint a token

Either via the dashboard (Users → your user → API Tokens tab →
**Mint token**, label e.g. `Cherry Studio laptop`), or via curl:

```bash
ADMIN_SECRET="<MCP_PROXY_ADMIN_SECRET from proxy.env>"
MASTIO_URL="https://mastio.acme.local:9443"

curl -X POST "${MASTIO_URL}/v1/admin/api-tokens" \
  -H "X-Admin-Secret: ${ADMIN_SECRET}" \
  -H "Content-Type: application/json" \
  -d '{
    "principal_id": "acme::user::daniele@acme.local",
    "label": "Cherry Studio laptop"
  }'
# {"token":"culk_x7q3...j9k2", ...}
```

Copy the `token` value. Subsequent reads only show the last 4 chars.

## 2. Add Cullis as a custom provider

Cherry Studio supports both OpenAI-style and Anthropic-style custom
endpoints. The Mastio exposes both — pick whichever your usual model
prefers.

### Option A — OpenAI-compatible (works for all providers)

1. Cherry Studio → **Settings** (gear icon, bottom-left).
2. **Model Providers** → **Add Custom Provider**.
3. Fill in:
   - **Provider Type**: `OpenAI-compatible`
   - **Name**: `Cullis`
   - **API Base URL**: `https://mastio.acme.local:9443/v1`
   - **API Key**: paste your `culk_*` token
4. Click **Fetch Models** — Cherry Studio queries
   `GET /v1/models` on the Mastio and populates the dropdown with
   everything the org has enabled.
5. **Save**.

### Option B — Anthropic-style (only when you want native Claude tool calls)

The Mastio's embedded LiteLLM serves `/v1/messages` (Anthropic
protocol) alongside `/v1/chat/completions` (OpenAI protocol). If
you prefer the native Anthropic surface (e.g. for richer tool-call
behaviour with Claude models):

1. Settings → Model Providers → **Add Custom Provider**.
2. Fill in:
   - **Provider Type**: `Anthropic`
   - **Name**: `Cullis (Anthropic)`
   - **API Base URL**: `https://mastio.acme.local:9443`
     (no `/v1` suffix — Cherry adds `/v1/messages` itself)
   - **API Key**: same `culk_*` token
3. Save.

Both options can coexist. You will see them as two separate
providers in the model picker.

## 3. TLS for the self-signed dev cert

If you are pointing Cherry Studio at a development Mastio bundle
(self-signed Org CA), the desktop app refuses the connection. Two
ways out:

- **Trust the Org CA on your laptop** (preferred). Copy
  `cullis-mastio-bundle/certs/org-ca.pem` from the deployment host to
  your Mac, then:
  - macOS: `sudo security add-trusted-cert -d -r trustRoot -k
    /Library/Keychains/System.keychain org-ca.pem`
  - Linux: copy to `/usr/local/share/ca-certificates/` and run
    `sudo update-ca-certificates`.
  - Windows: import into **Trusted Root Certification Authorities**
    via `certmgr.msc`.
- **Use the Mastio behind a real CA** (production). Front the Mastio
  with Caddy / nginx terminating Let's Encrypt and point Cherry at
  the public hostname.

## 4. MCP servers (the agentic part)

Cherry Studio's headline feature is MCP integration. The Cullis
Connector itself ships an MCP server you can expose to Cherry. This
gives the chat model tools like `cullis.send_oneshot`,
`cullis.list_agents`, `cullis.inbox` — turning Cherry into a
fully-fledged Cullis agentic frontend.

Setup is independent from the API token above. See the Connector
desktop docs (`docs/connector/quickstart.md`) for the MCP install
flow (`cullis-connector install-mcp --client cherry-studio`). The
MCP path runs over local stdio; the API token + Mastio path runs
over HTTPS. The two can coexist.

## 5. Verify

In Cherry Studio:

1. Start a new conversation.
2. Pick a model from the **Cullis** provider you just added.
3. Send `hello`.

Cross-check on the Mastio:

```bash
# from any shell that can reach the Mastio
curl -H "X-Admin-Secret: ${ADMIN_SECRET}" \
  "${MASTIO_URL}/v1/admin/api-tokens?principal_id=acme::user::daniele@acme.local" \
  | jq '.tokens[0] | {last_used_at, last_used_ip}'
```

You should see `last_used_at` updated to within the last few
seconds, and `last_used_ip` set to your laptop's address (or the
trusted-proxy IP if you're behind one).

## Troubleshooting

### "Connection refused" / network error

- Confirm the URL: include `https://` and the port (`:9443` for the
  bundle default).
- Test from the same machine: `curl -v
  "https://mastio.acme.local:9443/healthz"`. If that fails, the
  problem is networking (firewall, DNS), not Cherry.

### "Unauthorized" / 401

- The token is wrong, revoked, or expired. Re-mint and re-paste.

### Model dropdown is empty after "Fetch Models"

- The Mastio has no enabled AI provider yet. Sign in to the Mastio
  dashboard at `/proxy/ai-providers` and configure at least one
  (Anthropic with a valid `sk-ant-*` key is the easiest).

### Tools / function calls don't work

The Mastio normalises tool-call schemas between OpenAI and Anthropic
formats. Some edge cases (parallel tool calls, ultra-recent model
features) lag behind the upstream provider. If you hit one, try the
Anthropic-style provider (option B above) for Claude models —
native pass-through has fewer translation pitfalls.

## Single-user vs multi-user trade-off

Cherry Studio is desktop single-user by design. If you want the same
Cullis-attributed chat experience for multiple people in your team,
[LibreChat](librechat.md) is the better fit — same Mastio backend,
multi-user web UI. Both deployments can talk to the same Mastio at
the same time; they show up as different `last_used_ip` values in
the token's audit metadata.
