# `mcp_proxy` — Cullis Mastio

**The org-level trust authority for the Cullis federated agent-trust network.**

This directory implements **Cullis Mastio**, the per-organization component
that an org admin deploys inside their own infrastructure. The directory is
named `mcp_proxy/` for historical reasons, the brand name `Mastio` and the
directory name `mcp_proxy/` refer to the same thing. Same for the Python
package import path (`from mcp_proxy import ...`) and the published wheel
name (`cullis-mastio` on PyPI from v0.3.x onwards).

The Mastio is one of three Cullis components:

| Component       | Directory          | Runs where        | Owned by          |
|-----------------|--------------------|-------------------|-------------------|
| Cullis Court    | `app/`             | Cross-org network | Network operator  |
| Cullis Mastio   | `mcp_proxy/`       | Inside an org     | Org admin         |
| Cullis Connector| `cullis_connector/`| End-user laptop   | End user          |

## What the Mastio does

- Issues **agent identity** (x509 with SPIFFE SAN, optional BYOCA).
- Enforces **per-org policy** (default-deny session, default-allow message,
  PDP webhook with fail-safe deny-on-timeout).
- Records a **local hash-chain audit** that never leaves the org.
- Acts as the **MCP reverse-proxy** between in-org agents and the MCP
  servers exposed by the org.
- Hosts the **embedded AI gateway** (LiteLLM in-process by default,
  Portkey or BYO upstream optionally), so per-principal egress policy is
  enforced at the same trust boundary as A2A.
- Runs in two modes, **standalone** (air-gapped, single-org, no Court) or
  **federated** (attached to a Court for cross-org reachability). Same
  binary, admin action toggles.

## Code layout

```
main.py            FastAPI app, lifespan, routers
config.py          Settings (env vars, MCP_PROXY_* prefix)
db.py / db_models.py  SQLAlchemy async models
alembic/           Per-Mastio migrations (revision id ≤ 32 char)
admin/             Org admin API + dashboard backend
agents/            Agent enrollment, cert lifecycle, rotation
auth/              x509 + JWT + DPoP, federation bridge
audit/             Local hash chain, dual-write to Court
dashboard/         Admin web UI (Jinja2 + HTMX + Tailwind)
egress/            AI gateway dispatcher + LiteLLM embedded backend
enrollment/        Device-code, invite token, attach-CA flows
federation/        Court bridge, cross-org publish/subscribe
guardian/          LLM Guardian fast-path endpoint, ticket signer
ingress/           Inbound A2A receiver, decrypt + verify
local/             Standalone-mode shortcuts
middleware/        Auth + DPoP + rate limit + CORS
observability/     OpenTelemetry, custom metrics
pki/               CA chain, cert issuance, OCSP-equivalent revocation
policy/            PDP webhook, default rules
rbac.py            Multi-admin RBAC (ADR-018)
redis/             Connection pool
registry/          Local agent registry
reverse_proxy/     MCP reverse-proxy (auto-inject Cullis identity)
spiffe.py          SPIFFE ID translation
sync/              Federation sync workers
tools/             CLI helpers
```

## MCP builtin: `cullis_send_to_agent`

The Mastio's MCP aggregator (`POST /v1/mcp`) ships with a builtin tool
that lets any MCP client (Frontdesk SPA, Claude Code, Codex, Cursor,
LibreChat, ...) ask the model to send a one-shot message to another
Cullis agent without writing transport code. Identity propagation +
audit chain are handled server-side — the model only supplies
recipient and content.

```jsonc
// JSON-RPC tools/call body
{
  "jsonrpc": "2.0", "id": 1, "method": "tools/call",
  "params": {
    "name": "cullis_send_to_agent",
    "arguments": {
      "target_agent_id": "mario",              // bare name, or "orgb::mario", or "spiffe://..."
      "target_org_id": "orgb",                  // optional; defaults to caller's org
      "content": "lavoro finito",               // string → {"text": ...}, or pass a dict
      "correlation_id": "corr-abc",             // optional; server generates one when omitted
      "reply_to": "msg-prev",                   // optional
      "ttl_seconds": 300                        // optional; default 5 min, max 1 h
    }
  }
}
```

Response shape (success):

```jsonc
{
  "correlation_id": "...", "msg_id": "...",
  "status": "enqueued", "target_agent_id": "...", "target_org_id": "..."
}
```

Errors come back as `{ "error": "reach_denied" | "policy_denied" |
"invalid_recipient" | "broker_unavailable" | "broker_forward_failed" |
"send_failed" | "invalid_parameters", "reason": "..." }` so the model
can branch in-band. The Mastio audit chain still captures the specific
detail for ops.

Capability gate: agents need `cullis.a2a.send` in their scope. Typed
principals (user / workload) bypass the scope check — their binding
table is the authoritative authz — but the same reach + policy +
audit gates apply.

Implementation note: the tool invokes
`mcp_proxy.egress.oneshot.send_oneshot_internal` directly. There is
no loopback HTTP + ephemeral DPoP (the pattern that broke
`chat_completion`). The HTTP route `POST /v1/egress/message/send` is
now a thin wrapper around the same helper, so the two surfaces share
one implementation.

## Running

For local dev and demos, use the sandbox stack at the repo root:

```bash
./sandbox/demo.sh full
```

For self-hosted production deployment (Mastio standalone or attached to a
Court), see `deploy/` (Docker Compose + Helm chart) and the install guide
at [cullis.io/install/mastio-self-host](https://cullis.io/install/mastio-self-host).

The Mastio also ships as a standalone container bundle in
`packaging/mastio-bundle/` and a PyPI wheel `cullis-mastio` for embedded
deployments.
