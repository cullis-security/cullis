# Modern Dogfood Stack

Local-only, gitignored. Provides a single-command demo of the full
2026-Q1/Q2 Cullis surface (Court federation + Mastio + Frontdesk shared
mode + agent BYOCA enrollment + MCP tool calls with persistent DB +
Ollama AI gateway) that the legacy `sandbox/` does not exercise.

## Scope

What this stack proves on every run:

1. Court federates two orgs (orga, orgb) with their own Mastios
2. Mastio A runs in Frontdesk shared mode — a real human user (mario) logs in,
   gets a per-user identity, and chats with Ollama via the Mastio AI gateway
3. User-to-user (U2U) message from mario@orga to luigi@orgb traverses
   Court federation
4. Agent-a (BYOCA enrolled on Mastio A) invokes an MCP tool that
   persists into a real SQLite DB inside the mcp-messages container
5. Agent-a sends an A2A cross-org one-shot to agent-b on Mastio B,
   through the Court bridge

Ollama runs on the host (already installed). Mastios reach it via
`host.docker.internal:11434` — no model duplication in containers.

## NOT in scope

- SPIRE workload attestation (legacy `sandbox/` covers it; here BYOCA only)
- Keycloak OIDC (here we use Mastio local users + admin password seed)
- Production-mode `validate_config` gates (we run `ENVIRONMENT=development`)
- Vault KMS (local KMS sufficient for demo)
- Real TSA / RFC 3161 audit anchoring
- WebAuthn step-up
- Anthropic / OpenAI API keys (Ollama-only via AI gateway)

If you need any of these, fall back to `sandbox/demo.sh full`.

## Decisions (open questions from `imp/plans/sandbox-modern-stack.md`)

| Q | Answer |
|---|---|
| Frontdesk network | Joins orga-internal so the SPA reaches Mastio A by DNS |
| Ollama bridge | `host.docker.internal:11434` via `extra_hosts` |
| MCP server scope | New `mcp-messages` with persistent SQLite (`send_message`, `list_messages`) |
| TSA | Not in v1 — audit chain runs locally without TSA anchoring |
| WebAuthn | Not in v1 |
| Production-mode gates | Not in v1 — `ENVIRONMENT=development` |

## Layout

```
stack/
├── docker-compose.yml         # full topology
├── bootstrap/                 # CA mint + org register + agent cert mint
├── mcp-messages/              # MCP server with persistent SQLite
├── seed/                      # ad-hoc shared seed files (TLS, etc.)
├── scenarios/                 # replayable demo scripts
├── up.sh                      # bring stack up + bridge Ollama + provision mario+luigi
├── down.sh                    # teardown + volume drop
├── smoke.sh                   # 4 end-to-end assertions (~120s wall)
├── GUIDE.md                   # this file
└── imp/                       # maintainer notes (gitignored within gitignored)
```

## Run

```bash
# single command: up + smoke 5 E2E scenarios (~3-5 min cold, ~60s warm)
./stack/demo.sh

# sub-commands
./stack/demo.sh up           # alias of default (up + smoke)
./stack/demo.sh smoke        # re-run smoke against an up stack
./stack/demo.sh status       # ps + endpoint cheat-sheet
./stack/demo.sh logs [svc]   # tail logs (all or one service)
./stack/demo.sh restart      # down + up + smoke
./stack/demo.sh down         # teardown + drop volumes
```

The 6 smoke scenarios:

1. **B1** Ollama chat round-trip via Mastio A AI gateway (admin probe)
2. **B2** A2A cross-org one-shot agent-a@orga → agent-b@orgb via Court federation
3. **B3** MCP `send_message` tool call (DB write on persistent SQLite)
4. **B4** MCP `list_messages` tool call (DB read)
5. **B5** mario (Frontdesk user) → chat completion via Mastio AI gateway → Ollama qwen2.5:0.5b
6. **B6** Cross-user isolation — alice and mario on the same Frontdesk produce
        distinct `local_user_principals.cert_thumbprint` and distinct
        `audit_log.on_behalf_of_user_id` (Finding #16 regression: single-router
        fork on `_per_user_credentials`, no workload-cred leak across users)

## Prerequisites

- Docker Compose v2
- Ollama running on host at `127.0.0.1:11434` with at least one model pulled
  (default expected: `qwen2.5:0.5b` — ~350 MB)
- Free host ports: 8000 (Court), 9100 (Mastio A), 9200 (Mastio B),
  9443 (Mastio A nginx), 9543 (Mastio B nginx), 7777 (Frontdesk Connector),
  18080 (Frontdesk HTTP), 18443 (Frontdesk TLS)

## Topology

```
host:11434                              ← ollama (host)
   ↑
   │ via host.docker.internal
   │
   public-wan ───────────────────────────────────────────────────
       │
       ├── postgres-court ── redis-court ── court
       │
   orga-internal ────────────────────────────  orgb-internal ────────
       │                                          │
       ├── postgres-mastio-a                      ├── postgres-mastio-b
       ├── mastio-a (AMBASSADOR_MODE=shared)      ├── mastio-b
       ├── mastio-a-nginx (TLS sidecar :9443)     ├── mastio-b-nginx (TLS :9443)
       ├── frontdesk-connector (Ambassador)       ├── agent-b (BYOCA)
       ├── frontdesk-nginx (TLS :18443)           ├── mcp-messages (DB shared)
       └── agent-a (BYOCA)                        └─────────────────
```

`mcp-messages` is joined to BOTH org networks so both orgs' agents can
exercise the tool. The SQLite DB lives on a persistent volume.
