# `app` — Cullis Court

**The cross-organization control plane for the Cullis federated agent-trust network.**

This directory implements **Cullis Court**, the network-level component that
operators run to federate organizations together. The directory is named
`app/` for historical reasons, the brand name `Court` and the directory name
`app/` refer to the same thing.

The Court is one of three Cullis components:

| Component       | Directory          | Runs where        | Owned by          |
|-----------------|--------------------|-------------------|-------------------|
| Cullis Court    | `app/`             | Cross-org network | Network operator  |
| Cullis Mastio   | `mcp_proxy/`       | Inside an org     | Org admin         |
| Cullis Connector| `cullis_connector/`| End-user laptop   | End user          |

## What the Court does

- Maintains the federated **registry** of organizations and their agents.
- Issues **counter-signatures** on Mastio events so cross-org peers can
  trust them without trusting each Mastio individually.
- Enforces **federation policy** (default-deny, dual-allow, attach-CA flow).
- Anchors a **third-party audit hash chain** in parallel to per-org chains,
  so cross-org non-repudiation does not depend on either party's records
  alone.
- Operates the **A2A relay** for cross-org one-shot messages (encrypted
  end-to-end, the Court never reads plaintext).

## Code layout

```
main.py            FastAPI app, lifespan, routers, middleware
config.py          Settings (env vars)
auth/              x509 + JWT + DPoP, JTI blacklist, revocation
broker/            Sessions, messages, WebSocket, persistence
dashboard/         Operator web UI (Jinja2 + HTMX + Tailwind)
policy/            Federation policy engine, PDP webhooks
registry/          Orgs, agents, bindings, capability discovery
onboarding/        Join request + admin approve/reject
federation/        Cross-org publishing, registry sync
audit/             Hash chain, dual-write, TSA anchor
db/                SQLAlchemy models, migrations entry
spiffe.py          SPIFFE ID translation
e2e_crypto.py      AES-256-GCM + RSA-OAEP envelope helpers
kms/               KMS adapter (filesystem dev, HashiCorp Vault prod)
redis/             Connection pool, graceful fallback
rate_limit/        Sliding window (in-memory + Redis sorted set)
telemetry.py       OpenTelemetry init
```

Migrations live at the repo root in `alembic/`. The standalone-mode
counterpart (intra-org Mastio without a Court) is in `mcp_proxy/`, see its
own README.

## Running

The Court does not boot in isolation, the canonical way to run it is via the
sandbox stack at the repo root:

```bash
./sandbox/demo.sh full
```

That brings up Court + 2 Mastios + 3 agents + 2 MCP servers + SPIRE +
Keycloak + Vault + Postgres in two organizations.

For self-hosted production deployment, see `deploy/` (Docker Compose +
Helm chart) and the runbook at [cullis.io/operate/runbook](https://cullis.io/operate/runbook).
