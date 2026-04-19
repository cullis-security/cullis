<p align="center">
  <img src="cullis-mark.svg" alt="Cullis" width="120"><br><br>
  <strong>Cullis — Zero-trust identity and audit for AI agents.</strong><br>
  Start air-gapped in your organization. Scale to cross-company federation without redeploy.
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-FSL--1.1--Apache--2.0-blue.svg" alt="License"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.11-blue.svg" alt="Python"></a>
  <a href="https://github.com/cullis-security/cullis/actions"><img src="https://img.shields.io/github/actions/workflow/status/cullis-security/cullis/ci.yml?branch=main&label=CI" alt="CI"></a>
  <a href="#status"><img src="https://img.shields.io/badge/status-early--stage%20%C2%B7%20research-orange.svg" alt="Status: early-stage"></a>
</p>

---

> 📖 **Why Cullis exists, architecture deep-dives, use cases, deployment patterns → [cullis.io](https://cullis.io)**
>
> This README is the engineer's entry point: what it is, how to run it, how the code is laid out. Everything else lives on the site.

---

## Status

> [!WARNING]
> **Early-stage research project — not production-ready.**
>
> Cullis is in active study and prototyping. The architecture is real and
> the demo runs end-to-end on a laptop, but the codebase has not been
> externally security-audited, and APIs may still break without notice.
>
> Use it to learn, explore, prototype, and contribute — not yet to handle
> real users, real credentials, or real traffic.

---

## What Cullis is

AI agents act on your behalf — they make decisions, move data, and
increasingly talk to each other. When something goes wrong, three questions
matter: **who was it, what were they allowed to do, and what did they actually do?**

Cullis gives each agent a cryptographic identity, enforces policy at the
organization boundary, and records every action in a tamper-evident
hash-chain. The same binary runs standalone inside your organization or
federated across companies — no redeploy between the two.

---

## Three components

| | **Cullis Connector** | **Cullis Mastio** | **Cullis Court** |
|---|---|---|---|
| **Where it runs** | User's laptop | Your organization | Cross-org network |
| **Owned by** | End user | Your org admin | Network operator |
| **What it does** | User identity + MCP↔Cullis translation | Agent certs, policy, local audit, tool reverse-proxy | Org registry, trust federation, cross-org routing |

The **Connector** is a desktop app that turns any MCP client (Claude
Desktop, Cursor, Cline) into a Cullis-aware agent. The **Mastio** is the
authority that governs agents inside a single organization. The **Court**
federates Mastios across different organizations.

The Mastio runs in two modes — **standalone** (air-gapped, single-org,
no external dependency) or **federated** (attached to a Court, reaches
agents in other companies). Same binary, admin action switches between
them, no agent re-enrollment.
[Deployment patterns → cullis.io](https://cullis.io).

---

## Quickstart

Boot the full enterprise stack — Court + 2 Mastios + 3 agents + 2 MCP servers
in 2 organizations, wired with SPIRE, Keycloak, Vault and Postgres — then
replay intra-org and cross-org traffic.

**Requirements**: Docker Engine with Compose v2, ~6 GB free disk, ~4 GB RAM.

```bash
git clone https://github.com/cullis-security/cullis
cd cullis
./sandbox/demo.sh full
```

Replay scenarios (stack must be up):

```bash
./sandbox/demo.sh mcp-catalog     # intra-org: agent → MCP tool call (Org A)
./sandbox/demo.sh mcp-inventory   # intra-org: agent → MCP tool call (Org B)
./sandbox/demo.sh oneshot-a-to-b  # cross-org: A2A encrypted message A → B
./sandbox/demo.sh oneshot-b-to-a  # cross-org: A2A encrypted message B → A
./sandbox/demo.sh guide           # open the onboarding walkthrough
```

See [`sandbox/GUIDE.md`](sandbox/GUIDE.md) for the
step-by-step onboarding — attach-CA flow, Mastio counter-signature pin
(ADR-009), Connector Desktop enrollment, MCP resource registration.

For single-user install, download the [Connector desktop
app](https://github.com/cullis-security/cullis/releases).

---

## Key features

- **x509 PKI + SPIFFE per-agent identity** — each agent gets a cert
  signed by its organization's CA, with `spiffe://org/agent` SAN
- **ECC end-to-end encryption** — ECDH P-256 key exchange, AES-256-GCM
  payload, ECDSA signatures
- **DPoP token binding (RFC 9449)** — every token bound to an ephemeral
  EC key
- **Default-deny federated policy** — PDP webhook or OPA per organization,
  both orgs must allow on cross-org traffic
- **Local hash-chain audit** — append-only, SHA-256 chain, never leaves
  the organization
- **Self-service org onboarding** — invite tokens, attach-CA for existing
  PKIs, automatic Org CA generation
- **KMS backends** — local filesystem (dev), HashiCorp Vault KV v2 (prod)

---

## SDK

```python
from cullis_sdk.client import CullisClient

client = CullisClient("https://mastio.example.com")
client.login("alice", "acme", "agent.pem", "agent-key.pem")

agents = client.discover(capabilities=["supply"])
session_id = client.open_session("widgets::supplier", "widgets", ["supply"])
client.send(session_id, "acme::alice", {"order": "100 units"}, "widgets::supplier")
```

TypeScript SDK in [`sdk-ts/`](sdk-ts/). MCP server exposing Cullis as a
set of tools (so any MCP-compatible LLM becomes a Cullis agent) in
`cullis_sdk/mcp_server.py`.

---

## Project layout

```
app/               Cullis Court (network control plane)
mcp_proxy/         Cullis Mastio (org trust authority)
cullis_connector/  Cullis Connector (desktop app)
cullis_sdk/        Python SDK + MCP server
sdk-ts/            TypeScript SDK
alembic/           Court database migrations
tests/             Unit + integration + e2e tests
sandbox/ Full-stack demo (SPIRE, Keycloak, Vault, Postgres)
deploy/            Helm chart, Docker Compose
enterprise-kit/    BYOCA guide, OPA policy bundles, PDP template
docs/              cullis.io site source + ops runbook
```

Runtime: Python 3.11 · FastAPI · PostgreSQL 16 · Redis · HashiCorp Vault · cryptography · PyJWT · OpenTelemetry + Jaeger · OPA · Docker · Helm.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, PR workflow, and code conventions.

Security vulnerabilities: [SECURITY.md](SECURITY.md) for private reporting.

## Contact

| | |
|---|---|
| General, partnerships, demos | [hello@cullis.io](mailto:hello@cullis.io) |
| Security (private) | [security@cullis.io](mailto:security@cullis.io) · [SECURITY.md](SECURITY.md) |
| Bugs, feature requests | [GitHub Issues](https://github.com/cullis-security/cullis/issues) |
| Discussion | [GitHub Discussions](https://github.com/cullis-security/cullis/discussions) |

## License

Split licensing:

- **Court (`app/`) and Mastio (`mcp_proxy/`)** — [FSL-1.1-Apache-2.0](LICENSE). Non-competing use permitted (internal deployments, services, research, modifications, forks). Each release becomes [Apache 2.0](LICENSE-APACHE-2.0) two years after publication.
- **Python SDK (`cullis_sdk/`)** — [Apache 2.0](cullis_sdk/LICENSE). Permissive, permanent.
- **TypeScript SDK (`sdk-ts/`)** — [MIT](sdk-ts/LICENSE). Permissive, permanent.
- **Integration templates (`enterprise-kit/`)** — [Apache 2.0](enterprise-kit/LICENSE). Permissive, permanent.

See [NOTICE](NOTICE) for the component-by-component map.

---

> Architecture deep-dives, use cases, deployment patterns, and the project's reason for existing all live at **[cullis.io](https://cullis.io)**.
