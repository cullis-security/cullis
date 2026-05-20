<p align="center">
  <img src="branding/cullis-mark.svg" alt="Cullis" width="120"><br><br>
  <strong>Cullis — Zero-trust identity and audit for AI agents.</strong><br>
  Start air-gapped in your organization. Scale to cross-company federation without redeploy.
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-FSL--1.1--Apache--2.0-blue.svg" alt="License"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.11-blue.svg" alt="Python"></a>
  <a href="#status"><img src="https://img.shields.io/badge/status-alpha-yellow.svg" alt="Status: alpha"></a>
  <a href="https://github.com/cullis-security/cullis/releases"><img src="https://img.shields.io/github/v/release/cullis-security/cullis?label=release&include_prereleases&sort=semver" alt="Latest release"></a>
</p>

---

> 📖 **Why Cullis exists, architecture deep-dives, use cases, deployment patterns → [cullis.io](https://cullis.io)**
>
> This README is the engineer's entry point: what it is, how to run it, how the code is laid out. Everything else lives on the site.

---

## Status

**Alpha. Four components shipped, public release train active.**

| Component | Latest | What it is |
|---|---|---|
| **Cullis Mastio** | [`mastio-v0.5.1`](https://github.com/cullis-security/cullis/releases/tag/mastio-v0.5.1) | Org gateway, agent CA, policy enforcement, audit chain, MCP reverse proxy, embedded AI gateway |
| **Cullis Frontdesk Bundle** | [`frontdesk-bundle-v0.2.10`](https://github.com/cullis-security/cullis/releases/tag/frontdesk-bundle-v0.2.10) | Multi-user chat over Mastio, per-user identity, shared-mode deploy |
| **Cullis Connector** | [`connector-v0.5.1`](https://github.com/cullis-security/cullis/releases/tag/connector-v0.5.1) | Desktop app + MCP server, brings Claude Desktop / Cursor / Cline into Cullis |
| **Cullis SDK (Python)** | [`cullis-agent-sdk 0.1.3`](https://pypi.org/project/cullis-agent-sdk/) | Programmatic client: enroll, discover, send, audit |

The code runs end-to-end on a laptop and ships from a public release train with a multi-track security audit on every release. Externally audited and pilot-validated certification is in flight, not done yet — use this in evaluation, integration, and internal deploys; check with us before putting Cullis in front of regulated traffic.

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
| **What it does** | User identity + MCP↔Cullis translation | Agent certs, policy, local audit, tool reverse-proxy, embedded AI gateway | Org registry, trust federation, cross-org routing |

The **Connector** is a desktop app that turns any MCP client (Claude
Desktop, Cursor, Cline, Claude Code) into a Cullis-aware agent. The
**Mastio** is the authority that governs agents inside a single
organization. The **Court** federates Mastios across different
organizations.

The Mastio runs in two modes — **standalone** (air-gapped, single-org,
no external dependency) or **federated** (attached to a Court, reaches
agents in other companies). Same binary, admin action switches between
them, no agent re-enrollment.
[Deployment patterns → cullis.io](https://cullis.io).

---

## Try it

Three artefacts. Pull them, deploy, use. No repo clone needed — the bundles are self-contained, the SDK is on PyPI, the Connector ships per-platform binaries.

**Requirements**: Docker Engine with Compose v2, ~2 GB RAM per bundle.

### 1. Mastio — org gateway + dashboard

```bash
curl -L https://github.com/cullis-security/cullis/releases/download/mastio-v0.5.1/cullis-mastio-bundle.tar.gz | tar xz
cd cullis-mastio-bundle && ./deploy.sh
```

Dashboard at `https://localhost:9443/proxy/login` (self-signed TLS — accept the warning, first boot mints your Org CA + admin account). From here you mint agent certs, set policies, view audit, configure the embedded AI gateway (Anthropic / OpenAI / Gemini / Ollama via LiteLLM, or any alt AI gateway as sidecar).

See [`packaging/mastio-bundle/README.md`](packaging/mastio-bundle/README.md) for custom hostname, Postgres + Vault production overrides, and oauth2-proxy integration.

### 2. Frontdesk — multi-user chat on top of Mastio

A multi-user chat UI that exercises Mastio's per-user identity (each user gets their own cert and audit trail). Demonstrates the same Mastio works for headless agents and human users in one deploy.

```bash
curl -L https://github.com/cullis-security/cullis/releases/download/frontdesk-bundle-v0.2.10/cullis-frontdesk-bundle.tar.gz | tar xz
cd cullis-frontdesk-bundle && ./deploy.sh
```

SPA at `http://localhost:8080`. Sign up, talk to your configured LLM, audit lands in the same chain as agent traffic.

See [`packaging/frontdesk-bundle/README.md`](packaging/frontdesk-bundle/README.md) for TLS sidecar, public-URL config, and oauth2-proxy + IDP wiring.

### 3. Connector — plug your IDE into Cullis

Install once, configure each MCP client (Cursor, Claude Code, Claude Desktop, Cline). Every tool call your IDE makes flows through Cullis: identity, policy, audit.

**Install** — pick one:

```bash
# PyPI (any platform with Python 3.10+)
pip install cullis-connector

# Or: native binary
curl -LO https://github.com/cullis-security/cullis/releases/latest/download/cullis-connector-linux.zip
unzip cullis-connector-linux.zip && sudo mv cullis-connector-linux-x86_64 /usr/local/bin/cullis-connector
# macOS Apple Silicon and Windows zips are on the same release page.
```

**Enroll against your Mastio**:

```bash
cullis-connector dashboard
# Open http://127.0.0.1:7777 — 3-step wizard:
# 1. paste Mastio URL  →  2. admin approves in dashboard  →  3. connected
```

**Wire into your MCP client** — the dashboard auto-detects installed clients and writes the config entry for you. Or copy this snippet by hand:

```jsonc
// ~/.config/Claude/claude_desktop_config.json  (Claude Desktop)
// ~/.cursor/mcp.json                            (Cursor)
// claude mcp add cullis --scope user -- cullis-connector serve  (Claude Code CLI)
{
  "mcpServers": {
    "cullis": {
      "command": "cullis-connector",
      "args": ["serve"]
    }
  }
}
```

Restart the IDE. Cullis tools (`list_agents`, `open_session`, `send_message`, …) appear in its tool list, every call is identified + policy-checked + audit-logged.

---

## Key features

- **x509 PKI + SPIFFE per-agent identity** — each agent gets a cert
  signed by its organization's CA, with `spiffe://org/agent` SAN
- **Three-tier PKI hardening** — Org Root (cold) → Mastio Intermediate (3-5y) → leaf (1y), rotation via dashboard
- **ECC end-to-end encryption** — ECDH P-256 key exchange, AES-256-GCM
  payload, ECDSA signatures, broker never reads plaintext
- **DPoP token binding (RFC 9449)** + **mTLS (RFC 8705 §3)** — every token bound to an ephemeral
  EC key, certs pinned by thumbprint
- **Default-deny federated policy** — PDP webhook or OPA per organization,
  both orgs must allow on cross-org traffic, fail-safe deny on timeout
- **Tamper-evident audit chain** — append-only SHA-256 chain, optional RFC 3161 TSA anchoring (Court-side), replicated to Court for cross-org disputes
- **Multi-user shared mode** — one Mastio, many human users, per-user identity + audit (Frontdesk bundle)
- **Embedded AI gateway** — Anthropic, OpenAI, Gemini, Ollama via LiteLLM; alt gateway as sidecar is supported; identity propagated into every LLM call
- **Self-service org onboarding** — invite tokens, attach-CA for existing
  PKIs, automatic Org CA generation
- **KMS backends** — local filesystem (dev), HashiCorp Vault KV v2 (prod). Cloud KMS plugins (AWS / Azure / GCP) in `enterprise-kit/`.

---

## SDK

```python
from cullis_sdk import CullisClient

with CullisClient("https://mastio.example.com") as client:
    client.login("alice", "acme", "agent.pem", "agent-key.pem")
    agents = client.discover(capabilities=["supply"])
    session_id = client.open_session(agents[0].agent_id, agents[0].org_id, ["supply"])
    client.send(session_id, "acme::alice", {"order": "100 units"}, agents[0].agent_id)
```

TypeScript SDK in [`sdk-ts/`](sdk-ts/) (beta — see [`sdk-ts/README.md`](sdk-ts/README.md) for the Python surface gap). MCP server exposing Cullis as a set of tools (so any MCP-compatible LLM becomes a Cullis agent) in `cullis_sdk/mcp_server.py`.

---

## Enterprise

**Cullis Mastio Enterprise Bundle** ships the same Mastio with backup / restore tooling, longer-lived rotation cadence, cloud KMS plugins (AWS / Azure / GCP), and signed support. Available under a separate licence — contact [hello@cullis.io](mailto:hello@cullis.io) for evaluation.

`enterprise-kit/` (in this repo, Apache-2.0) carries the BYOCA quickstart, OPA policy bundles, PDP template, Intune/Jamf attestation runbooks, and monitoring dashboards.

---

## Project layout

```
app/               Cullis Court (network control plane)
mcp_proxy/         Cullis Mastio (org trust authority)
cullis_connector/  Cullis Connector (desktop app + MCP server)
cullis_sdk/        Python SDK + MCP server
sdk-ts/            TypeScript SDK (beta)
alembic/           Court database migrations
packaging/         Release bundles (Mastio, Frontdesk, Enterprise, PyPI, Homebrew)
enterprise-kit/    BYOCA guide, OPA bundles, PDP template, cloud KMS plugins
deploy/            Helm chart, Docker Compose, env templates
docs/              cullis.io site source + ops runbook + ratified ADRs
tests/             Unit, integration, e2e tests
sandbox/           Maintainer smoke gate (local CI, SPIRE + Keycloak + Vault). Not the user-facing demo — see "Try it" above.
```

> [!NOTE]
> `app/` and `mcp_proxy/` are legacy directory names that predate the
> Court / Mastio rebrand. The on-disk paths and the brand names refer to
> the same components. Python package imports follow the same legacy
> (`from app import ...` for Court, `from mcp_proxy import ...` for
> Mastio). Each directory has its own README with a per-component
> overview.

Runtime: Python 3.11 · FastAPI · PostgreSQL 16 · Redis · HashiCorp Vault · cryptography · PyJWT · OpenTelemetry + Jaeger (Court) · Prometheus (Mastio) · OPA · Docker · Helm.

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
