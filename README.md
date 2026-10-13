<p align="center">
  <img src="branding/cullis-mark.svg" alt="Cullis" width="120"><br><br>
  <strong>Cullis. Zero-trust governance layer for autonomous AI agents in regulated environments.</strong><br>
  Self-hosted. LLM-agnostic. FSL-1.1+Apache-2.0.
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-FSL--1.1--Apache--2.0-blue.svg" alt="License"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.11-blue.svg" alt="Python"></a>
  <a href="#status"><img src="https://img.shields.io/badge/status-alpha-yellow.svg" alt="Status: alpha"></a>
</p>

---

**What Cullis gives an autonomous agent:**

- **A real identity.** Each agent gets its own x509 certificate instead of an API key, presented over mTLS with a DPoP proof, so every agent request is tied to one cryptographic identity rather than a shared key. (Human users on OpenAI-compatible clients use scoped, revocable API tokens instead — see [Identity](#cullis-mastio).)
- **Policy before the call.** A decision point evaluates each request before the LLM or MCP tool runs, so an agent only does what you allowed.
- **A tamper-evident trail.** Every action lands in an append-only, hash-chained audit log an external auditor can verify offline, without trusting Cullis or your IT team.

---

## What Cullis does

Banks, insurers, and other regulated organizations are starting to put AI agents into production paths that touch real customer data and real money. A KYC screener calling a sanctions API. A pitchbook builder pulling MNPI off the deal-room drive. A vendor-risk reporter aggregating evidence for DORA Article 28. The agent code is the easy part. Proving to a regulator, eighteen months later, that the agent acted with the authority it claimed, on the inputs it claimed, and that nothing in the chain has been tampered with, is the hard part.

Cullis sits underneath any agent stack (Claude Agent SDK, OpenAI Agents SDK, custom loops) and supplies those three primitives without changing how the agent is written. It is LLM-agnostic: the default dispatch path uses Cullis-owned native adapters (the official Anthropic and OpenAI Python SDKs, a thin httpx client for Ollama), with no third-party AI gateway in the critical path. Switch providers with one env var; identity, policy, and audit stay the same.

---

## Quickstart

Pull the Mastio bundle, enroll an agent, install the SDK, run an agent loop. The Mastio bundle is a self-contained `docker compose` stack with first-boot Org CA minting, an admin account, and a dashboard.

```bash
# 1. Pull and deploy the Mastio bundle.
curl -L https://github.com/cullis-security/cullis/releases/download/mastio-v0.7.0/cullis-mastio-bundle.tar.gz | tar xz
cd cullis-mastio-bundle && ./deploy.sh

# 2. Open the dashboard URL the deploy script prints (auto-detected per host:
#    host.docker.internal on Docker Desktop, an interface IP on Linux pure so
#    a browser on a separate laptop on the same LAN can reach the VM).
#    Accept the self-signed TLS warning, create the admin account, go to
#    Agents > "Create agent manually", fill in a name, submit, and click
#    "Download identity bundle" to get an identity-bundle.zip containing
#    agent.crt + agent.key + ca-chain.pem + meta.json. Deliver that zip to
#    the agent host out of band (scp / KMS / Vault — whatever your runbook
#    says) and unzip it into the directory the SDK will read.

# 3. Install the SDK.
pip install cullis-sdk
```

Enable chat by adding an LLM provider in the dashboard's `AI Providers` page (Anthropic, OpenAI, or Ollama). Until one is configured, `chat_completion` returns `503 provider_key_missing` while registry, MCP, and audit work regardless.

Then run the agent loop with the identity bundle you downloaded — see the [SDK code example](#cullis-sdk-python-for-autonomous-agents) below. The first request lands as an audit row visible in the dashboard under `Audit`.

**Policies.** Open the dashboard's `Policies → Rego` tab and paste a Rego rule, or stay on the legacy `Built-in Rules` + `Tool Rules` tabs for simple allowlists. The Mastio compiles Rego on Save and evaluates the WebAssembly bundle in-process on every decision.

**Backend.** SQLite is fine for the quickstart, the demo VM, and the first one or two agents. Pilots above ~50 concurrent agents should switch to Postgres with `./deploy.sh --db postgres` (or point `PROXY_DB_URL` in `proxy.env` at a managed instance).

The Mastio bundle README in `packaging/mastio-bundle/` covers custom hostnames, Postgres and Vault production overrides, oauth2-proxy integration, and the upgrade procedure.

### Run from source (developer)

If you cloned the repo and want to run the Mastio against your working tree (not the released bundle), drive `docker compose` directly:

```bash
# Dev: standalone Mastio + nginx TLS sidecar, built from source
docker compose \
  -f deploy/compose/docker-compose.proxy.yml \
  --env-file deploy/proxy/proxy.env \
  up -d --wait

# Prod-safety overlay (fails fast on dev defaults)
docker compose \
  -f deploy/compose/docker-compose.proxy.yml \
  -f deploy/compose/docker-compose.proxy.prod.yml \
  --env-file deploy/proxy/proxy.env \
  up -d --wait
```

Copy `deploy/proxy/proxy.env.example` to `deploy/proxy/proxy.env` and fill in the required values before the first `up`. The customer bundle in `packaging/mastio-bundle/` mints these automatically; the from-source path is intentionally explicit.

---

## Cullis Mastio

Mastio is the gateway. One container, one organization, one source of truth for every agent action that touches the LLM or an MCP tool inside that organization. It runs standalone, air-gapped if you need it to be, with no external service dependency.

**Identity.** Each agent receives an x509 leaf certificate signed by an organization-owned CA, bound to a SPIFFE SAN and pinned by thumbprint. The certificate is the credential: Mastio rejects any token presented without the matching client certificate (mTLS RFC 8705 §3) and verifies a DPoP proof (RFC 9449) on every agent-authenticated request, refusing plain Bearer tokens on agent identity surfaces. The one deliberate exception is user API tokens (`culk_*`): scoped bearer credentials (path + provider scope, bcrypt-hashed at rest, revocable, 90-day default TTL) for human users on OpenAI-compatible clients that cannot perform DPoP — disabled in production unless the operator explicitly opts in (`MCP_PROXY_USER_API_TOKENS_INSECURE_OK`, gate F-B-15; threat model §5.1).

**Policy.** A policy decision point evaluates each request before the LLM or MCP tool is reached. Operators author **Rego in the dashboard**; Mastio compiles it with the bundled `opa build` and evaluates the WebAssembly bundle in-process on every decision. A legacy allowlist (`blocked_agents`, `allowed_orgs`, capability gates per typed principal) backs up the Rego layer for deployments that haven't adopted it. Default-deny for new sessions, default-allow for messages, fail-safe on timeout.

**Policy bridge.** The same Rego decisions are reachable over the **OPA Data API** (`/v1/data/cullis/policy/{session, tool_call}`) and the **CloudEvents HTTP binding** (`/v1/integrations/cloudevents`), HMAC-SHA256 guarded, so any external data plane that already speaks those protocols can use Cullis as its control plane without writing glue.

**Audit.** Every accepted action lands as a row in an append-only audit log: the primary chain is global per Mastio (v2 rows bind the agent's DPoP thumbprint and on-behalf-of attribution into the hash), a secondary chain is kept per organization, and both are optionally anchored to RFC 3161 TSA on a configurable cadence. The chains replay deterministically: `GET /v1/admin/audit/export` streams the NDJSON bundle and an external auditor can verify it offline without holding any Cullis credentials (`scripts/cullis-audit-verify.py`, stdlib-only).

**AI gateway.** Native adapters wrap the providers directly — the official Anthropic and OpenAI SDKs for the cloud paths, raw httpx against `/api/chat` for Ollama — with no third-party dispatch library in the critical path (ADR-039). Anthropic is wired out of the box; OpenAI and Ollama configure from the dashboard. Gemini, Bedrock, and Vertex still ride the legacy LiteLLM backend, opt-in. Per-agent identity rides into every upstream call as part of the audit trail; the provider switches by env var without touching agent code.

**MCP reverse proxy.** Mastio terminates MCP traffic from agents, applies the capability gate, propagates the agent identity into the tool call, and logs the result. Both stdio and HTTP transports are supported. Resources are declared per tool with explicit allowed-domain lists.

**Admin API.** A small set of administrative endpoints covers agent enrollment (CSR + BYOCA), cert rotation, policy push, audit export, AI-provider configuration, and user principal management. Everything an org admin needs in production is reachable both from the dashboard and from `curl`.

---

## Cullis SDK (Python, for autonomous agents)

`cullis-sdk` is the Python client an autonomous agent uses to talk to Mastio. It handles mTLS client cert presentation, DPoP signing, token refresh, and request retries, behind a small surface: ask the LLM something, list the MCP tools it is allowed to call, call one, and let the audit trail accumulate underneath.

Two entry points, depending on how the identity reaches the agent and whether the Mastio enforces DPoP:

- **`CullisClient.from_identity_dir(mastio_url, cert_path=..., key_path=...)`** — load an identity already on disk. An admin mints the agent in the dashboard ("Create agent manually"), downloads `identity-bundle.zip` (`agent.crt + agent.key + ca-chain.pem`), and delivers it out of band (scp, KMS, Vault, systemd LoadCredential). The cert IS the credential (ADR-014, RFC 8705 §3 mTLS); there is no shared API key to leak. This dashboard bundle is **cert-only** — it carries no DPoP key — so it authenticates against a Mastio running `egress_dpop_mode=optional`, the development default (`./deploy.sh`). Drop a `dpop.jwk` next to the cert and the SDK auto-discovers it; without one, calls are rejected wherever DPoP is required.
- **`CullisClient.enroll_via_dashboard_approval(mastio_url, requester_name=..., requester_email=..., save_to=...)`** — the agent host bootstraps its own identity. The SDK generates the keypair **and** a DPoP key locally, submits an enrollment request, polls until an admin clicks Approve, then writes the full identity dir (`agent.key + agent.crt + dpop.jwk + meta.json`) and registers the DPoP public key with the Mastio. This is the path for **production** (`./deploy.sh --prod`), where DPoP is required on every call and the private key never leaves the agent host.

Rule of thumb: the dashboard bundle + `from_identity_dir` is the fastest way to try Cullis on a dev deploy; `enroll_via_dashboard_approval` is the DPoP-bound path for production.

(`CullisClient.from_enrollment(...)` is deprecated since 0.2.0 and removed in 0.3.0; the admin-minted bundle flow above replaces it with stronger guarantees.)

`chat_completion` and `chat_completion_stream` route through Mastio's `/v1/llm/chat` endpoint. The provider, the model, and the upstream API key are configured org-side, so the agent never sees the upstream key and every prompt and response is audit-logged with the agent identity attached. `list_mcp_tools` returns the tools the agent is allowed to invoke; `call_mcp_tool(name, arguments)` invokes one, Mastio re-checks the gate server-side, applies the policy, writes an audit row, and propagates the same identity into the MCP server.

```python
from cullis_sdk import CullisClient

# Admin minted this identity in the dashboard ("Create agent manually") and
# sent you the resulting identity-bundle.zip. Unzip anywhere on the agent
# host — /etc/cullis/agent/, a KMS-mounted dir, a container volume, your
# call. The cert IS the credential (ADR-014, RFC 8705 §3 mTLS); there is
# no shared API key.
client = CullisClient.from_identity_dir(
    "https://mastio.acme.local:9443",
    cert_path="/etc/cullis/agent/agent.crt",
    key_path="/etc/cullis/agent/agent.key",
    verify_tls=False,  # self-signed Org CA on a laptop; pin ca_chain_path in prod
)

response = client.chat_completion(
    model="claude-sonnet-4-6",
    messages=[{"role": "user", "content": "Screen the latest applicant batch."}],
)

for tool in client.list_mcp_tools():
    print(tool["name"], tool.get("description", ""))

result = client.call_mcp_tool(
    "sanctions_lookup",
    {"full_name": "Acme Holding Ltd"},
)
```

---

## Project layout

```
mcp_proxy/         Cullis Mastio (org gateway, FastAPI)
cullis_sdk/        Cullis SDK (Python client + MCP server)
packaging/         Release bundles (Mastio container bundle, SDK PyPI build)
deploy/            Helm chart + Docker Compose for the Mastio
nginx/             TLS sidecar config used by the Mastio bundle
docs/              ops runbooks, integrations, architecture notes
scripts/           Maintainer scripts (env generation, audit verification, Postgres backup)
site/              cullis.io Astro site
```

Runtime: Python 3.11, FastAPI, PostgreSQL 16, Redis, HashiCorp Vault (optional), `cryptography`, PyJWT, OpenTelemetry, Prometheus, OPA (optional), Docker, Helm.

---

## Status

Alpha. The Mastio runs end-to-end on a laptop and ships from a public release train with a multi-track security audit on every release. External certification and pilot validation are in progress, not done.

| Component | Latest | What it is |
|---|---|---|
| **Cullis Mastio** | [`mastio-v0.7.0`](https://github.com/cullis-security/cullis/releases/tag/mastio-v0.7.0) | Org gateway, agent CA, Rego + allowlist policy engine, audit chain, MCP reverse proxy, embedded AI gateway, OPA Data API + CloudEvents bridge for external data planes |
| **Cullis SDK** | [`cullis-sdk 0.2.1`](https://pypi.org/project/cullis-sdk/) | Python client used by autonomous agents to talk to Mastio. Supports `from_identity_dir` (plain file), `from_systemd_credentials` (Linux production tmpfs delivery), and `cullis_httpx_client` drop-in for vanilla Anthropic/OpenAI SDKs |

Use Cullis in evaluation, integration, and internal deploys. The community release is the only release; there is no commercial tier today. Feedback, bug reports, and PRs in the public repo.

---

## License

Split licensing.

- **Cullis Mastio (`mcp_proxy/`)** under [FSL-1.1-Apache-2.0](LICENSE). Non-competing use permitted (internal deployments, services, research, modifications, forks). Each release becomes [Apache 2.0](LICENSE-APACHE-2.0) two years after publication.
- **Cullis SDK (`cullis_sdk/`)** under [Apache 2.0](cullis_sdk/LICENSE). Permissive, permanent.

See [NOTICE](NOTICE) for the component-by-component map.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, PR workflow, and code conventions.

Security vulnerabilities: [SECURITY.md](SECURITY.md) for private reporting.

## Contact

General, partnerships, demos: [hello@cullis.io](mailto:hello@cullis.io)

Security (private): [security@cullis.io](mailto:security@cullis.io) and [SECURITY.md](SECURITY.md)

Bugs, feature requests: [GitHub Issues](https://github.com/cullis-security/cullis/issues)

---

> Architecture deep-dives, deployment patterns, and the project's reason for existing live at **[cullis.io](https://cullis.io)**.
