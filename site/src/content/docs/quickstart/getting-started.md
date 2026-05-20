---
title: "Getting started"
description: "Pick the right Cullis component for your role and go from zero to running in 15 minutes — Mastio bundle, Frontdesk multi-user chat, or Connector for your IDE."
category: "Quickstart"
order: 10
updated: "2026-05-20"
---

# Getting started

**Who this is for**: anyone new to Cullis. You'll end this page knowing which of the three Cullis components you need, how to install it, and what to do next.

Cullis gives each AI agent a cryptographic identity, enforces policy at your organization boundary, and records every action in a tamper-evident audit chain. If you want the product pitch, go to [cullis.io](https://cullis.io). This page assumes you're already sold and want to try it.

## The three components, in one picture

```
    ┌────────────────┐
    │   Connector    │  End-user laptop. Turns any MCP client
    │                │  (Claude Desktop, Cursor, Cline, Claude Code)
    │                │  into a Cullis-aware agent.
    └────────┬───────┘
             │  API key + DPoP proof
             ▼
    ┌────────────────┐
    │     Mastio     │  Your organization. Holds agent certs,
    │                │  enforces policy, writes the local audit
    │                │  chain, reverse-proxies MCP resources,
    │                │  routes LLM calls via embedded AI gateway.
    └────────┬───────┘
             │  Counter-signed envelope
             ▼
    ┌────────────────┐
    │     Court      │  Cross-org network. Routes between
    │                │  Mastios from different companies.
    │                │  Optional — only for federation.
    └────────────────┘
```

**Standalone deploys run without the Court.** One Mastio + agents + MCP servers = a single-org Cullis. Add a Court later without re-enrolling anyone.

## Three paths from here

### A. I'm an operator, I want to stand up Cullis for my org

You'll deploy a **Mastio** — the org gateway that holds agent identities, policy, audit. Two commands on a Docker host get you a working dashboard:

```bash
curl -L https://github.com/cullis-security/cullis/releases/download/mastio-v0.5.1/cullis-mastio-bundle.tar.gz | tar xz
cd cullis-mastio-bundle && ./deploy.sh
```

Open `https://localhost:9443/proxy/login` (self-signed TLS — accept the warning). First boot mints your Org CA, creates the admin account, and lets you configure the embedded AI gateway (Anthropic / OpenAI / Gemini / Ollama).

For production deploys (custom hostname, Postgres, Vault KMS, oauth2-proxy + IDP), see [Self-host the Mastio](../install/mastio-self-host) or [Mastio on Kubernetes](../install/mastio-kubernetes).

### B. I want a multi-user chat over my Mastio

If your scenario is "let multiple humans in my org talk to LLMs through Cullis with per-user audit", deploy the **Frontdesk bundle** — a multi-user chat SPA on top of a shared-mode Mastio. Each user gets their own identity and audit trail.

```bash
curl -L https://github.com/cullis-security/cullis/releases/download/frontdesk-bundle-v0.2.10/cullis-frontdesk-bundle.tar.gz | tar xz
cd cullis-frontdesk-bundle && ./deploy.sh
```

Open `http://localhost:8080`, sign up, talk to your configured LLM. Audit lands in the same chain as agent traffic. See [Frontdesk bundle](../install/frontdesk-bundle) for TLS sidecar, public-URL config, and oauth2-proxy + IDP wiring.

### C. I'm a developer, I want Cullis-aware agents in my IDE

Install the **Connector** on your laptop and enroll against your org's Mastio. The Connector wraps MCP so Claude Desktop, Cursor, Cline, and Claude Code all speak Cullis.

```bash
# PyPI
pip install cullis-connector

# Or: native binary (macOS arm64, Linux x86_64, Windows x86_64)
# https://github.com/cullis-security/cullis/releases/latest
```

Then:

1. Your admin gives you the Mastio URL (`https://mastio.yourcompany.com`)
2. Run `cullis-connector dashboard` and open `http://127.0.0.1:7777` — the 3-step wizard handles enrolment via [device-code flow](../enroll/connector-device-code)
3. Click your IDE's card in the dashboard — Cullis writes the MCP entry into its config file

See [Install the Connector](../install/connector) for the full per-OS install + per-IDE wiring + troubleshooting.

## Three enrolment methods (one Mastio)

The Mastio supports three enrolment methods. Pick per-agent, mix freely in the same org.

| Method | Pick when | Trust anchor at enrolment |
|---|---|---|
| [Connector](../enroll/connector-device-code) | Dev laptops, interactive onboarding | OIDC login + admin approval in the Mastio dashboard |
| [BYOCA](../enroll/byoca) | Programmatic agents, CI/CD, enterprise PKI in place, air-gapped bootstrap | Admin secret + Org-CA-signed cert |
| [SPIRE](../enroll/spire) | K8s workloads under SPIRE | Admin secret + SVID verified against the SPIRE trust bundle |

The admin secret is the Mastio's own — not the Court's, not a per-user password. BYOCA and SPIRE use it because they're called non-interactively; the Connector doesn't need it because the admin approves the enrolment from the dashboard in person.

## Runtime — one path for every method

Regardless of how an agent enrolled, runtime code is identical:

```python
from cullis_sdk import CullisClient

with CullisClient("https://mastio.acme.corp") as client:
    client.login("alice", "acme", "agent.pem", "agent-key.pem")

    agents = client.discover(capabilities=["supply"])
    session_id = client.open_session(agents[0].agent_id, agents[0].org_id, ["supply"])
    client.send(session_id, "acme::alice", {"order": "100 units"}, agents[0].agent_id)
```

DPoP proof binds every request to the keypair the Mastio pinned at enrolment time.

## Common first-day questions

**Do I need the Court to run Cullis?**
: No. A single Mastio + agents is a complete standalone deploy. Add the Court later if you want cross-org federation — existing agents don't re-enrol.

**Can I have two enrolment methods in the same org?**
: Yes. A Connector-enrolled dev laptop and a BYOCA-enrolled CI agent coexist under the same `org_id`. The Mastio discriminates per-agent, not per-org.

**What happens if the Mastio is down?**
: Agents can't mint new DPoP-bound tokens — no new sessions or messages. Existing tokens stay valid until their 15-minute TTL expires. See [Runbook § Mastio is down](../operate/runbook#1-mastio-is-down) for recovery.

**Is the audit log admissible as legal evidence?**
: Every Mastio's audit is SHA-256 hash-chained and can be anchored against an RFC 3161 TSA for long-term integrity. See [Audit export](../operate/audit-export) for the flow.

## Next

- [Install the Connector](../install/connector) — single-user laptop setup
- [Self-host the Mastio](../install/mastio-self-host) — single-host enterprise deploy
- [Frontdesk bundle](../install/frontdesk-bundle) — multi-user chat over Mastio
- [Runbook](../operate/runbook) — bookmark before production
