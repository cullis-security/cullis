---
title: "Introducing Cullis — an Agent Trust Fabric"
description: "Why we are building cryptographic infrastructure for AI agents, and what ships on day one."
date: "2026-04-16"
author: "Cullis Security"
---

AI agents are moving from clever demos to production systems. They pay invoices, negotiate with suppliers, open customer tickets, and increasingly — they talk to each other. Not just inside a single company. Across companies. An Acme buyer-agent asking a Globex KYC-agent to verify a counterparty. A hospital triage-agent asking a lab-agent at a partner network to return a result.

The infrastructure for that conversation does not exist. Not really.

What exists today is a pile of API keys, webhooks, service tokens, and bespoke middleware. When the buyer-agent talks to the KYC-agent, the packets are TLS-encrypted in transit. But *who is it*, really? *What is it allowed to do*? And *what did it actually do* — can you prove it to a regulator three months later?

## Three questions

These are the three questions we keep coming back to.

**Who is it?** Not the user whose session cookie is still floating around. Not the service account some ops engineer created in 2023. The specific agent process, with a cryptographic proof that binds the request to a private key only that agent holds.

**What is it allowed to do?** Not what your policy document says. Not what your Slack #ai-ops channel agreed last week. A policy enforced at the boundary, default-deny, evaluated before the call lands — and on cross-org traffic, evaluated by *both* organizations.

**What did it actually do?** Not what you can piece together from CloudWatch and Grafana. An append-only, hash-chained audit log that cannot be silently rewritten — not by a compromised admin on your side, not by a compromised operator on the counterparty side.

## What Cullis is

Cullis is three components.

The **Connector** runs on the user's laptop, inside whatever MCP client they already use — Claude Desktop, Cursor, Cline. It handles device-code enrollment and speaks both wire protocols.

The **Mastio** runs inside your organization. It is the authority — the CA, the policy engine, the audit ledger. Intra-org traffic flows through it and never leaves. If you never talk to anyone outside your company, the Mastio is all you need.

The **Court** runs somewhere shared — hosted by a consortium, or by a single operator, or by you if you want to self-host the whole stack. It routes sealed envelopes between Mastios. It sees who spoke to whom and when. It never sees what was said.

## What Cullis is not

It is not an AI gateway. It does not route LLM providers, does not federate MCP servers, does not run outbound guardrails. Those problems have good solutions already — agentgateway, Pomerium, Lasso, Kong AI, a dozen others. Cullis lives underneath them, in the trust layer.

The rule we keep: *if the solution already exists and works, we compose with it. We do not rebuild it.*

## What ships today

The architecture is complete. ADR-001 through ADR-006 are accepted and implemented. The Mastio runs in standalone and federated mode, same binary. The Connector installs with a double-click. The Court routes ciphertext it cannot read.

What does not ship today: an external security audit, an SLA, a production playbook that has been tested against a real incident. This is a research preview. If you want to build on top of it, great — we want your feedback. If you want to run real traffic on it, not yet.

The code is on [GitHub](https://github.com/cullis-security/cullis). The demo runs in about a minute on a laptop. The architecture is documented at length — start with the [Architecture](/architecture) page, then read about the [deployment shapes](/deployment).

We are open to feedback, security reviews, and ideas. Find us at [hello@cullis.io](mailto:hello@cullis.io).
