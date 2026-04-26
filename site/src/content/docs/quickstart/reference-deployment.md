---
title: "Reference deployment"
description: "Infrastructure stress test with six real LLM-driven agents enrolled via three different methods (BYOCA, SPIFFE, Connector device-code), pumping real model-generated traffic through Cullis intra-org and cross-org."
category: "Quickstart"
order: 40
updated: "2026-04-26"
---

# Reference deployment

**Who this is for**: someone who has read [Sandbox walkthrough](sandbox-walkthrough) and wants to see Cullis carrying **real LLM traffic** — every agent in the deployment is its own container running Ollama-powered decisions, not a scripted ping-pong loop. The point is to verify that the infrastructure (enrollment, mTLS, DPoP, ECDH end-to-end, audit chain) carries the messy real-LLM traffic correctly, including loops that the hop counter has to cap.

The sandbox is a didactic playground (hard-coded nonce ping-pong, BYOCA-only enrollment). The reference deployment replaces the scripted agents with six real LLM containers and exercises all three enrollment paths in parallel.

## What's different from the sandbox

| | `sandbox/` | `reference/` |
|---|---|---|
| Agent runtime | Hard-coded nonce ping-pong | LLM-driven via Ollama |
| Enrollment | All BYOCA | BYOCA + SPIFFE + Connector device-code (simulated) |
| Scenario | `oneshot-a-to-b` (single message) | `widget-hunt` (multi-hop conversation) |
| Setup time | ~30s | ~30s + Ollama warm-up |
| Audience | Learning Cullis primitives | Pitch demo, integration reference, partner evaluation |

Both share the same infrastructure: two Mastios, one Court, Postgres, Redis, two SPIRE servers, two Keycloak instances, two MCP downstream servers. They're mutually exclusive at runtime — same host ports.

## The six agents

| Agent | Org | Enrollment | Role | Capability |
|---|---|---|---|---|
| `alice-byoca` | orga | BYOCA | BUYER | `order.create` |
| `alice-spiffe` | orga | SPIFFE/SPIRE | INVENTORY | `inventory.read` |
| `alice-connector` | orga | Device-code (simulated) | BROKER | `discovery.federate` |
| `bob-byoca` | orgb | BYOCA | INVENTORY | `inventory.read` |
| `bob-spiffe` | orgb | SPIFFE/SPIRE | SUPPLIER | `order.fulfill` |
| `bob-connector` | orgb | Device-code (simulated) | BROKER | `discovery.federate` |

Role determines the system prompt and tool set. Enrollment is orthogonal — every agent ends up with the same API-key + DPoP runtime auth (ADR-011 unified enrollment), regardless of how it got there.

## What the widget-hunt scenario exercises

```
[orga, intra-org, ADR-001 short-circuit]
  alice-byoca → alice-spiffe: "Do we have widget-X?"
  alice-spiffe → alice-byoca: "qty=0, out of stock"
  alice-byoca → alice-connector: "Find widget-X cross-org"

[discovery via Court registry]
  alice-connector → discover(capability="order.fulfill") → bob-spiffe

[cross-org, ADR-009 counter-signature, ECDH end-to-end]
  alice-connector → bob-connector: "Sourcing 100 widget-X for orga"

[orgb, intra-org]
  bob-connector → bob-spiffe: "Can you fulfill?"
  bob-spiffe → bob-byoca: "Check widget-X stock"
  bob-byoca → bob-spiffe: "qty=500"
  bob-spiffe → bob-connector → (cross-org) → alice-connector → alice-byoca:
    "Will fulfill 100 widget-X"
```

Five distinct things land in this run: every enrollment path is active, the intra-org short-circuit fires twice (Court never sees those hops), the cross-org envelope is counter-signed and ECDH-encrypted, the broker uses capability-based federated discovery, and every hop is a real LLM decision via Ollama (gemma3:1b at 100% accuracy, 100% valid JSON across 6 concurrent calls per the personal-agent benchmark).

## Quickstart

```bash
# Sandbox must be down (mutually exclusive — same ports)
bash sandbox/down.sh 2>/dev/null || true

# Bring up reference deployment
bash reference/up.sh

# (assumes Ollama is running on the host with `gemma3:1b` loaded —
# see reference/README.md §Host setup for NixOS specifics)

# Run the multi-hop scenario
bash reference/scenarios/widget-hunt.sh

# Smoke test
bash reference/smoke.sh

# Tear down
bash reference/down.sh
```

## Limitations (deliberate)

**`connector_devicecode_simulated` enrollment** posts to the BYOCA endpoint with a `(connector device-code, simulated)` suffix in the display name. Real Connector device-code requires a logged-in admin dashboard session + CSRF token (no `X-Admin-Secret` bypass), which is incompatible with a fully-automated reference deployment — there's no human in the loop to click "approve". The runtime credentials are identical; only the wire path during enrollment differs. A future auto-approver daemon (programmatic admin login + session cookie + CSRF) could fix this — tracked as Phase 2.5 follow-up.

**The LLM may go off-script.** The default model `gemma3:1b` is excellent at single-turn structured output (the personal-agent stress test measured 100% valid JSON across 6 concurrent calls × 3 roles), but small enough that multi-hop conversational state — *"I already asked X, got reply Y, now I should escalate to Z"* — is unreliable. You will see chains where the BUYER pings the INVENTORY a few times before the hop counter caps it, or where the BROKER terminates without routing. **This is by design for this deployment.** The point isn't "smart agents" — it's that the **infrastructure** (enrollment, mTLS, DPoP, ECDH end-to-end, audit chain) carries real LLM traffic correctly even when the model produces messy decisions. Swap in `gemma3:4b` or `qwen3.5:2b` for better narrative coherence; the Cullis side is unaffected.

**Production architecture would differ.** A real customer deploying Cullis would not run an LLM in the BROKER role — broker routing is deterministic. The reference deployment intentionally LLMs all six roles to maximise the surface area being stress-tested.

## Where to read more

- The full setup checklist (Ollama on NixOS, firewall rules, model choice) lives in [`reference/README.md`](https://github.com/cullis-security/cullis/blob/main/reference/README.md) in the repo.
- Each enrollment path has a dedicated docs page: [BYOCA](../enroll/byoca), [SPIRE](../enroll/spire), [Connector device-code](../enroll/connector-device-code).
- The [Python SDK quickstart](sdk) covers the runtime API the agents use under the hood (`from_api_key_file`, `send_oneshot`, `discover`).
