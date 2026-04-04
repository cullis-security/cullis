# Agent Trust Network

> A working prototype of a trust and governance layer for inter-organizational AI agents.

---

## Why this exists

Today, AI agents are mostly deployed **inside organizations**.
They automate workflows, call tools, and interact with internal systems.

What does not exist yet — but is likely to emerge — is **agent-to-agent interaction across organizational boundaries**.

When that happens, the problem changes completely.

Two companies cannot simply let autonomous systems interact without:

* strong identity (who is this agent, really?)
* authorization (what is it allowed to do?)
* policy (who can talk to whom, under what conditions?)
* audit (what actually happened?)

Today, every integration solves this **ad hoc**, with custom APIs, shared secrets, and no verifiable guarantees.

---

## What this project is

Agent Trust Network is a **working prototype** of a system that addresses this problem.

It explores how a network operator could provide:

* **Workload identity** for agents (x509 + SPIFFE-style identities)
* **Inter-organizational authorization**
* **Policy enforcement at network level**
* **End-to-end encrypted communication**
* **Auditability of every interaction**

This is not a standard, and not a production system.

It is a **concrete implementation** of a possible architecture — meant to make the problem tangible.

---

## What makes it different

Most work in this space today (including emerging drafts and proposals) focuses on:

* defining protocols
* describing trust models
* specifying how agents *should* interact

This project instead focuses on:

> **what it actually looks like to implement such a system end-to-end**

It includes:

* a broker that enforces identity and policy
* a PKI model for organizations and agents
* a session-based communication model
* real message signing and encryption
* a working demo with two independent agents

---

## High-level model

```
Org A agent  →   Trust Broker   →  Org B agent
                (enforces rules)
```

The broker:

* verifies identity (x509)
* enforces policy (default deny)
* forwards messages (E2E encrypted)
* logs all events (audit)

It does **not** read message contents.

---

## Core properties

### Identity

Each agent has:

* an x509 certificate issued by its organization
* a SPIFFE-style identity (`spiffe://...`)

The broker verifies the certificate chain against the organization’s CA.

---

### Authorization & Policy

* Agents must be explicitly approved (binding)
* Capabilities are enforced at session creation
* Policies define who can talk to whom

Sessions are **default deny**:
no policy → no interaction

---

### Communication

* Messages are end-to-end encrypted (AES-GCM + RSA-OAEP)
* Broker sees only ciphertext
* Two-layer signing:

  * inner (plaintext) → non-repudiation
  * outer (ciphertext) → transport integrity

---

### Audit

Every action is logged:

* authentication
* session creation
* message forwarding
* policy decisions

Message integrity can be verified via ciphertext hash + signature.

---

## Current limitations

This is a prototype, not a production system.

Known limitations include:

* Policy model is simplified and not yet fully robust
* JWT/token layer lacks advanced features (revocation, strict scoping)
* Broker is not hardened for adversarial environments
* Message validation is minimal
* No horizontal scalability yet
* Protocol is not standardized

---

## Why this matters

If agents begin to operate across organizations, we will need:

* a way to **trust them**
* a way to **control them**
* a way to **audit them**

This project explores what that layer might look like — in code, not just on paper.

---

## Status

* End-to-end system implemented
* 130+ tests passing
* Full local demo working

---

## Positioning

This project sits between:

* **theory / standardization efforts** (protocol design)
* and **real-world infrastructure** (actual systems)

It is not a standard.

It is not a finished product.

It is a **concrete exploration of the problem space**.

---

## Feedback

If you work on:

* agent infrastructure
* enterprise AI systems
* identity and trust systems

feedback is very welcome.
