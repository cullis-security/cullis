````md
# Architecture

Technical architecture of **Agent Trust Network** — a working prototype of a trust and governance layer for inter-organizational AI agents.

This document describes:

- what the system is trying to do
- how the current prototype is structured
- which guarantees it already provides
- which parts are still simplified or incomplete

This is **not** a final protocol specification and **not** a production architecture.  
It is an implementation-oriented exploration of a possible design space.

---

## 1. System goal

The system explores a simple but important question:

> How can two different organizations allow their agents to interact without relying on blind trust, shared secrets, or ad hoc integrations?

Inside a single organization, agent workflows can often rely on internal identity, internal policy, and internal infrastructure.

Across organizations, that is no longer enough.

A cross-organizational agent system needs at least:

- verifiable agent identity
- explicit authorization
- policy enforcement
- message integrity
- auditability
- operational governance

Agent Trust Network is a prototype that implements these concerns in one coherent system.

---

## 2. Current architectural model

The current prototype uses a **managed broker model**.

A network operator runs a broker that acts as the trust anchor for the network.  
Organizations do **not** run their own brokers in this prototype. Instead, they join the managed network and connect their agents to it.

At a high level:

```text
Org A agent  →  Broker  →  Org B agent
````

The broker is responsible for:

* verifying agent identity
* enforcing policy at session creation
* routing messages
* recording audit events

The broker is **not** the owner of agent behavior.
Each organization remains responsible for its own agent code and business logic.

---

## 3. Prototype scope

This prototype currently focuses on five layers:

1. **Identity**
2. **Authorization**
3. **Policy**
4. **Secure message transport**
5. **Audit and operational control**

It does **not** yet aim to define:

* a universal inter-agent message standard
* a production governance framework
* a full multi-node distributed deployment model
* a final standardization profile

Those would belong to a later phase.

---

## 4. Modules

| Module       | Responsibility                                                                           |
| ------------ | ---------------------------------------------------------------------------------------- |
| Auth         | x509 client assertion verification, broker JWT issuance, replay protection               |
| Registry     | organizations, agents, bindings, org CA storage, capability discovery, public key lookup |
| Broker       | session lifecycle, message routing, WebSocket push, persistence and restore              |
| Policy       | session authorization, message policy checks, role-based rules                           |
| Onboarding   | join flow for external organizations, admin approval/rejection                           |
| Rate Limit   | request throttling for auth, sessions, and messages                                      |
| Injection    | prompt-injection detection on the recipient side                                         |
| Signing      | message signing for integrity and non-repudiation                                        |
| E2E Crypto   | payload encryption and decryption between agents                                         |
| Audit        | append-only event logging                                                                |
| Traceability | optional domain extension for lot/event tracking                                         |

---

## 5. Identity model

### 5.1 Trust anchor

The prototype uses a three-level PKI model:

| Level      | Key Size | Validity | Controlled by       |
| ---------- | -------- | -------- | ------------------- |
| Broker CA  | RSA 4096 | 10 years | Network operator    |
| Org CA     | RSA 2048 | 5 years  | Member organization |
| Agent cert | RSA 2048 | 1 year   | Member organization |

The broker CA is the root of trust for the network.

Organizations generate their own CA and agent certificates, but those become valid in the network only after the broker operator approves the organization and stores its CA certificate.

### 5.2 Agent identity

Each agent certificate contains:

* `CN` for agent identifier
* `O` for organization identifier
* optionally or mandatorily a SPIFFE URI in SAN

Example:

```text
spiffe://atn.local/{org_id}/{agent_name}
```

The current implementation supports SPIFFE-style identity and uses it as the standardized subject form in broker-issued access tokens. The internal database still relies on an internal agent identifier model, so the system currently operates with both forms. 

### 5.3 Current limitations

The identity model is functional, but the current prototype is still simplified compared to a fully hardened PKI implementation:

* certificate validation is sufficient for the prototype but not yet a complete enterprise-grade X.509 validation stack
* the broker trusts a managed CA registry, not a federated trust framework
* identity semantics are still partly internal, partly SPIFFE-based

---

## 6. Authentication flow

When an agent authenticates, it presents a signed JWT client assertion containing its certificate in the `x5c` header.

Current flow:

1. Agent builds a `client_assertion` signed with its private key.
2. Broker extracts the certificate from `x5c`.
3. Broker loads the organization CA from the database.
4. Broker verifies the certificate against the registered org CA.
5. Broker checks certificate validity period.
6. Broker checks revocation status.
7. Broker verifies the JWT signature using the agent certificate public key.
8. Broker checks that JWT subject matches the certificate identity.
9. Broker checks that an approved binding exists for the agent.
10. Broker consumes the JWT `jti` for replay protection.
11. Broker stores the agent certificate for later message-signature verification.
12. Broker issues a broker-signed access token.

This gives the system:

* strong workload authentication
* replay protection on login
* organizational control over membership

### Current limitations

The authentication layer works end-to-end, but is still a prototype implementation:

* token semantics are still minimal
* access-token hardening is incomplete
* certificate validation can be strengthened further
* session/context binding is not yet as strict as it should be in a hardened deployment

---

## 7. Authorization model

Authorization in the current prototype is split across two stages:

### 7.1 Binding

Before an agent can operate, it must have an approved binding in the registry.

A binding represents network-level approval that the agent exists and is allowed to participate.

No binding → no access.

### 7.2 Session authorization

When an agent opens a session with another agent, the broker checks:

* both agents exist and are active
* both agents have approved bindings
* requested capabilities are allowed by both sides
* a session policy allows the interaction

The session layer is intentionally **default deny**:

> if no session policy allows the interaction, the session does not open

This is one of the strongest design choices in the prototype and is central to the trust model. 

---

## 8. Policy model

The current policy engine is a prototype policy layer designed to make governance concrete.

It is deliberately simple, but already demonstrates the distinction between:

* network-wide role policy
* organization-specific policy

### 8.1 Session policy

Session policy is evaluated with **default deny**.

Two policy layers exist:

#### Role policies

Defined by the network operator.
These allow interactions between broad classes of agents.

Example:

```text
role:buyer → role:supplier
```

This allows any buyer-role agent to reach any supplier-role agent, subject to capability constraints and session limits.

#### Org-specific policies

Organization-scoped fallback rules for finer control.

These can constrain:

* target organizations
* capabilities
* max active sessions

### 8.2 Message policy

Message policy is currently **default allow** once a session is active.

Policies can currently block based on:

* maximum payload size
* required fields
* blocked fields

### 8.3 Important note

The current policy system is intentionally simplified.

It is enough to run the prototype and demonstrate governance concepts, but it is **not yet a final policy model**. In particular:

* rule composition is still basic
* deny semantics are limited
* policy precedence needs further hardening
* message policy is lighter than session policy by design

So the policy engine should currently be understood as:

> a functioning governance prototype, not a finished authorization language

---

## 9. Session model

Sessions are explicit communication contexts between two agents.

A session has:

* initiator
* target
* capability set
* status (`pending`, `active`, `closed`)
* expiration time

Flow:

1. Initiator requests a session.
2. Broker verifies identity, scope, and policy.
3. Session is created in `pending`.
4. Target accepts it.
5. Session becomes `active`.
6. Messages can now transit through the broker.
7. Either side can close the session.

This session-oriented model exists to make cross-organizational interaction explicit and auditable, instead of allowing free-form stateless messaging.

### Current limitations

The session model is functional, but still needs hardening around:

* tighter token/session binding
* stricter expiry enforcement
* multi-node concurrency guarantees

---

## 10. Message security model

The broker routes messages, but the message-security model is designed so that trust does not depend on the broker reading the plaintext.

### 10.1 End-to-end encryption

Messages are encrypted end-to-end using a hybrid scheme:

* AES-256-GCM for payload encryption
* RSA-OAEP-SHA256 for wrapping the AES key

The sender encrypts the payload for the recipient using the recipient’s public key.

The broker stores and forwards only an opaque encrypted blob.

### 10.2 Two-layer signing

The prototype uses two distinct signatures.

#### Inner signature

Signed by the sender over the plaintext payload:

```text
session_id | sender_agent_id | nonce | canonical_json(payload)
```

This is verified by the recipient after decryption.

Purpose:

* sender authenticity at the message-content level
* non-repudiation within the system

#### Outer signature

Signed by the sender over the encrypted blob:

```text
session_id | sender_agent_id | nonce | canonical_json(ciphertext_blob)
```

This is verified by the broker.

Purpose:

* transport integrity
* detection of tampering in transit

### 10.3 Security properties provided today

The current prototype already provides:

* confidentiality of message content against the broker
* integrity of transported messages
* replay protection via nonce tracking
* sender-verifiable message authenticity

### 10.4 Current limitations

This layer is one of the strongest parts of the prototype, but it is still custom and not yet standardized.

Limitations include:

* message signing format is application-specific
* message/context binding can be tightened further
* HTTP-level signature standardization is not yet implemented
* cryptographic hardening can still improve

So this is best understood as:

> a functioning secure-message design for the prototype, not yet a final interoperable protocol

---

## 11. Injection detection model

Because the broker cannot decrypt message contents, it cannot inspect prompt content directly.

Injection detection therefore happens **client-side** after decryption and before payload is passed to the LLM.

Current design:

### Stage 1 — regex fast path

Immediate rejection for clearly malicious patterns such as:

* instruction override attempts
* role hijacking
* prompt leak requests
* suspicious system/instruction tags
* encoding tricks

### Stage 2 — LLM judge

Only suspicious payloads are escalated to an LLM classifier.

This keeps the model practical:

* structured B2B payloads usually pass directly
* only suspicious free-text payloads are escalated

This choice is not accidental. It is a direct consequence of end-to-end encryption.

---

## 12. Replay protection

The prototype currently protects against replay in two separate places:

| Attack surface              | Mechanism                       |
| --------------------------- | ------------------------------- |
| Reuse of login assertion    | JWT `jti` blacklist             |
| Reuse of message in session | per-session nonce deduplication |

This is a strong and useful property already present in the prototype.

---

## 13. Revocation and operational control

The system supports certificate revocation via an append-only revocation table.

When a certificate is revoked:

* future authentications fail immediately
* already-issued access tokens still live until expiry

This is an intentional prototype tradeoff.

There is also operational tooling to revoke a certificate and terminate a running agent process locally.

This gives the system a real operational-control story, even though full token/session revocation semantics are not finished yet.

---

## 14. Persistence and recovery

Session state is persisted to the database on every lifecycle change.

On startup, the broker restores:

* pending sessions
* active sessions
* message history
* used nonces

This means the prototype already supports restart recovery without losing session continuity.

That is an important practical feature and one of the strengths of the implementation.

---

## 15. Audit model

The system maintains an append-only audit log for major events:

* authentication
* session creation and acceptance
* message forwarding
* policy decisions
* onboarding
* revocation-related actions

For messages, the log stores transport-level forensic data such as:

* ciphertext hash
* outer signature
* metadata about the event

The plaintext is not logged.

This is an intentional design tradeoff:

* preserve end-to-end confidentiality
* retain operational and forensic evidence

---

## 16. Onboarding and governance

Organizations do not appear in the network automatically.

They go through a join flow:

1. submit org details and CA certificate
2. enter `pending` state
3. wait for admin review
4. become `active` only after approval

This means the network is governed at the **organization level**, not only at the agent level.

That is a key architectural principle of the project.

Agents are workloads.
Governance belongs to organizations.

---

## 17. SDK and agent model

The prototype includes an SDK plus example agents.

This is important because it shows the system is not only theoretical.

The included agents demonstrate:

* real authentication
* real session establishment
* real encrypted messaging
* integration with real LLM backends

The example domain is intentionally simple. It is not meant to claim a full industry workflow. It exists to demonstrate the trust architecture in action.

---

## 18. Traceability module

The traceability layer is an optional vertical extension built on top of the trust core.

It demonstrates how the same trust primitives can be reused for a domain workflow involving:

* lot creation
* event signing
* hash chaining
* certification references
* ledger anchoring

This module should be understood as:

> a domain demonstration of the trust layer, not the core of the project itself

The core remains the inter-organizational trust architecture.

---

## 19. What this prototype already proves

Even with its limitations, the current implementation already proves that the following can work together in one system:

* organizational onboarding
* workload identity
* broker-mediated session governance
* secure inter-agent messaging
* end-to-end confidentiality
* auditability
* policy-driven interaction control

That is meaningful, because many current discussions in this area still remain at a conceptual or standards-definition level.

This prototype shows what those ideas look like when implemented concretely.

---

## 20. What is still unfinished

This is a functioning prototype, but not a finished infrastructure.

Open areas include:

* stronger token semantics and token revocation
* stricter session/context binding
* harder broker-side validation and abuse resistance
* more mature policy semantics
* standardization of message/auth flows
* multi-node deployment robustness
* broader governance model beyond the managed-broker prototype

---

## 21. Positioning

This project should be understood as:

* more concrete than a draft
* less mature than a production platform
* closer to a reference implementation / architecture prototype

It does not try to compete with standards work by replacing it.

Instead, it explores what standard ideas and trust primitives look like when assembled into a working system.

---

## 22. Summary

Agent Trust Network is a working prototype of a managed trust architecture for inter-organizational AI agents.

It is not complete.
It is not hardened enough yet for production.
It is not a standard.

But it is also not only a concept.

It is a functioning implementation that demonstrates a plausible architecture for a problem space that is likely to become increasingly important as autonomous systems move beyond the boundaries of a single organization.
