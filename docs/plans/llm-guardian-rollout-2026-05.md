# LLM Guardian rollout plan (May 2026)

Companion to ADR-016. This document is the operational map: phase-by-phase deliverables, dependencies, parallelisation slots, risk register, and the immutable safety gates that govern promotion to enforcement mode.

## Goals

- Ship `enforce-fast` Guardian usable by the first design partner within ~3 weeks of the kickoff PR.
- Add no more than 30% p99 latency overhead and no more than 25% throughput drop on the existing nightly stress baseline.
- Keep the rollout opt-in per customer; no existing deployment changes behaviour without explicit operator action.
- Preserve the ability to ship the audit-only signal (Phase 4 slow-path) even when the customer never promotes to `enforce-fast`.

## Phase summary

| # | Phase | Repo | Effort | Parallelisable | Blocks |
|---|---|---|---|---|---|
| 1 | ADR + endpoint scaffolding + SDK no-op hook | cullis (public) | ~1d | no | 2, 3, 6 |
| 2 | `llm_guardian` plugin: fast-path tools + cache + modes | cullis-enterprise (private) | ~3d | with 3, 6 | 4, 5, 7 |
| 3 | SDK cooperation flow (send + receive paths) | cullis (public) | ~1d | with 2, 6 | 5, 7 |
| 4 | Slow-path async pipeline + LLM-judge plugin | cullis-enterprise (private) | ~2d | no | 7 |
| 5 | Nightly stress lane + perf gate in CI | cullis (public) | ~1d | no | 7 |
| 6 | Dashboard UI (rule editor, audit timeline, mode toggle) | cullis-enterprise (private) | ~2d | with 2, 3 | 7 |
| 7 | Image rebuild, integration kit, customer runbook | cullis-enterprise (private) | ~1d | no | release |

**Total wall-clock with parallelisation: ~9-10 days. Sequential: ~11 days.**

## Phase detail

### Phase 1 — Foundation (cullis public, ~1d)

**Branch:** `feat/guardian-foundation`. **PR target:** main.

Files added or extended:

- `docs/adrs/0016-llm-guardian-bidirectional.md` (this PR brings it from Proposed to Accepted once reviewed).
- `mcp_proxy/guardian/__init__.py`
- `mcp_proxy/guardian/endpoint.py` — `POST /v1/guardian/inspect`, mTLS-authenticated, returns `pass` for everything (no logic yet). Supports the `direction`, `peer_agent_id`, `msg_id`, `payload_b64` body shape from the ADR. Always emits an `audit_id` and a signed ticket so the SDK side can be developed against a real response.
- `mcp_proxy/guardian/registry.py` — `Tool` ABC + `register_tool(direction, mode, fn)`. Plugin entry point `cullis.guardian_tools` for downstream plugins.
- `mcp_proxy/guardian/ticket.py` — JWT sign/verify with `MCP_PROXY_GUARDIAN_TICKET_KEY`, exp 30s, fields `agent_id`, `peer_agent_id`, `msg_id`, `direction`, `decision`, `audit_id`.
- `mcp_proxy/guardian/audit.py` — `record(audit_id, decision, reasons[])` writes to a new `guardian_audit` table (alembic migration in this PR). Hash-chained (reuses the audit-chain helper coming out of security Sprint 4 if landed; otherwise plain append-only with a TODO).
- `cullis_sdk/guardian/__init__.py`
- `cullis_sdk/guardian/client.py` — `inspect_before_send(payload, peer)` and `inspect_before_deliver(payload, peer)`. NO-OP unless `MCP_PROXY_GUARDIAN_ENABLED=1`. When enabled, POSTs to the local Mastio guardian endpoint and returns the decision + ticket. Exposes `verify_ticket(jwt, expected_msg_id)` for the agent runtime to use before acting on a delivered message.
- Tests:
  - `tests/test_guardian_endpoint.py` — passthrough returns `pass`, ticket signs + verifies, mTLS auth required, unknown agent 401, malformed body 422.
  - `tests/test_guardian_ticket.py` — sign + verify roundtrip, expired ticket rejected, wrong msg_id rejected, missing key 503.
  - `tests/test_sdk_guardian_client.py` — NO-OP when disabled, posts when enabled (httpx mock), surfaces decision + ticket, raises `GuardianBlocked` on `decision=block`.

**Deliverable:** end-to-end skeleton green in CI. The SDK can call the endpoint, get a `pass` decision, get a ticket, verify it. No real inspection happens yet but the contract is locked.

### Phase 2 — Fast-path tools (cullis-enterprise, ~3d)

**Branch:** `feat/mastio-llm-guardian`. **PR target:** main of cullis-enterprise.

Plugin layout:

```
cullis_enterprise/mastio/llm_guardian/
  __init__.py
  plugin.py           # registers tools into mcp_proxy.guardian.registry
  config.py           # CULLIS_GUARDIAN_* env loader, mode resolver per binding
  cache.py            # sha256 idempotence cache (Redis when configured, in-memory dev fallback)
  tools/
    __init__.py
    prompt_injection.py
    tool_escalation.py
    loop_detection.py
    pii_egress.py
    secret_leak.py
    reach_guard.py
  rules/
    prompt_injection.yaml   # ships with starter pattern set
    pii.yaml
    secrets.yaml            # imports TruffleHog regex catalog
```

Each tool implements `Tool.evaluate(payload, ctx) -> ToolResult` where `ToolResult` carries `decision`, `redacted_payload`, `reasons`. The plugin's `startup` registers each tool in the appropriate fast-path direction. Mode resolution per binding consults the `binding_guardian_modes` table (new alembic migration here, in the public repo? — see open question below).

Tests target ~40 cases: per-tool positive + negative + redaction, per-mode behaviour (audit-only returns pass, enforce-fast returns the tool decision), cache hit + miss, parallel `asyncio.gather` correctness, mode override per binding.

### Phase 3 — SDK cooperation flow (cullis public, ~1d)

**Branch:** `feat/sdk-guardian-cooperation`. **PR target:** main.

Wires `cullis_sdk.guardian.client.inspect_before_send` into the existing send paths (`send_oneshot`, `reply`, `send_message`, internal `_send_envelope`). Wires `inspect_before_deliver` into the receive path (`receive_oneshot`, `await_response`, `_decrypt_envelope`).

Introduces `cullis_sdk.guardian.GuardianBlocked` exception so the agent code can handle blocks distinctly from network errors. When mode is `redact`, the SDK substitutes the `redacted_payload` returned by Mastio before encrypting (send) or before delivering (receive).

The agent runtime template (`cullis_sdk.runtime.Agent`) calls `verify_ticket` before invoking the user-provided `on_message` handler. Tests cover NO-OP path (env off), pass path, redact path, block path, ticket verification failure (rejects message even if SDK got `pass`).

This is the breaking-change PR. Customers running pinned SDK versions are not affected (they keep ignoring the endpoint); customers on the latest SDK opt in via env var.

### Phase 4 — Slow-path async pipeline (cullis-enterprise, ~2d)

**Branch:** `feat/mastio-guardian-slow-path`. **PR target:** main.

Adds:

- `cullis_enterprise/mastio/llm_guardian/slow_path.py` — bounded asyncio task queue. The endpoint enqueues a copy of the payload after it has computed and returned the fast-path decision.
- `cullis_enterprise/mastio/llm_guardian/judges/` — pluggable judge adapters: `llama_guard_local.py`, `bedrock_guardrails.py`, `openai_moderation.py`. Each implements `Judge.evaluate(payload, ctx) -> JudgeResult`. Customer picks via `CULLIS_GUARDIAN_JUDGE_BACKEND`.
- `cullis_enterprise/mastio/llm_guardian/alerting.py` — when a slow-path tool fires, post to the configured webhook (Slack, PagerDuty, generic JSON POST). Includes the audit_id, the tool name, the matched reason, and a deeplink to the audit timeline.

Decision on judge backend deferred to Phase 4 kickoff: benchmark all three on a 1000-message corpus, report latency + accuracy + cost, pick. The pluggable adapter shape lets customers swap later.

### Phase 5 — Nightly + perf gate (cullis public, ~1d)

**Branch:** `feat/nightly-guardian-lane`. **PR target:** main.

Extends the existing nightly stress harness (the one that surfaced the DPoP concurrency stall) with a Guardian lane:

- New compose stack `nightly/guardian/` with the plugin loaded, mode `enforce-fast`, 100% Redis cache hit rate baseline + 0% baseline + 50% baseline.
- Three runs: 10 agents, 25 agents, 50 agents. Compares p50/p95/p99 latency and rps to the no-Guardian baseline.
- CI assertion: nightly fails if p99 > 1.3x baseline OR rps < 0.75x baseline OR error rate > 1%.
- Result published as a comment on the nightly run summary issue (existing pattern).

This phase establishes the go/no-go signal for promoting any customer from `audit-only` to `enforce-fast`. Without a green nightly, the dashboard refuses the promotion (Phase 6 enforces this in UI).

### Phase 6 — Dashboard UI (cullis-enterprise, ~2d)

**Branch:** `feat/mastio-guardian-dashboard`. **PR target:** main of cullis-enterprise.

Adds three pages under `/proxy/guardian/`:

- **Modes**: per-binding mode toggle, global default, history of mode changes. Promotion to `enforce-fast` shows the latest nightly perf report and asks for confirmation.
- **Rules**: starter rules ship read-only; operator extends via YAML editor (Monaco) or visual builder (form-based) for the simple cases. Live preview against pasted sample payloads.
- **Audit timeline**: queryable view of guardian decisions, filter by tool, decision, agent, peer, time window. Each row links to the full payload (admin-only access, gated by RBAC `admin` role from PR #15).

UI uses the existing dashboard template / asset pipeline. New tests: ~15 cases covering mode change persistence, rule validation, audit query filters, RBAC gates.

### Phase 7 — Image, integration kit, runbook (cullis-enterprise, ~1d)

**Branch:** `feat/mastio-guardian-release`. **PR target:** main of cullis-enterprise.

- `Dockerfile` rebuilds with the `llm_guardian` plugin extras pre-installed.
- `scripts/dogfood.sh` extends the smoke to issue a guardian-blocked message, a guardian-redacted message, a guardian-passed message; verify audit rows + ticket signing.
- `docs/integration/guardian-quickstart.md` — operator-facing guide: enable the SDK env, pick a mode, monitor audit, promote to `enforce-fast`, customer-specific rules.
- `docs/integration/guardian-customer-runbook.md` — incident runbook: false-positive triage, rule rollback, emergency disable (`MCP_PROXY_GUARDIAN_MODE=disabled` global override + audit annotation explaining why).
- Release notes + changelog entries on both repos.

## Dependencies

```
PR #378 #15 #16 (RBAC + SCIM, in review or recently merged)
       │
       ▼
  Phase 1 (foundation)
       │
       ├─► Phase 2 (plugin tools)  ──┬─► Phase 4 (slow-path)
       ├─► Phase 3 (SDK cooperation) ┤
       └─► Phase 6 (dashboard UI)    │
                                     ▼
                                Phase 5 (nightly perf gate)
                                     │
                                     ▼
                              Phase 7 (image + docs)
```

## Parallelisation slots

After Phase 1 lands, three slots open:

1. **Slot A — plugin author**: Phase 2 (fast-path tools). Largest piece.
2. **Slot B — SDK author**: Phase 3 (cooperation flow).
3. **Slot C — dashboard author**: Phase 6 (UI).

Each slot can be a separate Claude Code session in a dedicated worktree:

- Slot A: `/home/daenaihax/projects/cullis-enterprise-guardian-tools` on `feat/mastio-llm-guardian`.
- Slot B: `/home/daenaihax/projects/agent-trust-sdk-guardian` on `feat/sdk-guardian-cooperation`.
- Slot C: `/home/daenaihax/projects/cullis-enterprise-guardian-ui` on `feat/mastio-guardian-dashboard`.

Slots A and C touch only `cullis-enterprise`; Slot B only `cullis` (public). No file collisions among the three. Slots A and B share the contract from Phase 1 but do not edit the same files. The security agent on Sprint 3+4 stays on `cullis` main repo touching `mcp_proxy/auth/`, `mcp_proxy/audit/`, `app/auth/`, `app/kms/`, `cullis_sdk/crypto/` — none overlap with `mcp_proxy/guardian/` or `cullis_sdk/guardian/`.

## Risk register

| ID | Risk | Probability | Impact | Mitigation |
|---|---|---|---|---|
| R1 | Performance regression beyond budget | medium | high | Phase 5 perf gate as CI hard fail. Phase 2 ships with the `audit-only` default; promotion gated by Phase 5 result. |
| R2 | SDK breaking change strands old clients | medium | medium | Feature flag `MCP_PROXY_GUARDIAN_ENABLED` in SDK, default off. Customers pin and upgrade on their own cadence. |
| R3 | LLM-judge model choice locks us in | low | medium | Pluggable adapter from Phase 4 day one. Three backends shipped (local, Bedrock, OpenAI). |
| R4 | Trust assumption on agent runtime | low | medium | Documented in ADR; out-of-scope for v1. Phase 7 runbook flags it for the customer. |
| R5 | Scope creep into v2 LLM-judge sync mode | high | medium | ADR explicitly says v1 is async-only for the slow path. `enforce-strict` is documented as a v1 mode but not implemented (returns 501 in v1). |
| R6 | Idempotence cache cross-tenant contamination | low | high | Cache key includes `agent_id` and `peer_agent_id`. Per-org Redis namespace from existing convention. Phase 2 includes a dedicated test for cross-tenant isolation. |
| R7 | Rule false-positive rate too high on first customer | medium | medium | Mandatory 2-week `audit-only` bake before any `enforce-fast` promotion. Phase 7 runbook documents the triage workflow. |

## Immutable safety gates (pre-go-live)

These cannot be bypassed by feature flag or operator override:

1. Nightly with `enforce-fast` ON for 24h, no failures.
2. p99 latency end-to-end < 1.3x baseline pre-Guardian.
3. Throughput rps > 0.75x baseline.
4. False-positive rate on customer audit-only sweep < 5%.
5. Each tool ships with: rule reference, positive example (block), negative example (legitimate traffic that must not block).

If any gate fails, mode promotion to `enforce-fast` is blocked at the dashboard level. The operator can still flip to `audit-only`. They cannot enable enforcement without all five gates green.

## Open questions to resolve during implementation

- **Q1**: where does the `binding_guardian_modes` table live — on the Mastio core (public) or the plugin (private)? Argument for core: dashboard for mode toggle is a UI on top of binding, which is core. Argument for plugin: keeps the public schema clean. **Default**: in the plugin; revisit if a community dashboard needs to read the mode.
- **Q2**: ticket key distribution to agent runtimes. Same identity bundle as the org CA chain (rotated together) vs separate channel. **Default**: piggyback on identity bundle; rotate together; document the operational implication.
- **Q3**: cache backend default. Redis is the production answer; in-memory works for single-Mastio dev. **Default**: in-memory dev fallback, Redis required for multi-replica deployments (already the existing pattern).
- **Q4**: dashboard rule editor: visual builder, YAML, both. **Default**: YAML editor first (Monaco), visual builder deferred to v1.1 unless a design partner asks for it explicitly during the bake-time.
- **Q5**: LLM-judge model choice (Llama Guard 1B local vs Bedrock Guardrails vs OpenAI Moderation). **Decision**: Phase 4 kickoff benchmark.

## Out of scope for v1

- `enforce-strict` mode actual implementation (returns 501 + clear error message; ADR documents it as v2).
- Customer-trained classifiers beyond the off-the-shelf judges.
- Multi-modal payload inspection (images, audio). v1 is text only.
- Cross-Mastio rule sync (each Mastio carries its own rule set; federation of rules deferred).
- Court-side guardian (cross-org metadata anomaly detection — that's the separate `cross_org_guardian` plugin in the Court Enterprise roadmap).
