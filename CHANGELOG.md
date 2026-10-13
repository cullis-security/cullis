# Changelog

Notable changes to the Cullis components released out of this
monorepo. Each component has its own release cadence and tag prefix:
`connector-vX.Y.Z` for the Connector, `mastio-vX.Y.Z` for the Mastio
(both open-core and enterprise bundles), `court-vX.Y.Z` for the Court.
Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The `release-*.yml` workflows extract the section for the released
version from this file via `awk` matching `## [v<version>]`; bodies
flow until the next `## ` heading.

## [Unreleased]

Changes for the next Mastio release will be collected here.

## [v0.7.0] — Local agent demo, authorization hardening and audit controls — 2026-10-13

Adds an isolated local agent demo to the downloadable bundle, makes authorization checks cumulative, and strengthens production authentication, key storage and audit controls. This is a Mastio release; the Python SDK keeps its separate release version.

### Upgrade notes

- **Explicit tool capabilities are required** (#1084). Tools and MCP resources without a declared capability now deny execution. Add capabilities and grants before upgrading; bindings are still required. Static denials take precedence over Rego, and malformed policy configuration or failed Rego evaluation denies access. Review existing rules against [the policy upgrade guide](https://github.com/cullis-security/cullis/blob/mastio-v0.7.0/site/src/content/docs/operate/rego-policies.md#upgrade-behavior).
- **Production LOCAL_TOKEN authentication requires DPoP** (#1065). Standalone production enables this automatically when no posture was explicitly configured. An explicit `MCP_PROXY_LOCAL_TOKEN_REQUIRE_DPOP=false` now prevents production boot unless the operator declares a temporary migration exception with `MCP_PROXY_LOCAL_TOKEN_DPOP_INSECURE_OK=true`.
- **Preserve the database encryption key and Vault data during upgrades.** Legacy Mastio signing keys are encrypted on boot when a master key is configured (#1067). Changing the master requires the [rewrap procedure](https://github.com/cullis-security/cullis/blob/mastio-v0.7.0/docs/operate/master-key-rotation.md), not simply replacing the environment value (#1070). The disaster-recovery guide now makes persistent Vault storage an explicit production prerequisite (#1066).
- **Redis container names follow the Compose project** (#1086). Independent bundle installations no longer collide with a globally named Redis container. The service hostname remains `redis`; update any external scripts that relied on the old container name.

### Breaking — production deployments using `culk_*` user API tokens

- **F-B-15 boot gate.** `culk_*` user API tokens are plain Bearer credentials (no mTLS client cert, no RFC 9449 DPoP proof). With `MCP_PROXY_ENVIRONMENT=production` the Mastio now **refuses to boot** while the surface is enabled (the default) unless the operator either disables it (`MCP_PROXY_USER_API_TOKENS_ENABLED=false`) or explicitly accepts the risk (`MCP_PROXY_USER_API_TOKENS_INSECURE_OK=true`), mirroring the F-B-11/F-B-14 gates. Listing and revoking existing tokens keeps working with the surface disabled; only authentication and minting are gated. Threat model §5.1 documents the trade-off.
- **90-day default TTL at mint.** Tokens minted without an explicit expiry now default to 90 days (`MCP_PROXY_USER_API_TOKEN_DEFAULT_TTL_DAYS`, 0 restores the legacy behaviour). "Never expires" remains available as an explicit choice (`expires_in_days: 0` on the admin API, the new checkbox in the dashboard). Existing tokens are untouched.
- README and threat model no longer claim "refuses plain Bearer outright" unqualified: the claim is now scoped to agent identity surfaces, with the `culk_*` exception documented instead of implied away.

### Audit

- **Audit durability posture is explicit.** The batched audit chain (the default write path) has a bounded crash-loss window: on SIGKILL/OOM/power loss the queued tail — up to `MCP_PROXY_AUDIT_CHAIN_BATCH_SIZE` rows or `MCP_PROXY_AUDIT_CHAIN_FLUSH_INTERVAL_S` seconds — is lost, and the loss is **not detectable by chain verification** (hashes are computed at flush time, so the chain stays contiguous). This was previously documented only in source comments. Now: (a) threat model §2.4 states the boundary and the external cross-check it requires; (b) Mastio declares the active posture at boot (`AUDIT_DURABILITY:` log line); (c) the new `MCP_PROXY_AUDIT_CHAIN_DURABLE=true` opts into per-row durable writes — every row hashed + INSERTed before the request proceeds, write failures surfacing per `MCP_PROXY_AUDIT_FAIL_DENY` — at the cost of the batched path's throughput headroom. SIGTERM/graceful shutdown was and remains loss-free (the shutdown drains the queue).
- **Offline verification and export for the primary `audit_log` chain** (#1077), alongside the existing chain verifier. The verifier's `--require-anchors` floor excludes mock anchors (#1063, #1064).

### Bundle and local demo

- **Local demo with real inference** (#1085). `local-demo.py` prepares a local Ollama model, starts Mastio and an agent in isolated Docker networks, and guides enrollment through administrator approval. The runtime confines agent access to Mastio's TLS endpoint and blocks direct model access and outbound Internet access. Preparation downloads the required artifacts; the default model is approximately 400 MB. State, identities and trust survive restart. See [LOCAL_DEMO.md](https://github.com/cullis-security/cullis/blob/mastio-v0.7.0/packaging/mastio-bundle/LOCAL_DEMO.md).
- The bundle includes `first-agent.py` and its enrollment, authentication and chat instructions. Async database dependencies are included in clean builds (#1084).
- The production Compose memory limit increases from 512 MB to 2 GB (#1062); Helm generates the DPoP nonce secret per installation (#1071). Release image builds now receive the requested version explicitly.

### Authorization and dashboard

- **Required per-agent delegations** (#1084). Sensitive resources can persist `requires_delegation` independently of their rules. Execution requires the declared capability, binding, applicable device tier, static conditions, delegation and Rego approval. Removing a required delegation or its policy denies access. Delegation conditions are separate from caller-supplied arguments.
- **Dashboard write access is centrally enforced** for non-writer roles (#1083). Rotated organization CA keys go through KMS, and newly minted user tokens no longer appear in redirect URLs (#1081).

### AI gateway

- **Per-agent cumulative token budgets** and dashboard usage views by agent and provider (#1073, #1074). Budget enforcement reserves capacity at admission, accounts for streamed usage and preserves counters during seeding (#1082).
- Blocking CPU and DNS operations move off the async event loop (#1078).

### Validation

- CI now includes Ruff and regression coverage for cumulative authorization, policy failures and delegation persistence. SQLite and PostgreSQL smoke suites exercise authorization, audit verification and multi-worker behavior (#1079, #1084).
- Local demo acceptance checks real inference, enrollment, restart persistence, TCP and DNS isolation, and nginx privilege restrictions (#1085).

## [v0.6.6] — Security super-audit + production-shape resilience hardening — 2026-06-05

Two waves of adversarial work on top of v0.6.5. First, an 11-agent red-team super-audit with adversarial verification closed a batch of trust-boundary bugs (SSRF connect-pin gaps, an unauthenticated bridge path, a weak-key signing floor, a multi-worker PKI race, and audit-chain binding gaps). Second, a destructive prod-shape stress test (Postgres + Vault + `environment=production` + 4 workers, validated live end-to-end and under chaos/fault injection) found and fixed the failures that only surface under a real multi-agent production load: a Postgres-only enrollment crash, a runtime that booted green then 500'd on the first login without Redis, identity-creation events that fell outside the tamper-evident hash chain, and `/v1/llm/chat` 401-churn under worker concurrency. Plus the carry-over fixes from the 48h soak.

### Security

- **DPoP server nonce is worker-shared** (#1050). The RFC 9449 §8 nonce was per-process `os.urandom`, so under 4 uvicorn workers a nonce minted by one worker was rejected by another and `/v1/llm/chat` churned `use_dpop_nonce` 401s under concurrency (0/40 chats succeeded in the stress test). The nonce is now derived as `HMAC(secret, time_window)` from a worker-shared secret — stateless, reproducible on every worker — and the secret is wired through `deploy/compose` + the bundle so it is delivered out-of-the-box.
- **Identity audit events join the hash chain** (#1049). `agent.create` / `agent.cert_rotated` / `device_attestation.verified` were written with a raw `INSERT` inside the enrollment transaction, landing with `chain_seq` NULL — outside the tamper-evident chain. They now route through the hash-chained `log_audit` (create-then-audit, post-commit), so identity creation is tamper-evident.
- **Outbound SSRF connect-pin extended to the remaining callers** (#1038, #1039, #1033). The LLM adapter, MCP forwarder, and the last outbound callers now connect to the pre-validated IP, closing DNS-rebinding gaps (M7/M8).
- **`/v1/auth/token` pins the leaf cert and enforces CA constraints** (#1032); **the integrations bridge fails closed on unsigned requests in production** (#1035); **agent cert signing enforces a key-strength floor** (#1036).
- **Multi-worker PKI provisioning serialised** (#1037) — nginx server-cert + legacy migration no longer race across workers. **`dpop_jkt` + on-behalf-of are bound under the v2 audit hash on the batched flush path** (#1031). **The DB password is redacted from the `init_db` boot log** (#1034).
- **`agent.create` is Postgres-safe** (#1047). The dashboard-approval enroll path wrote `federated` as an integer on a BOOLEAN column and reused a text bind on a `timestamptz`, so the first agent approval crashed with HTTP 500 on Postgres (masked by type-permissive SQLite). Now boolean-correct, with a Postgres-backed regression test.
- **Operator Rego policy enforced on the executor tool_call path** (#1059). The executor gated only on capability + binding + tier; it now consults the operator Rego policy with the call arguments, so a data-aware deny (e.g. by `customer_id`) is enforced and audited.

### Reliability

- **Production refuses to boot without a shared security store** (#1048). The DPoP JTI and login-challenge stores require Redis in production; the proxy used to boot green and then 500 on the first agent login. It now fails closed at boot (Redis required, or an explicit single-worker in-memory opt-in), and `deploy/compose` ships Redis so the gate is satisfiable out-of-the-box.
- **Graceful degradation on runtime dependency loss** (#1056, #1052, #1053). A runtime Redis/Postgres outage now returns `503 + Retry-After` instead of a bare 500 or an unbounded worker hang (statement timeout + dependency-aware exception handlers; fail-closed stays fail-closed, only the response shape changes). Enrollment rate-limit 429s carry `Retry-After`, and nginx reshapes upstream-saturation 502/504 into a graceful 503.
- **`/readyz` reflects the Redis backing store** (#1057). Readiness now drains a worker when Redis is down and re-admits it on recovery; `/health` (liveness) is unchanged so a transient blip does not restart-loop the pod.
- **`deploy/compose --prod` is self-sufficient on production secrets** (#1051). `generate-proxy-env.sh --prod` now mints `DB_ENCRYPTION_KEY`, the PDP webhook HMAC, vault secret/KMS backend, and the WebAuthn posture, and the compose maps them — so `deploy --prod` boots without hand-editing `proxy.env`.

### Operations

- **Vault KMS token renewal** (#1041) so the token never lapses under a long-running Mastio. **Refuse-to-boot via a readiness gate** (#1042) instead of a SystemExit respawn loop. **nginx reload-watcher restored** (#1043) so cert rotation / org-change hot reload works. **Audit-log admin chain verified in the dashboard integrity check** (#1040).
- **Server-side pagination for the audit log view** (#1058) — every row is reachable on a large chain and the count is accurate, replacing the in-memory ~1000-row cap.
- **Court/federation UI hidden in standalone mode** (#1060) — a standalone Mastio no longer renders Court references it has no use for.

## [v0.6.5] — Production-shape hardening: DPoP-strict default, multi-worker Vault CA fix, DR guards — 2026-06-02

The output of taking the Postgres + HashiCorp Vault production shape through a faithful end-to-end dogfood and disaster-recovery drills. It closes the bugs that only surface under `kms_backend=vault` + multiple workers + `environment=production` — the exact combination dev and smoke (local KMS, single worker) never exercised: a multi-worker Intermediate CA race that broke agent mTLS, a bundle that could not boot in production, and DPoP-strict egress that was wired to the wrong env var and so never engaged.

### Security

- **Multi-worker Vault CA race closed** (#1022). Under `kms_backend=vault` with the default multi-worker uvicorn (4 workers), no agent could authenticate over mTLS: every worker that booted while the CA was still absent wrote its own Org Root + Intermediate (last-write-wins), so nginx trusted one worker's chain while enrollment signed leaves off another. `VaultKMSProvider` now writes the CA create-only via KV v2 `cas:0`; one worker wins, the losers re-read and adopt the winner's pair. `kms_backend=local` was never affected (atomic `set_config_if_absent`), which is why dev and smoke never caught it.
- **DPoP-strict egress required in production** (#1020, F-B-11). Production now defaults the egress DPoP mode to `required`; plain Bearer egress is refused rather than silently downgraded.
- **DPoP egress mode wired to the env the server actually reads** (#1018). The egress DPoP mode honoured `MCP_PROXY_EGRESS_DPOP_MODE`, but the templated/documented knob used a `CULLIS_…` prefix, so strict mode silently never engaged (fail-open against a zero-trust default). The prefixes are reconciled so the knob takes effect.
- **Postgres advisory lock for `mastio_keys` leaf mint, plus Helm prod-gate parity** (#1024). Closes the multi-worker `mastio_keys` active-signer race (#997) on Postgres with `pg_try_advisory_lock`, and brings the Helm chart's production gates in line with the compose/bundle posture.
- **Refuse-to-boot guards against PKI material loss** (DR-1, #1025). A disaster-recovery drill on a faithful prod-shape stack (Vault + Postgres + 4 workers + production) found that a partial restore (Postgres data restored but Vault CA material not) made the boot mint fresh CA material and silently orphan every enrolled agent's mTLS identity (mTLS 400 for the whole fleet). Two boot-time safety nets close it: (1) the boot refuses, in production, to generate an Org Root or mint a Mastio Intermediate when CA material is absent but enrolled agents already exist, rather than orphaning the fleet (`MCP_PROXY_ALLOW_PKI_REKEY` opts into an intentional re-key; non-production warns and proceeds); (2) first-time Org CA provisioning in production is now explicit (`MCP_PROXY_ALLOW_CA_BOOTSTRAP`), while dev/test keeps zero-config auto-bootstrap. The bundle's `generate-proxy-env --prod` warns about the explicit first-boot provisioning step.

### Operations

- **Working DR backup/restore for the Postgres + Vault pilot shape.** The legacy `scripts/pg-backup.sh`/`pg-restore.sh` pointed at a `deploy/compose/docker-compose.yml` that no longer exists and the pre-pivot `atn`/`agent_trust` database, so they ran against nothing; rewritten to run against the real container (`cullis-mastio-postgres` / `cullis_mastio`) with a fail-closed guard, optional AES-256 encryption, and `.enc` decrypt on restore. New `scripts/vault-ca-backup.sh`/`vault-ca-restore.sh` capture BOTH crown-jewel Vault secrets (Org Root `org-ca` + Mastio Intermediate `intermediate-ca`); a CA backup missing the Intermediate orphans every agent on restore. New `docs/operate/disaster-recovery.md` documents the procedure, the infra-first / Mastio-last restore order, the upgrade and rollback steps (#1027), and the known limitations (single instance, operator-scheduled, Vault snapshot operator-owned, audit-chain ceiling).

### Tests

- **Operator Rego deny end-to-end smoke scenario** (#1019), exercising a policy-driven deny through the real stack, plus AI-gateway and DPoP documentation fixes.

## [v0.6.4] — Capability enforcement, opaque-404 fixes, cold-reader doc hardening — 2026-06-01

Minor on top of v0.6.3, accumulating two-plus weeks of polish. The headline is **real capability enforcement** on the chat and MCP-discovery surfaces (previously decorative), plus the close-out of the opaque-404 the flag-mcp demo surfaced, plus a sweep of SDK-quickstart fixes found by fresh-install cold-reads. The whole release was dogfooded end-to-end on `mastio-demo` against a fresh install (deploy / mint / `pip install` / login / live Anthropic chat / audit chain) with zero workarounds.

### Security

- **`llm.chat` and `mcp.tools.list` capability gates are now enforced** (#1002, closes #22 / #23). Pre-fix these checks were Phase-1 decorative: an authenticated, bound agent reached the chat endpoints (`/v1/chat/completions`, `/v1/llm/chat`, `/v1/messages`) and MCP `tools/list` regardless of its capabilities. Now the gate is the first check after mTLS+DPoP auth and fail-closed: an agent without `llm.chat` gets `403 capability_missing` before any provider dispatch, and the denial is audited (`egress_llm_chat status=denied`). Symmetric fix on the Anthropic-shape router (audit 2026-05-28 BLOCKER B1).
- **Org CA `org_id` bound to the winning CA pair** (#1007, close D-9 split-brain). A multi-worker cold boot could derive the `org_id` from a different CA pair than the one that won the mint race, leaving a fresh install with two views of org identity. The `org_id` now derives from the adopted (surviving) Org CA pair.

### AI gateway / egress

- **Strip the `provider/` routing prefix for native adapters** (#1012). `cullis_native` passed the model id through verbatim, so `anthropic/claude-…` reached the Anthropic API as a literal model name and 404'd upstream. The prefix is now stripped for the native adapters (litellm / portkey keep it for their own routing). Resolves axis (a) of the opaque 404.
- **Caller-safe hint on gateway errors** (#1013). The router discarded `exc.detail`, surfacing a bare 404 with no clue. A self-authored `GatewayError.hint` (model + provider + status only, never `str(exc)`) is now exposed in the HTTP/SSE body while `detail` stays log-only (H-IO-2 preserved). A non-existent model now returns a 404 whose hint names the model and suggests the bare id. Resolves axis (b).
- **Pin `anthropic` + `openai` for the `cullis_native` default** (#1005). The two provider SDKs were missing from the runtime requirements, so the now-default native backend raised `503 provider_sdk_missing` on a clean install.

### SDK & quickstart (cold-reader findings)

- **Vanilla provider drop-in works from the documented zip layout** (#1006). The Anthropic/OpenAI drop-in failed from the exact `identity-bundle.zip` layout the docs ship (`dpop.jwk` required, doubled `/v1` on the Anthropic base_url → 404).
- **SDK quickstart + `deploy.sh` synced to the real agent-create contract** (#1010, #1011). Endpoint is `POST /v1/admin/agents` (not `/create`); response carries `cert_pem` / `cert_chain_pem` / `private_key_pem`; `deploy.sh` guards three informational `grep` reads so a no-match under `set -euo pipefail` no longer truncates the "Next steps" banner; Org CA is read from the user-readable `certs/org-ca.pem`, not the uid-10001 `nginx-certs/org-ca.crt`.
- **Document the `llm.chat` capability in the SDK quickstart** (#1014). Following the quickstart verbatim minted an agent without `llm.chat`, then the companion chat page taught `chat_completion`, which now 403s. The quickstart and chat-completion prerequisites now include `llm.chat` and explain the reserved built-in capabilities.

### Dashboard

- **Backends nav labelled "Backends", not "Tools"** (#1016). The MCP-backend registration page (where you set a tool's `required_capability` and manage agent bindings) was labelled "Tools" in the sidebar and overview topology, colliding with the adjacent "Tool Registry" entry. Both labels are now "Backends".
- **Provider rows labelled native-support vs requires-litellm** (#1008). The AI Providers page distinguishes providers with a native adapter from those still needing the legacy LiteLLM backend.

### Observability & deps

- **App loggers survive the in-process Alembic upgrade** (#1003). Alembic's `fileConfig` ran with `disable_existing_loggers` defaulting to True, silencing every `mcp_proxy.*` logger after the in-process migration on boot (audit DB itself intact). The migration now preserves the application loggers.

### Tests / CI

- **Core Mastio unit tests repatriated into the public repo** (#1004). After the 2026-05-29 finding that `.core-ref` was 261 commits behind and core coverage only ran in the enterprise repo, 127 core-pure unit tests now live and run in the public CI on every PR.
- **Smoke runs the default `cullis_native` backend + capability unit tests land** (#1009). The smoke suite now exercises the shipped default backend, and the capability-enforcement / patch-endpoint unit tests are wired into `test/unit`.

### CHANGELOG hygiene

- `CHANGELOG.md` — new `[v0.6.4]` section above `[v0.6.3]`.
- `README.md` — quickstart curl + project-component table flipped to `mastio-v0.6.4`.
- `site/src/pages/index.astro` + `index-dark.astro` — hero quickstart curl flipped to `mastio-v0.6.4`.

## [v0.6.3] — Fix mastio_keys mint race + LOCAL_TOKEN auth recovery — 2026-05-28

Same-day patch on top of v0.6.2. Restores `/v1/auth/token` and every downstream surface that depends on it (SDK `list_mcp_tools` / `call_mcp_tool`, Connector login, dashboard signing) on fresh installs. Issue cullis#997.

Before this patch, the four uvicorn workers at lifespan startup each entered `AgentManager._mint_mastio_leaf` with their per-process `self._active_key == None` cache and each INSERTed a fresh active row into `mastio_keys`. The `current_signer()` invariant (`activated_at IS NOT NULL AND deprecated_at IS NULL` == 1) was broken on every cold boot; `RuntimeError("N active mastio keys")` was caught silently in `main.py:704`; `app.state.local_issuer` stayed None; `/v1/auth/token` returned 503 `local issuer not initialized` for the rest of the deploy. The bug was confirmed on the v0.6.2 cold-reader run: a fresh `mastio-v0.6.2` deploy reached 4 active rows in 80 ms, and the SDK quickstart snippets that traverse LOCAL_TOKEN auth all failed end-to-end.

### Fix

- **`AgentManager._mint_mastio_leaf` is now single-writer across workers** (#1000). New `_acquire_mastio_mint_lock` / `_release_mastio_mint_lock` helpers in `mcp_proxy/db.py` mirror the existing `_run_migrations_sync_under_flock` pattern: a blocking `fcntl.LOCK_EX` on a sibling-of-DB lockfile (`<db>.mastio_mint.lock`) serialises the mint critical section. Inside the lock the worker re-reads `get_mastio_keys_active()`, adopts the existing row when N=1, repairs the invariant when N>1 (keeps the newest by `activated_at`, deprecates the rest via the new `deprecate_mastio_keys_by_kids` helper), and only mints fresh material when truly absent.
- **Lazy in-place repair for pre-existing N>1 state** (#1000). Operators whose `mastio_keys` table already accumulated stale active rows from pre-fix boots (16 observed on `mastio-demo`) get the repair on the next boot — no manual SQL, no migration step. The first worker to acquire the flock prunes the stale rows; subsequent workers adopt the survivor.

### Scope

- SQLite-only fix; Postgres deploys (0 in the wild today) take the original racy branch. A follow-up patch will switch to `pg_try_advisory_lock` for symmetric coverage.
- 4 unit tests in `test/unit/test_mastio_keys_invariant_997.py` pin the corrected behaviour against both the fresh-boot and N>1-repair paths.

### CHANGELOG hygiene

- `CHANGELOG.md` — new `[v0.6.3]` section above `[v0.6.2]`.
- `README.md` — quickstart curl + project-component table flipped to `mastio-v0.6.3`.
- `site/src/pages/index.astro` + `index-dark.astro` — hero quickstart curl flipped to `mastio-v0.6.3`.

## [v0.6.2] — ADR-039 drop LiteLLM from the critical path — 2026-05-28

Dependency-hygiene patch on top of v0.6.1. Removes LiteLLM from the default chat-completion dispatch path and replaces it with three Cullis-owned native adapters (Anthropic, OpenAI, Ollama). The LiteLLM library is no longer a runtime requirement; operators on Gemini, Bedrock, or Vertex can still opt in via the legacy backend (`pip install 'cullis-sdk[litellm-legacy]'` + `MCP_PROXY_AI_GATEWAY_BACKEND=litellm_embedded`) until their native adapters land.

Triggered by the CVE cluster on the LiteLLM 1.x line in April–May (SQLi `CVE-2026-42208` listed in CISA KEV; RCE `CVE-2026-42271`, RCE `CVE-2026-35029`, OIDC `CVE-2026-35030`, multiple `GHSA-69x8…` advisories). Pinning was the v0.6.x posture; v0.6.2 removes the dependency from the default path entirely.

This is a dependency-hygiene release, not a performance release. End-to-end stress against a mock provider (200 ms artificial latency, single agent, peak 200 VU, 4 minutes) showed `cullis_native` ~5% above `litellm_embedded` in sustained throughput and ~9% lower p50 latency; against Ollama (`qwen2.5:0.5b`, peak 60 VU) the delta is statistically irrelevant (model queue dominates). Image size on disk drops by ~360 MB once the `litellm` wheel and transitive deps are removed from the runtime layer.

### Egress (ADR-039)

- **`mcp_proxy.egress.ProviderAdapter` scaffold** (#988, PR-A). Defines the per-provider dispatch interface (`dispatch`, `dispatch_stream`, model-id resolution, error mapping to `GatewayError`) so each provider lives behind a small, testable surface instead of an `if backend == "...":` ladder in `ai_gateway.py`. Zero behaviour change at this step.
- **`AnthropicAdapter` (`anthropic.AsyncAnthropic`)** (#989, PR-B). Native dispatch via the official Anthropic Python SDK. Maps `claude-…` model ids to the SDK's `messages.create` / `messages.stream`. Preserves the existing audit row shape (`backend="cullis_native", provider="anthropic"`) and the per-agent identity propagation.
- **`OpenAIAdapter` (`openai.AsyncOpenAI`)** (#990, PR-C). Same treatment for the official OpenAI SDK. `gpt-…`, `o1-…`, and any `openai/<model>` prefix resolve here; streaming uses the SDK's `chat.completions.create(stream=True)`.
- **`OllamaAdapter` (raw `httpx`)** (#991, PR-D). Thin client against `POST /api/chat`. No SDK in between because `ollama` Python doesn't add anything we use, and a raw `httpx.AsyncClient` lets us reuse the connection-pool primitive PR-I introduces. `ollama_chat/<model>` resolves here.
- **Default backend flipped to `cullis_native`** (#992, PR-E). `settings.ai_gateway_backend` default is now `"cullis_native"`. Existing deployments that pinned the env var explicitly are unaffected. Operators on Gemini / Bedrock / Vertex still need `MCP_PROXY_AI_GATEWAY_BACKEND=litellm_embedded` until their native adapters land.
- **AI gateway docs reframed** (#993, PR-G). README, site landing page, and the threat model now lead with the native-adapter narrative ("no third-party AI gateway in the critical path"); LiteLLM is presented as the opt-in legacy backend for the still-unported providers, not the default.
- **`litellm` removed from `requirements.txt`** (#994, PR-F). The runtime dependency line is gone from the default install. Operators who still want the legacy backend install it explicitly via the new `litellm-legacy` extra on `cullis-sdk` (or, equivalently, `pip install 'litellm>=1.83.7,<2.0'` next to the Mastio). The `LiteLLMAdapter` in `mcp_proxy/egress/adapters/litellm.py` lazy-imports the package and emits `GatewayError(503, "litellm_not_installed")` on the first dispatch when the operator forgot the extra. Image size drops ~360 MB on the Mastio container.
- **Helm `proxy.aiGatewayBackend` value** (#995, PR-H). New top-level Helm value so Kubernetes operators can flip the backend without templating the env var by hand. Default mirrors the code default (`cullis_native`).
- **Client pooling for the native adapters** (#996, PR-I). The Anthropic, OpenAI, and Ollama adapters now cache their `AsyncAnthropic` / `AsyncOpenAI` / `httpx.AsyncClient` instances in a module-level dict keyed on credential fingerprint. Earlier revisions of the PR-B/C/D adapters built a fresh client per request, which paid the TCP/TLS handshake + auth-header bootstrap cost on every chat call. Measured 4× speedup in the local micro-benchmark; the visible delta in the end-to-end stress is smaller because the audit chain global lock is the next bottleneck.

### Defensive pin retained

- **`litellm>=1.83.7,<2.0` floor on the legacy extra** (#987). The pin landed before the native adapters did, while LiteLLM was still in the default critical path; it now applies only when an operator explicitly installs the `litellm-legacy` extra. Matches the upstream advisory floor for `CVE-2026-42208` / `42271` / `35029` / `35030`.

### CHANGELOG hygiene

- `CHANGELOG.md` — new `[v0.6.2]` section above `[v0.6.1]`.
- `README.md` — quickstart curl + project-component table flipped to `mastio-v0.6.2`.
- `site/src/pages/index.astro` + `index-dark.astro` — hero quickstart curl flipped to `mastio-v0.6.2`.

## [v0.6.1] — Sidebar update-advisory regex fix — 2026-05-27

Same-day patch on top of v0.6.0. The sidebar update advisory on a fresh v0.6.0 install rendered "Update: 0.5.4.1 (running 0.6.0)" — pointing the operator at a tag strictly older than the one they were running. Confidence-killer banner that cold-readers see within seconds of first login.

### Dashboard

- **`mcp_proxy/version_check.py::_SEMVER_RE` accepts 4-component hotfix versions** (#978). The regex matched only `MAJOR.MINOR.PATCH[-PRE]` and the `_version_key` fallback for unparseable strings returned `(1, v)` — strictly greater than every parseable `(0, ...)` tuple. The v0.5.4.1 emergency hotfix tag therefore won `max(candidates, key=_version_key)` over the GitHub releases list, and the banner reported it as the latest. Extended regex to accept `.HOTFIX` 4th component, flipped the unparseable fallback to `(-1, v)` so garbage sorts BEFORE parseable (defence in depth: even if a future tag style slips past the regex, `max()` can no longer pick it). 10/10 new unit tests in `test/unit/test_version_check_hotfix_regex.py` pin the corrected behaviour: 3- and 4-component acceptance, prerelease ordering, hotfix-between-minors, `max()` selection against the exact GitHub release shape that triggered the bug.

## [v0.6.0] — Provider SDK drop-in + VM cold-reader fixes + SDK PyPI catch-up — 2026-05-27

End-to-end cold-reader gate cut on top of v0.5.5. Bundle deploy script auto-detects an interface IP on Linux pure hosts so a VM-on-libvirt + browser-on-laptop setup just works without `host.docker.internal` DNS detours. Vanilla Anthropic SDK and OpenAI SDK reach Mastio via a 3-line `cullis_httpx_client(identity_dir=...)` helper that returns an `httpx.Client` with mTLS + DPoP baked in (ADR-038 Phase 0). And the public PyPI wheel `cullis-sdk` finally catches up with the 4-week monorepo drift: `chat_completion`, `list_mcp_tools`, `call_mcp_tool`, and the post-ADR-014 identity factories are now installable via `pip install cullis-sdk` instead of only readable in the repo.

### Bundle

- **`MCP_PROXY_PROXY_PUBLIC_URL` auto-detected at deploy time** (#971). Previous default of `https://host.docker.internal:9443` silently broke VM + remote-laptop setups: the magic name resolves only on macOS / Windows / Docker Desktop, leaving Linux pure cold-readers with DNS errors on the dashboard URL and 401 `Invalid DPoP proof: htu mismatch` on every enrollment. New `_detect_default_public_host` helper in `packaging/_common-deploy-helpers.sh` picks `host.docker.internal` when `/etc/hosts` carries the entry or the host is not Linux, otherwise the IPv4 of the interface holding the default route, otherwise `localhost`. Both the interactive `deploy.sh` prompt and the `generate-proxy-env.sh --defaults` path use the detected value, and the nginx server cert SAN list now includes the detected IP alongside the operator-typed hostname so an agent reaching the Mastio over IP and a sibling container reaching it over DNS both complete the TLS handshake.

### Provider SDK drop-in (ADR-038 Phase 0)

- **`cullis_sdk.providers_compat.cullis_httpx_client(identity_dir=...)`** (#969). LLM-agnostic helper returning an `httpx.Client` with mTLS client cert + DPoP signing transport. Vanilla Anthropic SDK constructor: `Anthropic(base_url="https://mastio:9443", api_key="cullis", http_client=cullis_httpx_client(...))`. Vanilla OpenAI SDK constructor: `OpenAI(base_url="https://mastio:9443/v1", api_key="cullis", http_client=cullis_httpx_client(...))`. Three lines, no Cullis SDK on the agent code path, no proxy library wrapping.
- **`POST /v1/messages` Anthropic-shape endpoint** (#969). New `mcp_proxy/egress/anthropic_messages_router.py` translates Anthropic Messages requests/responses to the existing OpenAI-shape LiteLLM dispatch. Agent code written for the Anthropic SDK runs unmodified through Mastio's policy + audit + capability gate.
- **nginx mTLS regex extended to `^/v1/(llm|mcp|chat|messages)`** (#969). The previous regex covered only `/v1/llm` and `/v1/mcp`; vanilla SDK paths (`/v1/chat/completions`, `/v1/messages`) fell into the catchall location which strips `X-SSL-Client-Cert` by design, making the handshake invisible to FastAPI. Adding `chat` and `messages` lets the cert reach the principal-resolver while the catchall keeps protecting truly anonymous endpoints.

### SDK (cullis-sdk PyPI 0.2.0)

- **PyPI release 0.2.0** (#972). First publish since 2026-05-01 (0.1.3). The ~4-week drift between the published wheel and the repo HEAD left the public README quickstart examples (`chat_completion`, `list_mcp_tools`, `from_enrollment`, `enroll_via_dashboard_approval`) broken on a fresh `pip install cullis-sdk`. 0.2.0 closes the gap. Bumps: `cullis_sdk/__init__.py::__version__` 0.1.3 → 0.2.0; `packaging/pypi-sdk/pyproject.toml::version` 0.1.3 → 0.2.0; `pyproject.toml` top-level `version` 0.1.0 → 0.2.0 (drift fix). New SDK-specific changelog at `packaging/pypi-sdk/CHANGELOG.md` (distinct from this monorepo file).
- **`CullisClient.from_enrollment(enroll_url)` deprecated** (#973). Cold-reader finding from the 2026-05-27 v0.5.5 VM dogfood: the README quickstart pointed at this method, but the dashboard exposes no surface to generate the one-shot URL it requires, and the server-side `GET /v1/enroll/<token>` endpoint did not survive the 2026-05 pivot. Runtime `DeprecationWarning` emitted on call; removal in 0.3.0. Replacement is `from_identity_dir(...)` after unzipping the admin-minted `identity-bundle.zip` (PR #954). README quickstart rewritten to point at the working flow.

### CI / infrastructure

- **Cloudflare Pages deploy hook** (#970). The native Cloudflare → GitHub webhook started marking production auto-deployments as `skipped` around 2026-05-26 (root cause Cloudflare side, untriaged); the site stayed pinned 17 commits behind `main` until a manual "Retry deployment" was clicked, including across the v0.5.5 release. New `.github/workflows/cloudflare-deploy.yml` POSTs to a Deploy Hook URL (repo secret `CLOUDFLARE_DEPLOY_HOOK_URL`) on every push to `main`. The native webhook still fires for PR preview deploys; this only adds a deterministic trigger for production.

## [v0.5.5] — Dashboard sidebar consolidation + SSRF community default + cold-reader polish — 2026-05-26

Evening minor cut on top of v0.5.4.1, batching the afternoon dogfood findings, the dashboard sidebar consolidation, the agent-create error hardening, and the tier-aware SSRF default for the community bundle. A cold-reader on a vanilla Linux laptop now lands on a less crowded sidebar, dedicated Settings cards for the operator-rare surfaces (PKI, Vault, Network, AI Providers), clickable rows on the Agents and Users tables, and a backend-save that succeeds at the first try when the MCP target is a sibling container on the docker bridge.

### Dashboard

- **Session cookie now python-requests compatible** (#948, D-6). The dashboard cookie value was JSON-serialised with outer quotes plus `\054` (comma) escape sequences; vanilla `python-requests` cookielib mangled the value on the next request and the HMAC verify failed silently, dropping cold-readers who scripted with `requests` (instead of `cullis-sdk` httpx) into a session-invalid loop. New format is `base64url(json).hex(hmac)`, all RFC 6265 cookie-octet characters; `requests`, `httpx`, and `curl` round-trip identically. Legacy-format cookies are still parseable for the 8h migration window.
- **Audit counter tooltips** (#949, A-2). Sidebar / header / chain-verify / DB row counts measure different things; each now carries a `title=""` tooltip explaining what it counts.
- **`/proxy/update` (singular) redirects to `/proxy/updates`** (#949, A-4). 301 redirect preserves the query string.
- **Overview update-available banner** (#949, A-5). Server-rendered inline fallback in addition to the HTMX advisory.
- **A-3 regression guard** (#947). The `agent_cert_grace_cleanup` lifespan watcher's `WHERE previous_grace_period_expires_at IS NOT NULL` filter is the load-bearing line preventing false-positive `grace period expired` warnings. The SQL was already correct; this commit adds 3 regression tests and strengthens the docstring so a future refactor cannot silently relax the filter.

### Bundle

- **`deploy.sh --wipe-data` actually wipes the bind-mounted dirs** (#949, D-10). The host-side `compgen -G` empty-check short-circuited the busybox wipe because the data dir is mode 0700 owned by uid 10001 post init-permissions, so the operator's host uid saw the dir as "empty" even when `mcp_proxy.db` was inside. Removed the compgen probe.
- **Community bundle `MCP_PROXY_POLICY_WEBHOOK_ALLOW_PRIVATE_IPS` default flipped to `1`** (C-3 tier-aware fix). `proxy.env.example` and the compose fallback in both `packaging/mastio-bundle/docker-compose.yml` and `deploy/compose/docker-compose.proxy.yml` now ship `1` instead of `0`. The first-Save-of-an-MCP-backend HTTP 400 (resolves to RFC 1918) no longer hits every cold-reader of the community bundle out of the box, since the primary scenario for the community release is docker-compose with sibling MCP-backend containers on the bridge network. Cloud-metadata (`169.254/16`) and CGNAT (`100.64/10`) stay blocked at the helper level regardless of this knob (`mcp_proxy/utils/url_safety.py:80-83`); the IMDS attack surface is not re-openable from `proxy.env`. The enterprise bundle keeps default-deny because its primary scenario is cloud-hosted with externally-routable backends. Runbook `site/src/content/docs/operate/internal-mcp-backends.md` updated to describe the per-bundle default + posture matrix.

### Enrollment

- **`poll_url` carries the operator-visible `:9443`** (#949, B-1). The `start_enrollment` response now prefers `settings.proxy_public_url` (operator-visible URL) over `request.base_url` (which inside the container resolves to the internal mcp-proxy hostname).

### Site / docs

- **cullis.io hero quickstart pointed at `mastio-v0.5.4.1`** (#946). The site code-block was four releases stale (`v0.5.1`); cold-readers copying the hero command got a 404. Both `index.astro` and `index-dark.astro` bumped.
- **README quickstart polish** (#946). `chat_completion` example switched to OpenAI-compat kwargs style. Added `enroll_via_dashboard_approval` to the entry-points table. `from_identity_dir` signature shows the auto-discovery `dpop.jwk` shape (the D-11 fix made the explicit kwarg unnecessary).
- **Site + README community-only framing** (#951). Removed the "schedule a 30-minute call" CTA and the "Talk to us before regulated production" caveat. Bait-and-switch is the fastest way to burn an HN audience's trust; the community release is the only release today, full stop. Pilot CTA can land again with v0.6.x when the commercial tier actually exists.

### Dashboard — afternoon dogfood findings (2026-05-26 PM)

- **Sidebar footer divider no longer reads as `Settings` underline** (#952). Footer `<div class="border-t">` drew its top border immediately under the Settings nav item with no margin-top; operators perceived Settings as "end of list with underline" rather than the start of the footer block. Added `mt-2` + split `py-3` into `pt-4 pb-3`.
- **Mastio Intermediate CA lazy-reload at signing time** (#953, D-13). The dashboard Create Agent admin path hit `500 Mastio Intermediate CA not loaded` with a 1-in-4 lottery rate: `main.py:332-336` wraps `ensure_mastio_identity()` in a try/except that swallowed transient bootstrap failures silently, so one of the four uvicorn workers could finish boot with `_mastio_ca_key=None` and still accept requests. New `_reload_intermediate_ca_from_persistence()` helper is now called from the 4 sign sites (`_generate_agent_cert`, `sign_external_pubkey`, `ensure_nginx_server_cert`, `_mint_mastio_leaf`) and from `principals_csr.sign_principal_csr` before the existing raise. Same loser-adopt pattern D-9 uses at boot, applied at signing time. `_generate_agent_cert` and `sign_external_pubkey` promoted from sync to async (only two non-test call sites in `admin/agents.py` + `enrollment/service.py`, both already async).
- **Admin identity-bundle.zip download endpoint** (#954, D-14). Post Create Agent the banner said "Open the agent's detail page to download cert + key" but no such endpoint shipped; the `/env-download` button returned only a config `.env` with no credential material. Cold-reader admins who pre-provisioned via the dashboard had no way to deliver the minted identity to the actual agent host. New `GET /proxy/agents/{id}/identity-bundle.zip` returns a 4-file zip (`agent.crt + agent.key + ca-chain.pem + meta.json`) admin-role-only, audited per download (`agent.identity_bundle_downloaded`). DPoP key intentionally NOT in the zip: per RFC 9449 + ADR-014 the DPoP private key is client-side only, generated by `cullis_sdk.dpop.DpopKey.load_or_generate` on first SDK call as a sibling of `agent.crt` (D-11 auto-discovery). Agents minted via BYOCA / SDK enrollment paths (no server-side private key) return 409 with a pointer to the SDK enrol factory.
- **Route-shadow side fix on `agent_detail_page`** (#954). The detail-page route was declared with `{agent_id:path}` which Starlette's greedy `.*` converter silently shadowed for every per-agent sub-route (`env-download`, `reach`, `deactivate`, `delete`). The pre-existing `.env` download endpoint was unreachable through the dashboard for the same reason. Switched to the default `str` converter; agent_ids are pinned to `org_id::name` shape by migration 0041, never contain `/`.

### Dashboard — sidebar consolidation + UX polish (2026-05-26 evening)

- **Sidebar consolidation: PKI / Vault / Network / AI Providers / Updates moved into Settings as labelled cards** (#964). The left sidebar was carrying ten items, most of which an operator opens once during onboarding and then never again. The remaining day-to-day items (Agents, Users, Approvals, Tools, Policies, Audit Log) now have room to breathe; the operator-rare surfaces (`/proxy/pki`, `/proxy/mastio-key`, `/proxy/vault`, `/proxy/network`, `/proxy/ai-providers`) land on the Settings page as five labelled cards with a short blurb each. Updates link removed entirely from the chrome; the `/proxy/updates` route remains reachable by URL. Routes and backend handlers unchanged.
- **Clickable rows on Agents + Users tables** (#965). Whole row navigates to the detail page (mouse click or Enter when focused). Dedicated Actions / Details column removed since its only payload was a button pointing at the same target as the display-name link. Inline mutating controls keep their button-like behaviour via `event.stopPropagation()`: agent Reach toggle (Local / Federated / Both) and user Delete (with confirm dialog) both submit their forms without navigating. `tabindex="0"` + Enter handler preserve keyboard access; `cursor-pointer` makes the affordance visible.
- **Agent-create error path never leaks `str(exc)` into the response body** (#963). Extends the #962 hardening pattern to the dashboard `agents/create` handler. The previous bare `except Exception` interpolated the raw SQLAlchemy string into the error banner; the bound parameters of an `IntegrityError` on `internal_agents.agent_id` already contained the freshly minted cert PEM, so a duplicate-name submission would have spilled the credential material onto the page. Split into a specific `IntegrityError` handler that surfaces "Agent name '<name>' is already taken in this org" and a defensive catch-all that logs the traceback to stderr (visible via `docker logs`) while rendering a generic message to the operator.

Three confidence-killer bug fixes between v0.5.4 release this morning and the public Show HN announce this evening:

- **A-1** dashboard PKI page rendered `Key Size: RSA-256` on the Org CA which is EC P-256 (#944). The `f"RSA-{key_size}"` formatter was wrong for any non-RSA key; `key.key_size` returns the bit-size for every key family (256 for P-256, 4096 for RSA-4096). The new `_format_key_algorithm()` helper inspects the public-key class and renders `EC P-256` (or P-384, P-521) for EC keys and `RSA-{bits}` for RSA keys. Same helper used by the `ca.rotate` audit detail (was hard-coded `RSA-4096`).
- **A-9** dashboard agent detail rendered `CERTIFICATE: No cert` for agents whose cert was valid and verifiable via mTLS (#944). The template was checking `agent.cert_thumbprint` but `_agent_row_to_dict()` never populated that key (no DB column, derive-from-PEM only). The route now passes a parsed `cert_summary` dict (CN, SHA-256 fingerprint, not-after) and the template renders a 3-column grid under the `Issued` badge.
- **D-8** `client.chat_completion(model=..., messages=...)` raised `TypeError` because the SDK accepted only a dict argument (#943). Cold-readers familiar with the OpenAI / Anthropic SDK pattern hit this on the first call. Signature now accepts either form (dict OR kwargs), routes both to the same downstream egress call, raises on the ambiguous "both at once" combo. 4 new unit tests pin the behaviour.

No other changes from v0.5.4.
## [v0.5.4] — Cold-reader dogfood cascade (PKI race + SDK enrol factory + DPoP htu binding) — 2026-05-26

The 2026-05-25 cold-reader dogfood on a fresh-install Mastio bundle exposed six blocking gaps between the operator handing the bundle to a developer and the developer's first chat reply. Five close in v0.5.4 so the open-source path is green end-to-end: `tar xz | ./deploy.sh | SDK enrol | chat reply` on a vanilla Linux laptop, without manually editing `proxy.env`.

### Mastio — multi-worker PKI bootstrap race (D-9)

- **`AgentManager.generate_org_ca` race-safe persistence** (#937). Under `MASTIO_WORKERS=4` each uvicorn worker raced on Org CA generation; the nginx sidecar exported one worker's pair while sibling workers signed the Mastio Intermediate with a different in-memory key, breaking ECDSA chain verification at the mTLS boundary. Fix mirrors `_mint_mastio_ca` winner-election with key+cert coupled into a single JSON payload via `set_config_if_absent`. 3 unit tests pin it.

### SDK — enrol factory + cert chain emission (B-2 / B-4 / B-7)

- **`CullisClient.enroll_via_dashboard_approval` factory** (#934). Zero-boilerplate path from CSR submit to a working `CullisClient`; materialises `agent.key + agent.crt + dpop.jwk + meta.json` into the identity directory.
- **`/admin/agents/{id}/approve` returns `cert_chain_pem`** (#934). Admin path emits the full chain (`leaf || Mastio Intermediate || Org Root`) in one PEM blob.
- **DPoP key persisted as JWK JSON** (#934). `dpop.jwk` loads via `DpopKey.load(...)` with the same canonicalised representation the proxy verifies the thumbprint against.

### Packaging — post-Portkey-pivot public wheel (B-3)

- **`pyproject.toml` no longer force-includes `cullis_connector`** (#935). After the Portkey pivot the Connector moved to the enterprise repo; the public `cullis-sdk` wheel now installs clean from a vanilla checkout. Package list pinned to `["cullis_sdk"]`.

### SDK + Mastio + bundle — DPoP cold-reader hardening (D-11)

- **SDK `from_identity_dir` auto-discovers `dpop.jwk` sibling** (#938). Mirrors the `ca-chain.pem` auto-discovery pattern; customers replaying the quickstart with `cert_path + key_path` alone now load the DPoP key transparently. Load errors downgrade to warning. 4 unit tests pin it.
- **Mastio `_build_htu` returns a tuple of acceptable URLs** (#939). Cold-reader dogfood VM confirmed the actual root cause: `_build_htu` was pinned to `MCP_PROXY_PROXY_PUBLIC_URL` (community bundle default `https://host.docker.internal:9443`), which never resolves from a vanilla Linux host. Fix widens the acceptable set: pinned URL, actual request URL, Host-header URL are all valid `htu` binding candidates. `htu` is the anti-replay binding, not an identity assertion; the client still has to sign with the registered DPoP key, so widening the URL set does not reduce the security posture.
- **Bundle plus Mastio propagate `X-Forwarded-{Host,Port,Proto}`** (#940). Follow-up to #939: `request.url` reconstructed server-side dropped the `:9443` port because nginx forwarded `Host: $host` (no port) and uvicorn rebuilt the URL without it. Bundle nginx forwards `X-Forwarded-{Host,Port,Proto}` explicitly with `$http_host` (carrying the port), Mastio registers uvicorn's `ProxyHeadersMiddleware`, and `_build_htu` adds the X-Forwarded-assembled URL as a belt-and-suspenders candidate. Cold-reader on a vanilla Linux laptop (`localhost:9443`) and on a LAN-reachable VM (`192.168.x.x:9443`) both work out-of-the-box without manually editing `PROXY_PUBLIC_URL`.

### Dashboard — SSRF escape knob discoverability (C-3)

- **Backend-save 400 now surfaces the SSRF escape knobs** (#936). Customers hit `400 outbound URL blocked (RFC 1918 / link-local)` on the first attempt to register an MCP backend reachable only on the Docker bridge network. The dashboard form now renders the exact env vars and per-backend toggle in the error response body. Default posture (`deny`) unchanged.

### Known issues / out of scope

- **D-10**: `deploy.sh --down --wipe-data` does not remove `data/mcp_proxy.db` on Linux hosts where the bundle volume was bind-mounted as the invoking user. Workaround: `rm -rf data/` manually. Tracked, fix in v0.5.5.
- **Encrypted KMS Org CA path** (`LocalKMSProvider.store_org_ca` with `MCP_PROXY_DB_ENCRYPTION_KEY` set) is still race-vulnerable at the provider level. The cold-reader path does not hit this (`validate_config` refuses production starts without the at-rest passphrase), but the encrypted variant deserves the same winner-election treatment in a follow-up.

## [v0.5.3] — Merkle audit anchoring + Rego policy engine + Postgres binding — 2026-05-25

### Late shipping cascade (2026-05-25)

- **`/admin/agents` atomic enrollment transaction** (#928). `INSERT
  first` semantics: when the same agent ID is re-enrolled, the
  primary-key constraint serialises duplicates at the DB layer
  instead of clobbering signing keys mid-write. Removes the
  `MASTIO_WORKERS=1` workaround previously needed to avoid the
  multi-worker race on first enrol. Connection-shared `set_config`
  for the audit trigger so the txn stays atomic across workers.

- **`cert_chain_pem` emitted on agent enrol + SDK auto-discovers
  sibling `ca-chain.pem`** (#929). The admin path now returns the
  full chain (`leaf || Mastio Intermediate || Org Root`) in one
  PEM blob, and `CullisClient.from_identity_dir` looks for a
  sibling `ca-chain.pem` next to `agent.crt` when no explicit
  `ca_bundle` is passed. Zero-boilerplate enrol → first MCP call.

- **SDK lazy auto-login on first MCP call after
  `from_identity_dir` / `from_enrollment`** (#927). Factory no
  longer requires the caller to call `.login_via_proxy(...)` before
  `chat_completion` / `list_mcp_tools`. The client mints its
  Mastio session on demand. 270 regression scenarios cover all
  five auto-login gotchas surfaced during the 2026-05-24 dogfood.

- **`scripts/cullis-audit-verify.py --archive-*` flags** (#925) —
  the offline verifier now also reads `audit_archive` rows
  (Mastio enterprise / Court federation export format) so the
  same tool covers both the live chain and the long-retention
  archive. Inclusion proofs against the Merkle root land in the
  same verification report.

- **nginx — `/saml`, `/scim/v2`, `/admin` routes allowed through
  the mTLS-required group** (#926). Prior nginx config only routed
  the historical surface; the SAML SSO + SCIM provisioning + admin
  bridge endpoints introduced by the audit hardening sprint were
  silently 404'd by the sidecar. Smoke ephemera also dropped from
  the image build context via `.dockerignore`.

- **Smoke framework B1-B12 (`test/smoke/`)** (#931). Single-command
  end-to-end dogfood stack: compose-managed Mastio + mock TSA +
  twelve scenarios covering boot, admin bootstrap, agent enrol,
  Rego policy, chat completion, MCP tool call, audit chain
  integrity, RFC 3161 TSA anchor, offline verify, multi-worker
  enrol race, Merkle anchor. 11/12 PASS on the cold-reader run
  that gates this release.

- **Bundle staging script `scripts/stage-mastio-bundle.sh`**
  (#930). Reproducible builder for the GitHub Release tarball,
  with an explicit file allowlist (no `cp -r`) so v0.5.2's
  missing `_common-deploy-helpers.sh` regression cannot recur.
  Quickstart copy on `packaging/mastio-bundle/README.md` rewritten
  to match the actual one-liner customers paste.

### Mastio — audit chain TSA anchoring (tamper-evident vs operator + vendor)

- **New lifespan watcher `audit_anchor_watcher`** — periodically
  (default hourly) reads the audit_log's chain head, POSTs the
  current `row_hash` to a public RFC 3161 TSA (default
  `http://timestamp.digicert.com`), and persists the signed
  TimeStampToken in the new `audit_chain_anchors` table. Forging
  the chain end-to-end now requires forging the TSA's signature —
  the audit trail is tamper-evident even against an operator
  colluding with the Cullis vendor.

- **New table `audit_chain_anchors`** (migration
  `0043_audit_chain_anchors`) — append-only via the same plpgsql /
  SQLite trigger pattern as audit_log (F-A-402). Stores the
  TimeStampToken raw bytes prefixed with `T1|` so the offline
  verifier `scripts/cullis-audit-verify.py` (which already
  understood the schema) can route them to the asn1crypto / rfc3161
  decoder.

- **`mcp_proxy/audit/tsa_client.py`**: synchronous RFC 3161 client.
  Build the TimeStampReq with `rfc3161-client`, POST over httpx,
  parse the response with `asn1crypto.tsp` (lenient about non-DER
  SET ordering inside SignedData.certificates which several real
  TSAs emit). Re-check the token's messageImprint matches the
  digest we sent before returning, so a rogue TSA cannot poison
  the local table.

- **Configuration**: `MCP_PROXY_AUDIT_ANCHOR_{ENABLED,TSA_URL,
  INTERVAL_SECONDS,TSA_TIMEOUT_SECONDS}`. Default on, default TSA
  DigiCert public, default interval 1h.

- **5 new unit tests** in `test/unit/test_audit_anchor_watcher.py`:
  watcher anchors the latest chain head, skips when already
  anchored, persists nothing on TSA failure, silent on empty chain,
  exits cleanly on `stop_event` set.

- **Dependencies**: `rfc3161-client` + `asn1crypto` added to
  `mcp_proxy/requirements-proxy.txt`.

- **Docs**: new
  [Operate → Audit chain TSA anchoring](https://cullis.io/docs/operate/audit-anchoring)
  page.

### Mastio — Rego engine perf: OPAPolicy instance cache + bench tool

- **Process-wide `OPAPolicy` instance cache** keyed on
  `compiled.sha256`. First evaluate per WASM bundle pays the
  wasmtime instantiation cost (~15-25ms on dev hardware); every
  subsequent decision on the same bundle reuses the cached
  instance. Cache trims at 32 entries (operator policies rotate at
  human pace, FIFO trim is enough).

  Measured impact on a representative 58-line Rego (default-deny
  tool_call + per-agent allowlist + cross-org session gate):

  | metric                  | pre-cache | post-cache | delta |
  |-------------------------|-----------|------------|-------|
  | `evaluate` p50          | 16.23 ms  | **0.21 ms** | **-77×** |
  | `evaluate` p99          | 19.93 ms  | **0.29 ms** | **-68×** |
  | `evaluate` throughput   | 60 op/s   | **4 650 op/s** | **+77×** |
  | `evaluate_decision` p99 | 19.47 ms  | **0.30 ms** | **-65×** |

- **New `scripts/bench-rego-eval.py`** — reproducible bench the
  operator (or anyone evaluating Cullis vs alternatives) can run
  from a clean checkout. Compile time, per-decision latency
  percentiles, throughput. Writes a Markdown report under `imp/` for
  retention.

- **Two new unit tests** in `test_rego_engine.py`: cache reuse on
  same SHA, distinct instances on different SHAs. Autouse fixture
  resets the cache between tests.

### Mastio — embedded Rego policy engine (operator beyond allowlists)

- **New `mcp_proxy/policy/rego_engine.py` module**: compile a Rego
  source via the bundled `opa build -t wasm` CLI, persist the WASM
  bundle, evaluate it in-process via `opa-wasmtime` on every PDP
  decision. No sidecar OPA daemon, no extra container. Sub-millisecond
  eval per decision after the first instantiation (per opa-wasmtime
  benchmarks).

- **Two-layer policy on `/pdp/policy` + `/v1/data/cullis/policy/*`**:
  the operator's Rego (when configured) evaluates first; the legacy
  allowlist (`blocked_agents`, `allowed_orgs`, `capabilities`,
  `tool_rules`) stays active as the fallback for deployments that
  haven't adopted Rego AND as the safety net when Rego runtime eval
  fails (logged at warning, never silently denies). `/v1/policy/tool-call`
  (Connector legacy ambassador path) is intentionally out of scope —
  it carries federation logic that needs a separate coordination pass.

- **Storage**: two new fields inside the existing
  `proxy_config.policy_rules` JSON document — `rego` (operator-authored
  source, kept for the dashboard editor) and `rego_wasm_base64` (the
  compiled WASM bundle, base64-encoded). Backward-compatible: no
  schema migration; existing `policy_rules` documents without these
  fields stay on the allowlist path.

- **Operator UX**: `MCP_PROXY_OPA_BINARY` env pins the OPA binary
  location (defaults to PATH search + `/usr/local/bin/opa`). Compile
  timeout 10 seconds with explicit error message on the Save flow.
  `RegoCompileError` surfaces the `opa build` stderr verbatim so the
  dashboard renders the exact line + column the operator typed wrong.

- **Failure semantics**: `RegoCompileError` blocks Save (operator
  must fix); `RegoEvalError` at runtime → fall through to the legacy
  allowlist + warning log (operator's broken Rego does not brick
  every previously-allowed call). Future work to add a strict mode
  that fails-closed on runtime error tracked separately.

- **23 new unit tests**: `test/unit/test_rego_engine.py` (15 cases —
  compile success / failure / timeout / bundle extraction / WASM eval
  / decision normalisation) + `test/unit/test_policy_helper.py`
  (8 cases — `try_rego_decision` contract: no Rego / malformed
  base64 / runtime error / passthrough on both surfaces).

- **Docs**: new
  [Operate → Rego policies](https://cullis.io/docs/operate/rego-policies)
  page with two complete example policies (org-allowlist + capability
  gate for `session`, per-agent tool whitelist for `tool_call`), the
  authoring workflow against the dashboard Policies page, and the
  constraints (which OPA built-ins do not work in the WASM target).

### Mastio — policy bridge (OPA Data API + CloudEvents sink)

- **New `/v1/data/cullis/policy/{path}` endpoint** — OPA Data API
  compatible binding. Any external agent infrastructure component
  that already consumes the OPA Data API contract can use Cullis as
  its external policy decision point. Two paths wired today:
  `session` (mirror of `/pdp/policy`) and `tool_call` (mirror of
  `/v1/policy/tool-call`). Unknown paths return `{"result": null}`
  per OPA convention so the caller's `default` posture wins. Reuses
  the existing `policy_rules` config from the Policies dashboard —
  the operator writes a policy once and both planes honour it.

- **New `/v1/integrations/cloudevents` sink** — CloudEvents HTTP
  binding (binary mode + structured mode) consumer. Every event
  becomes one row on the append-only hash-chained `audit_log` via
  `db.log_audit`. Mapping documented under
  [Integrations → policy bridge](https://cullis.io/docs/integrations/policy-bridge).
  The customer that runs an external data plane gets one
  cryptographically verifiable audit trail covering both planes
  without writing glue code. External-emitter rows are namespaced
  with an `external:` prefix on `agent_id` so dashboard queries can
  isolate them from native Cullis agents.

- **HMAC guard `MCP_PROXY_INTEGRATIONS_HMAC_SECRET`** — independent
  rotation from the broker PDP plane (`pdp_webhook_hmac_secret`).
  Same posture as the existing PDP webhook: when unset, endpoints
  accept unsigned calls (eases rollout); when set, missing or
  mismatched signatures return 401 with no body so an unauthenticated
  caller cannot probe `policy_rules` content via differential timing.

- **18 new unit tests** in `test/unit/test_policy_bridge.py` cover
  OPA session / tool_call decisions (allow / deny via blocked_agents,
  allowed_orgs, capabilities, blocked_tools, allowed_tools), unknown
  OPA path → null, malformed body → 400, CloudEvents binary +
  structured modes, missing required attributes → 400, HMAC unsigned
  / signed / mismatched / matching.

- **Docs**: new
  [Integrations → policy bridge](https://cullis.io/docs/integrations/policy-bridge)
  page with the architecture diagram, the external-side config knobs
  to set, the smoke commands, and the CloudEvent → audit_log column
  mapping reference.

### SDK — `from_systemd_credentials` factory (Tier 2 agent key storage)

- **New `CullisClient.from_systemd_credentials()` factory** for the
  Linux production deployment pattern that replaces plain 0600 files
  on a writable disk. The factory reads systemd's
  `$CREDENTIALS_DIRECTORY` (set automatically by the unit's
  `LoadCredential=` lines), loads cert + key + DPoP key from there,
  and optionally lifts `mastio_url` / `agent_id` / `org_id` out of
  an `agent.json` metadata file shipped alongside the credentials.
  Credentials live on tmpfs only for the unit's lifetime; the agent
  never reads from a writable disk at runtime.

- **13 new unit tests** in `test/unit/test_sdk_systemd_credentials.py`
  cover the resolution order ($CREDENTIALS_DIRECTORY → argument →
  RuntimeError), eager file-existence checks (named errors on missing
  cert / key, DPoP optional), metadata auto-population vs explicit
  arg precedence, malformed `agent.json` surfaces a clear
  `RuntimeError`, custom credential names (`cert_name=`,
  `key_name=`, `dpop_key_name=`) for operators who deviated from the
  SDK's persisted layout.

- **Docs**: new "Production: systemd LoadCredential" section in
  [Python SDK quickstart](https://cullis.io/docs/quickstart/sdk)
  with a complete unit-file example and the matching agent code.

### Mastio — production-ready Postgres binding (F0.2)

- **Bundle ships `--db postgres` flag** for `deploy.sh`. Brings up a
  bundled Postgres 16 container alongside the Mastio via
  `docker-compose.postgres.yml` overlay; the Mastio reads
  `PROXY_DB_URL` (asyncpg) pointing at it. Default backend stays
  SQLite for the quickstart / demo VM path.

- **Integration test suite `test/integration/test_alembic_full_chain_postgres.py`**
  (gated by `@pytest.mark.postgres` + `CULLIS_TEST_PG_URL`) pins the
  asyncpg binding contract end-to-end: full 43-migration walk against
  a fresh Postgres, append-only `BEFORE UPDATE/DELETE` trigger on
  `audit_log`, `UNIQUE(chain_seq)` surfacing as
  `sqlalchemy.exc.IntegrityError` (the multi-worker retry path
  depends on this), advisory-lock observability via `pg_locks`. Run
  via `./test/run-pg-nightly.sh` which boots the ephemeral
  `test/compose-pg.yml` service, exports the URL, and tears it down.

- **Soak baseline script `scripts/load-soak-pg.sh`**. Replica of the
  A.1b Run 3 SQLite soak profile (ramp 0 → 5000 VU over 30 minutes
  on `/health`) but against the Postgres backend, with a Markdown
  report under `imp/load-test-run4-postgres-<timestamp>.md` showing
  p50/p95/p99 ingress, audit row count, `pg_stat_activity`, error
  rate, and the Run 3 SQLite baseline side-by-side as the decision
  gate.

- **Helm chart `postgres-statefulset.yaml`** comment refreshed —
  removed the obsolete caveat that the proxy image did not read from
  Postgres. The chart has been fully wired for the asyncpg binding
  since ADR-001 Phase 1.3; the new note clarifies how to switch
  between `postgres.internal: true` (bundled StatefulSet) and
  `postgres.externalUrl` (managed cloud).

- **New cullis.io page `operate/postgres-pilot`** covers both the
  bundled overlay and managed cloud Postgres, the required database
  privileges, how to verify the binding with the integration suite,
  and the operator-side troubleshooting matrix (`POSTGRES_PASSWORD`
  missing, orphan SQLite guard, stuck Alembic advisory lock).

[v0.5.5]: https://github.com/cullis-security/cullis/releases/tag/mastio-v0.5.5
[v0.5.4.1]: https://github.com/cullis-security/cullis/releases/tag/mastio-v0.5.4.1
[v0.5.4]: https://github.com/cullis-security/cullis/releases/tag/mastio-v0.5.4
[v0.5.3]: https://github.com/cullis-security/cullis/releases/tag/mastio-v0.5.3

## [Connector v0.5.2] — CRITICAL chat-history cross-user leak — 2026-05-20

### Security

- **CRITICAL — `/v1/conversations` cross-user data leak** (#843).
  Frontdesk bundle deployments running `AUTH_MODE=local` (default for
  Frontdesk v0.2.x) leaked chat history across all enrolled users:
  every user listed, read, AND wrote into the same conversation slot,
  regardless of which cookie authenticated the request.

  Root cause: the Connector cert middleware
  (`cullis_connector/auth/cert_middleware.py`) declared the URL
  prefixes that needed per-user `UserPrincipal` cert binding —
  `/v1/chat/completions`, `/v1/models`, `/v1/mcp`, `/v1/inbox` — but
  the prefix list was missing `/v1/conversations`. The
  conversations router fell back to the Connector-wide `agent_id`
  on every request, collapsing all per-user `principal_id` scoping.

  Fix: one-line addition to `_GUARDED_PREFIXES`. The router-side
  `_authenticate` helper was already correct; the missing middleware
  hookup was the entire bug.

  **All Frontdesk multi-user deployments must update immediately**.
  Pre-fix `conversations.db` rows already store the correct
  per-user `principal_id` columns (writes were just always landing
  on the Connector `agent_id` slot), so no schema migration is
  required. Operators that need to clean the leaked rows from the
  shared slot can run, AFTER REVIEW:

  ```sql
  -- Inside <config_dir>/conversations.db
  DELETE FROM messages
   WHERE conversation_id IN (
     SELECT id FROM conversations
      WHERE principal_id = '<connector-agent-id>'
   );
  DELETE FROM conversations
   WHERE principal_id = '<connector-agent-id>';
  ```

  Tests (`tests/connector/test_cert_middleware.py`, 3 new):
  - `test_guarded_prefixes_includes_v1_conversations` — sentinel
    pin so a refactor can't drop the prefix silently
  - `test_v1_conversations_binds_per_user_principal` — two cookies
    → two distinct `principal_id`s
  - `test_v1_conversations_subpaths_also_guarded` — `/v1/conversations/{id}`
    and `/v1/conversations/{id}/messages` also bound via prefix match

  Standalone Connector desktop (single user, `AUTH_MODE` absent) is
  not affected: only one user exists on the process and the fallback
  to `agent_id` was the same as the real user's principal.

## [Frontdesk bundle v0.2.11] — CRITICAL Connector hotfix passthrough — 2026-05-20

### Security

- Bumps default `CONNECTOR_VERSION` from `0.5.1` to `0.5.2` so a
  fresh `./deploy.sh` (or an `./deploy.sh --upgrade`) on a Frontdesk
  bundle host picks up the Connector cross-user chat history leak
  fix automatically. Operators that pinned a specific
  `CONNECTOR_VERSION` in `frontdesk.env` must update the pin
  manually to `0.5.2` and re-run `./deploy.sh --upgrade`.

### Fixed

- `packaging/frontdesk-bundle/docker-compose.yml` default fallback
  for `${CONNECTOR_VERSION:-…}` was stuck at the stale `0.4.4` even
  though `deploy.sh` had been bumped to `0.5.1` in v0.2.10. A
  deployment that bypassed `deploy.sh` (`docker compose up -d`
  directly with no env file) would have pulled the year-old
  Connector image. Aligned to `0.5.2`.
- `packaging/frontdesk-bundle/frontdesk.env.example` reference
  comment refreshed from the stale `# CONNECTOR_VERSION=0.4.6` to
  `# CONNECTOR_VERSION=0.5.2`.

## [Connector v0.5.1] — Per-user auth gate, bcrypt knob, dir-norm HTTPS — 2026-05-20

### Fixed

- **Per-user auth gate at the Frontdesk root URL** (#827, #828). A fresh
  visitor (new phone on the LAN, fresh incognito tab) used to land on
  the chat surface as the workload principal — the backend refused
  every actual chat call, leaving the user stuck on a logged-in-looking
  shell. The Connector now redirects to `/login` when no
  `cullis_local_session` cookie is present (defence-in-depth alongside
  the nginx gate in the bundle below). Standalone desktop Connector
  unchanged (`is_frontdesk_bundle()` gates the new branch).
- **`/admin/users` paginates** (#828). The endpoint now accepts
  `offset: int = Query(0, ge=0)` and passes it through to
  `list_users(..., offset=int(offset))`, so dev scripts walking the
  table in 500-row pages (`scripts/stress/bulk_create_frontdesk_users.py`)
  actually advance instead of returning the same first 500 rows
  forever.

### Added

- **`CULLIS_BCRYPT_COST` env knob** (#827), clamped `[10, 14]`, default
  `12`. Drop to `10` (~62 ms vs ~250 ms / verify, ~4x faster) when the
  deployment expects bursts of concurrent morning logins above the
  ~16 logins/s ceiling on a 4-worker box at cost 12. Verified
  end-to-end: cost 10 → 67 ms login mediana, cost 12 → 222 ms. Floor
  at 10 to avoid an accidental footgun, cap at 14 to bound worker
  monopoly. Values are read once at module import; bundle env file
  carries an example commented block.

[Connector v0.5.1]: https://github.com/cullis-security/cullis/releases/tag/connector-v0.5.1

## [Frontdesk bundle v0.2.10] — Cookie gate, $effective_scheme, bcrypt knob passthrough — 2026-05-20

### Fixed

- **Inner nginx `location = /` gates on the session cookie** (#827, #828).
  Without a non-empty `cullis_local_session` cookie value, the inner
  nginx now returns `303 /login` instead of proxying the visitor to the
  static SPA shell. Path-only `Location` header (`absolute_redirect
  off`) so the redirect resolves against the operator's actual host:port
  (LAN deployments where the published port differs from the default).
  Tightened in #828 to require a non-empty value after `=` so an empty
  cookie does not tunnel past the gate.
- **`$effective_scheme` map honours `X-Forwarded-Proto: https`** (#827).
  The catch-all `proxy_redirect` that rewrites absolute upstream
  `Location` headers from the SPA's dir-norm 301s now stays on HTTPS
  when the TLS sidecar fronts the bundle. Previously the rewrite used
  `$scheme` which evaluated to `http` (the sidecar→inner hop is plain
  HTTP), producing `http://<host>:8443/login/` and a `400 The plain
  HTTP request was sent to HTTPS port` on the follow-up.

### Changed

- **`CULLIS_BCRYPT_COST` passthrough** in the bundle's
  `docker-compose.yml`. Drop to 10 in `frontdesk.env` when expecting
  morning-login bursts above the cost-12 ceiling. See
  `frontdesk.env.example` for the security tradeoff and the
  2026-05-20 load-test reference.
- **`deploy.sh` defaults to `CONNECTOR_VERSION=0.5.1`** (was `0.4.6`,
  stale since the v0.5.0 release). Fresh installs now pull the new
  Connector image without needing the operator to override the env.

[Frontdesk bundle v0.2.10]: https://github.com/cullis-security/cullis/releases/tag/frontdesk-bundle-v0.2.10

## [v0.5.2] — Pre-pilot audit hardening + dashboard router decomposition + post-Portkey pivot — 2026-05-22

Backfilled 2026-05-25 (image was pushed at tag time but the CHANGELOG entry was
deferred while the audit-hardening sprint kept landing follow-ups). The
release shipped end-to-end on 2026-05-22 22:12 +02:00 (commit `f0902449`,
PR #888); this entry catalogues the work that landed between
`mastio-v0.5.1` and `mastio-v0.5.2` retrospectively.

### Security — pre-pilot CISO sprint (1 CRIT + 16 HIGH + 5 BLOCKER closed)

- **CRITICAL — Court CSR TOFU pubkey pin** (#832, F-A-201). The
  Court principal-CSR endpoint now pins the public key on first
  sight and refuses subsequent rotations that present a different
  pubkey under the same principal ID. Removes a federation-takeover
  vector flagged by the parallel-subagent audit.
- **Refuse-to-start production gates** (#830, H4 sweep) — Mastio
  + Court bundles now fail closed on boot when key safety knobs
  (`VAULT_ALLOW_HTTP=1` in prod, missing `ADMIN_SECRET`,
  `audit_tsa_backend=mock` in prod) are left at dev defaults. Pre-
  fix the gates were fail-open warnings that silently degraded the
  production posture.
- **SSRF shared helper `assert_safe_outbound_url`** (#831). All
  Mastio + Court outbound HTTP calls (PDP webhook, TSA, federation
  push) now route through the same allowlist/private-net guard.
- **Append-only audit triggers + hash v2** (#833). Mastio
  `audit_log` rows are now protected by plpgsql / SQLite triggers
  that reject UPDATE and DELETE at the DB layer; row hash v2
  binds the chain header to the principal type and prevents the
  `T1|` prefix smuggling vector.
- **Court replication recomputes `entry_hash` from canonical
  payload** (#834, F-A-401). The replication consumer no longer
  trusts the producer-side hash; it re-derives from the canonical
  JSON before appending, so a compromised producer cannot inject
  rows that look chain-consistent.
- **Dispute-grade TSA verify + background fail-deny** (#835).
  Offline verifier now treats TSA timestamp tokens as authoritative
  for the chain head ordering, and the in-process anchor watcher
  marks runs as fail-deny when the TSA is unreachable.
- **HTTPException detail leak sweep** (#836, F-A-306 / F-B-119 /
  F-B-402). Every router that returned raw exception text in the
  response body is now wrapped in `safe_detail()` so stack-trace
  fragments and internal IDs no longer reach unauthenticated
  callers.
- **Connector atomic 0600 secret writes** (#838, F-B-401).
  Connector token + key files are now written via `tempfile` +
  `os.replace` under `umask 0o077`, never via streaming write to
  the destination path.
- **Court principal CSR refuses non-NIST EC curves** (#855,
  F-A-102). Curves outside `secp256r1` / `secp384r1` / `secp521r1`
  are now rejected at the signing edge.
- **`/v1/guardian/inspect` routed through the mTLS-required
  nginx group** (#874). Pre-fix the LLM guardian inspection path
  was reachable on the public sidecar without client cert.
- **MCP tool gate fails closed on empty `required_capability`**
  (#858, F-A-304). A tool registered with an empty capability list
  no longer short-circuits to allow; it now requires an explicit
  bypass token from the operator.
- **Caller-controlled audit `details` payload size cap** (#861,
  F-A-410). Caps the JSON serialised size at 64 KiB so a malicious
  agent cannot wedge the audit chain with megabyte-scale rows.
- **Rate-limit on Connector login endpoints** (#862, F-A-208).
- **Tool-call payload size + message count cap** (#863, F-A-303).
- **`ADMIN_SECRET` required on production bundles** (#864,
  F-A-507). `./deploy.sh` refuses to start the production
  Postgres compose if `ADMIN_SECRET` is unset.

### Connector — CRITICAL chat-history cross-user leak

- **`/v1/conversations` cross-user leak** (#843). See the
  `[Connector v0.5.2]` entry below for full root cause + fix
  detail; the Mastio side of the bundle was bumped in lockstep
  via PR #828 / #844. Defence-in-depth follow-up in #845 to
  refuse the legacy `agent_id` fallback in Frontdesk multi-user
  mode.

### Mastio — dashboard router decomposition (closes F-B-201 + F-B-202)

- **`mcp_proxy/dashboard/router.py` decomposed from 5106 LOC to
  236 LOC** (#839 → #879, 13 PRs). Every Mastio + Court dashboard
  surface now lives in its own `mcp_proxy/dashboard/sub_routers/`
  module: auth, setup wizard, agents, badges, enrollments, key
  rotation, PKI, vault, OIDC, audit, policies, tools, network,
  users, settings, api_status. Sister-files on the Court side
  cover orgs, org_onboard, org_seal, agents lifecycle, policies,
  bindings, sessions, audit, rfq, agents_demo. 66/67 routes
  extracted; only the bare-path `overview` stays inline (FastAPI
  bare-path constraint).
- **Court dashboard `agent-rotate-cert` + `upload-cert` fixed for
  EC org CAs and path-converter shadowing** (#878). The legacy
  god-object obscured a path conflict where `agents/<id>` shadowed
  the rotate-cert sub-path on EC-only orgs.

### Mastio — audit log surface

- **Audit log now records tool parameters + result summary on
  success** (#886). Pre-fix the chain only carried the policy
  decision; the actual tool input/output was elsewhere. The
  dashboard "tool call" detail view is now self-contained.
- **Audit envelope + grouped CISO dashboard + chain-integrity
  verify endpoint** (#887). Single export bundle (chain head +
  signed payloads + TSA anchors) consumable by the standalone
  `cullis-audit-verify.py`. CISO dashboard regroups by principal
  and adds the chain-integrity status badge.

### Docs + repo — Portkey-style pivot

- **Pivot to Portkey-style public repo: Mastio + Python SDK only**
  (#884). Internal-only modules (Connector, Frontdesk, Court,
  agents-demo, sandbox, TS SDK, modern stack) moved to the
  cullis-enterprise private mirror.
- **Site cleanup + filtered navigation** (#885, #890-#892,
  #895-#902). Drops legacy runbooks, Court references, integration
  pages that no longer apply to the open-core surface.
- **README + site repositioning** (#867, #880, #883). Replaces
  unverified statistics with a pain narrative + three
  primary-source quotes, tightens the frustrated-pilot
  governance-layer angle.
- **Repo hardened for outside reviewers** (#882). Drops dev-only
  scripts, secrets templates, and contributor-private notes from
  the public tree.

### Demo / dogfood

- **Three reference demo agents under Cullis governance** (#881):
  KYC, Pitchbook, DORA. Run on the modern dogfood stack
  introduced by PR #846.
- **Modern dogfood stack — local smoke for the post-2026-02
  surface** (#846). Single `./stack/smoke.sh` brings up Mastio,
  the three demo agents, and walks the agent-to-agent flow.

### Fixed

- **Dockerfile no longer COPYs gitignored
  `app/dashboard/templates/`** (#888). Tail of the pre-pivot
  cleanup; the gitignored directory occasionally surfaced as an
  empty layer in the image cache.

[v0.5.2]: https://github.com/cullis-security/cullis/releases/tag/mastio-v0.5.2

## [v0.5.1] — Mastio bundle: `--upgrade` defaults to bundle refresh — 2026-05-20

### Fixed

- **`./deploy.sh --upgrade <ver>` now refreshes the bundle files**, not only
  the image (#823). Pre-fix, the upgrade rewrote `CULLIS_MASTIO_VERSION` in
  `proxy.env` and pulled the new image, but left `docker-compose.yml` +
  helpers at the version the operator originally installed. Env
  passthrough added by newer releases (e.g. PR #818's
  `MCP_PROXY_FRONTDESK_VERIFY_TLS` and `MCP_PROXY_FRONTDESK_CA_BUNDLE`)
  silently disappeared between `proxy.env` and the running container,
  surfacing as "Frontdesk unreachable" on the dashboard for any operator
  who upgraded a v0.4.x bundle to v0.5.0. `--upgrade` is now an alias
  for `--upgrade-bundle`, which downloads the released tarball, extracts
  the new helpers in place (preserving `proxy.env`, `./data`,
  `./nginx-certs`, `./backups`), bumps the version pin, pulls the
  matching image, and restarts the stack with `compose up -d --wait`.

### Changed

- New opt-in `./deploy.sh --upgrade <ver> --image-only` preserves the
  legacy image-only behaviour for air-gapped / forked deploys where the
  operator manages bundle files out-of-band. Default is now the safer
  full refresh; the image-only path is reachable but documented as
  advanced.
- `README.md` ("Updating" section) and `--help` text rewritten to
  reflect the new default. The dashboard's update-available banner
  one-liner (`./deploy.sh --upgrade <ver>`) now genuinely does what
  operators expect.

[v0.5.1]: https://github.com/cullis-security/cullis/releases/tag/mastio-v0.5.1

## [v0.5.0] — Frontdesk Finding #16 closer, ADR-034 PR-A..F shipped — 2026-05-19

### Added

- **`sandbox/dogfood-frontdesk.sh` end-to-end gate** (#819, #820, #821).
  Spawns Ollama on the shared docker bridge, brings up Mastio + the
  Frontdesk bundle, drives `/setup` as a `workload`, approves enrollment
  via the Mastio dashboard, creates user `mario`, logs in through the
  SPA, and asserts `/v1/models` + `/v1/chat/completions` round-trip
  live with a real local model. Moves Finding #16 from "manual VM
  repro" to one command.
- **Delete user action on the Mastio users list** (#818). Operator
  can remove a `local_user_principal` row directly from
  `/proxy/users` instead of poking the DB.
- **`verify_tls` knob on Frontdesk-bridge admin actions** (#818).
  When the Mastio dashboard reaches a Frontdesk container that fronts
  itself with a self-signed cert, the admin can opt into trusting it
  for the duration of the bridge call without weakening the global
  TLS posture.

### Fixed

- **User-principal CSR response now carries `leaf + Mastio Intermediate`**
  (#820). `mcp_proxy/registry/principals_csr.sign_user_csr` mirrors the
  workload fix shipped in #816: nginx's `ssl_client_certificate`
  (Org Root only) cannot walk leaf → root without the intermediate
  the SDK ships at the TLS handshake, so user mTLS calls into
  `/v1/(egress|agents|llm|chat)` 401'd on every modern Frontdesk
  bundle. Closes the elusive "200 OK in subprocess, 401 in uvicorn
  worker" reported by the sandbox.
- **`/v1/models` honours the per-user cert in single-mode**
  (#821). The single Ambassador router forked on
  `request.state.user_credentials` for `chat_completions` already
  (ADR-025 Phase 3), but `list_models` was still going through the
  Connector workload `AmbassadorClient` — which is not a
  UserPrincipal, so Mastio's mTLS gate dropped the request. Build a
  per-request `CullisClient` from the bound credential, cache on
  `principal_id`, and promote the fail-loud branch from
  `is_shared_mode()` to `is_frontdesk_bundle()` so the modern bundle
  (no `AMBASSADOR_MODE=shared`) gets the same 503 instead of
  silently advertising hardcoded Claude defaults.
- **`principal_type` propagated through enrolment UPDATE path** (#815).
  Re-enrolling a workload after the first wizard pass kept the
  `principal_type` empty on the `internal_agents` row, so downstream
  capability gates treated the principal as an agent. The UPDATE path
  now sets the column alongside the cert and DPoP fields.
- **External pubkey responses include the Mastio Intermediate** (#816).
  Same shape as the user-CSR fix above, but for the agent path
  `sign_external_pubkey`. Pre-fix, `cullis_sdk._egress_http` could not
  build a chain into the Mastio Intermediate without an extra
  side-channel CA fetch.
- **Admin password reset + initial-admin picker on the dashboard**
  (#817). The "Admins" surface now lets the operator promote an
  existing principal to admin and reset a known principal's password
  inline, instead of relying on the auto-generated bootstrap password
  the bundle prints to stderr on first start.

### Security

- **Three-tier PKI hardening, end of the leaf-only pocket**: with
  #816 + #820 both the workload and user paths now ship the full
  `leaf → Mastio Intermediate` chain. The Org Root stays cold-by-
  default; the Mastio Intermediate is the one signing every
  end-entity certificate. No more silent fallbacks to leaf-only PEMs.

[v0.5.0]: https://github.com/cullis-security/cullis/releases/tag/mastio-v0.5.0

## [v0.4.7] — Connector wizard pop_signature + Frontdesk TLS sidecar Host port — 2026-05-19

### Fixed

- **Connector in-browser setup wizard now signs `pop_signature` on `POST /v1/enrollment/start`.**
  `cullis_connector/web.py:setup_post` generates a fresh keypair, hands the
  public half to `_start(...)`, but pre-fix it left `private_key` at the
  kwarg default `None`. The helper gates the proof-of-possession signature
  behind `if private_key is not None` (`enrollment.py:267`), so the
  body shipped without `pop_signature`. Mastio v0.4.5+ closed the
  transition window for that field (PR #787), so every wizard-driven
  enrollment against a current Mastio returned HTTP 422 `Field required:
  pop_signature`. The CLI device-code path already passed the kwarg and
  was unaffected. Customer-blocker surfaced during the 2026-05-19 dogfood
  (Frontdesk first-boot wizard against the freshly released Mastio
  v0.4.5).
- **Frontdesk TLS sidecar preserves the request port on `Host` and
  `X-Forwarded-Host`.** `packaging/frontdesk-bundle/nginx-tls/default.conf`
  forwarded the inner nginx with `proxy_set_header Host $host`, which
  strips the port. Any deployment reachable on a non-default HTTPS port
  (the default `:8443` already qualifies, plus any custom port) saw
  every POST from the in-browser enrollment wizard hit
  `403 cross-origin request blocked`: the Connector CSRF middleware
  (`cullis_connector/web.py:881-892`) built `expected_origins` from
  `request.url.netloc` (port stripped by the sidecar) and the browser's
  `Origin` header (port intact) failed to match. Switch to `$http_host`
  on both `Host` and `X-Forwarded-Host` so the port survives both proxy
  hops.

## [v0.4.5] — Mastio three-tier PKI + WebAuthn user sessions + dogfood UX fixes — 2026-05-19

### Added
- nginx sidecar runtime cert rotation via leader-elected lifespan
  watcher (default 24h tick). Pairs with a polling reload-watcher
  script in the sidecar that detects mtime changes on
  `mastio-server.crt` and triggers `nginx -s reload`. Mastio
  containers up beyond the 90-day cert validity now rotate
  automatically without restart. Tunable via
  `MCP_PROXY_NGINX_CERT_WATCHER_INTERVAL_SECONDS` (default 86400)
  and `NGINX_RELOAD_POLL_SECONDS` (default 60). Audit chain entry
  `pki.nginx_server_cert_rotated` per rotation.

### Fixed
- **TLS server cert SAN now auto-includes the host of
  `MCP_PROXY_PROXY_PUBLIC_URL`** (`mcp_proxy/lifespan/_san_resolver.py`,
  customer-blocker fix). Pre-fix the SAN list came verbatim from
  `MCP_PROXY_NGINX_SAN` (default `mastio.local,localhost,host.docker.internal,mastio-nginx,mcp-proxy`)
  and no code path appended the operator-configured public hostname.
  Operators who set `PROXY_PUBLIC_URL=https://<custom-fqdn-or-ip>:9443`
  got a cert that did not match their own URL, so any TLS-strict client
  (Frontdesk Connector, Python SDK, browser without `--insecure`) hit
  `CERTIFICATE_VERIFY_FAILED / hostname doesn't match` on first
  handshake. The new resolver parses `urlparse(public_url).hostname`,
  splits IPv4/IPv6 literals into `IPAddress` SAN entries and DNS names
  into `DNSName` entries, and idempotently appends them to the list
  passed to `ensure_nginx_server_cert`. Surfaced during the 2026-05-19
  dogfood on a VM at `192.168.122.62`.
- **Org display name is now editable inline from the dashboard
  overview card** (`mcp_proxy/dashboard/router.py`,
  `_org_title_block.html` partial). Pre-fix the amber CTA "Set a
  friendly display name" linked to `/proxy/setup`, the full broker
  uplink wizard with six unrelated fields. The wizard's
  `Organization ID` input also looked editable but was silently
  ignored in standalone mode (derived from the Org CA pubkey,
  ADR-006 §2.2), so an operator trying to rename the org typically
  edited the wrong field, hit Save, and saw no change. Three new
  endpoints (`GET /proxy/settings/org/display-name/edit`,
  `POST /proxy/settings/org/display-name`, view fragment) drive an
  HTMX inline edit on the overview title. The setup wizard's
  `org_id` input is now `readonly` when the CA is loaded, with a
  small note explaining the derivation. Surfaced during the
  2026-05-19 dogfood.
- `AgentManager.ensure_nginx_server_cert` now writes
  `mastio-server.crt` as a **full chain bundle** (leaf || Mastio
  Intermediate) instead of leaf-only. Pre-fix the file held only the
  Intermediate-signed leaf, so strict TLS clients (Python `ssl`,
  OpenSSL, Go `crypto/tls`) whose trust store contains only the Org
  Root cert (the sandbox / standalone bundle layout) failed the
  handshake with `unable to get local issuer certificate`, the path
  `Leaf -> Intermediate -> Org Root` was un-buildable. Symptom
  observed in `./sandbox/demo.sh full` post-PR #795: agent-a, agent-b,
  byoca-a unhealthy with `broker https://mastio-nginx-a:9443 not
  reachable`. The reuse path also regenerates a pre-fix single-cert
  `mastio-server.crt` on next boot so upgrades self-heal without
  manual file deletion. Wave 1-A bootstrap follow-up #2 to PR #788
  (which had already updated the `org-ca.crt` trust bundle to the
  full chain but missed the server cert path).
- Phase 0 PKI bootstrap now **migrates** legacy plaintext
  `proxy_config.org_ca_key` / `mastio_ca_key` rows into the encrypted
  `pki_key_store` table before archiving and deleting them. Pre-fix
  the wipe destroyed the only copy of the Org Root keypair on first
  boot post-upgrade, and the federated lifespan
  (`MCP_PROXY_STANDALONE=false`) short-circuited the
  `generate_org_ca` fallback, leaving the Mastio without a usable
  chain and cascading into nginx cert + Mastio Intermediate
  provisioning failures (`./sandbox/demo.sh full` boot failure). The
  migration preserves the existing Org Root pubkey so cross-org
  federation trust pinning (`organizations.mastio_pubkey` on the
  Court) survives the upgrade unchanged. Wave 1-A bootstrap
  follow-up to PR #794.

### Breaking changes

- **`POST /v1/enrollment/start` now requires `pop_signature`** (H-csr-pop
  audit fix). The `pop_signature` field on `StartEnrollmentRequest` was
  Optional during the transition window: a Connector that did not sign
  `"enrollment-pop:v1|<pubkey-sha256-hex>"` still enrolled, with the
  server logging a WARNING. The transition window is closed and the
  field is now mandatory. Pre-v0.4.4 Connectors that don't ship a PoP
  signature fail enrollment with HTTP 400 and a structured detail.
  Connectors v0.4.4+ already ship `_build_pop_signature` and sign by
  default. SDK callers building their own request body must add a
  `pop_signature` over `"enrollment-pop:v1|<pubkey-sha256-hex>"`
  (RSA-PSS or ECDSA-P256, base64url).
- **PKI three-tier chain rebuilt** so agent / Connector / nginx leaves
  are signed by the Mastio Intermediate CA, not the Org Root. The Org
  Root stays cold (private key not in memory at steady state) and is
  only unsealed for rare operations: minting the Intermediate at first
  boot, rotating the Intermediate, generating the CA bundle. Every
  unseal lands a `pki.org_root_unsealed` audit row with the operator
  and reason.
- **Private CA keys are Fernet-encrypted at rest.** New table
  `pki_key_store` (Alembic `0038_pki_key_store`) replaces the
  historic plaintext `proxy_config.org_ca_key` /
  `proxy_config.mastio_ca_key` rows. Envelope is PBKDF2-HMAC-SHA256
  600k iterations + Fernet, keyed off the operator-supplied
  `MCP_PROXY_DB_ENCRYPTION_KEY` passphrase.
- **`MCP_PROXY_DB_ENCRYPTION_KEY` is now required in production.**
  `validate_config` refuses to start when the value is empty or
  shorter than 32 chars. Generate one with `openssl rand -hex 48`.
- **Rebalanced cert validities**:
  - Org Root: 10y to 15y (cold root, longer-lived).
  - Mastio Intermediate: 3y to 5y (auto-rotation hooks make a wider
    window safe).
  - Mastio Leaf: 1y (unchanged).
  - Agent leaf: 1y (unchanged; Wave 2 narrows further with
    grace-period support).
  - nginx server TLS: 1y to 90d (short-lived TLS, auto-renew via
    `ensure_nginx_server_cert` boot pass).
- The nginx trust bundle file (`org-ca.crt` inside `nginx_cert_dir`)
  now holds the **full chain** (Org Root and Intermediate). Strict
  path validation on the client side needs both certs since leaves
  are no longer Org-Root-signed.

### Security

- **Frontdesk shared-mode audit warning (ADR-033 Phase 1).** When the
  Frontdesk Connector forwards a user session to the Mastio without a
  cryptographic assertion from the user (the current state pre-Phase-2
  WebAuthn), the Mastio now emits a structured WARNING log entry and an
  audit chain row of type
  `frontdesk_shared_unauthenticated_user_session_warning`. This gives
  operators a baseline metric for alerting on anomalous impersonation
  patterns before the Phase 2 cryptographic fix ships.
  Opt-out for dev/test: `MCP_PROXY_FRONTDESK_AUDIT_WARNING_ENABLED=false`.
- **Mastio Intermediate CA rotation** lands as `POST /v1/admin/mastio-ca/rotate`
  (admin-secret gated, with `?dry_run=true`). A weekly leader-elected
  background watcher (`mastio_ca_rotation_watcher`) warns at < 180
  days to expiry, errors at < 60, auto-rotates at < 30.
- **Cert expiry watcher daemon (`cert_expiry_watcher`).** Wave 2
  follow-up to the three-tier hardening. A leader-elected background
  loop (24h tick) inspects every cert tier the Intermediate watcher
  does NOT cover and emits warning logs + audit chain rows on
  per-tier thresholds: Org Root (1825d), Mastio leaf (90d), agent
  leaves (90d, one row per agent pinned to the agent_id so the
  audit-by-agent query surfaces it), nginx server cert (30d).
  Visibility only, no auto-rotation. Tunable via
  `MCP_PROXY_CERT_EXPIRY_WATCHER_INTERVAL_SECONDS`,
  `MCP_PROXY_CERT_EXPIRY_WARN_DAYS_ORG_ROOT`,
  `MCP_PROXY_CERT_EXPIRY_WARN_DAYS_INTERMEDIATE`,
  `MCP_PROXY_CERT_EXPIRY_WARN_DAYS_MASTIO_LEAF`,
  `MCP_PROXY_CERT_EXPIRY_WARN_DAYS_AGENT`,
  `MCP_PROXY_CERT_EXPIRY_WARN_DAYS_NGINX`. Opt-out for
  single-shot scripts via
  `MCP_PROXY_CERT_EXPIRY_WATCHER_ENABLED=false`.
- **WebAuthn-bound user session tokens (ADR-033 Phase 2)** for Frontdesk
  shared mode. A new optional `[webauthn]` extra (`pip install
  'cullis-agent-sdk[webauthn]'`) pulls `webauthn>=2.0,<3.0`. Five new
  endpoints under `/v1/principals/{id}/webauthn/*` drive the
  registration + authentication ceremonies; the Connector dashboard
  exposes `/webauthn` for credential management. `user_sessions`
  carries new `user_signed_assertion` (TEXT) + `user_credential_id`
  (BLOB) columns populated when the Connector forwards a verified
  assertion. Migration `0039_webauthn_credentials` is idempotent and
  reversible. Enforcement is gated by `MCP_PROXY_WEBAUTHN_ENFORCEMENT`
  (`off`, `warn`, `required`), defaulting to `warn` so the Phase 1
  audit warnings keep firing during the migration window. When
  enforcement is `required` the Mastio refuses to start without the
  `webauthn` library and `maybe_stamp_user_session` raises HTTP 401
  for any session row missing an assertion. See
  `docs/runbooks/frontdesk-shared-hardening.md` (§WebAuthn user
  enrollment procedure) for the migration playbook.

### Migration

- **Hard wipe at first boot post-upgrade.** When legacy plaintext
  rows are present in `proxy_config` and `MCP_PROXY_DB_ENCRYPTION_KEY`
  is set, the lifespan archives them into `legacy_pki_archive` and
  deletes from `proxy_config`. The Mastio re-issues the chain under
  the encrypted `pki_key_store` schema on the same boot. Operators
  who upgrade without setting the env var see a warning, the legacy
  rows stay in place, and the wipe retries on the next boot.
- All currently-issued agent and Connector certs become Org-Root-issued
  *legacy* certs after the upgrade. They keep working until expiry
  (1 year, the prior validity) because the verifier-side trust store
  pins the Org Root, which still appears in the bundle alongside the
  Intermediate. New issuances and renewals chain under the
  Intermediate.

### Documentation

- **`packaging/mastio-bundle/proxy.env.example` AI gateway block
  refreshed** to reflect the six-provider catalog (Anthropic, OpenAI,
  Gemini, AWS Bedrock, Vertex AI, Ollama). The prior wording told
  operators "only `anthropic` is wired (other providers return 501
  `provider_not_implemented`, OpenAI / Gemini are roadmap)" which had
  been stale since the catalog grew. New copy points operators at the
  dashboard `Settings -> AI Providers` as the recommended config path,
  reframes `MCP_PROXY_ANTHROPIC_API_KEY` as optional-legacy backward
  compat, and clarifies that `MCP_PROXY_AI_GATEWAY_PROVIDER` is a
  fallback tag rather than a hard whitelist. Surfaced during the
  2026-05-19 dogfood (operator read env file before opening dashboard,
  mentally ruled out Ollama as unsupported).
- **Frontdesk shared-mode security hardening runbook** added at
  `docs/runbooks/frontdesk-shared-hardening.md`. Covers container
  security configuration, network isolation, monitoring, update cadence,
  compromise response procedure, and the Phase 2 WebAuthn roadmap.
- **CISO-ready security bundle** published under `docs/security/` and
  `docs/runbooks/`. Four new customer-facing documents land in one PR:
  - `docs/security/threat-model.md` (v1.0): threat catalog (in scope +
    out of scope), trust boundaries, cryptographic primitives, key
    lifecycle, audit trail integrity, compliance mapping preview.
    Cross-links the STRIDE per-component walkthrough on cullis.io.
  - `docs/security/post-quantum-roadmap.md` (v1.0): hybrid-first PQC
    strategy across five phases gated by upstream library maturity
    (`pyca/cryptography` ML-KEM, `liboqs-python` on NixOS, IETF
    composite-sig RFC). Includes spike validation numbers from
    2026-05-06 (X25519 + ML-KEM-768, ~4 to 5 ms roundtrip, +1088 bytes
    overhead). Documents the Org Root rotation coupling with Phase 1a
    kickoff (Wave 1-A deferred rotation automation by design).
  - `docs/runbooks/incident-response.md` (v1.0): severity classification
    (Sev 1 through Sev 4) keyed to Cullis-specific assets (Org Root
    compromise, Mastio Intermediate compromise, agent cert leak,
    Frontdesk Connector compromise). Per-severity response procedure,
    customer notification template, public disclosure template, SLA
    summary matrix.
  - `docs/security/README.md`: index for the new `docs/security/`
    directory with quarterly review cadence note.

### Reference

- ADR-033 PKI three-tier hardening (internal-only) records the threat
  model, design decisions, and effort discovery for the chain rebuild.
- ADR-033 Frontdesk threat model shared-mode (internal-only, separate
  document) records Phase 1 audit baseline + Phase 2 WebAuthn roadmap.

---

## [v0.4.4] — Mastio multi-worker default — 2026-05-16

First Mastio release that uses this file for release notes (the
component had no dedicated changelog before; release notes were
generated from the boilerplate in `release-mastio.yml`).

### Performance

- **Multi-worker uvicorn enabled by default in both bundles** (`mastio-bundle`
  and `mastio-enterprise-bundle`): the compose `command:` for the
  `mcp-proxy` service now passes `--workers ${MASTIO_WORKERS:-4}` on
  top of the existing `--proxy-headers --forwarded-allow-ips '*'`.
  Operators override the count via `MASTIO_WORKERS` in `proxy.env`.
- A.1b stress test (May 2026, internal) confirmed multi-worker
  ship-safe on the default SQLite WAL: 0 audit-chain integrity
  errors in 472k concurrent audit rows across 4 worker processes.
  The `_AUDIT_CHAIN_MAX_RETRIES=5` path in `mcp_proxy/db.py` handles
  cross-process concurrency transparently via the
  `UNIQUE(chain_seq)` constraint + retry.
- Throughput uplift +25–240% RPS on Tier 1 scenarios (50–500
  concurrent agents). The mint endpoint p99 latency dropped ~100x
  (3399ms → 25ms aggregate).

### Notes

- **DPoP replay protection** stays per-worker by default. For
  cross-worker enforcement (recommended for any deploy that
  publishes to the public internet), point the Mastio at Redis via
  `MCP_PROXY_REDIS_URL`. Existing config, now relevant for
  multi-worker deploys.
- **Tier 2+ throughput** (sustained >500 RPS under p99 1s) requires
  the batched audit chain landing in Mastio v0.5 (ADR-033, separate
  roadmap). This release does not change the audit-chain shape.
- **Helm chart and Dockerfile are unchanged.** The bundle compose
  files are the only surface that ships a multi-worker default;
  Helm operators who want the same behaviour set
  `proxy.args[]` accordingly in their `values.yaml`.

## [v0.4.4] — 2026-05-12

Bug-fix release. Two ambassador-side fixes from the 2026-05-12 VPS
demo dogfood that the operator hit while configuring an Ollama
provider through the Mastio dashboard.

### Fixed

- **User keypair now persists across Connector restarts so the
  Mastio's TOFU pubkey pin survives a process restart, cookie TTL
  expiry, or admin-driven password reset** ([#656]): ADR-021 v0.1
  cached the per-user EC keypair in an in-memory dict with a 1 h TTL.
  Each cache miss minted a fresh keypair and re-issued a CSR; the
  Mastio's `principals_csr.py` pinned the public key on first sight
  and refused subsequent CSRs that presented a different one. End
  result: any user who survived a restart got a permanent `403 TOFU
  pubkey mismatch` until an admin manually unpinned them. New
  `UserKeyStore` writes PEMs to
  `~/.cullis/<profile>/user_keys/<sha256(principal_id)>.pem` with a
  tmp + chmod 600 + os.replace atomic write (matches the pattern in
  `cullis_connector/identity/store.py`), shared by both the
  loopback `UserProvisioner` and the shared-mode Ambassador.
- **`/v1/models` now surfaces a fallback indicator instead of
  silently lying when the live Mastio fetch fails** ([#657]): the
  Ambassador's `client.list_models()` call against the Mastio
  failed silently and returned the compiled-in `advertised_models`
  list with no signal to the SPA. Dogfood users who saved an Ollama
  provider but had a broken cert path saw three Anthropic models in
  the dropdown with no hint that the list was not authoritative.
  The `/v1/models` envelope now carries an additive
  `cullis_meta.source` ∈ {`live`, `fallback`} field (OpenAI clients
  ignore unknown top-level fields, so Cursor / LibreChat / raw curl
  keep working unchanged). The Cullis Chat SPA renders an amber
  `offline` chip next to the dropdown when the source is
  `fallback`, with the underlying error string in the `title`
  tooltip.

[#656]: https://github.com/cullis-security/cullis/pull/656
[#657]: https://github.com/cullis-security/cullis/pull/657

## [v0.4.3] — 2026-05-12

Customer-path bug fix for Linux native deployments (issue #634).
Closes the ADR-025 `/api/auth/login` regression that crashed uvicorn
mid-response with `RuntimeError: Invalid HTTP header value` when CSR
provisioning failed.

### Fixed

- **`/api/auth/login` no longer crashes when CSR is unreachable**
  ([#635]): `_bind_login_cert` collapses CSR failures into
  `("deferred", str(MastioCsrError(...)))`. httpx multi-line error
  messages leak LF straight into the `X-Cullis-Provisioning-Detail`
  response header, which uvicorn rejects. The fix introduces a new
  `_sanitize_header_value` helper (strips CR/LF/control bytes, forces
  latin-1, truncates to 256 chars) applied at all three call sites:
  `/api/auth/login`, `/api/auth/change-password`, and
  `/api/auth/reprovision`. Regression test covers the helper directly
  + the deferred-with-multiline-detail path end-to-end. Bug surfaced
  in the 2026-05-12 VPS demo dogfood on NixOS, where
  `host.docker.internal` did not resolve from inside the Connector
  container and every CSR call deferred with a multi-line httpx error.

### Not in this release

- The complementary deploy-side fix that makes
  `host.docker.internal` resolve from the Connector container on
  Linux native ships as `frontdesk-bundle-v0.2.3` rather than a
  Connector release — it lives in
  `packaging/frontdesk-bundle/deploy.sh`.

[#635]: https://github.com/cullis-security/cullis/pull/635

## [v0.4.2] — 2026-05-12

Bug-fix release that ships two crash-class fixes uncovered during the
2026-05-11 VPS demo dogfood, plus the ADR-029 tool-call PDP gate on the
Connector and the conversation-history REST surface the SPA needs.

### Fixed

- **Bug #10 — `/api/status` MUST be async def** ([#631]): the Connector
  dashboard inbox poller spawned a background task at import time
  against a sync `def` handler. On any worker that re-imported the
  module (autoreload, multi-worker uvicorn) the spawn raised
  `RuntimeError: no running event loop`. Customer-path smoke caught it
  before the merge, but the class of regression was real.
- **Bug #5 — `X-Enrollment-Proof` on dashboard `/api/status` poll**
  ([#624]): the dashboard health poll talks to the Mastio with the
  enrollment token but did not attach the DPoP-bound enrollment proof.
  Mastio rejected with 401 once Wave B PR7 ([#627]) tightened
  `LOCAL_TOKEN` DPoP binding.

### Added

- **Conversation history REST + SQLite store** ([#610]): Sprint 1
  Step 6 PR-A. The Connector now persists chat conversations locally
  and exposes them via REST so the Cullis Chat SPA can render a
  sidebar history. Per-user attribution is preserved (ADR-021 KMS path).
- **ADR-029 Phase D-1 — Connector PDP gate per tool call** ([#602]):
  the Connector now enforces the tool-level PDP decision returned by
  the Mastio when an MCP client invokes a tool. Closes the last
  cross-org enforcement gap in the ADR-029 tool-call DAG.

[#631]: https://github.com/cullis-security/cullis/pull/631
[#624]: https://github.com/cullis-security/cullis/pull/624
[#610]: https://github.com/cullis-security/cullis/pull/610
[#602]: https://github.com/cullis-security/cullis/pull/602

## [v0.4.1] — 2026-05-11

Patch release. Restores the PyInstaller binary distribution path that was
broken in v0.4.0: ADR-021's ``cullis_connector.identity`` modules import
SQLAlchemy at module load, but ``packaging/pyinstaller/build.sh`` did not
install SQLAlchemy in the build venv nor declare it as a hidden import, so
the resulting executable crashed at first launch with
``ModuleNotFoundError: No module named 'sqlalchemy'``. PyPI wheel and Docker
image of v0.4.0 were unaffected (they install from
``packaging/pypi/pyproject.toml``, which lists sqlalchemy) — only the
single-binary download path was broken.

### Fixed

- **PyInstaller binary now bundles SQLAlchemy + aiosqlite + bcrypt**
  ([#588]): install ``sqlalchemy[asyncio]>=2.0`` and ``aiosqlite>=0.19`` in
  the build venv, and add them — plus ``sqlalchemy.dialects.sqlite``,
  ``sqlalchemy.dialects.sqlite.aiosqlite``, ``sqlalchemy.ext.asyncio``,
  ``sqlalchemy.orm`` — to ``--hidden-import``. SQLAlchemy resolves
  dialects by name at first ``create_async_engine`` call, so static
  analysis cannot see them even when the package is installed.

### Not in this release

- The two fixes for the Frontdesk bundle dev shell (PR #586
  ``deploy.sh`` default version and PR #587 nginx ``Host`` header
  preserving the client port) ship as
  ``frontdesk-bundle-v0.2.1`` rather than a Connector point release —
  they live in ``packaging/frontdesk-bundle/`` and do not touch the
  Connector binary.

[#588]: https://github.com/cullis-security/cullis/pull/588

## [v0.4.0] — 2026-05-11

Stable cut of the v0.4.0 line. Folds five Connector + Ambassador bug
fixes that landed after `-rc1` during the Frontdesk bundle dogfood
sprint (2026-05-08 → 2026-05-11). The Ambassador / ADR-019 / ADR-020 /
ADR-021 headline features are unchanged from `-rc1`; see that section
below for the full feature set.

### Fixed

- **Connector + SPA bundle dogfood polish** ([#564]): N17 + N20 + N21
  fixes for the Frontdesk SPA bundle.
- **ADR-025 chat unblocked end-to-end** ([#565]): admin secret + auth
  gates + typed-principal bypass. Cullis Chat U2U intra-org now lands
  the message at the recipient's inbox without manual cert exchange.
- **First-boot auto-discovery wizard for Mastio** ([#574]): the
  Connector now finishes enrollment from the browser via the new
  `/admin/connector-bootstrap` discovery endpoint on the Mastio. No
  more out-of-band token exchange.
- **Loopback guard override for docker-bundle topology** ([#582]):
  `CULLIS_AMBASSADOR_LOOPBACK_ONLY=false` opts the bundle out of the
  127.0.0.1 IP guard so the nginx sidecar IP can reach
  `/api/session/init`. The cookie / Bearer gate remains the auth
  boundary in that topology.
- **`/api/session/whoami` returns the signed-in user** ([#582]): when
  a valid ADR-025 `cullis_local_session` cookie is present, surface
  the local user as the principal instead of the bundle's
  `::frontdesk` bearer identity. Bearer-only callers (Cursor,
  OpenWebUI on loopback) untouched.
- **Ollama chain-of-thought timeout** ([#582]):
  `CULLIS_REQUEST_TIMEOUT_S` now flows into the SDK
  `CullisClient(timeout=…)` on every build, so local models like
  qwen3.5 and deepseek-r1 stop returning 502 after ~12 s.

### Added

- **ADR-020 U2U intra-org dataplane wired end-to-end** ([#569]):
  per-user agent client construction surfaces the user principal on
  intra-org sessions; the typed-principal `::` reconstruction gotcha
  is closed.
- **`CULLIS_ADVERTISED_MODELS` env override** ([#582]): operator-
  supplied fallback list for the SPA model dropdown when the live
  `/v1/models` fetch path degrades.

[v0.4.0]: https://github.com/cullis-security/cullis/releases/tag/connector-v0.4.0
[#564]: https://github.com/cullis-security/cullis/pull/564
[#565]: https://github.com/cullis-security/cullis/pull/565
[#569]: https://github.com/cullis-security/cullis/pull/569
[#574]: https://github.com/cullis-security/cullis/pull/574
[#582]: https://github.com/cullis-security/cullis/pull/582

## [v0.4.0-rc1] — 2026-05-08

First connector minor since `connector-v0.3.6` (1 May). Folds ~17
PRs of work driven by ADR-019 (Cullis Frontdesk) and ADR-021
(shared-mode + multi-user KMS). Pre-release tag (`-rc1`) so the
image lands on `ghcr.io` for end-to-end validation before the
final v0.4.0 cut.

### Highlights

- **Ambassador, single-mode and shared-mode** ([#406], [#417],
  [#418], [#428], [#430]): the Connector now exposes an
  OpenAI-compatible Ambassador surface. `AMBASSADOR_MODE=single`
  serves the desktop user (one local identity); `=shared` serves
  N users behind an SSO-terminating reverse proxy via per-user
  cookie + UserPrincipalKMS-signed requests.
- **Cullis Chat SPA at `/chat`** ([#429], [#432]–[#434]): the
  static SPA mounts directly under the Connector dashboard,
  authenticated by the same cookie minted at `/api/session/init`.
  PyInstaller binaries embed the bundle so single-user installs
  work with no extra server.
- **Shared-mode → Mastio CSR + MCP roundtrip** ([#437], [#442],
  [#445]): per-user CSR endpoint is owned by the Mastio (moved
  off Court), the Connector mints a per-user agent cert on
  cookie issuance, and shared-mode requests reach MCP servers
  with the right user identity attached to the audit chain.
- **`/v1/inbox` passthrough on shared ambassador** ([#488]): the
  inbox endpoints (list/ack/archive) bypass the Mastio hop and
  call the broker directly with the user's own cert+key.
- **Dashboard restyle to the cullis.io design system** ([#425],
  [#426]): tokens, palette, typography aligned to the public
  site.

### Fixed

- **`cullis-connector` Docker image now installs the
  `[dashboard]` extra** ([#436]): previously `cullis-connector
  dashboard` ImportError'd on `fastapi`. The Frontdesk container
  bundle no longer needs its `Dockerfile.connector` wrapper as a
  workaround.
- **`/chat` gated behind enrollment** ([#433]): pre-enrollment
  visits redirect to `/setup` instead of rendering the SPA with
  a missing identity.

### Notes

- `cullis-sdk>=0.1.3` is now required at runtime for the
  user-principal factory + `chat_completion`. The wheel install
  pins this transitively.
- Ambassador cookie TTL defaults to 1h (`CULLIS_FRONTDESK_COOKIE_TTL_S`).

[#406]: https://github.com/cullis-security/cullis/pull/406
[#417]: https://github.com/cullis-security/cullis/pull/417
[#418]: https://github.com/cullis-security/cullis/pull/418
[#425]: https://github.com/cullis-security/cullis/pull/425
[#426]: https://github.com/cullis-security/cullis/pull/426
[#428]: https://github.com/cullis-security/cullis/pull/428
[#429]: https://github.com/cullis-security/cullis/pull/429
[#430]: https://github.com/cullis-security/cullis/pull/430
[#432]: https://github.com/cullis-security/cullis/pull/432
[#433]: https://github.com/cullis-security/cullis/pull/433
[#434]: https://github.com/cullis-security/cullis/pull/434
[#436]: https://github.com/cullis-security/cullis/pull/436
[#437]: https://github.com/cullis-security/cullis/pull/437
[#442]: https://github.com/cullis-security/cullis/pull/442
[#445]: https://github.com/cullis-security/cullis/pull/445
[#488]: https://github.com/cullis-security/cullis/pull/488

## [v0.3.1] — 2026-05-07 (cullis-mastio)

First minor since `mastio-v0.3.0-rc3` (29 April). Folds 116 commits
worth of work, organised by ADR. The on-disk schema is automatically
upgraded on first boot via Alembic; no manual migration step is
required.

### Highlights

- **ADR-016 — LLM Guardian (AI safety layer)** ([#465], [#469], [#473]):
  fast-path tool dispatch + slow-path adjudication via 5 judge adapters
  (prompt injection, PII egress, secret leak, loop detection, tool
  escalation, reach guard). The SDK hooks Guardian into both
  `send_oneshot` and `decrypt_oneshot`. Off by default; enable per-org
  via the new admin endpoints.
- **ADR-017 — AI gateway co-resident with Mastio** ([#435], [#450]):
  the AI egress path moves from a separate Court component into
  `mcp_proxy` itself. Streaming SSE on `stream=true` is now real (was
  a Connector-side fake-stream fallback) via `litellm_embedded` with
  `include_usage`.
- **ADR-019 — Cullis Frontdesk** ([#427]–[#434], [#487], [#492]): a
  packaged container distribution of the SPA + Ambassador for
  multi-user deployments behind an existing IdP. Includes the new
  `packaging/frontdesk-bundle/` artefact. The Ambassador now serves
  the SPA statically (Astro `output: 'static'`) and exposes
  single-mode + shared-mode session routes on the Connector itself.
- **ADR-020 — User principal + four quadrants** ([#444], [#476]–[#478],
  [#481]–[#484], [#492]): user principals are first-class citizens
  alongside agents and workloads. New `principal_type` column on
  `audit_log`, new `reach_consents` table gating A2A / A2U / U2A / U2U
  policy, new `user_inbox_messages` primitive. Bindings are now keyed
  by `(principal_id, principal_type)` so a user and a workload sharing
  a name no longer collide.
- **ADR-021 — Frontdesk shared mode + per-user KMS** ([#412]–[#418]):
  the Ambassador can now multiplex many users behind a single
  container, with a new `UserPrincipalKMS` protocol (embedded /
  Vault / AWS-KMS / Azure-KV adapters) provisioning each user's
  signing key on first SSO. New endpoint `POST /v1/principals/csr`
  on the Mastio mints user certs from CSRs; `app/auth/mastio_countersig.py`
  now exempts user principals from the per-login counter-signature
  (the cert *is* the Mastio's vouch — issuing a fresh signature per
  request would require the user's private key resident at the
  Mastio, which the KMS model forbids).
- **Insurance demo backend** ([#475], [#480], [#492]): the reference
  scenario stands up an end-to-end multi-surface demo with Marco /
  Lucia (IT) and Kenji (JP) personas across mediterranean and
  asia-pacific orgs. The Frontdesk identity bootstrap phase mints an
  agent cert via BYOCA + writes the four-file identity drop into the
  Connector's volume. The scenario sources are kept locally for the
  current release cycle and will be re-published once they stabilise
  on the public quickstart shape; the public demo entry point is
  `sandbox/demo.sh`.

### Tests

- **Tier 2 cross-org NixOS scenario** ([#446]–[#449], [#456], [#457],
  [#474]): four-VM scenario (Roma + San Francisco + Tokyo + Court)
  exercising real federation publish + cross-org A2A oneshot
  end-to-end. Replaces the docker-compose sandbox path for the
  cross-org-policy regression suite.
- **Mock LLM + mock MCP postgres for tier1 demo** ([#452]): mockable
  upstream lets the demo run without an Anthropic key or a live
  Postgres.

### Migrations (auto-applied on first boot)

- `audit_log.principal_type` column (ADR-020 Phase 2)
- `reach_consents` table (ADR-020 Phase 3)
- `user_inbox_messages` table (ADR-020 Phase 4)
- `user_principals` table (ADR-021 PR2)
- audit chain `UNIQUE(org_id, chain_seq)` for multi-worker safety

### Breaking

- The `audit_log` JSON schema gains a `principal_type` field. Consumers
  that strict-validate on the row shape must accept the new field.
- `Binding` rows are now keyed by `(principal_id, principal_type)`. If
  you wrote tooling that joined on `principal_id` alone, add the
  `principal_type` filter.

[#412]: https://github.com/cullis-security/cullis/pull/412
[#413]: https://github.com/cullis-security/cullis/pull/413
[#414]: https://github.com/cullis-security/cullis/pull/414
[#416]: https://github.com/cullis-security/cullis/pull/416
[#417]: https://github.com/cullis-security/cullis/pull/417
[#418]: https://github.com/cullis-security/cullis/pull/418
[#427]: https://github.com/cullis-security/cullis/pull/427
[#428]: https://github.com/cullis-security/cullis/pull/428
[#429]: https://github.com/cullis-security/cullis/pull/429
[#430]: https://github.com/cullis-security/cullis/pull/430
[#431]: https://github.com/cullis-security/cullis/pull/431
[#432]: https://github.com/cullis-security/cullis/pull/432
[#434]: https://github.com/cullis-security/cullis/pull/434
[#435]: https://github.com/cullis-security/cullis/pull/435
[#444]: https://github.com/cullis-security/cullis/pull/444
[#446]: https://github.com/cullis-security/cullis/pull/446
[#448]: https://github.com/cullis-security/cullis/pull/448
[#449]: https://github.com/cullis-security/cullis/pull/449
[#450]: https://github.com/cullis-security/cullis/pull/450
[#452]: https://github.com/cullis-security/cullis/pull/452
[#456]: https://github.com/cullis-security/cullis/pull/456
[#457]: https://github.com/cullis-security/cullis/pull/457
[#465]: https://github.com/cullis-security/cullis/pull/465
[#469]: https://github.com/cullis-security/cullis/pull/469
[#473]: https://github.com/cullis-security/cullis/pull/473
[#474]: https://github.com/cullis-security/cullis/pull/474
[#475]: https://github.com/cullis-security/cullis/pull/475
[#476]: https://github.com/cullis-security/cullis/pull/476
[#477]: https://github.com/cullis-security/cullis/pull/477
[#478]: https://github.com/cullis-security/cullis/pull/478
[#480]: https://github.com/cullis-security/cullis/pull/480
[#481]: https://github.com/cullis-security/cullis/pull/481
[#482]: https://github.com/cullis-security/cullis/pull/482
[#483]: https://github.com/cullis-security/cullis/pull/483
[#484]: https://github.com/cullis-security/cullis/pull/484
[#487]: https://github.com/cullis-security/cullis/pull/487
[#492]: https://github.com/cullis-security/cullis/pull/492

## [v0.1.3] — 2026-05-01 (cullis-sdk)

### Security
- **ECDH key wrap upgraded from XOR to AES-KW (RFC 3394)** ([#377]):
  the one-shot end-to-end encryption envelope now wraps the per-message
  key with AES-KW instead of an HKDF-derived XOR mask. HKDF `info`
  is bumped to `cullis-oneshot-v2-aeskw` and the wrapped key is now
  40 bytes (was 32). Cross-language interop with `sdk-ts` is
  preserved.
- **`verify_oneshot` rejects bare-SPKI senders, binds cert↔sender,
  optional chain trust** ([#379]): a new `cullis_sdk/crypto/_cert_trust.py`
  module enforces three checks on the sender's identity certificate:
  the cert must not be a bare SPKI, its CN/SPIFFE SAN must match the
  declared `sender_agent_id`, and (when `trust_anchors_pem` is
  provided) it must chain to a known anchor. `CullisClient.from_connector`
  now passes the Org CA from `identity/ca-chain.pem` as the anchor by
  default.
- **`ca_chain_path` threaded through every constructor** ([#381]):
  `from_enrollment`, `from_identity_dir`, `_do_enroll`,
  `enroll_via_byoca`, `enroll_via_spiffe`, and `from_api_key_file` all
  accept a new `ca_chain_path` kwarg, which is now routed through
  `_build_proxy_http_client` for both the bootstrap GET/POST and the
  runtime client. This closes a gap where some bootstrap paths were
  silently using the system CA bundle instead of the TOFU-pinned chain.

### Changed
- This is the second SDK release published to PyPI via OIDC trusted
  publishing instead of a long-lived `PYPI_TOKEN` (#394 enabled OIDC
  for both SDK + Connector workflows; connector v0.3.6 was the first
  to validate the path end-to-end).

[#377]: https://github.com/cullis-security/cullis/pull/377
[#379]: https://github.com/cullis-security/cullis/pull/379
[#381]: https://github.com/cullis-security/cullis/pull/381

## [v0.3.6] — 2026-05-01

### Security
- **Dashboard CSRF / cross-origin guard** ([#371]): middleware checks
  `Origin` and `Referer` on POST/PUT/DELETE/PATCH to the local
  Connector dashboard, with a Bearer-token exemption for the
  statusline integration. Mitigates DNS-rebinding attacks against
  `127.0.0.1:7777` from a hostile webpage in the same browser.
- **Proof-of-possession on enrollment status polling** ([#389]): the
  `/enroll/status` polling loop now signs each request with the
  enrollment keypair, so a network attacker who learns the
  enrollment ID can no longer substitute their own approval result.
- **Proof-of-possession on enrollment start** ([#393]): the initial
  `/enroll/start` request is now also bound to the keypair, closing
  the matching gap on the create side.

### Changed
- This is the first connector release published to PyPI via OIDC
  trusted publishing instead of a long-lived `PYPI_TOKEN` (#394).

[#371]: https://github.com/cullis-security/cullis/pull/371
[#389]: https://github.com/cullis-security/cullis/pull/389
[#393]: https://github.com/cullis-security/cullis/pull/393
[#394]: https://github.com/cullis-security/cullis/pull/394

## [v0.3.5] — 2026-04-30

### Fixed
- **Client cert is now actually presented at the nginx mTLS gate**
  (monorepo #365). httpx 0.28 silently drops the client cert when
  ``verify=<path-string>`` is combined with ``cert=(crt, key)``. The
  SDK's egress + proxy clients now build an ``ssl.SSLContext``
  explicitly and pass it via ``verify=ctx``, restoring the cert at
  the TLS handshake. Symptom this closes: ``discover_agents`` /
  ``send_oneshot`` / ``open_session`` returning 401 from
  ``/v1/(egress|agents|audit)`` while ``hello_site`` (TLS-only)
  succeeded.
- **TOFU-pinned ``ca-chain.pem`` is preserved across re-enrollments**
  (monorepo #364). ``save_identity`` previously overwrote the pinned
  chain with whatever the bootstrap response carried, which broke
  the SDK's verifier on the next call. The pin is now stable for the
  lifetime of the identity.
- **Proxy http client uses the TOFU-pinned ``ca-chain.pem``**
  (monorepo #363). The SDK now points at the same chain the rest of
  the connector trusts, instead of the system bundle that doesn't
  know the Org CA.

### Compat
- Requires ``cullis-sdk>=0.1.2`` for the rebuilt SSLContext path.
  Older SDK installs continue to 401 against the nginx mTLS gate.

## [v0.3.4] — 2026-04-28

### Fixed
- **`install-mcp` now propagates the shared CLI flags into the saved
  IDE / MCP-client entry** (monorepo #339). Previously every config
  was hard-wired to ``args = ["serve"]`` regardless of what the
  operator typed; ``--profile`` / ``--site-url`` / ``--config-dir`` /
  ``--no-verify-tls`` are now carried through. Closes the workaround
  in memory ``feedback_install_mcp_no_profile``.
- **`cullis-connector serve --no-verify-tls` now actually disables
  TLS verification** end-to-end. The flag set ``cfg.verify_tls=False``
  but the SDK's ``CullisClient.from_connector`` derived its own
  default from the site URL scheme (https → True), so the eager
  ``login_via_proxy_with_local_key`` against a self-signed Org CA
  failed at SSL handshake and left ``state.client = None``. The SDK
  now accepts an explicit ``verify_tls`` override that the CLI
  passes through.

### Compat
- Requires `cullis-sdk>=0.1.1` for the new `verify_tls` parameter on
  `CullisClient.from_connector`. Older SDK installs raise `TypeError`
  at startup.

## [v0.3.3] — 2026-04-28

### Changed
- **Drop the `api_key` runtime path entirely** (Mastio ADR-014 PR-C,
  monorepo #334). The TLS client cert presented at the per-org nginx
  sidecar's handshake is now the only agent credential — `X-API-Key`
  header is no longer emitted, `~/.cullis/identity/api_key` is no
  longer written, and `cullis_connector._generate_api_key` /
  `_bcrypt_hash` are gone. Connectors enrolled with this version (or
  upgraded in place — the cert+key were already on disk from
  enrollment) continue to authenticate seamlessly to a post-PR-C
  Mastio. **A pre-PR-C Mastio is no longer compatible** — match the
  Mastio version when upgrading the Connector.

### Fixed
- `cullis-connector` is back in sync with the Mastio wire protocol.
  0.3.2 against a post-PR-C Mastio would 401 on every egress call
  (the Mastio's `get_agent_from_dpop_api_key` dep is gone).

## [v0.1.0] — 2026-04-14

Initial public release of the Cullis Connector.

### Added
- **MCP stdio server** (`cullis-connector serve`) exposing nine neutral
  tools for local MCP clients: session, discovery, and diagnostics.
- **Device-code enrollment** (`cullis-connector enroll`) — keypair
  generation, submission to the Cullis Site, admin approval polling,
  and local identity persistence under `~/.cullis/identity/`.
- **Config resolution** with clear precedence: CLI flags override env
  vars (`CULLIS_SITE_URL`, etc.) override `~/.cullis/config.yaml`.
- **Multi-transport support** planned via config: defaults to stdio,
  prepared for SSE and HTTP transports in later phases.
- **Packaging & distribution** (this release):
  - PyPI: `pip install cullis-connector` (standalone distribution).
  - Homebrew: `brew install cullis-security/tap/cullis-connector`
    (template formula, tap repo to be provisioned).
  - Docker: `ghcr.io/cullis-security/cullis-connector:v0.1.0`.
  - GitHub Releases: PyInstaller binaries for Linux amd64 and
    macOS (best effort on arm64).
- **Release automation**: `.github/workflows/release-connector.yml`
  triggered on `connector-v*` tags.

### Changed
- None (first release).

### Security
- Identity private key is stored with `0600` permissions in
  `~/.cullis/identity/`. Never transmitted to the Site beyond the
  initial public-key enrollment.
- TLS verification is enabled by default; `--no-verify-tls` is
  accepted only for local development and logs a prominent warning.

[v0.3.4]: https://github.com/cullis-security/cullis/releases/tag/connector-v0.3.4
[v0.3.3]: https://github.com/cullis-security/cullis/releases/tag/connector-v0.3.3
[v0.1.0]: https://github.com/cullis-security/cullis/releases/tag/connector-v0.1.0
