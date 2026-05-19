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
