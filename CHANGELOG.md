# Changelog

All notable changes to `cullis-connector` are documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
The connector follows its own release cadence, independent from the
broker and proxy components of the Cullis monorepo. Connector releases
are tagged `connector-vX.Y.Z`.

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
