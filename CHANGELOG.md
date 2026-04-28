# Changelog

All notable changes to `cullis-connector` are documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
The connector follows its own release cadence, independent from the
broker and proxy components of the Cullis monorepo. Connector releases
are tagged `connector-vX.Y.Z`.

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
