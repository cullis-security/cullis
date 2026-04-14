# Changelog

All notable changes to `cullis-connector` are documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
The connector follows its own release cadence, independent from the
broker and proxy components of the Cullis monorepo. Connector releases
are tagged `connector-vX.Y.Z`.

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

[v0.1.0]: https://github.com/cullis-security/cullis/releases/tag/connector-v0.1.0
