# ADR-030 — Mastio bundle: operator-driven upgrade + bind-mount data layout

Status: Accepted - 2026-05-13
Date: 2026-05-13
Supersedes: none
Related: ADR-014 (mastio-nginx sidecar), ADR-024 (Frontdesk TLS sidecar), `[[court-is-federation-broker-not-management-hub]]`

## Context

Two operational issues surfaced after `mastio-v0.3.9` shipped:

1. **Update flow is four manual commands.** PR #668 added the dashboard "update available" banner with a copy-paste block. `--pull` updates the image tag, but `deploy.sh`, `docker-compose.yml`, and `generate-proxy-env.sh` stay frozen at the version of the tarball the operator first downloaded. New env vars added by future releases never reach `proxy.env`; bug fixes in `deploy.sh` itself never apply. Customer on `0.3.6` who runs `./deploy.sh --pull` gets the `0.3.9` container but ships old scripts. Silent drift.
2. **Asymmetric persistence layout vs Frontdesk.** Frontdesk bundle uses bind mounts (`~/cullis-frontdesk-bundle/connector_data/`). Mastio bundle uses named volumes (`mcp_proxy_data`, `mastio_nginx_certs`). One `docker system prune --volumes`, one daemon reset, one accidental `compose down -v` and Org CA + DB Mastio vanish without warning. Same operator, two bundles, two semantics.

## Decisions

### Decision A — Upgrade is operator-driven, never self-update

`deploy.sh` gains `--upgrade-bundle <version>` which downloads the released tarball, extracts it preserving user state (`proxy.env`, bind-mounted data/certs, backups), bumps `CULLIS_MASTIO_VERSION`, and restarts the stack. The banner copies the operator the single command `./deploy.sh --upgrade-bundle <version> --from-banner`.

No `docker.sock` mount. No privileged sidecar updater. No background daemon polling for releases (the banner polls from the Mastio process itself, login-gated, outbound directly to `api.github.com`). Threat model: an attacker who compromises GitHub releases or pins a malicious tag still requires the operator to paste a command into a root shell — same trust surface as `apt upgrade`, no privilege escalation beyond what the operator already wields. Distinct from "operational outbound from Mastio to GitHub releases API" which is **not** federation traffic and does **not** route via Court (see `[[court-is-federation-broker-not-management-hub]]`).

### Decision B — Bind mounts for Mastio data

`docker-compose.yml` mounts `${MASTIO_DATA_DIR:-./data}:/data` and `${MASTIO_NGINX_CERTS_DIR:-./nginx-certs}:/var/lib/mastio/nginx-certs`. (`./nginx-certs/` is the *internal* path where Mastio writes the Org CA + nginx server cert; `./certs/` keeps its existing meaning as the *corporate CA bundle* read-only mount + host-side `org-ca.pem` export target, unchanged.) The mcp-proxy image runs as a fixed UID/GID (`10001:10001`, aligned with Frontdesk), and an `init-permissions` busybox service `chown -R`s the bind dirs at every `compose up`. Existing customers on named volumes get `./deploy.sh --migrate-volumes`, which `cp -a`s the volume contents to the host bind dir via a transient busybox container. Migration is idempotent and never auto-deletes the source named volume — the operator decides when to `docker volume rm` after verifying the new layout boots clean.

Benefits over named volumes: native backup via `tar`/`rsync`, edge-case-safe (`docker system prune --volumes` leaves host filesystem untouched), explicit wipe semantics (`rm -rf ./data` instead of the magic `-v` flag), uniformity with Frontdesk operator mental model.

### Decision C — Version validation = HTTPS host hardcoded + tight regex

Tarball URL hardcoded: `https://github.com/cullis-security/cullis/releases/download/mastio-v${VERSION}/cullis-mastio-bundle-${VERSION}.tar.gz`. Version validated against `^[A-Za-z0-9.\-]+$` — same shape as `_TAG_SAFE_RE` in `mcp_proxy/dashboard/update_check.py` (PR #668), so a tag with shell metacharacters never reaches `curl` or `tar` as an argument. No SHA-256 checksum verification, no cosign/sigstore signature — explicitly Phase 2 follow-up, documented in §Future work below. The current trust anchor is HTTPS + GitHub release controls, same as every other `curl | bash` install in the ecosystem.

## Migration path

Operator on v0.3.x: first run of `./deploy.sh --upgrade-bundle <new-version>` detects named volumes via `docker volume inspect mcp_proxy_data` and prompts "migrate to bind mounts? [y/N]". `--from-banner` (used by the banner one-liner) auto-accepts the migration (banner-driven flow is the recommended path, the prompt is for operators who run the command manually and want a chance to back out).

Fresh installs at v0.4.0+ never see named volumes — `generate-proxy-env.sh` seeds `MASTIO_DATA_DIR=./data` and `MASTIO_NGINX_CERTS_DIR=./nginx-certs` in `proxy.env` from the first boot.

Backup is automatic: every `--upgrade-bundle` and every `--migrate-volumes` snapshots `proxy.env` + `./data/` + `./nginx-certs/` to `./backups/pre-upgrade-<ts>/` or `./backups/pre-bind-migration-<ts>/` respectively before touching anything.

## Future work (Phase 2)

- **SHA-256 checksum verification**: release workflow publishes `cullis-mastio-bundle-<version>.tar.gz.sha256`, `deploy.sh` downloads + verifies before extract. Closes MITM-on-CDN gap. ~30min implementation, no key management.
- **Cosign/sigstore signature**: full supply-chain. Requires release workflow integration + key publication. Significant work, defer until first design partner asks.
- **Frontdesk bundle inherits the pattern**: same `--upgrade-bundle` flow, once Mastio implementation proves stable.
- **Bundle upgrade telemetry**: opt-in callback to a Cullis Court endpoint summarising "v0.3.x → v0.4.x success/failure" — useful for the maintainer to know which versions are actually deployed. Sensitive: must respect the [[no-operational-via-court]] rule (this is the **maintainer** asking a Court instance for help, not federation).

## Consequences

- Mastio v0.4.0 is a major bump (data layout change) but the migration is mechanical and automated.
- Customers who never run `--upgrade-bundle` and never see the banner stay on their current named-volume layout indefinitely. Acceptable: existing behaviour is preserved.
- Documentation for the four-step manual flow stays in the README under "Advanced / step-by-step" as a fallback for operators who don't trust the one-liner.
