# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Cullis, please report it responsibly.

**Do not open a public GitHub issue.**

### How to Report

**Email: [security@cullis.io](mailto:security@cullis.io)** — preferred channel.

This mailbox is monitored continuously by the maintainers. Please include
"SECURITY" or a CVE-style identifier in the subject line to make sure your
report is triaged quickly.

Alternative channel: [GitHub's private vulnerability reporting](https://github.com/cullis-security/cullis/security/advisories/new) if you cannot send email.

Both channels keep the report confidential until a fix is available. We do
**not** want public GitHub issues, X/Twitter posts, or blog posts about
vulnerabilities before a coordinated disclosure window has passed.

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

We aim for the following service-level targets, measured from the moment
we receive the report:

| Phase | Target |
|---|---|
| Acknowledgment | within 48 hours |
| Initial triage + severity assignment | within 7 days |
| Fix for CRITICAL severity | within 7 days |
| Fix for HIGH severity | within 14 days |
| Fix for MEDIUM severity | within 30 days |
| Fix for LOW severity | best effort, next minor release |
| Public disclosure | 90 days after report, or upon coordinated release, whichever comes first |

Severity follows [CVSS v3.1](https://www.first.org/cvss/v3.1/specification-document)
base score:

- **CRITICAL** — CVSS 9.0 - 10.0
- **HIGH** — CVSS 7.0 - 8.9
- **MEDIUM** — CVSS 4.0 - 6.9
- **LOW** — CVSS 0.1 - 3.9

If a fix will take longer than the target window (e.g. it requires a
breaking change or a coordinated upstream release), we will say so in
the acknowledgment and agree a revised timeline with the reporter.

## Supported Versions

Cullis ships several components, each released independently. We patch
security issues on the **latest stable release of each release track**.
Older tags are end-of-life unless explicitly listed below.

| Component | Release tag prefix | Supported window |
|---|---|---|
| Cullis Court (federation broker) | `court-v*` | latest stable |
| Cullis Mastio (open-core image) | `mastio-v*` | latest stable |
| Cullis Mastio Enterprise (paid image) | `mastio-enterprise-v*` | latest stable + previous minor |
| Cullis Mastio open-core bundle | `mastio-bundle-v*` | latest stable |
| Cullis Mastio enterprise bundle | `mastio-enterprise-bundle-v*` | latest stable |
| Cullis Frontdesk bundle | `frontdesk-bundle-v*` | latest stable |
| Cullis Chat SPA | `chat-v*` | latest stable |
| Cullis Connector (desktop / PyPI / Docker) | `connector-v*` | latest stable |
| Python SDK (`cullis-sdk`) | PyPI semver | latest minor |
| TypeScript SDK (`@cullis/sdk`) | npm semver | latest minor |

While Cullis is pre-1.0, the "previous minor" support window is
intentionally narrow — operators should expect to track the latest
release. Once a paid component reaches 1.0, the support window will
widen and the support policy will be re-published here in this file
before the change takes effect.

## Scope

In scope for this policy:

- This repository (`cullis-security/cullis`) — Court, Mastio open-core,
  Connector, Cullis Chat, SDKs, deploy bundles, site sources.
- The private companion repo (`cullis-security/cullis-enterprise`) —
  paid plugins, signing pipeline. Reports there are handled through
  the same channels.
- The published container images on `ghcr.io/cullis-security/*`.
- The published PyPI / npm packages (`cullis-sdk`, `cullis-connector`,
  `@cullis/sdk`).
- The published license verification pipeline (signing keys, JWT
  verifier, supply-chain artefacts attached to GitHub Releases).

Out of scope:

- Customer-operated deployments (we ship images and bundles; operators
  are responsible for runtime configuration). We are still happy to
  receive reports about hardening defaults that make customer
  misconfiguration easy.
- Third-party AI providers reachable through the embedded AI gateway
  (Anthropic, OpenAI, etc.). Report those upstream.
- The `cullis.io` marketing site (`docs/` source + Cloudflare Pages)
  for non-security cosmetic issues — open a regular GitHub issue
  instead.

## Safe Harbour

We will not pursue legal action against researchers who:

- Make a good-faith effort to follow this policy.
- Avoid privacy violations, destruction of data, and disruption of our
  services or others' services.
- Only interact with accounts and infrastructure that they own, or for
  which they have explicit permission from the owner.
- Give us a reasonable time to respond before any public disclosure.

If you are unsure whether your testing falls within these boundaries,
contact us first at security@cullis.io and we will discuss before you
start.

## Acknowledgements

We will credit reporters in the release notes of the fix unless they
ask to remain anonymous. We currently do not run a paid bounty
programme; this section will be updated here when that changes.

## Security Design

Cullis is built with security as a core design principle:

- x509 PKI with 3-tier certificate chain
- DPoP token binding (RFC 9449) — no plain Bearer tokens
- E2E encryption (AES-256-GCM + RSA-OAEP) — broker never reads plaintext
- Default-deny session policy with federated PDP webhooks
- Append-only cryptographic audit log
- Certificate thumbprint pinning
- Rate limiting on all public endpoints

For a full security architecture overview, see the [README](README.md#security-architecture).
