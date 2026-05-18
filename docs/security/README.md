# `docs/security/` index

This directory holds the customer-facing security documents for
Cullis. They are intended for CISOs, security architects, blue-team
engineers, and customer due diligence reviewers evaluating Cullis
before a pilot.

Operational runbooks (incident response, Frontdesk shared-mode
hardening, Postgres pilot) live in [`docs/runbooks/`](../runbooks/).
The responsible disclosure policy lives in
[`SECURITY.md`](../../SECURITY.md) at the repository root.

## Documents

| Document                                                    | Audience                                | Updated    |
|-------------------------------------------------------------|-----------------------------------------|------------|
| [`threat-model.md`](./threat-model.md)                      | CISO, security architect                | 2026-05-18 |
| [`post-quantum-roadmap.md`](./post-quantum-roadmap.md)      | CISO, cryptography team                 | 2026-05-18 |

### Threat model

Threat catalog (in scope and out of scope), trust boundaries,
cryptographic primitives, key lifecycle, audit trail integrity,
compliance mapping preview. Cross-links the STRIDE per-component
walkthrough on cullis.io (source in
`site/src/content/docs/security/threat-model.md`).

### Post-quantum roadmap

Five-phase hybrid-first PQC strategy. Phase 0 (positioning) is
active; Phase 1a triggers are gated by upstream library maturity
(`pyca/cryptography` ML-KEM, `liboqs-python` on NixOS) or by a
concrete buyer signal. Includes the validation spike numbers from
2026-05-06 (X25519 + ML-KEM-768, ~4 to 5 ms roundtrip, +1088 bytes
overhead).

## Related documents

- [`SECURITY.md`](../../SECURITY.md): responsible disclosure
  policy, response SLAs, supported version matrix, safe harbour.
- [`docs/runbooks/incident-response.md`](../runbooks/incident-response.md):
  severity classification, response procedure per severity,
  communication templates.
- [`docs/runbooks/frontdesk-shared-hardening.md`](../runbooks/frontdesk-shared-hardening.md):
  Frontdesk shared-mode operational hardening (Phase 1 audit
  warning, Phase 2 WebAuthn).
- [`docs/architecture/byoca-current-state.md`](../architecture/byoca-current-state.md):
  Bring Your Own CA implementation status and gap.
- ADRs: public ADRs in [`docs/adrs/`](../adrs/), internal ADRs in
  `imp/adrs/` (gitignored, commercial-sensitive).

## Review cadence

Documents in this directory are reviewed **quarterly**. Each
document has its own "Next review" date in its header. An
out-of-cycle revision is triggered by: a new ADR ratified, a new
threat discovered, a third-party penetration test report, or
customer feedback that lands a substantive correction.
