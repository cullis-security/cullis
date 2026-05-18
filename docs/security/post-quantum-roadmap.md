# Post-quantum cryptography roadmap (Cullis)

**Audience:** CISOs, security architects, and customer cryptography
teams asking how Cullis will remain secure once cryptanalytically
relevant quantum computers (CRQCs) are available.

**Status:** Version 1.0, 2026-05-18. Quarterly review.
Next review: 2026-08-06.

**Contact:** security@cullis.io for technical clarifications;
hello@cullis.io for pilot timing alignment.

---

## 1. Why PQC matters for Cullis

Three classes of material that Cullis stores or transmits today are
sensitive to **Harvest Now, Decrypt Later (HNDL)** attacks: an
adversary captures classical-encrypted ciphertext today and decrypts
it once a CRQC is available.

- **Audit chain contents.** The append-only audit log records every
  authenticated action, with structured detail. Customers in
  regulated industries (banking, insurance, supply chain) retain
  audit material for 7 to 10 years. A 2032-grade CRQC against
  2026-grade RSA-OAEP-SHA256 envelope keys is in scope.
- **Federation handshake material.** Mastio-to-Court and
  Mastio-to-Mastio traffic carries identity assertions signed by
  the org's Intermediate CA. Captured handshakes plus access to the
  CA chain decrypt those assertions retroactively.
- **Cert authority chains.** Org Root CA validity is 15 years. A
  cert signed today must remain unforgeable to a 2035-grade
  adversary.

NIST standardised the first three PQC algorithms in **August 2024**:

- **FIPS 203 ML-KEM** (Kyber): key encapsulation.
- **FIPS 204 ML-DSA** (Dilithium): digital signature.
- **FIPS 205 SLH-DSA** (SPHINCS+): hash-based signature, stateless.

European regulators are tracking the transition. BSI Germany and
ANSSI France have published draft timelines aligning the sunset of
classical-only crypto to **2030**. NIS2 readiness reviews for
critical infrastructure now expect a documented PQC migration plan,
even if the migration itself has not started.

This document is that plan for Cullis. It is intentionally honest
about what is in code (nothing yet), what is validated (one local
spike), and what is gated by upstream library work.

---

## 2. Current cryptographic posture (classical baseline)

| Category               | Algorithm                                | Use in Cullis                                              |
|------------------------|------------------------------------------|------------------------------------------------------------|
| Asymmetric signature   | ECDSA P-256                              | Per-agent identity cert, DPoP proof (ES256).               |
| Asymmetric signature   | RSA-PSS-SHA256                           | E2E inner and outer signature (legacy classical path).     |
| Asymmetric encryption  | RSA-OAEP-SHA256                          | E2E key encapsulation.                                     |
| Symmetric              | AES-256-GCM                              | E2E payload, audit log encrypted columns.                  |
| Key exchange           | ECDH P-256                               | TLS 1.3 ephemeral handshake.                               |
| At-rest envelope       | PBKDF2-HMAC-SHA256 (600k) + Fernet       | Org Root and Mastio Intermediate private keys (`pki_key_store`, PR #788). |
| Hash                   | SHA-256                                  | Audit chain, cert thumbprint, JWK thumbprint (RFC 7638).   |

SHA-256 is **not** PQC-broken. Symmetric primitives (AES-256-GCM)
remain Grover-resilient at acceptable security margin. The
roadmap below targets the asymmetric and KEM primitives, which is
where the quantum threat materialises.

---

## 3. Cullis PQC strategy: hybrid-first

ADR-022 (Cullis internal, ratified 2026-05-06) selects a
**hybrid-first** migration path: every PQC primitive is rolled out
alongside its classical counterpart for a multi-year transition
window, never as a direct full-PQ replacement.

Three reasons:

1. **Standards are still maturing.** NIST FIPS 203/204/205 are
   final, but the protocol-level standards that Cullis depends on
   (JOSE, COSE, SPIFFE, X.509 composite signatures) are at draft
   stage. A full-PQ deployment today would land on top of
   protocol drafts that may still change.
2. **Python ecosystem is not ready.** `pyca/cryptography` does not
   ship ML-KEM or ML-DSA today and has not published a roadmap for
   them. `liboqs-python` is the alternative but does not install
   cleanly on NixOS at the version Cullis uses, because the Python
   wrapper tag mismatches the bundled liboqs C library version.
3. **Interop with classical peers.** Federation peers move at
   different speeds. Hybrid lets a Cullis Mastio negotiate with a
   classical-only peer (during the transition) without
   downgrading its own posture; the classical peer verifies the
   classical signature, ignores the PQ signature, the Mastio
   notices the absence of the PQ verification on its side and
   logs the degradation for the audit chain.

Hybrid-first is the established direction in industry: TLS 1.3
hybrid KEM (`draft-ietf-tls-hybrid-design`), X.509 composite
signatures (`draft-ietf-lamps-pq-composite-sigs`), COSE / JOSE PQ
`alg` registration in progress. Cullis tracks these drafts.

---

## 4. Five-phase roadmap

The roadmap below is **trigger-driven**, not date-driven. Phase 0
is active today. Each subsequent phase has explicit upstream
triggers; the next quarterly review re-evaluates whether any
trigger has fired.

### Phase 0: positioning and monitoring (active, today)

**Status:** Active. No code changes.

**Deliverables (in flight or done):**

- Cryptographic primitive inventory (this document, section 2).
- Audit-log schema reserves space for `kem` and `sig_alg` fields,
  populated as classical strings today. Adding hybrid values is
  additive.
- Quarterly upstream tracking (section 6). The next review is
  **2026-08-06**.
- Validation spike, see section 7 for details.

### Phase 1a: hybrid KEM in E2E envelope

**Trigger (any one):**

- `pyca/cryptography` ships ML-KEM stable.
- `liboqs-python` installs cleanly on NixOS at a version compatible
  with the Cullis dependency tree.
- Concrete buyer signal: a CISO commits to a pilot conditional on
  PQ-ready primitives in the E2E path.
- Cryptanalytic break in classical KEM that accelerates the
  timeline (low probability, high impact).

**Deliverables:**

- Replace the spike's `kyber-py` (pure-Python, single-maintainer,
  unaudited) with a production-grade ML-KEM provider (`pyca` or
  `liboqs-python`).
- Implement **E2E envelope v3** with an `mlkem_ct` field
  discriminator in `cullis_sdk/crypto/e2e.py` and
  `app/e2e_crypto.py`.
- API-additive: new `recipient_mlkem_pub` kwarg. Callers that do
  not pass it stay on v2 classical envelopes; callers that do
  pass it get hybrid envelopes that are decryptable by hybrid
  peers and rejected by v2-only peers with a clear error.
- Inner signature stays classical (RSA-PSS / ECDSA) until Phase 2b.

**Effort estimate:** 2 to 3 engineer-weeks once the upstream library
is in place. Test coverage including tamper detection across the
hybrid envelope follows the existing E2E pattern.

### Phase 1b: hybrid KEM in TLS handshake (federation)

**Trigger:** OpenSSL 3.5+ rollout in the deploy targets (NixOS,
Debian 13, Alpine), with `httpx` exposing the hybrid groups. Best
estimate today: 2027 H1.

**Deliverables:**

- Federation handshake Mastio to Court and Mastio to Mastio
  negotiates `X25519MLKEM768` (IETF
  `draft-ietf-tls-hybrid-design`) as the preferred group.
- Classical fallback (`X25519`, `secp256r1`) remains for
  classical-only peers.
- Audit row records the negotiated group on every federation
  handshake, populating the reserved `kem` field.

### Phase 2a: hybrid cert chain dual-signing

**Trigger:** Composite signature RFC published. Current best
estimate: 2027 H1 to H2. SPIFFE PQ extension proposal also has to
land for the typed-principal SAN format to remain stable.

**Deliverables:**

- New cert issuance dual-signs: ECDSA P-256 (classical) **plus**
  ML-DSA-65 (PQ). Composite signature format following
  `draft-ietf-lamps-pq-composite-sigs`.
- Backward compat by design: classical-only verifiers verify the
  classical signature and ignore the PQ signature. Hybrid
  verifiers require both.
- Mastio Intermediate CA, Mastio Leaf, agent leaf, Connector cert,
  and nginx server TLS cert all gain dual-sig at issuance time.
- Org Root CA gains dual-sig at the Phase 1a kickoff rotation
  (see section 8).

### Phase 2b: hybrid JWT and DPoP signing

**Trigger:** JOSE PQ `alg` registration completed at IETF (current
draft only). Best estimate: 2028.

**Deliverables:**

- DPoP proof `alg` upgraded from `ES256` to a composite alg
  (working name `composite-ES256-ML-DSA-65`, awaiting
  registration).
- Access token signing follows the same migration.
- License JWT signing key migrates to composite signature; the
  baked-in public key fingerprint is rotated as part of the
  annual ceremony.

### Phase 3: PQC-only opt-in (post-2028)

**Trigger:** Hybrid stable in production for at least 12 months, no
material interop issues with classical peers, customer opt-in
signal.

**Deliverables:**

- Operator can set `MCP_PROXY_PQC_ONLY=true` to disable classical
  fallback on a per-Mastio basis. Federation peers that are not
  PQC-ready are refused at handshake time, with a clear audit row.
- Recommended for new greenfield deployments where the
  customer's other infrastructure is already PQC-ready.

### Phase 4: classical sunset

**Trigger:** Aligned with regulator sunset dates (BSI, ANSSI, NIS2),
currently drafted around 2030. Cullis sunset will follow the most
conservative applicable regulator for the customer base, with at
least 12 months of advance notice.

**Deliverables:**

- Classical-only deployments are deprecated; the validate_config
  startup gate emits a hard warning and refuses to start in
  production mode if classical-only is configured past the sunset
  date.
- Removal of classical primitives from the codebase (not just
  deprecation) follows in the release after the sunset date,
  conditional on no customers requesting an extension.

---

## 5. Standards followed

Cullis tracks the following standards and drafts. Each is
re-evaluated at the quarterly review.

| Standard / draft                                  | Status (2026-05)            | Cullis use                                                |
|---------------------------------------------------|------------------------------|-----------------------------------------------------------|
| NIST FIPS 203 ML-KEM (Kyber)                      | Final (Aug 2024)             | Phase 1a, 1b: hybrid KEM in E2E and TLS.                  |
| NIST FIPS 204 ML-DSA (Dilithium)                  | Final (Aug 2024)             | Phase 2a, 2b: hybrid signatures.                          |
| NIST FIPS 205 SLH-DSA (SPHINCS+)                  | Final (Aug 2024)             | Considered for long-term signatures (Org Root). Decision deferred until Phase 1a kickoff. |
| `draft-ietf-tls-hybrid-design`                    | IETF draft (active)          | Phase 1b: TLS 1.3 hybrid KEM.                             |
| `draft-ietf-lamps-pq-composite-sigs`              | IETF draft (active)          | Phase 2a: X.509 composite signatures.                     |
| `draft-ietf-cose-dilithium` (and JOSE PQ alg)     | IETF draft (active)          | Phase 2b: DPoP, JWT, license signing.                     |
| ETSI Quantum-Safe Cryptography reports            | Published                    | Background, no direct dependency.                         |
| SPIFFE PQ extension                               | Not proposed yet             | Phase 2a: typed-principal SAN format compatibility.       |

---

## 6. Upstream blockers (transparency)

This is the table that gates the Phase 1a kickoff. Every quarter we
re-check each row.

| Blocker                                       | Status (2026-05)                                                       | Required for             | Cullis decision                                       |
|-----------------------------------------------|------------------------------------------------------------------------|--------------------------|-------------------------------------------------------|
| `pyca/cryptography` ML-KEM support            | Not in roadmap as of 2026-05. No public ETA.                          | Phase 1a production       | Wait, monitor quarterly, default if `liboqs-python` lands on NixOS first. |
| JOSE PQ `alg` IETF registration               | Draft only.                                                            | Phase 2b                  | Wait for RFC publication.                             |
| SPIFFE PQ extension proposal                  | No proposal at the SPIFFE Technical Steering Committee.                | Phase 2a workload SAN     | Track quarterly, raise the question at the next SPIFFE community sync. |
| `liboqs-python` installable on NixOS          | Tag mismatch between the Python wrapper and the bundled liboqs C lib. Manual rebuild possible, automated install fails. | Phase 1a alternative      | Try liboqs upstream upgrade at quarterly review; otherwise wait for `pyca`. |
| `kyber-py` library                            | Pure-Python, single maintainer, no formal audit.                       | Phase 1a only if `pyca` and `liboqs-python` both blocked. | Acceptable for the local spike (section 7), **not** acceptable for production. |
| X.509 composite signatures RFC                | IETF draft, multiple revisions.                                        | Phase 2a                  | Wait for RFC publication.                             |
| TLS 1.3 hybrid group in OpenSSL / `httpx`     | OpenSSL 3.5 ships hybrid groups; rollout to NixOS / Debian 13 / Alpine TBD. | Phase 1b                  | Track quarterly, depends on distro updates.           |

---

## 7. Validation: spike numbers

**Date:** 2026-05-06.

**Location:** local worktree `/home/daenaihax/projects/agent-trust-pq`,
branch `feat/pq-e2e-hybrid`. Spike code is intentionally **not
committed**; the worktree is a local validation laboratory only.
Production code lives on `main` once Phase 1a triggers.

**Setup:**

- Hybrid envelope: X25519 (classical ECDH) + ML-KEM-768 (PQ KEM)
  with a single AES-256-GCM AEAD over the concatenated shared
  secret.
- ML-KEM provider: `kyber-py` 0.x (pure Python, used for the spike,
  unsuitable for production).
- Test vectors: 1000 random plaintexts ranging from 64 bytes to 4 KiB.

**Performance:**

- Encrypt: ~2.4 ms median, ~3.1 ms p95 (laptop, no specialised
  hardware).
- Decrypt: ~2.0 ms median, ~2.6 ms p95.
- End-to-end roundtrip (encrypt + transport + decrypt): ~4 to 5 ms.

**Overhead:**

- +1088 bytes per message (ML-KEM-768 ciphertext field added to
  the envelope).
- Negligible impact on AEAD ciphertext size.

**Tamper detection:** verified. A modified ML-KEM ciphertext, a
modified X25519 ephemeral pubkey, or a modified AEAD ciphertext all
result in a clean decrypt failure with no plaintext exposure.

**Conclusion:** performance and overhead are acceptable for Phase
1a production. The blocker is the production-grade library, not
performance.

---

## 8. Org Root rotation coupling

Wave 1-A (Mastio Org Root and Intermediate CA hardening, PR #788)
**intentionally did not implement Org Root rotation automation**.
This is a conscious architectural choice, not a gap. The reason:

- Org Root validity is 15 years (Wave 1-A baseline).
- The Phase 1a kickoff requires an Org Root algorithm change from
  pure-classical ECDSA P-256 to hybrid (ECDSA P-256 + ML-DSA-65)
  per Phase 2a.
- Implementing rotation now with a classical-only target would
  force a second rotation when hybrid arrives, doubling the
  operational risk and the customer-side re-issuance work.

The Mastio Intermediate CA, by contrast, **does** have rotation
automation today (Wave 1-A), using ECDSA P-256. It gains dual-sig
at Phase 2a without an additional rotation: the next scheduled
auto-rotation simply emits a composite-signed Intermediate.

Customers asking when Org Root rotation will be available get this
explanation. The roadmap item is **"Org Root rotation arrives with
Phase 1a kickoff"**.

---

## 9. Threat model interaction

The PQC roadmap interacts with the threat model
[`docs/security/threat-model.md`](./threat-model.md) at three points:

- **HNDL on audit logs.** Today's audit log entries are protected
  by AES-256-GCM payload encryption (Grover-resilient at acceptable
  margin) and SHA-256 hash chain integrity (PQ-safe). The
  asymmetric exposure is on the envelope keys used to seal
  archived chunks; Phase 2a closes this with composite-signed
  envelope keys. Mitigation today: customers requiring forward
  secrecy on long-retention audit data should re-key the at-rest
  envelope (`MCP_PROXY_DB_ENCRYPTION_KEY` rotation procedure) on
  the cadence their compliance team requires.
- **HNDL on cert chains.** Today's chain is classical-only. Phase
  2a hybridises every new cert issuance. The Org Root issued at
  Phase 1a kickoff will be hybrid from day one (section 8).
- **CRQC timeline.** Best public estimate is 2030 to 2040 (NIST
  and NSA briefings). Cullis migration plan is **ahead of curve**,
  not panic-driven. If a credible CRQC announcement compresses
  the timeline, Phase 1a trigger fires immediately.

---

## 10. Review cadence and governance

**Cadence:** Quarterly.

**Next review:** 2026-08-06.

**Review checklist:**

1. PyPI search for ML-KEM and ML-DSA in `pyca/cryptography`. Has
   the upstream shipped, has it published a roadmap?
2. `liboqs-python` latest version. Test the NixOS install on a
   fresh shell.
3. IETF datatracker review:
   - `draft-ietf-lamps-pq-composite-sigs` advancement.
   - `draft-ietf-tls-hybrid-design` advancement.
   - JOSE PQ `alg` registration progress.
4. SPIFFE Technical Steering Committee minutes for PQ extension.
5. NIST and NSA public statements: CRQC timeline shift?
6. Customer or buyer signal: has a CISO asked about PQC-ready
   primitives in a pilot conversation? Phase 1a trigger.
7. Update this document's "Next review" date.

**Phase 1a kickoff trigger:** any two of the six blockers in
section 6 close, **or** a single concrete buyer signal lands.

---

## 11. What customers should do today

- **No immediate action required.** Cullis is classical today;
  classical primitives remain secure against today's adversaries.
- **Plan the upgrade window.** When Phase 1a ships (estimated 2027
  H1), the upgrade is API-additive on the SDK side and config-flag
  on the Mastio side. Plan a 24-hour window to flip the flag and
  validate the federation handshake.
- **Dual-chain your own org PKI.** If your security team operates a
  corporate PKI that issues Cullis agent certs via the BYOCA flow
  (see [`docs/architecture/byoca-current-state.md`](../architecture/byoca-current-state.md)),
  start planning dual-signature support in your CA. Cullis can
  accept dual-signed certs as soon as the composite-sig RFC is
  published.
- **Track NIS2 PQC migration in your sector.** Banking, energy,
  healthcare, and critical infrastructure each have their own
  applicable timeline. Cullis migration aligns to the most
  conservative customer.
- **Reach out** if your security team has a specific PQC pilot in
  mind: hello@cullis.io. A concrete buyer signal is itself a
  Phase 1a trigger.

---

## 12. References

- NIST PQC project: <https://csrc.nist.gov/Projects/post-quantum-cryptography>
- ETSI Quantum-Safe Cryptography reports: <https://www.etsi.org/technologies/quantum-safe-cryptography>
- IETF LAMPS working group: <https://datatracker.ietf.org/wg/lamps/documents/>
- IETF TLS working group hybrid drafts: <https://datatracker.ietf.org/wg/tls/documents/>
- ADR-022 (Cullis internal): `imp/adrs/adr-022-post-quantum-strategy.md`, ratified 2026-05-06.
- Wave 1-A PKI hardening (Cullis internal): `imp/adrs/adr-033-pki-three-tier-hardening.md`, classical baseline.
- [`docs/security/threat-model.md`](./threat-model.md): threat
  model and trust boundaries.
- [`SECURITY.md`](../../SECURITY.md): responsible disclosure
  policy.

---

## 13. Revision history

| Version | Date       | Author              | Notes                                                                |
|---------|------------|---------------------|----------------------------------------------------------------------|
| 1.0     | 2026-05-18 | Cullis security team | First public publication. ADR-022 ratified internally on 2026-05-06; this document is the public-facing summary. |

Next review: 2026-08-06. Update the "Next review" date in the
document header at every quarterly checkpoint.
