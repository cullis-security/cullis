# ADR-032 — Device attestation architecture: multi-MDM + BYOD with deferred FIDO2 step-up

Status: Accepted - 2026-05-16
Date: 2026-05-16
Supersedes: none
Related: ADR-019 (Frontdesk shared mode), ADR-020 (User principal + 4 quadranti A2A/A2U/U2A/U2U), ADR-021 (multi-user KMS), ADR-029 (tool-level PDP), ADR-031 (Vault Org CA KMS provider)

## Context

The 2026-05-16 strategic pivot (memory `project_target_customer_enterprise_regulated_only`) re-focused Cullis target audience exclusively on enterprise regulated (banks, insurers, healthcare, pharma, defense, public sector). The driver of acquisition for this audience is compliance (DORA, NIS2, GDPR, PSD2, ISO 27001, PCI-DSS), not productivity convenience. SMB-generic positioning was abandoned.

This re-focusing exposed a foundational gap in the identity model implementation (memory `project_identity_model_today_4_quadrants_audit_attribution`, `project_connector_login_gap_future_user_identity`):

1. **Connector device-code enrollment produces an Agent principal only.** The Cullis Connector today registers as `cullis-connector` MCP server with a single agent identity per device-installation. There is no user identity propagated, no login/logout post-enroll, no device-bound cryptographic proof, no attestation chain back to a trusted hardware root.

2. **Audit row attribution is incomplete.** Customer CISO inspecting Cullis audit_log sees `caller_principal_type="agent"` with no `on_behalf_of_user_id` and no `device_attestation`. The audit chain answers "what agent did what" but not "who is the responsible human" and not "is the device the agent ran on actually under organizational control".

3. **Conditional Access is not enforceable.** Customer CISO cannot express policies like "tools.call.customer_db SOLO from Intune-managed device with TPM enabled". Today Cullis treats all agent enrollments as equivalent in trust regardless of host device posture.

4. **The market is already moving.** Intesa Sanpaolo recently rolled out Microsoft Copilot enterprise across its workforce (one of Italy's largest banks). Other Italian banks and insurers will follow. The signal is clear: regulated organizations are integrating AI agents into critical workflows AND they have already standardized on managed-device + IdP (M365 Intune for Italian enterprise majority). A Cullis offering that lacks device attestation will not pass the procurement security review of these organizations.

The user (Daniele, founder, 2026-05-16) confirmed:
- Use case primary: **mixed managed + BYOD dev/consultants** (banks employ both corporate-owned managed laptops AND external developers/consultants on BYOD)
- MDM scope: **multi-MDM from day 1** (Intune + Jamf + Kandji + WorkspaceONE — agnostic positioning, even if implementation is phased)
- FIDO2/WebAuthn granular step-up per capability: **deferred to post-first-deal roadmap** (avoid scope explosion, ship MDM-based attestation first)

## Decisions

### A. Four-layer attestation architecture

Cullis adopts a layered attestation model. Each layer addresses a distinct dimension of the trust problem; all four together produce the audit row + access control posture needed by regulated customers.

| Layer | Dimension | What it answers | Scope in this ADR |
|---|---|---|---|
| **1. Device identity** | Which physical device is running the Connector | Hardware-rooted device cert (TPM-bound or MDM-issued) | In scope (mandatory baseline) |
| **2. User identity** | Which human is responsible for the action | SSO/SAML/OIDC login propagated to Connector session | In scope |
| **3. Capability per attestation tier** | What that user+device combination can do | Policy engine matrix evaluating tier (managed / BYOD-trusted / BYOD-untrusted) against capability | In scope |
| **4. Continuous evaluation** | Has the device fallen out of compliance since enrollment? | CAEP subscription to IdP signals + periodic re-attestation | In scope (Microsoft IdP only initially, others as CAEP support emerges) |

### B. Dual device-identity path: managed (MDM) and BYOD (TPM custom CA)

Cullis Connector enrollment differentiates two device-identity paths:

**Managed device path** (corporate-owned, enrolled in customer MDM):
- Connector reads the MDM-issued device certificate from the OS platform certificate store (Windows certificate store, macOS keychain, Linux PKCS11 or filesystem)
- Connector includes the device cert thumbprint in the CSR sent to Mastio
- Mastio verifies via MDM API (Microsoft Graph for Intune, Jamf Pro API, Kandji Public API, WorkspaceONE REST API) that the device is currently managed AND compliant
- On success, Mastio issues the agent cert with `device_attestation: {mdm: "intune", device_id: "...", compliance: "compliant", verified_at: ts}` claim embedded

**BYOD path** (personal device, not enrolled in customer MDM, but TPM/Secure Enclave available):
- Connector generates the agent's DPoP private key INSIDE the platform hardware secure store (TPM 2.0 on Windows/Linux, Apple Secure Enclave on macOS Apple Silicon, Android Strongbox on mobile if future)
- The key is non-extractable: any DPoP proof signed by it cryptographically proves the request originated from a process with access to that specific device's hardware key
- **Attestation strength varies by platform** (research 2026-05-16 confirmed):
  - **TPM 2.0** (Windows/Linux): full chain verification via AIK quote → manufacturer CA (Infineon/Nuvoton/ST/Intel PTT). `attestation_strength = hw_attested`. Cullis must ship a `cullis-ek-roots/` bundle (mozilla/nss-style) refreshed quarterly
  - **Windows Hello + TPM**: full chain via Microsoft TPM Root CA 2014 / Cloud AIK CA + silicon vendor EK. `attestation_strength = hw_attested`. Overlaps with TPM 2.0; pick one as primary per fleet
  - **Apple Secure Enclave on macOS**: **NO third-party verifiable attestation chain**. App Attest is iOS/iPadOS/tvOS only and requires App Store distribution. macOS Secure Enclave provides key isolation (non-extractable P-256 ECDSA key) but no manufacturer chain Cullis can verify. `attestation_strength = hw_isolated`
  - **Android Strongbox**: full chain via Google Hardware Attestation Root. Out of 2026 scope (no mobile client planned)
- The Mastio adds `device_attestation: {hardware: "...", strength: "hw_attested" | "hw_isolated" | "soft_only", manufacturer: "...", verified_at: ts}` claim to the issued agent cert. The `strength` field is consumed by the policy engine in decision E

The two paths are not mutually exclusive: a managed device can ALSO use TPM-bound DPoP keys for added defense in depth (recommended for high-value capability bindings).

### C. Multi-MDM support, phased implementation behind agnostic interface

The product positioning is "Cullis supports any MDM the customer uses". The internal implementation is phased to control effort:

| MDM | Priority | Phase | Driver |
|---|---|---|---|
| Microsoft Intune | P0 | Phase 1 (~2 months) | M365 ubiquitous in Italian enterprise. Intesa Sanpaolo Copilot rollout signal. Microsoft Graph API mature, well-documented |
| Jamf Pro | P1 | Phase 2 (~1 month after P0) | macOS-heavy customers (creative, fintech, tier-1 banks with BYOD Mac) |
| Kandji | P2 | Phase 3 (~3 weeks after P1) | Modern macOS-only MDM, smaller but growing |
| WorkspaceONE (Omnissa) | P2 | Phase 3 (~3 weeks after P1) | VMware/Broadcom heritage, enterprise installed base, in transition post-divestiture |

Architecture: `mcp_proxy/attestation/mdm_provider.py` defines an `MDMProvider` protocol with `verify_device_compliance(device_thumbprint) -> ComplianceResult` and `subscribe_caep_events(device_id, callback)`. Per-MDM implementations live in `mcp_proxy/attestation/intune.py`, `jamf.py`, etc. Customer admin configures one or more providers via `MCP_PROXY_MDM_PROVIDERS=intune,jamf` env or dashboard UI.

**Pre-revenue constraint (resolved 2026-05-16 by user)**: Cullis publishes a standard multi-tenant Entra app for Intune integration, NOT a Microsoft AppSource Marketplace listing. Marketplace certification ($500-1000/yr + ongoing Microsoft security review) is deferred post-revenue (first paying customer OR seed funding). Sales playbook transparently communicates the 2-4 weeks bank-side IT process for admin consent as part of the early-adopter design partner relationship.

### D. User identity propagation: Connector `login` subcommand + bound session

The Connector gains `cullis-connector login` subcommand that opens a local browser to the customer SSO endpoint. On successful authentication, the user token is bound to the active device cert in a session record. Subsequent MCP tool calls from that Connector instance include `on_behalf_of_user_id` in the request envelope, which Mastio propagates to the audit row.

**Session lifetime: 1 hour idle timeout default (banking-grade), tunable up via `MCP_PROXY_USER_SESSION_TTL_SECONDS`** (resolved 2026-05-16 by user). Aligned to tier-1 bank standard (typical 1h idle timeout for privileged sessions). Customer admin can extend to 4h-8h via env override if their threat model accepts longer sessions for dev/ops team convenience, but the secure-by-default posture is preserved.

Refresh via SSO IdP refresh token where supported (OIDC). `cullis-connector logout` invalidates the session locally and notifies Mastio. Re-login required after session expiry; uninterrupted agent operations during the gap fall back to `agent-only` attribution (logged as a downgrade event for CISO visibility).

This decision implements the gap identified in `project_connector_login_gap_future_user_identity`. The implementation reuses the ADR-021 multi-user KMS infrastructure (user_principals table + `POST /v1/principals/csr` Mastio CSR signing) — the missing piece was the client-side flow.

### E. Capability per attestation tier (policy engine extension)

The PDP (ADR-029 tool-level PDP) extends to evaluate per-capability the device attestation tier required. The tier is the COMBINATION of MDM-managed state AND device cryptographic attestation strength (per decision B).

Five-level effective tier ladder (orderable):

| Tier (low → high) | Composition |
|---|---|
| `untrusted` | No MDM management AND `attestation_strength=soft_only` |
| `byod_isolated` | No MDM AND `attestation_strength=hw_isolated` (e.g. macOS BYOD with Secure Enclave) |
| `byod_attested` | No MDM AND `attestation_strength=hw_attested` (e.g. Linux/Windows BYOD with TPM 2.0) |
| `managed` | MDM-managed (compliant) AND any attestation_strength |
| `managed_attested` | MDM-managed AND `attestation_strength=hw_attested` (defense in depth) |

Customer CISO configures the capability matrix via dashboard:

| Capability example | Minimum tier required |
|---|---|
| `tools.call.echo`, `tools.call.public_data_retrieval` | `untrusted` (any) |
| `tools.call.internal_docs`, `tools.call.code_review` | `byod_attested` |
| `tools.call.customer_db`, `tools.call.financial_transaction_read` | `managed` |
| `tools.call.transfer_money`, `admin.*` | `managed_attested` (with future FIDO2 step-up, deferred) |

PDP evaluation order: `agent_capability_grant AND (effective_tier ≥ required_tier)`. Mismatch returns 403 with `denied_reason: "insufficient_attestation_tier"` + `effective_tier: "<actual>"` + `required_tier: "<needed>"` for CISO forensic visibility.

**Important consequence for macOS BYOD**: a Mac without MDM enrollment can never exceed `byod_isolated` even with Secure Enclave key isolation. Customers wanting "BYOD Mac with full attestation" must enroll the device in MDM (Jamf/Kandji/Intune for Mac) to reach `managed` or higher. This is the honest delivery of the macOS attestation gap noted in decision B.

### F. Continuous evaluation: per-MDM mechanism (NOT CAEP for third-party)

**Critical correction (2026-05-16 research)**: Microsoft CAEP is NOT exposed to third-party relying parties as of 2026. CAEP is currently a server-to-server protocol between Microsoft Entra ID and Microsoft-first applications. There is roadmap work between Microsoft and OpenID Foundation to open CAEP to third parties, but it is NOT production-available for Cullis to consume Intune compliance signals in real-time.

Realistic per-MDM mechanism:

| MDM | Push mechanism | Cullis fallback | Stale window |
|---|---|---|---|
| Microsoft Intune | NONE (CAEP not third-party accessible) | Polling via Graph `/managedDevices/delta` every 5-15 min | Up to 15 min |
| Jamf Pro | Native webhooks (`ComputerInventoryCompleted`, `SmartGroupComputerMembershipChange`) | Polling fallback every 4h | Near-real-time if webhook subscribed |
| Kandji / Iru | NONE (only Slack/email/Teams alerts) | Polling every 10-15 min | Up to 15 min |
| WorkspaceONE (Omnissa) | Native Event Notifications v1/v2 (`Compliance Status Change`) | Polling fallback every 4h | Near-real-time if webhook subscribed |

The polling cadence is configurable per-MDM via `MCP_PROXY_MDM_POLL_INTERVAL_SECONDS_<provider>`. Customer CISO accepts the stale window as documented in compliance posture: "Cullis device compliance signal has TTL up to N minutes depending on MDM provider, NOT real-time. For real-time revocation on Intune managed devices, customer must implement separate Microsoft Conditional Access policies as defense in depth."

On compliance-change-detected (push OR polling), Mastio revokes the agent cert tied to that device, forcing the Connector to re-enroll. Revocation is immediate at Mastio side; the Connector may still be operating with cached token until token refresh hits Mastio.

### G. FIDO2/WebAuthn granular step-up: explicit roadmap deferral

FIDO2 step-up authentication for individual sensitive capability invocations (e.g., Yubikey tap before `tools.call.transfer_money` executes) is NOT in scope of this ADR. It is documented as Q2-Q3 2026 roadmap with implementation estimate 6-8 weeks post-first-deal.

Rationale for deferral: scope control. The four-layer architecture above already places Cullis ahead of all known agent-identity competitors. FIDO2 step-up is a differentiator for tier-1 banks at the highest risk-control tier; pursuing it pre-revenue is over-engineering. Customer pre-sales Q&A response: "Q2-Q3 2026 roadmap, architecture designed, implementation 6-8 weeks once contracted".

Open admission in compliance posture statement (per memory `project_target_customer_enterprise_regulated_only`): customers who need step-up before first-deal will sign with the explicit roadmap commitment.

### H. BYOD gap with FIDO2 deferred: explicit downgrade

For BYOD path with FIDO2 deferred, capabilities at the highest sensitivity tier ("transfer_money", "admin.*") are simply NOT GRANTED to BYOD-trusted tier regardless of TPM presence. The matrix in decision E hard-blocks them.

This is the explicit trade-off of decision G. Customers who absolutely require BYOD consultants to perform high-sensitivity operations must either (a) issue managed devices to those consultants, (b) wait for FIDO2 step-up implementation, or (c) accept compliance posture risk and document it.

### J. KMS strategy for Org CA private key (resolved 2026-05-16 by user)

Decision Q4: **A+B combined**. Two-track KMS strategy:

- **Track A (open-core)**: complete ADR-031 `VaultKMSProvider` for HashiCorp Vault self-hosted opensource. Customer deploys and operates Vault, Cullis Mastio reads Org CA key from Vault KV v2. Effort ~2 weeks completion of ADR-031 implementation
- **Track B (enterprise plugin)**: **Azure Key Vault provider FIRST** (priority among cloud KMS plugins). Italian banks with M365 Premier tier already have Azure Key Vault deployed and audited. Cullis adds `AzureKeyVaultProvider` in `cullis-enterprise` private repo, customer pays enterprise license, gets allaccio to their existing Azure Key Vault. Effort ~4-6 weeks. AWS KMS + GCP KMS provider deferred post-first-Azure-customer

This decision REPLACES the implicit ADR-031-only path. The combined A+B is the path that minimizes onboarding friction for the first regulated customer (most banks have Azure Key Vault already) while keeping Cullis open-core viable for non-Azure deployments (Vault self-hosted).

### K. Raw TPM AIK chain verification deferred (BYOD pilot scope, resolved 2026-05-16 by user)

Decision Q8: **Differ raw TPM AIK chain verification + EK CA bundle assembly**. For first pilot design partner, BYOD path uses only:

- MDM-issued device cert verification (Intune SCEP, Jamf built-in CA, Kandji, WS1 OAuth issuance) — covered by decision B managed path
- macOS Secure Enclave key isolation (`hw_isolated` tier, no chain verification) — decision B BYOD path subset
- For pure BYOD without MDM AND requiring `hw_attested` tier: capability denied per decision E matrix, documented gap

Raw TPM AIK chain verification + Cullis EK CA bundle assembly (Infineon/Nuvoton/ST/Intel PTT manufacturer roots) DEFERRED until first customer with BYOD-pure + `hw_attested` requirement requests it explicitly. Avoids ~1 week initial assembly + ~4-8 days/year ongoing maintenance burden during pre-revenue founder-solo period.

When triggered post-revenue: assemble baseline bundle (Infineon + Nuvoton, ~80% market dominant) + customer override option for ST/Intel PTT/other manufacturers.

### I. KeyStore interface + per-OS native helper binaries (NOT pure Python)

**Critical architectural pattern (2026-05-16 research)**: TPM/Secure Enclave access in pure Python is NOT production-grade. `tpm2-pytss` is Linux-only in practice (Windows binary wheels do not exist, requires custom MinGW build chain). macOS Secure Enclave from Python requires PyObjC bridging that is fiddly and lacks the attestation API. Windows TPM requires raw NCrypt FFI (~500 LOC custom).

Cullis adopts the industry pattern (1Password CLI, Bitwarden, Tailscale, signal-desktop):

1. Define a `KeyStore` interface in Python (`cullis_connector/keystore/interface.py`) with methods: `generate_nonextractable_key()`, `sign(payload, key_id)`, `get_attestation(key_id) -> AttestationStatement`
2. Per-OS native helper binaries:
   - **Windows**: NCrypt FFI helper (C++ or Rust) calling `MS_PLATFORM_KEY_STORAGE_PROVIDER`, distributed as `cullis-keystore-helper.exe` next to Connector binary
   - **macOS**: Swift helper binary using `Security.framework` `SecKeyCreateRandomKey` with `kSecAttrTokenIDSecureEnclave`, distributed as `cullis-keystore-helper` Mach-O binary
   - **Linux**: `tpm2-pytss` in-process (mature), fallback to spawn `tss2-esys` C helper if `tpm2-pytss` unavailable on customer distro
3. Helper binaries inherit the parent's signing requirements: macOS notarization requires every embedded executable signed, Windows MSI requires every bundled .exe Authenticode-signed

This decision impacts decision B (BYOD path implementation), the packaging strategy (decision in implementation roadmap F3), and the CI signing pipeline.

## Consequences

### Positive

- **Compliance posture upgrade**: Cullis audit row attribution moves from "agent X" to "user Y on device Z attested by tier T", enabling regulated customer CISO procurement approval
- **GTM positioning**: "multi-MDM agnostic with TPM-bound BYOD fallback" is differentiated from agent-only competitors (LangChain, Semantic Kernel, generic MCP servers) on the dimension that matters for regulated procurement
- **Defense in depth**: hardware-rooted device identity + SSO user identity + per-capability attestation tier + continuous evaluation, all enforced at the Mastio PDP, eliminates entire categories of credential-exfiltration attacks
- **Frontdesk path retained**: ADR-019 Frontdesk SPA continues to serve U2A and U2U scenarios with its existing user-first model; this ADR adds attestation to the Connector path that was previously identity-incomplete
- **Reuse of ADR-021 multi-user KMS infrastructure**: the user_principals table and CSR signing endpoints already exist; this ADR completes the client-side flow

### Negative

- **Implementation scope is 3-4 months of focused engineering** for Layers 1-4 across all 4 MDMs. Even with phased delivery, Phase 1 (Intune-only) is ~2 months before first customer can deploy a working integration. The stress test in C2 Fase A is necessary baseline but does not validate this scope; this is net-new development
- **PyInstaller binary distribution complexity grows**: signed installers per OS (Windows Authenticode, macOS notarization, Linux deb/rpm signed) become mandatory for TPM/Secure Enclave access. CI/CD overhead +1 month, signing cert annual cost ~$500-1500
- **Multi-OS support obligation**: TPM 2.0 library (Python `tpm2-pytss`) maturity is uneven on Linux distributions; macOS Secure Enclave access from Python requires PyObjC bridging to Security.framework or a Swift helper binary. Windows TPM access via WinRT is straightforward but requires Windows 10 Enterprise+. Each platform is its own engineering surface
- **BYOD residual gap until FIDO2 ships**: customers who need BYOD consultants to perform "transfer_money"-grade operations cannot do so under this architecture without managed devices. The compliance posture statement must document this honestly
- **Customer admin onboarding complexity**: configuring Cullis as an integration in 4 different MDM portals (Azure AD app registration, Jamf API account, Kandji API token, WorkspaceONE OAuth) is a customer-facing onboarding burden. Mitigation: per-MDM step-by-step playbook in `enterprise-kit/mdm-integration/` documented and field-tested
- **CAEP availability is uneven**: Phase 1 Microsoft CAEP is solid, but Phase 2-3 MDMs fall back to polling with 4-hour cadence. A device that becomes non-compliant has up to 4 hours of residual agent access. Acceptable for most regulated use cases but worth flagging to CISO
- **Vault Org CA dependency** (ADR-031): the device attestation chain ultimately bottoms out at the Org CA private key signing agent certs. If Vault is misconfigured or the Org CA is compromised, attestation provides no protection. ADR-031 hardening is a pre-requisite, not optional

## Alternatives considered

### Alternative 1: Build TPM-bound end-to-end (rejected)

Skip MDM integration entirely. Cullis Connector generates DPoP key in TPM/Secure Enclave on all devices regardless of management state. Mastio verifies AIK chain. No customer MDM configuration required.

**Rejected because**:
- Effort 6+ months for cross-OS TPM library maturity (`tpm2-pytss` is C-binding wrapper, fragile on Linux distros; macOS Secure Enclave from Python is not first-class)
- Does not address Conditional Access (CISO wants policies tied to MDM compliance state, not just "device has TPM")
- Does not leverage customer's existing M365/Intune investment (negative posture vs Microsoft)
- Better as long-term hardening layer (decision B "managed device CAN also use TPM-bound key for defense in depth") rather than primary path

### Alternative 2: MDM-agnostic via OIDC claims standard (rejected)

Cullis accepts JWT claims like `device_id`, `device_compliance`, `mdm_provider` from any IdP that asserts them. Customer is responsible for configuring their IdP to emit the claims; Cullis does not integrate any MDM directly, only trusts the IdP's assertions.

**Rejected because**:
- Standardized claims for device attestation across IdPs do not yet exist (CAEP is closest but still emerging)
- Trust delegation is too permissive: Cullis cannot verify the claims independently, must trust customer IdP entirely
- Customer onboarding is more complex (configure IdP to emit custom claims) rather than less (most enterprise IdPs cannot do this without significant identity engineering)
- Direct MDM API integration is more reliable and produces verifiable evidence in audit log (Mastio retained the Graph API response for the verification, not just the IdP's claim)

### Alternative 3: Single attestation tier (rejected)

Cullis treats all attestation states equally: device is either "attested" (binary check) or "not attested". No tier matrix, no per-capability policy.

**Rejected because**:
- Loses the entire policy enforcement value: CISO cannot say "managed device required for customer data, BYOD acceptable for docs"
- Reduces Cullis to "binary attestation gate" which adds little over MDM's own conditional access
- The differentiator IS the per-capability policy engine integration. Without it, this ADR's value proposition collapses

### Alternative 4: Defer entire attestation to V2 (rejected for primary customer)

Ship V1 with current agent-only model, focus on stress test + audit log scaling. Attestation in V2 post-first-deal.

**Rejected because**:
- First customer is enterprise regulated by strategic pivot; they will require attestation in procurement Q&A
- Without attestation, the audit row attribution gap is visible immediately; CISO will reject pre-deal
- The C2 hardening fase becomes irrelevant numbers (stressing the wrong model)

Acceptable for non-primary scenarios: if there is a non-regulated early-adopter customer with relaxed compliance requirements (e.g., internal tooling at a tech company), V1 ship without attestation is viable for them. But not for the strategic primary customer.

## Open questions (resolved by 2026-05-16 research + remaining)

### Resolved

1. **~~TPM library Python maturity on Linux~~** → CLOSED: `tpm2-pytss` is mature on Linux (Ubuntu 22.04+, Fedora 38+ ship native packages). Requires `libtss2-esys-0` + `tpm2-abrmd` (resource manager). Decision I adopts in-process integration on Linux.

2. **~~Secure Enclave from Python on macOS~~** → CLOSED: PyObjC bridging is fiddly and lacks attestation API access. Decision I adopts Swift helper binary pattern (industry standard, used by 1Password and Bitwarden). macOS Secure Enclave provides key isolation only (`hw_isolated` tier), NO third-party verifiable attestation chain (Apple App Attest is iOS-only).

3. **~~CAEP support in non-Microsoft MDMs~~** → CLOSED: CAEP is NOT third-party accessible from Microsoft as of 2026 (only Microsoft-first applications). Jamf and WorkspaceONE have native webhooks (decision F updated). Kandji and Intune are polling-only. Decision F revised accordingly.

5. **~~Connector binary code signing CI cost~~** → CLOSED: Windows $180-700/yr (DigiCert KeyLocker recommended for HSM cloud signing, clean GHA integration), macOS $99/yr (Apple Developer Program), Linux $0 (self-hosted GPG repo). Total ~$300-800/yr signing costs + 6-9 weeks one-shot engineering for full cross-OS signed installer pipeline.

### Resolved 2026-05-16 by user (founder Daniele)

4. **~~Customer Vault dependency~~** → CLOSED by decision J: A+B combined strategy. Vault self-hosted opensource (ADR-031 completion) + Azure Key Vault enterprise plugin (priority) + AWS/GCP plugins deferred post-first-Azure-customer. Cullis-managed KMS SaaS deferred post-revenue (requires SOC 2 audit ~$50k+, infeasible pre-revenue).

6. **~~User-bound session lifetime~~** → CLOSED by decision D update: default 1h idle timeout (banking-grade), tunable up via `MCP_PROXY_USER_SESSION_TTL_SECONDS`. Customer admin can extend to 4-8h if their threat model accepts.

7. **~~Multi-tenant Entra app friction~~** → CLOSED by decision F update: no Microsoft AppSource Marketplace listing pre-revenue. Standard multi-tenant Entra app published, sales playbook transparently communicates 2-4 weeks bank IT process as part of early-adopter design partner relationship. AppSource listing deferred post-revenue (~$500-1000/yr + Microsoft security review).

8. **~~EK CA bundle distribution + maintenance~~** → CLOSED by decision K: raw TPM AIK chain verification deferred. For first pilot, BYOD path uses only MDM-issued cert (managed device) or `hw_isolated` (macOS BYOD no MDM). Pure BYOD + `hw_attested` requirement = capability denied with documented gap. EK bundle assembly triggered only when first customer explicitly requests `hw_attested` BYOD path.

### Open (no longer blocker, deferred to post-implementation iteration)

(Empty: all original open questions closed via founder decisions or deferral.)

### Constraint context

Decisions above made under explicit constraint (memory `project_pre_revenue_budget_zero_vendor_fees`): Cullis is pre-revenue, founder-solo, budget for vendor ecosystem fees (Microsoft Partner, AppSource, Apple Enterprise scalato, code-signing HSM, Cullis-managed SaaS KMS with SOC 2) = ZERO. All such investments deferred to post first paying customer OR seed funding.

Pilot customer profile: NOT full enterprise tier-1 (Intesa Sanpaolo-grade), but design partner accepting UX/integration compromises in exchange for early-adopter pricing + roadmap input. Fintech startup small-but-regulated, scaleup with compliance need, innovation department of tier 2-3 bank with discretional budget.

## Implementation roadmap (revised post-research 2026-05-16)

| Fase | Scope | Effort estimate | Output |
|---|---|---|---|
| **F1** | This ADR ratification + remaining open questions (4, 6, 7, 8) | 1 week | `docs/adrs/adr-032-...` ratified |
| **F2** | Spike Intune integration: multi-tenant Entra app + admin consent flow + Microsoft Graph polling + SAN-based device-id binding via SCEP profile | **2-3 weeks** | Working demo + report |
| **F3** | Spike TPM-bound DPoP key on **Linux first** (mature `tpm2-pytss`): KeyStore interface + tpm2-pytss in-process integration + AIK verify | 2 weeks | Working demo on Linux |
| **F4** | User identity propagation: `cullis-connector login` subcommand + SSO web flow + bound session | 2 weeks | Layer 2 done |
| **F5** | Policy engine extension: capability per 5-tier attestation matrix + dashboard UI | 1-2 weeks | Layer 3 done |
| **F6** | Per-MDM continuous evaluation: Intune polling + Jamf/WS1 webhook receivers | 2 weeks | Layer 4 done across MDMs |
| **F7** | Multi-MDM expansion: Jamf, Kandji, WorkspaceONE | **2-3 + 1-2 + 3 = 6-8 weeks** (parallel partial) | F2 extended to 4 MDMs |
| **F8a** | BYOD path Windows: NCrypt FFI helper binary (~500 LOC C++/Rust) + Authenticode signing + WiX MSI | **3-4 weeks** (signing + helper) | Windows BYOD ready |
| **F8b** | BYOD path macOS: Swift helper binary + Apple Developer Program + Notarization + DMG/PKG packaging | **2-3 weeks** (signing + helper) | macOS BYOD ready (`hw_isolated` tier only) |
| **F9** | Audit log extension to include device_attestation claim + 5-tier strength + dashboard CISO views | 2 weeks | Forensic visibility complete |
| **F10** | EK CA bundle initial assembly (`cullis-ek-roots/`) + quarterly refresh process documentation | 1 week | Ongoing operational asset |
| **F11** | Compliance posture statement updated (`enterprise-kit/compliance-posture.md`) explicitly documenting macOS BYOD `hw_isolated` gap, Intune polling stale window, FIDO2 step-up roadmap | 1 week | Customer-facing CISO doc |

| Milestone | Effort total | Output |
|---|---|---|
| **First customer ready** (Intune + Linux/Windows TPM + Layer 1-4) | **~12-14 weeks** | Production deployable |
| **Multi-MDM + multi-OS complete** | **+8-10 weeks** | Full posture statement |
| **TOTAL** | **~20-24 weeks** (5-6 months) | Full ADR-032 implementation |

NB: estimates assume single dedicated engineer. Parallelization possible on F7 (per-MDM independent) and F8a+F8b (per-OS independent). With 2-3 engineers in parallel, total compresses to ~3-4 months.

### Pre-revenue roadmap subset (resolved 2026-05-16)

Given pre-revenue constraint, the ACTUAL first-pilot-ready scope is reduced from F1-F11 to:

| Pre-revenue minimum | Effort | Output |
|---|---|---|
| **F1** ADR ratification (this doc) | 1 week | `docs/adrs/adr-032-...` ratified |
| **F2** Intune integration (standard multi-tenant Entra app, NO AppSource) | 2-3 weeks | Working demo + customer onboarding playbook |
| **F3** TPM-bound DPoP Linux only (skip Windows NCrypt + macOS Swift helper) | 2 weeks | Linux BYOD `hw_attested` path |
| **F4** User identity propagation: `cullis-connector login` + SSO + 1h idle TTL | 2 weeks | Layer 2 done |
| **F5** Policy engine: 5-tier matrix + dashboard UI | 1-2 weeks | Layer 3 done |
| **F6** Intune polling (no CAEP) + audit log device_attestation claim | 1-2 weeks | Layer 4 partial + forensic visibility |
| **F-KMS-A** Complete ADR-031 VaultKMSProvider open-source | 2 weeks | Org CA on Vault for opensource customers |
| **F-KMS-B** AzureKeyVaultProvider enterprise plugin | 4-6 weeks | Cloud-KMS allaccio for Azure-heavy customers |
| **PRE-REVENUE TOTAL** | **~14-19 weeks** (3.5-4.5 months) | First pilot design partner ready |

**Deferred post-revenue** (NOT in pre-revenue pilot scope):
- AppSource Marketplace listing + Microsoft Partner certification
- Windows TPM helper binary + Authenticode signing
- macOS Secure Enclave Swift helper binary + Apple Notarization at scale
- Jamf, Kandji, WorkspaceONE MDM plugins (only when specific customer asks)
- AWS KMS, GCP KMS enterprise plugins
- FIDO2/WebAuthn granular step-up
- Raw TPM AIK chain verification + EK CA bundle assembly
- Cullis-managed KMS SaaS + SOC 2 audit
- CAEP subscription (not available to third-party from Microsoft as of 2026 anyway)
- BYOD path on macOS Secure Enclave key isolation (Mac BYOD users get `hw_isolated` tier maximum, which doesn't unlock customer-sensitive capabilities — acceptable gap for first pilot)

## References

- TPM 2.0 specification (TCG) — https://trustedcomputinggroup.org/work-groups/trusted-platform-module/
- Microsoft Graph API device management — https://learn.microsoft.com/en-us/graph/api/resources/intune-graph-overview
- Apple App Attest framework — https://developer.apple.com/documentation/devicecheck/preparing_to_use_the_app_attest_service
- CAEP — https://openid.net/specs/openid-caep-1_0.html
- FIDO2 / WebAuthn — https://www.w3.org/TR/webauthn-3/
- Memorie progetto correlate: `project_target_customer_enterprise_regulated_only`, `project_identity_model_today_4_quadrants_audit_attribution`, `project_connector_login_gap_future_user_identity`, `feedback_security_keys`, `feedback_chat_completion_dpop_pinning_bug`, ADR-019, ADR-020, ADR-021, ADR-029, ADR-031
