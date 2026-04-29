# ADR-015 — TLS bootstrap & TOFU CA pinning for the Connector

- **Status:** Accepted
- **Date:** 2026-04-29
- **Related:** ADR-014 (nginx mTLS for Connector ↔ Mastio), ADR-006 (Trojan Horse standalone Mastio), ADR-011 (unified enrollment), ADR-013 (layered defence)

## Context

ADR-014 made the Connector's certificate the only credential it carries to its Mastio. The Mastio terminates TLS on a sidecar nginx serving a leaf cert signed by the Org CA the Mastio itself generates at first-boot. This is the right shape for production once both sides know each other — but it leaves the very first request exposed.

A self-host operator who just installed the Mastio bundle has:

- A leaf cert signed by an Org CA only the Mastio knows about.
- No way to publish the CA out-of-band that doesn't already require trust (a webhook to Slack, a one-pager on a wiki — any of these are downstream of the same network the operator wants the Connector to traverse safely).

A new Connector profile has:

- A `verify_tls` boolean wired into every `httpx` call.
- A `ca_chain_path` field on `ConnectorConfig` that points at `<profile>/identity/ca-chain.pem`. That file was *intended* to hold the Org CA, but `enroll()` set `ca_chain_pem=None` (a TODO from Phase 2c) and every httpx call passed `verify=cfg.verify_tls` — a bool — so even if the file had been populated, the client would have ignored it.

The result observed in the 2026-04-29 dogfood (Finding #3 in `project_dogfood_findings_2026_04_29.md`): the only honest path through the Connector setup is "Disable TLS verification". The dashboard exposes a checkbox for this. There is no middle ground — no way to verify a fingerprint, no way to pin a CA, no way to refuse to continue if a fingerprint changes between sessions.

This is not a fix for someone in deep MITM position; that's downstream of cryptographic identity, not bootstrap. This is a fix for the 95% case where the operator just wants to know they're talking to the Mastio they installed five minutes ago, and to continue knowing that on subsequent restarts.

## Decision

Trust on First Use (TOFU) pinning of the Org CA, surfaced as an explicit dashboard step that hands the operator a SHA-256 fingerprint to compare against an out-of-band channel.

1. **The Mastio publishes its Org CA at an anonymous endpoint** — `GET /pki/ca.crt`, served as `application/x-pem-file`, no auth, no client cert, ETag + 5-minute Cache-Control. The endpoint sits outside any reverse-proxied prefix so it is served directly by the Mastio process, not forwarded. nginx exposes the path via `location = /pki/ca.crt` (exact match — no path traversal).

   Publishing the CA leaks no information that one TLS handshake wouldn't reveal already. What it adds is a stable, canonical artifact that a UI can show to a human and that another machine can hash repeatably.

2. **The Connector dashboard scripts a two-step pin flow.** On the setup screen, before the operator submits the enrollment form:

   1. Click **"Fetch fingerprint"** → dashboard POSTs to `/setup/preview-ca` → backend GETs the Site's `/pki/ca.crt` with `verify=False` (the whole point — we don't trust the leaf yet) and returns the PEM body, the raw 64-char hex SHA-256, and a colon-separated short form (`AB:CD:EF:…`) easier for humans to compare visually.
   2. Operator compares the displayed fingerprint with what their admin gave them out-of-band (signal, in person, signed email). If it matches, click **"Pin this CA"** → dashboard POSTs to `/setup/pin-ca`, the backend **re-fetches** the CA, recomputes the fingerprint, refuses to pin if it changed, and on match writes the PEM to `<profile>/identity/ca-chain.pem`.

   The re-fetch closes the TOCTOU between preview and pin: an attacker who could swap the served CA between the two calls would need to produce a different cert with the same SHA-256 digest, which is the property the pin relies on.

3. **`httpx` calls inside the Connector resolve their `verify=` value through `ConnectorConfig.verify_arg`** (or the module-level helper `verify_arg_for(verify_tls, ca_chain_path)` for callers that have a form-supplied bool). Resolution rules:

   | Operator says verify | CA pinned on disk | `verify_arg` |
   |---|---|---|
   | True (default) | yes | `str(ca_chain_path)` — httpx uses pinned CA as trust store |
   | True (default) | no | `True` — system trust store, will fail for self-signed Sites |
   | False (`--no-verify-tls` / checkbox) | yes | `False` — opt-out is opt-out, pinned CA does not silently re-enable verification |
   | False | no | `False` |

   The "opt-out is opt-out" rule matters: an operator who has explicitly chosen to skip verification (because they're debugging a setup, or running an air-gapped lab, or whatever) must not have their choice silently overridden the moment a CA file appears under the profile dir.

4. **The "Disable TLS verification" checkbox stays as a fallback,** with the field hint clarifying it's for development. We add the TOFU path as the recommended primary, but we don't remove the escape hatch — it's load-bearing for CI smoke tests, for one-off debugging, and for operators whose Site genuinely doesn't have a CA endpoint yet (older Mastio versions, custom proxies in front of the Mastio that don't proxy `/pki/`).

5. **No automatic re-pin on rotation.** When the Mastio rotates its Org CA (rare — days-to-years cadence), the Connector's pinned CA stops matching the served leaf, every `httpx` call fails with a TLS verification error, and the operator goes through the dashboard flow again. This is a feature, not a bug: silent re-pinning would defeat the entire purpose of pinning.

   Future ADR can address rotation UX (a "your pinned CA no longer matches — re-verify with your admin?" prompt). Out of scope for this one.

## Consequences

### Positive

- The dogfood lockup ("the only honest option is to disable verification") goes away. The recommended path actually verifies.
- The fingerprint shown in the dashboard is the same artifact a security-conscious admin can publish in their own onboarding doc / wiki / runbook — making out-of-band verification cheap.
- `httpx` clients across the Connector now actually use `ca_chain_path` after enrollment; the TODO from Phase 2c (`save_identity(..., ca_chain_pem=None)`) effectively closes by the dashboard populating the file directly.
- `tls_verified` in the `hello_site` MCP tool's response is now meaningful: it reports whether the leaf was actually verified, not just whether the operator ticked the right checkbox.

### Negative

- The setup form gains a JS-driven step. We previously had a pure server-rendered form; now there's a `fetch()` block doing two POSTs. Trade-off accepted because the alternative (server-driven multi-page wizard) costs more usability than it saves complexity.
- TOFU still asks the operator to compare a fingerprint with an out-of-band channel. The threat model is "the channel that delivered the Mastio install instructions is at least as trustworthy as the channel delivering the fingerprint." For most self-host operators this is the same human's keyboard. We are not solving deep-MITM; we are giving honest verification a shape that a human can execute.
- Two `/pki/ca.crt` GETs per enrollment instead of zero. Both anonymous, both ETag-cached for 5 minutes — the load is negligible.

## Alternatives considered

- **Let's Encrypt for the Mastio leaf.** Requires the Site to be reachable from the public internet at a stable hostname during ACME challenges. Self-host operators on private IPs, internal DNS, or ephemeral hostnames (most of them) can't use this. Forces a topology assumption ADR-006 explicitly rejected.
- **Web PKI (operator buys a public cert from a public CA).** Same topology constraint as Let's Encrypt, plus monetary cost, plus most self-host operators don't have a public DNS record to attach a cert to. A non-starter for the trojan-horse standalone case.
- **SPKI/SKI pinning instead of full-cert pinning.** Marginally more durable across cert rotations *within the same key*, but the Mastio's first-boot CA is generated locally and rotated by regenerating the entire keypair (ADR-014). Same-key rotation is not a workflow we support; SPKI pinning gives nothing extra and makes the artifact harder to display ("paste this 30-char base64 blob" vs. "match these 64 hex chars").
- **Bundle the CA fingerprint into the Mastio install command** (`./install-mastio.sh --emit-fingerprint > /tmp/fp`). Useful as a *complement* but not a substitute — it requires the Mastio admin and the Connector operator to be the same person, or to share a filesystem. The dashboard flow works for both same-person and admin-distributing-to-team cases.
- **Skip TOFU, ship deep PKI from day one** (intermediate CA from a customer's existing root). Right answer for enterprise design partner deployments. Wrong answer for the self-host install path that drives community adoption — it pushes a half-day Vault/PKI exercise onto someone who just wants `docker compose up` to work.

## Implementation footprint (for the PR)

- New: `mcp_proxy/pki/public.py` — anonymous CA endpoint with rate-limit, ETag, Cache-Control.
- New: `cullis_connector/web.py` — `/setup/preview-ca` and `/setup/pin-ca` endpoints; setup template gains a TOFU box with `fetch()` JS.
- New: `cullis_connector/config.py` — `ConnectorConfig.verify_arg` property and module-level `verify_arg_for(verify_tls, ca_chain_path)` helper.
- Wired: every `httpx` call in `cullis_connector/{tools,web,enrollment,cli}.py` that previously passed `verify=cfg.verify_tls` (bool) now passes the resolved `verify_arg` (`bool | str`). `enrollment.py` widens its parameter type.
- nginx: `nginx/mastio/mastio.conf` and `packaging/mastio-bundle/nginx/mastio/mastio.conf` gain `location = /pki/ca.crt`.
- Tests: `tests/test_pki_public_ca.py` (anonymous endpoint), `tests/connector/test_config.py` (`verify_arg` matrix), `tests/connector/test_web_tofu.py` (preview + pin endpoints, TOCTOU, fingerprint match).
