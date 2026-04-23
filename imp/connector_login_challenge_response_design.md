# Challenge-response login for device-code Connectors — design

Status: **Proposal — design review**
Date: 2026-04-23
Scope: Tech-debt #2 from `project_connector_tech_debt`.
Author: Agent 2 (session, not merged).

## Problem

Device-code-enrolled Connectors hold the agent private key **locally**
(`~/.cullis/identity/agent.key`). The existing `POST /v1/auth/sign-assertion`
endpoint signs the client_assertion **server-side** using
`AgentManager.get_agent_credentials(agent_id)`, which fetches the key
from Vault or `proxy_config`. Device-code enrollment never deposits the
key on the Mastio, so the lookup raises `ValueError` → 404
`"agent credentials not available on proxy"`.

Current Connector `cli._cmd_serve` sidesteps this by **not** calling
`login_via_proxy` eagerly; `cullis_connector/tools/session.py::_require_client`
tries it lazily and logs a warning when it fails. Net result: the
Connector can only use `send_oneshot` (X-API-Key + DPoP + local inner/outer
signatures, no broker JWT). `client.discover()`, `open_session()`, and
cross-org federation lookups that require a broker JWT all fail.

## Goal

Give device-code Connectors a broker access token without depositing the
agent private key on the Mastio — keep the key-stays-on-device invariant
intact while enabling the full broker session surface.

## Alternatives

### A — New dedicated challenge-response endpoints (recommended)

Two new endpoints, additive:

```
POST /v1/auth/login-challenge              → { nonce, expires_in, agent_id }
POST /v1/auth/sign-challenged-assertion    → { client_assertion, agent_id, mastio_signature }
```

Separate from `/v1/auth/sign-assertion`. The legacy endpoint keeps its
"Mastio signs for you" semantics for BYOCA/Vault-held-key agents;
the new pair implements "client signs, Mastio endorses".

- **Pro:** semantics stay pure — endpoint name and contract tell you
  which entity holds the key. Zero risk of regressing the BYOCA path
  that the sandbox agents rely on. Auditable: a 2-call flow is easy
  to follow in logs.
- **Con:** two new routes + a nonce store to add.

### B — Polymorphic `/v1/auth/sign-assertion` with optional `client_assertion`

Single endpoint that branches: if the body contains a client-signed
`client_assertion`, verify+counter-sign; if absent, fall back to the
legacy "sign on agent's behalf" path.

- **Pro:** one endpoint, backward-compatible at the URL level.
- **Con:** branching auth endpoint increases attack surface and makes
  logs ambiguous (same path, different trust model). Reviewers have
  to read both branches to understand any change. No challenge means
  **no anti-replay** for the client-signed path unless the body is
  made more complex — arguably worse than adding a separate endpoint.

### C — Reuse `/v1/auth/sign-assertion` + challenge header

Client posts to `/v1/auth/sign-assertion`, Mastio returns 401 with a
`WWW-Authenticate: Challenge nonce="…"` header, client retries with the
nonce baked into a JWT in the body.

- Rejected: stateful 2-phase dance on a single route is fragile, the
  WWW-Authenticate header semantics are for client-initiated challenges
  not server-issued ones, and the replay window during retries is fuzzy.

**Recommendation: Alternative A.** Justification in §7.

## Flow (Alternative A)

```
Connector                                   Mastio (mcp_proxy)
─────────                                   ──────────────────
 1. POST /v1/auth/login-challenge    ──►    generate nonce (32 rand bytes b64url)
    headers: X-API-Key                      store login_challenge:{agent_id}:{nonce}
                                            with TTL 120s, value "issued"
                                     ◄──    { nonce, expires_in: 120,
                                              agent_id: "<org>::<name>" }

 2. build client_assertion JWT              wait for step 3
    signed locally with agent.key:
    {
      "iss": agent_id,
      "sub": agent_id,
      "aud": broker_url,
      "iat": now,
      "exp": now+180,
      "jti": <uuid>,
      "nonce": <b64url from step 1>,
      "cnf": { "jkt": <dpop-jkt> }       (optional, ADR-012 parity)
    }
    header: x5c = [agent cert DER b64]

 3. POST /v1/auth/sign-challenged-assertion
    headers: X-API-Key
    body: { client_assertion, nonce }  ──►  (a) consume login_challenge:{agent_id}:{nonce}
                                               atomic SET NX EX → DEL. If missing → 401.
                                            (b) jwt.get_unverified_header → extract x5c cert.
                                                Verify cert chain against Org CA
                                                (reuse mcp_proxy.auth.x509_verifier).
                                                Verify cert_pem == internal_agents.cert_pem
                                                (certificate thumbprint pin).
                                            (c) jwt.decode(assertion, cert_public_key, algorithms=["RS256","ES256"])
                                                with verify_exp=True, leeway=30s.
                                            (d) assert decoded["sub"] == agent.agent_id
                                                assert decoded["nonce"] == nonce (anti-confused-deputy:
                                                  forgets a nonce reuse would still have to
                                                  pin sub to caller's X-API-Key).
                                                assert decoded["exp"] - decoded["iat"] ≤ 300.
                                            (e) mastio_signature = agent_manager.countersign(
                                                    client_assertion.encode()
                                                )  (reuses ADR-009 Phase 2 machinery)
                                     ◄──    { client_assertion: <echo>,
                                              agent_id,
                                              mastio_signature }

 4. POST /v1/auth/token  (via reverse-proxy)
    body: { client_assertion }
    headers: DPoP <proof>,
             X-Cullis-Mastio-Signature: <mastio_signature>
                                     ──►    (unchanged — Court validates cert chain,
                                             assertion signature, and the mastio
                                             counter-sig against organizations.mastio_pubkey)
                                     ◄──    { access_token }  ← DPoP-bound
 5. client.token = access_token
```

### Field choices

| Element | Choice | Rationale |
|---|---|---|
| Nonce format | 32 random bytes → base64url (43 chars) | Same entropy budget as DPoP JTIs; opaque to client; fits in JWT claim. |
| Nonce TTL | 120s | Covers round-trip + clock skew + slow human OAuth popup (none here but keep parity with DPoP iat window). Shorter than assertion exp (≤300s) so the nonce can't outlive the token it issued. |
| Nonce store key | `login_challenge:{agent_id}:{nonce}` | Binds nonce to caller — a leaked nonce can't be reused by a different API-key holder, defence-in-depth on top of `sub == agent.agent_id` check. |
| Nonce consume | Atomic `SET NX EX`, then `DEL` on first use | Same pattern as `DpopJtiStore.consume_jti`. Redis in prod, in-memory fallback. |
| What client signs | Full client_assertion JWT with `nonce` claim | The nonce is IN the assertion so it's covered by the client signature — rebinding to a different nonce is a tamper the server catches. |
| Algo | RS256 or ES256 (PyJWT auto-dispatch on key type) | Matches existing enrollment/cert types (dual-stack RSA/ECDSA). |
| Server verify | `x5c` → cert → chain verify against Org CA → pin against `internal_agents.cert_pem` → decode JWT with cert's public key | Identical trust model to the broker-side verification at `/v1/auth/token`; Mastio is now a local mirror of that check before counter-sig. |
| Counter-sign | `agent_manager.countersign(assertion.encode())` — ES256 on mastio leaf | Reuses ADR-009 Phase 2 primitive. No new crypto. |
| Response body shape | Echo assertion + agent_id + mastio_signature | Same wire shape as `/v1/auth/sign-assertion` → SDK code path merges at step 4. |

### Anti-replay guarantees

1. **Nonce freshness**: nonce is single-use (consumed on first valid call). A replayed `/sign-challenged-assertion` call with the same nonce returns 401 before any crypto runs.
2. **Nonce binding**: store key includes `agent_id` — a nonce issued for `agentA` cannot be redeemed by an attacker holding `agentB`'s API-key.
3. **Assertion signature**: tampering with the nonce claim invalidates the client signature → JWT decode fails.
4. **Assertion short exp**: `exp - iat ≤ 300` enforced server-side; stolen-in-transit assertions have a 5-minute window and the DPoP-bound token that results is further bound to a key the attacker doesn't have.
5. **Cert pin**: `cert_pem == internal_agents.cert_pem` (thumbprint equivalent) prevents a valid cert chain from a rotated/unrelated cert sneaking in.

## File tree

### Mastio (new + modified)

- **New** `mcp_proxy/auth/challenge_store.py` (~80 LOC) — `ChallengeStore` Protocol + `InMemoryChallengeStore` + `RedisChallengeStore`. Mirrors `dpop_jti_store.py` exactly. `issue_challenge(agent_id) → nonce`, `consume_challenge(agent_id, nonce) → bool`.
- **New** `mcp_proxy/auth/challenge_response.py` (~150 LOC) — `POST /v1/auth/login-challenge` + `POST /v1/auth/sign-challenged-assertion` handlers. Auth via `Depends(get_agent_from_api_key)` (same dep sign-assertion uses).
- **Modified** `mcp_proxy/main.py` — `include_router(challenge_response.router)` next to the existing `sign_assertion_router` wiring.

### SDK (modified)

- **Modified** `cullis_sdk/client.py`:
  - New method `login_via_proxy_with_local_key(self) -> None` (~80 LOC). Reads `self._signing_key_pem` (already populated by `from_connector` + `cli._cmd_serve`). Posts challenge → builds client_assertion locally (uses `cullis_sdk.auth.build_client_assertion` with cert + key) → posts sign-challenged-assertion → forwards to `/v1/auth/token` exactly like `login_via_proxy` does today.
  - Existing `login_via_proxy(self)` untouched — BYOCA/Vault-held agents keep their path.
- **No change** to `cullis_sdk/auth.py` (`build_client_assertion` already exists and is the same helper the Mastio imports at line 23 of `sign_assertion.py`).

### Connector (modified)

- **Modified** `cullis_connector/cli.py::_cmd_serve`:
  - Remove the "We deliberately *do not* call login_via_proxy eagerly" block + comment.
  - After `client.identity = identity` and signing-key load: `client.login_via_proxy_with_local_key()`. Wrap in try/except with the existing diagnostic pattern; non-fatal (falls through to lazy path).
- **Modified** `cullis_connector/tools/session.py::_require_client`:
  - Replace `state.client.login_via_proxy()` with `state.client.login_via_proxy_with_local_key()`.
  - Drop the "device-code 404s, use send_oneshot instead" diagnostic message — with the fix, device-code works.

### Tests

- **New** `tests/test_proxy_challenge_response.py` — endpoint tests:
  - happy path (200, mastio_signature present when ADR-009 loaded, absent when legacy)
  - replay: second call with same nonce → 401
  - expired nonce → 401
  - nonce bound to different agent: issued for A, consumed by B → 401
  - cert chain fail (assertion x5c not signed by Org CA) → 401
  - cert pin fail (assertion x5c ≠ internal_agents.cert_pem) → 401
  - `sub` claim ≠ X-API-Key's agent_id → 401
  - missing nonce claim in assertion → 400
  - assertion exp > iat + 300 → 400
  - unauthenticated (no X-API-Key) → 401
- **New** `tests/test_sdk_login_via_proxy_with_local_key.py`:
  - happy path (mock proxy responses for both hops + mock Court `/v1/auth/token`)
  - challenge endpoint 404 → `PermissionError` (no silent fallback — see §Risks)
  - sign endpoint 401 → `PermissionError` with status surfaced
  - no local signing key → `RuntimeError("requires local signing key")`
- **New** `tests/connector/test_cli_eager_login.py`:
  - `_cmd_serve` calls `login_via_proxy_with_local_key` exactly once
  - failure is non-fatal (serve continues, lazy path remains for session tools)
- **Sandbox dogfood**: extend `sandbox/demo.sh` scenarios with `session-a-to-b` (open_session + send + close) that requires a broker JWT. Today the sandbox agents use direct Court login with local certs (bypass of device-code issue), so this scenario should be wired to exercise the new path via a simulated-device-code agent. If wiring the sandbox to the Connector is too large (likely — Connector isn't in the sandbox today), defer the sandbox scenario and land unit + integration tests only.

## Risks

| Risk | Mitigation |
|---|---|
| Nonce store unbounded in memory backend | TTL 120s + automatic expiry; single-worker mode only (prod uses Redis). Add a periodic sweep task guarded by `asyncio.Lock` (copy from `dpop_jti_store.py`). |
| Downgrade attack (MITM forces client to legacy `sign-assertion`) | Connector always calls `login_via_proxy_with_local_key`. No fallback to legacy. `login_via_proxy()` and `login_via_proxy_with_local_key()` are **separate methods**; choosing is a client-side config decision made at construction, not a runtime negotiation. |
| Clock skew between Connector and Mastio | 30s leeway on assertion `exp` + `iat`. Matches existing `/v1/auth/token` leeway on the Court side. |
| Agents with BOTH local key + Mastio-held key (hybrid) | Legitimate ambiguity — pick one explicitly. Documented: `login_via_proxy_with_local_key` uses `self._signing_key_pem`; `login_via_proxy` uses Mastio-held Vault key. Caller picks. No auto-detect. |
| Rotated cert / key mismatch | Cert pin vs `internal_agents.cert_pem` catches this. Rotation flow (when implemented) updates the row first, then the Connector re-enrolls. |
| Observability — someone fails login in CI and diagnostics are thin | Log at `_log.info` on each step transition, WARNING on 401, with enough detail to distinguish replay/expired/pin/cert-chain failures. Audit row on every success + every denied attempt (reuse `log_audit`). |
| Rate-limit bypass via login spam | Inherits from `get_agent_from_api_key` → `rate_limit_per_minute` global bucket. Per-route override not added (consistent with `/v1/auth/sign-assertion`). |
| BYOCA / Vault-held-key regression | Legacy path untouched. Existing `tests/test_proxy_sign_assertion*` should pass unchanged — CI gate. |
| Performance (2 round-trips vs 1) | ~20-40ms per hop on local network → ~60-80ms total login. Login happens once at serve bootstrap + on 401 refresh. Not in the request hot path. |

## Deferral / scope cuts

Out of this implementation — follow-ups:

- **mTLS hybrid binding (RFC 8705)**: would bind the resulting access token to a client cert thumbprint on top of DPoP. Orthogonal to challenge-response; separate audit item.
- **Hardware token support** (TPM/YubiKey holding the private key): the flow is already compatible (the Connector abstracts key storage via `agent.key` file), but plumbing a PKCS#11 backend is its own project.
- **Per-route rate-limit for `/v1/auth/login-challenge`**: inherits global bucket; if enumeration probes become an issue, add a separate bucket later (pattern from #289).
- **Nonce-per-DPoP-jkt binding**: could strengthen the flow by having the client send its DPoP thumbprint in the challenge request and bind the nonce to it. Good hardening but adds complexity and isn't strictly required with per-agent binding. Defer.
- **Challenge endpoint on the Court side** (so agents could log in directly to the Court without a Mastio): not needed — ADR-004 pins "agents always go through proxy" and this design keeps that invariant.
- **Signed response from Mastio to client on challenge**: currently the challenge response is unsigned JSON (only integrity-protected by TLS). A malicious proxy replacing the nonce mid-flight would cause the client to sign an attacker-chosen nonce, but the `consume_challenge` step still gates redemption by `agent_id` — the attacker gains nothing except a signed-over-nonce artifact they can't spend. If we want defence-in-depth for untrusted-transport deployments (none today), sign the challenge response with the mastio leaf. Defer.

## Recommendation

**Alternative A** — dedicated `/v1/auth/login-challenge` + `/v1/auth/sign-challenged-assertion` pair.

Why:

1. **Semantic clarity wins.** `sign-assertion` means "server signs on your behalf"; `sign-challenged-assertion` means "server verifies + endorses what you signed". Different trust models deserve different endpoints. A future reader of the auth code gets this in five seconds.

2. **Zero risk to the existing BYOCA path.** The sandbox agents, enterprise deployments with Vault-held keys, and every test in `tests/test_proxy_sign_assertion*` exercise the legacy endpoint. Touching it to add polymorphism (Alternative B) has a non-zero chance of regressing that surface — and login is the last place we want a stealth regression.

3. **Anti-replay is built-in.** The challenge step exists specifically to make replay detection cheap and explicit. Retrofitting Alternative B to have equivalent anti-replay guarantees means adding a nonce claim anyway — at which point it's just Alternative A with a confusing URL.

4. **Auditability.** Two log lines per login (challenge issued, assertion endorsed) is easier to triage than one polymorphic line. This matters once a customer rings asking "did my Connector actually log in at 14:02:38 UTC or did the attacker?".

Scope estimate: ~500 LOC production + ~400 LOC tests, 1-2 days including sandbox scenario integration. Alternative B would be ~300 LOC but I judge the semantic and review cost of the polymorphic endpoint to exceed the LOC savings.

Next step on approval: open PR with `feat/connector-login-challenge-response` branch, landing endpoint + SDK + Connector together (three-part atomic PR, same pattern as #292).
