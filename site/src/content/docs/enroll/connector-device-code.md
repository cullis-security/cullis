---
title: "Connector device-code enrollment"
description: "The Cullis Connector enrollment flow — local keypair + admin approval + challenge-response handshake — that turns a developer's laptop into an enrolled agent without ever transmitting the private key."
category: "Enroll"
order: 10
updated: "2026-04-23"
---

# Connector device-code enrollment

**Who this is for**: a developer enrolling their own laptop (interactive), or a platform engineer who wants to understand the protocol before scripting around it. If you're programmatically provisioning headless agents from CI/CD or Kubernetes, use [BYOCA](byoca) or [SPIRE](spire) instead.

## Prerequisites

- Connector installed and on your `PATH` (see [Install the Connector](../install/connector))
- Your org's Mastio URL
- An admin reachable to approve the enrollment

## The protocol, in one diagram

```
Developer laptop                        Mastio                       Admin
─────────────────                       ──────                       ─────
1. cullis-connector enroll
   generate P-256 keypair (local)
   POST /v1/enrollments  ───────────→   persist row, status=pending
                                        issue enrollment_session_id
                            ←────────   { session_id, approval_url }
2. share approval_url  ──────────────────────────────────────────→  open in browser
                                                                    click Approve,
                                                                    fill capabilities
                                        ←──────  POST /proxy/enrollments/{id}/approve
3. poll every 3s
   GET /v1/enrollments/{id}  ────────→  check status
                            ←────────   status=approved, challenge_nonce
4. POST /v1/auth/sign-challenged-assertion
   signed with local key   ──────────→  verify signature + cert chain + nonce
                                        counter-sign with Mastio key
                            ←────────   { client_assertion, mastio_signature }
5. persist identity.pem, identity-key.pem, agent.json to ~/.cullis/identity/
```

Five properties the protocol enforces:

- **Private key never leaves the laptop.** The Connector generates it locally; the Mastio sees only the public key.
- **Admin approval is binding to this exact keypair.** The `cert_pem` signed at step 2 pins the public key; step 4 proves the Connector still holds the matching private key.
- **Nonce is single-use and agent-bound.** A leaked nonce can't be redeemed by a different `X-API-Key` holder.
- **Assertion lifetime is capped at 300s.** The Mastio refuses anything older.
- **Leaf cert is pinned to `internal_agents.cert_pem` at runtime.** A cert swap after enrollment is rejected.

## 1. Run `enroll`

```bash
cullis-connector enroll \
    --site-url https://mastio.acme.local \
    --requester-name "Alice Example" \
    --requester-email "alice@acme.example" \
    --reason "New laptop, replacing the old MBP"
```

Expected output:

```
[cullis-connector] Generated fresh P-256 keypair → ~/.cullis/identity/identity-key.pem
[cullis-connector] Posting public key to https://mastio.acme.local/v1/enrollments
[cullis-connector] ✓ Enrollment session: 01JXF2T4RKBQWM5VS6JJGA7SRV
[cullis-connector] Share this URL with your admin:

    https://mastio.acme.local/proxy/enrollments/01JXF2T4RKBQWM5VS6JJGA7SRV

[cullis-connector] Waiting for admin approval (poll every 3s, timeout 1h)...
```

The private key file is created with mode `600`. Verify: `ls -l ~/.cullis/identity/identity-key.pem`.

## 2. Admin approves

Your admin opens the URL above while logged in to the Mastio dashboard with their admin secret. They see the pending enrollment row:

```
Pending enrollment
    Session:        01JXF2T4RKBQWM5VS6JJGA7SRV
    Requester:      Alice Example <alice@acme.example>
    Reason:         New laptop, replacing the old MBP
    Public key:     -----BEGIN PUBLIC KEY-----
                    MFkwEwYHKoZIzj0CAQYIKoZIzj...
                    -----END PUBLIC KEY-----
    Fingerprint:    SHA-256:3f:4a:9b:...:2b:1e
```

Confirm the fingerprint with the developer out-of-band — Slack DM, video call, physical. The fingerprint is displayed in the Connector terminal too; they should match exactly.

The admin fills three fields:

- **agent_id**: `acme::alice` (format `<org>::<short-name>`)
- **capabilities**: comma-separated — `order.read, catalog.read, oneshot.message` is common for new developers
- **groups**: optional tag, e.g. `engineering`

Press **Approve**. The Mastio issues a leaf cert signed by the Org CA, pinning the public key the developer submitted.

## 3. Challenge-response handshake

As soon as the admin clicks approve, the Mastio flips the enrollment row to `approved` and writes a fresh nonce (32 random bytes, TTL 120s) into the challenge store. The Connector's poll picks this up:

```
[cullis-connector] ✓ Approved by admin@acme.example
[cullis-connector] Received challenge nonce, signing assertion...
[cullis-connector] POST /v1/auth/sign-challenged-assertion
[cullis-connector] ✓ Mastio counter-signature received
[cullis-connector] ✓ Identity persisted:
    ~/.cullis/identity/identity.pem
    ~/.cullis/identity/identity-key.pem
    ~/.cullis/identity/agent.json
```

What the Mastio verifies before signing:

1. The JWS signature on the client assertion matches the public key on the `cert_pem` it just issued.
2. The embedded `nonce` claim matches the single-use nonce it stored for this `agent_id`.
3. The `iat` and `exp` timestamps are within 300 seconds of now (clock-skew WARNING if off by >10s).
4. The leaf cert chains cleanly to the Org CA + Mastio intermediate.
5. The nonce hasn't been consumed before.

Any failure returns `401 invalid_assertion` with a diagnostic body. The Connector propagates the failure to the CLI.

## 4. Verify the identity

```bash
cullis-connector status
```

Expected:

```
Agent ID:       acme::alice
Org:            acme
Mastio URL:     https://mastio.acme.local
Cert valid:     2026-04-23T19:12:08Z → 2027-04-23T19:12:08Z
Capabilities:   order.read, catalog.read, oneshot.message
Last refresh:   10 seconds ago
```

Run one MCP tool call to confirm end-to-end:

```bash
cullis-connector tool-call list_agents
# [ { "agent_id": "acme::alice", ... },  ]
```

## Runtime behavior

After enrollment, the Connector serves MCP requests from your IDE. On every tool call that hits the Cullis network:

1. The Connector reads `identity-key.pem` from disk (never sent over the wire).
2. Builds a `client_assertion` JWT signed with that key.
3. Sends it through `/v1/auth/sign-challenged-assertion` — the Mastio re-validates nonce + cert chain + binding — and receives the counter-signed envelope.
4. The Connector forwards the envelope to the Court (or to the target Mastio for cross-org traffic).

The challenge-response happens on every token mint, not just enrollment. The nonce rotates per request, binding the `X-API-Key` to the key-in-hand proof every time.

## Troubleshoot

**`Enrollment timed out — no admin approval within 1 hour`**
: The session TTL expired. Re-run `cullis-connector enroll` from scratch; the local keypair is reused.

**`Mastio rejected sign-challenged-assertion: nonce already consumed`**
: Two Connectors tried to complete the same enrollment. Exactly one will succeed; the other re-runs `enroll` from scratch.

**`Mastio rejected: agent_id sub mismatch`**
: The admin typed an `agent_id` that doesn't match the one bound to this enrollment row. Admin re-approves with the correct id; the Connector's next poll picks up the new state.

**`Certificate verification failed`**
: The Mastio is on a self-signed cert (dev deploy) or the Connector's system trust store doesn't include your internal CA. For dev, use `--insecure-tls`. For prod, import your org's TLS root into the OS trust store.

**`Signed assertion outside clock skew`**
: The Connector's clock is off by more than 300 seconds. Fix with `sudo timedatectl set-ntp on` (Linux) or System Settings → Date & Time (macOS). The Mastio logs a WARNING pointing at NTP.

## Next

- [BYOCA enrollment](byoca) — for headless agents where the org already runs an internal PKI
- [SPIRE enrollment](spire) — when Kubernetes workloads already have SVIDs
- [Runbook § admin lockout](../operate/runbook#7-admin-lockout) — what to do if the admin who can approve just quit
- [Install the Connector](../install/connector) — the desktop client that drives this flow on an end user's laptop
