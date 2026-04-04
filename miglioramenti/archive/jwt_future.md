# JWT — Future Improvements

Features deliberately excluded from the current implementation.
Implement when the system grows beyond single-broker, single-process deployment.

---

## 1. Token Versioning (`ver`)

**When:** before the first breaking change to the token payload structure.

**What to change:**
- `create_access_token` → add `"ver": 1` to payload
- `TokenPayload` → add `ver: int = 1`
- `decode_token` → after decoding, `if raw.get("ver") != CURRENT_VERSION: raise 401`

**Benefit:** allows rolling migrations — old tokens keep working until expiry,
new tokens carry the new structure. No flag day required.

---

## 2. Key Rotation (JWKS)

**When:** external parties (microservices, MCP proxy, partner orgs) need to verify
broker tokens without calling the broker on every request.

**What to change:**

1. `Settings` → `broker_keys: list[BrokerKey]` where `BrokerKey` has `kid`, `private_pem`, `public_pem`, `active: bool`
2. `create_access_token` → picks the active key, adds `kid` to JWT header
3. `decode_token` → reads `kid` from unverified header, loads matching public key, verifies
4. New endpoint `GET /.well-known/jwks.json` → returns active public keys in JWKS format (RFC 7517)

**Rotation procedure:**
- Generate new key → add to key set as active
- Old key stays in set (verify-only) until all tokens signed with it expire
- Remove old key after max token TTL has passed

**Benefit:** zero-downtime key rotation, standard OAuth/OIDC interoperability.

---

## 3. Token Binding

**When:** high-security deployments where stolen tokens are a primary threat.

### Option A — Session binding (simplest, fits current architecture)
- Add `"session_id"` to tokens issued for session-scoped operations
- Verify in broker that the token's `session_id` matches the endpoint's session
- Low complexity, no protocol changes

### Option B — DPoP (RFC 9449, strongest)
- Agent generates ephemeral key pair per session
- Every request includes a `DPoP` proof header signed with the ephemeral key
- Broker verifies proof → token is useless without the ephemeral private key
- Requires changes to the client SDK and all endpoints
- Full standard compliance with WIMSE draft

**Benefit:** stolen access token cannot be replayed from a different client.

---

## Notes

- Key rotation is the highest-priority item once external verifiers exist
- Token versioning is a 30-minute task whenever the payload changes
- Token binding (DPoP) only makes sense after MCP proxy / microservices are in place
