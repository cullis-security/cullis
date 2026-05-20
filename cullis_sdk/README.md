# `cullis-sdk`

**Python SDK for the Cullis federated agent-trust network.**

The Cullis SDK is the library you import from your Python agent code to
talk to a Cullis broker. It handles enrollment, mutual TLS / DPoP-bound
authentication, agent discovery, session management, and end-to-end
encrypted messaging — so your agent code stays focused on what it does,
not on the wire format.

The SDK is one of three Python distributions in the Cullis monorepo:

| Distribution      | Purpose                                                          |
|-------------------|------------------------------------------------------------------|
| `cullis-sdk`      | Library you `import cullis_sdk` from your agent code (this one). |
| `cullis-connector`| End-user MCP server bridging Claude Code / Cursor / etc.         |
| `mcp-proxy`       | Org-level gateway (deployed as a container, not pip-installed).  |

---

## Install

```bash
pip install cullis-sdk
```

Python 3.10+ required.

For [SPIFFE](https://spiffe.io/) workload-API integration (enroll an
agent using its SPIRE-issued SVID), install the optional extra:

```bash
pip install 'cullis-sdk[spiffe]'
```

---

## Quick start

The SDK talks to your org's Mastio (the local proxy), not directly to
a central broker. The Mastio handles enrollment, mTLS, DPoP and
forwards encrypted payloads on your behalf.

Two entry points, depending on how your agent gets its identity:

### Desktop / Connector flow

When the agent lives next to a Cullis Connector (Claude Desktop,
Cursor, Cline, or any local MCP client), the Connector has already
enrolled an identity under `~/.cullis/identity/`. The SDK reads it:

```python
from cullis_sdk import CullisClient

client = CullisClient.from_connector()       # loads ~/.cullis/identity/
client.login_via_proxy_with_local_key()      # mint a proxy-scoped token

resp = client.send_oneshot(
    recipient_id="acme::supplier-agent",
    payload={"text": "Quote for 1000 M8 bolts please."},
    ttl_seconds=300,
)
print(resp["msg_id"])
```

### Server / BYOCA flow

When the agent runs server-side and the cert+key are provisioned by
your own PKI (Bring-Your-Own-CA), build the client from the identity
directory directly. The mTLS client cert *is* the credential, so no
separate login step is needed:

```python
from cullis_sdk import CullisClient

client = CullisClient.from_identity_dir(
    "https://mastio.example.com:9443",
    cert_path="/etc/cullis/agent/cert.pem",
    key_path="/etc/cullis/agent/key.pem",
    dpop_key_path="/etc/cullis/agent/dpop.jwk",
)

resp = client.send_oneshot(
    recipient_id="acme::supplier-agent",
    payload={"text": "Quote for 1000 M8 bolts please."},
    ttl_seconds=300,
)
print(resp["msg_id"])
```

The SDK does the heavy lifting: mTLS to your Mastio with the agent
cert, DPoP-bound bearer tokens for replay protection, AES-256-GCM +
RSA-OAEP/ECDH key wrap for end-to-end encryption to the recipient
agent (the broker never sees the cleartext), and (on receive)
hash-chain verification of the per-org audit log.

### Migrating from v0.3 sessions

The v0.3 `login()` / `open_session()` / `send()` surface is
deprecated and will be removed in `cullis-sdk` v0.5 (~2026-08-15).
Map the legacy API to the canonical one-shot surface:

| v0.3 (deprecated, `DeprecationWarning` at call time) | Canonical (use this) |
|---|---|
| `CullisClient(url)` + `client.login(agent_id, org_id, cert, key)` | `CullisClient.from_identity_dir(url, cert_path=, key_path=, dpop_key_path=)` |
| `client.open_session(target_agent, target_org, caps)` + `client.send(session_id, ...)` | `client.send_oneshot(recipient_id="org::agent", payload=, ttl_seconds=)` (no session needed) |
| `client.discover(capabilities=[...])` | Same. Discovery still lives on the canonical surface. |

The one-shot surface (ADR-008) is sessionless: every message is its
own correlation-ID-tagged transaction, intra-org uses signed
plaintext over mTLS, cross-org uses end-to-end encrypted envelope.

---

## Architecture

```
       ┌──────────┐  mTLS + DPoP   ┌──────────┐  mTLS + DPoP  ┌──────────┐
       │ Agent A  │───────────────▶│  Broker  │◀──────────────│ Agent B  │
       │ (cullis- │                │ (Cullis  │               │ (cullis- │
       │   sdk)   │                │  Site)   │               │   sdk)   │
       └──────────┘                └──────────┘               └──────────┘
            │                                                       ▲
            └─── E2E-encrypted payload (ECDH, broker can't read) ───┘
```

The broker authenticates both endpoints, routes messages, and
appends a tamper-evident hash-chain entry per send. It never sees
the cleartext payload.

---

## Documentation

- Repository: https://github.com/cullis-security/cullis
- Site: https://cullis.io
- Issues: https://github.com/cullis-security/cullis/issues
- Quickstart: https://cullis.io/docs/quickstart/getting-started/

---

## License

Functional Source License 1.1 with Apache-2.0 future grant
([`LICENSE`](https://github.com/cullis-security/cullis/blob/main/LICENSE)).
You can use, modify, and self-host the SDK for any non-competing
purpose; competing-use restriction lifts after two years to Apache 2.0.
