# Bring Your Own CA — Integration Guide

How to connect your organization to the Agent Trust Network using your own
Certificate Authority. No ATN tools need to run in your infrastructure — you
only provide public artifacts (CA cert, webhook URL) to the broker.

---

## Prerequisites

- A running ATN broker (your partner or the network operator gives you the URL)
- An internal CA (HashiCorp Vault, AWS ACM Private CA, step-ca, openssl, ...)
- A PDP webhook endpoint your org controls (see `pdp-template/`)

## 1. Generate your Org CA (if you don't have one)

Any x509 CA works. Example with openssl:

```bash
# Generate CA private key
openssl genrsa -out org-ca-key.pem 4096

# Generate self-signed CA certificate (valid 10 years)
openssl req -new -x509 -key org-ca-key.pem -out org-ca.pem -days 3650 \
  -subj "/CN=MyOrg CA/O=my-org"
```

Keep `org-ca-key.pem` **private** — it never leaves your infrastructure.
Only `org-ca.pem` (the public certificate) goes to the ATN broker.

## 2. Register your organization

Call the broker's onboarding API or use the dashboard:

### Option A: API

```bash
curl -X POST https://broker.example.com/onboarding/join \
  -H "Content-Type: application/json" \
  -d '{
    "org_id": "my-org",
    "display_name": "My Organization",
    "secret": "a-strong-shared-secret",
    "ca_certificate": "'"$(cat org-ca.pem)"'",
    "contact_email": "security@my-org.com",
    "webhook_url": "https://pdp.my-org.internal/policy"
  }'
```

The broker admin will approve your join request.

### Option B: Dashboard

If you have dashboard access, the admin can onboard your org directly at
`/dashboard/orgs/onboard`.

## 3. Issue agent certificates

For each agent your org wants to deploy, issue a certificate signed by your
Org CA. The certificate **must** include:

- **CN** = `{org_id}::{agent_name}` (e.g. `my-org::procurement-agent`)
- **SAN URI** = `spiffe://{trust_domain}/{org_id}/{agent_name}`

Example with openssl:

```bash
ORG_ID="my-org"
AGENT_NAME="procurement-agent"
TRUST_DOMAIN="atn.local"  # ask the broker admin for this

# Generate agent key
openssl genrsa -out agent-key.pem 2048

# Create CSR with SAN
openssl req -new -key agent-key.pem -out agent.csr \
  -subj "/CN=${ORG_ID}::${AGENT_NAME}/O=${ORG_ID}" \
  -addext "subjectAltName=URI:spiffe://${TRUST_DOMAIN}/${ORG_ID}/${AGENT_NAME}"

# Sign with your Org CA
openssl x509 -req -in agent.csr -CA org-ca.pem -CAkey org-ca-key.pem \
  -CAcreateserial -out agent.pem -days 365 \
  -extfile <(echo "subjectAltName=URI:spiffe://${TRUST_DOMAIN}/${ORG_ID}/${AGENT_NAME}")
```

## 4. Register the agent in the broker

```bash
curl -X POST https://broker.example.com/registry/agents \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "my-org::procurement-agent",
    "org_id": "my-org",
    "display_name": "Procurement Agent",
    "capabilities": ["order.read", "order.write"]
  }'
```

## 5. Create and approve a binding

Bindings prove org membership. The org must create and approve:

```bash
# Create binding
curl -X POST https://broker.example.com/registry/bindings \
  -H "X-Org-Id: my-org" \
  -H "X-Org-Secret: a-strong-shared-secret" \
  -H "Content-Type: application/json" \
  -d '{
    "org_id": "my-org",
    "agent_id": "my-org::procurement-agent",
    "scope": ["order.read", "order.write"]
  }'

# Approve (use the binding ID from the response)
curl -X POST https://broker.example.com/registry/bindings/{id}/approve \
  -H "X-Org-Id: my-org" \
  -H "X-Org-Secret: a-strong-shared-secret"
```

## 6. Create a session policy

Session policies control who your org can communicate with. Default is **deny**.
You must create at least one session policy per target org:

```bash
curl -X POST https://broker.example.com/policy/rules \
  -H "X-Org-Id: my-org" \
  -H "X-Org-Secret: a-strong-shared-secret" \
  -H "Content-Type: application/json" \
  -d '{
    "policy_id": "my-org::session-partner-org-v1",
    "org_id": "my-org",
    "policy_type": "session",
    "rules": {
      "effect": "allow",
      "conditions": {
        "target_org_id": ["partner-org"],
        "capabilities": ["order.read", "order.write"]
      }
    }
  }'
```

## 7. Deploy your agent

See `docker-compose.agent.yml` for a ready-to-use template. Your agent needs:

| Variable | Value |
|----------|-------|
| `BROKER_URL` | The broker's public URL |
| `AGENT_ID` | `my-org::procurement-agent` |
| `ORG_ID` | `my-org` |
| `AGENT_CERT_PATH` | Path to agent.pem (mounted secret) |
| `AGENT_KEY_PATH` | Path to agent-key.pem (mounted secret) |
| `CAPABILITIES` | `order.read,order.write` |

The agent's private key should be injected via Kubernetes Secrets, Vault Agent,
or equivalent — **never baked into the container image**.

## 8. Set up your PDP webhook

The broker calls your webhook for every session request involving your org.
See `pdp-template/` for a working example with real authorization rules.

Your webhook receives:
```json
{
  "initiator_agent_id": "partner-org::their-agent",
  "initiator_org_id": "partner-org",
  "target_agent_id": "my-org::procurement-agent",
  "target_org_id": "my-org",
  "capabilities": ["order.read", "order.write"],
  "session_context": "target"
}
```

Return `{"decision": "allow"}` or `{"decision": "deny", "reason": "..."}`.

---

## Security checklist

- [ ] Org CA private key stored in HSM/KMS, never on disk
- [ ] Agent private keys injected at runtime, not in container images
- [ ] PDP webhook runs inside your network (not exposed to internet)
- [ ] PDP webhook validates the request comes from the known broker IP
- [ ] Org secret is rotated periodically
- [ ] Agent certificates have a reasonable expiry (e.g. 90 days)
- [ ] Monitor the ATN audit log for unexpected session attempts
