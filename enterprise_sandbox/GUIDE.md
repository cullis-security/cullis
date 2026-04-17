# Onboard Org A into the Cullis sandbox

You spun up the sandbox with `./demo.sh up`. Org B (Globex Inc) is
fully wired — you can inspect it already. Org A (Acme Corp) has its
Mastio running in **standalone** mode but is not yet registered on the
Court. Walk through the four steps below to complete the onboarding
end-to-end.

Every command is copy-paste-ready with the exact values used by this
sandbox — no placeholders. You'll see the same flow a real customer
follows when joining a federated Cullis network for the first time.

---

## Step 1 · Attach Mastio A to the Court

The Court is the shared broker. The Mastio is your org's gateway. The
handshake between them is the **attach-ca** flow — admin side creates
a single-use invite, proxy side redeems it with its CA and a secret
of its choice.

### 1a · Court admin creates the attach invite

```bash
curl -X POST http://localhost:8000/v1/admin/invites \
  -H "Content-Type: application/json" \
  -H "X-Admin-Secret: sandbox-admin-secret-change-me" \
  -d '{
    "label": "acme-corp attach",
    "ttl_hours": 1,
    "invite_type": "attach-ca",
    "linked_org_id": "orga"
  }'
```

Output:

```json
{ "token": "inv_xxxxxxxxxxxx...", ... }
```

Copy the `token` — you'll paste it into the Mastio dashboard next.

### 1b · Mastio A admin redeems it

Open the Mastio A dashboard: <http://localhost:9100/proxy/link-broker>
Log in with admin secret `sandbox-proxy-admin-a`.

Fill the form:

- Broker URL: `http://broker:8000` (the Court, reachable from the
  Mastio container)
- Invite token: the value from Step 1a

Press **Link broker**. The dashboard will reload; Mastio A is now
federated.

Verify from the terminal:

```bash
curl -s http://localhost:8000/v1/registry/orgs \
  -H "X-Admin-Secret: sandbox-admin-secret-change-me" | jq '.[] | {org_id, status}'
```

You should see both `orga` and `orgb` with `"status": "active"`.

---

## Step 2 · Pin the Mastio counter-signature public key

ADR-009 requires every `/v1/auth/token` call to carry a
`X-Cullis-Mastio-Signature` header. The Court pins the mastio's EC
P-256 public key at onboarding; any subsequent login for that org
must be counter-signed by the matching private key. This closes the
"agent bypasses the proxy" gap.

### 2a · Fetch the key from Mastio A

```bash
curl -s http://localhost:9100/v1/admin/mastio-pubkey \
  -H "X-Admin-Secret: sandbox-proxy-admin-a"
```

Output:

```json
{ "mastio_pubkey": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n", "org_id": "orga" }
```

### 2b · Pin it on the Court

```bash
MASTIO_PUBKEY=$(curl -s http://localhost:9100/v1/admin/mastio-pubkey \
  -H "X-Admin-Secret: sandbox-proxy-admin-a" | jq -r .mastio_pubkey)

curl -X PATCH http://localhost:8000/v1/admin/orgs/orga/mastio-pubkey \
  -H "Content-Type: application/json" \
  -H "X-Admin-Secret: sandbox-admin-secret-change-me" \
  -d "$(jq -n --arg k "$MASTIO_PUBKEY" '{mastio_pubkey: $k}')"
```

Expected: `{"org_id":"orga","mastio_pubkey_set":true}`

From this moment on the Court will refuse to emit a token for `orga`
without a valid counter-signature.

---

## Step 3 · Install the Connector Desktop and enroll Alice

The Connector Desktop is the end-user app. A developer on their
laptop runs it to enroll an agent, then their Python code uses
`CullisClient.from_connector()` to talk to the network.

### 3a · Download and run

Open <http://localhost:9100/downloads> from your host browser.
Download the zip for your OS, unpack, run.

The Connector opens a local dashboard on **<http://127.0.0.1:7777>**.

### 3b · Enrollment session — user side

On the Connector dashboard, paste:

- **Mastio URL**: `http://localhost:9100`
- **Requester name**: `alice`
- **Reason**: `demo onboarding`

Press **Start enrollment**. The Connector generates a fresh EC P-256
keypair locally, POSTs the public key to the Mastio, and shows a
"waiting for admin approval" screen.

### 3c · Admin approves

Open the Mastio A admin dashboard:
<http://localhost:9100/proxy/enrollments>.
Log in with `sandbox-proxy-admin-a`. You'll see Alice's pending row.

Click **Approve**, fill:

- `agent_id`: `orga::alice`
- `capabilities`: `oneshot.message, order.read`
- `groups`: `demo`

Press **Approve**. Within 5s the Connector dashboard flips to
"Connected" and writes the identity under `~/.cullis/identity/`.

---

## Step 4 · Register an MCP server + bind Alice

Alice needs a capability to call — an MCP server. Use the Connector's
admin mode (no separate dashboard login required).

### 4a · Unlock admin mode in the Connector

On the Connector dashboard, open the **MCP Resources** link in the
sidebar. Paste the Mastio admin secret (`sandbox-proxy-admin-a`).

### 4b · Register a resource

Fill the form:

- Name: `acme-catalog`
- Endpoint: `http://mcp-catalog:9300/`
- Description: `Acme Corp catalog`
- Required capability: `order.read`

Press **Register**. The Connector calls
`POST /v1/admin/mcp-resources` on the Mastio.

### 4c · Bind Alice to the resource

From the resource list, click **Bind me** on the `acme-catalog` row.
That issues `POST /v1/admin/mcp-resources/bindings` with Alice's
`agent_id` + the new `resource_id`.

---

## Step 5 · Test end-to-end

From your host (with the Connector still running and Alice enrolled),
run the host-agent example:

```bash
CULLIS_TARGET_AGENT=orgb::agent-b python cullis_sdk/examples/host_agent.py
```

Expected output: `✓ one-shot sent to orgb::agent-b`.

Then inspect Bob's inbox:

```bash
./demo.sh logs agent-b | tail -20 | grep received
```

You'll see Bob's agent printing the nonce Alice just sent.

---

## What happens if you run `demo.sh full` instead?

Same endpoint, same certs, same counter-signature. All four steps
above are done for you at bootstrap time, so you skip straight to
scenarios:

```bash
./demo.sh oneshot-a-to-b
./demo.sh oneshot-b-to-a
```

Use `up` when you want to *learn* the onboarding flow; use `full`
when you want to *replay* scenarios without any setup.
