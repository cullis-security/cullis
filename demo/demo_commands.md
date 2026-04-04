# Demo — ERP-Triggered Agent Negotiation

Two organizations (ElectroStore and ChipFactory) negotiate purchase orders
through ATN. An inventory watcher detects low stock and triggers the buyer
agent automatically. The supplier agent is always listening.

## Prerequisites

- `nix-shell` (provides Python, openssl, deps)
- Docker + Docker Compose

## Setup

### 1. Start the full stack

```bash
nix-shell
docker compose down -v   # if restarting from scratch
./setup.sh
```

Wait for "Setup complete!". Stack:
- Dashboard: `https://0.0.0.0:8443/dashboard`
- Broker direct: `http://localhost:8000`
- Vault: `http://localhost:8200` (token: `dev-root-token`)

### 2. Generate org certificates

```bash
python demo/generate_org_certs.py --org chipfactory
python demo/generate_org_certs.py --org electrostore
```

### 3. Onboard orgs from the dashboard

Go to `https://0.0.0.0:8443/dashboard` → login as Network Admin.
- Password: `trustlink-admin-2026`

For each org (chipfactory, electrostore):
- Organizations → + Onboard Org
- Org ID: `chipfactory` / `electrostore`
- Display Name: `ChipFactory` / `ElectroStore`
- Secret: `chipfactory` / `electrostore`
- CA Certificate: paste contents of `certs/chipfactory/ca.pem` / `certs/electrostore/ca.pem`
- Click Register & Approve

```bash
# Quick way to copy CA cert to clipboard (Linux):
cat certs/chipfactory/ca.pem | xclip -selection clipboard
cat certs/electrostore/ca.pem | xclip -selection clipboard

# macOS:
cat certs/chipfactory/ca.pem | pbcopy
cat certs/electrostore/ca.pem | pbcopy
```

### 4. Generate agent certificates

```bash
python demo/generate_org_certs.py --agent chipfactory::supplier-agent --secret chipfactory
python demo/generate_org_certs.py --agent electrostore::buyer-agent --secret electrostore
```

### 5. Register agents from the dashboard

For each agent:
- Agents → Register Agent
- Select org, type agent name, capabilities: `order.read, order.write`

Agents:
- chipfactory → `supplier-agent`
- electrostore → `buyer-agent`

Note: certificate thumbprint pinning is automatic — the cert is pinned at first agent login.

### 6. Create session policies

```bash
python demo/create_policies.py
```

This creates bidirectional session policies: electrostore ↔ chipfactory.

## Run the demo

### Terminal 1 — Supplier (always listening)

```bash
python demo/supplier_agent.py --config certs/chipfactory/chipfactory__supplier-agent.env
```

Wait for "Listening for sessions..."

### Terminal 2 — Inventory watcher (ERP trigger)

```bash
python demo/inventory_watcher.py
```

The watcher detects low stock in `inventory.json` and launches buyer agents
automatically. Two items are below threshold (BLT-M8-ZN and BLT-M10-ZN),
so two negotiations happen in parallel.

## What happens

```
[inventory.json]     stock < threshold
       |
       v
[inventory_watcher]  detects low stock → launches buyer_agent.py
       |
       v
[buyer_agent]        auth (x509+DPoP) → discover → open session → RFQ (JSON)
       |
       v
[broker]             policy check → cert pinning → session active → relay E2E messages
       |
       v
[supplier_agent]     receives RFQ → LLM checks catalog → sends quote (JSON)
       |
       v
[buyer_agent]        evaluates quote → accepts → order confirmed → result saved
       |
       v
[result_*.json]      ready for ERP integration
```

## Tear down

```bash
docker compose down -v
```

## Reset and redo

```bash
docker compose down -v
rm -rf certs/chipfactory certs/electrostore
./setup.sh
# Then repeat from step 2
```

## Files

| File | What it does |
|------|-------------|
| `generate_org_certs.py` | Generate org CA or agent certificates |
| `create_policies.py` | Create session policies (who can talk to who) |
| `inventory.json` | Simulated ERP inventory (edit stock to trigger) |
| `inventory_watcher.py` | Monitors inventory, launches buyer when low |
| `buyer_agent.py` | On-demand: auth → negotiate → save result → exit |
| `supplier_agent.py` | Daemon: listen → accept → respond → wait for next |
| `result_*.json` | Negotiation results (created after successful orders) |
