#!/usr/bin/env bash
# ============================================================================
# Enterprise Lab — Full Bootstrap
#
# Brings up all 3 "VMs" (Docker Compose stacks), seeds ERP/CRM data,
# generates PKI certificates, onboards orgs, and registers agents.
#
# Prerequisites:
#   - Docker + Docker Compose
#   - Python 3.11+ with httpx, cryptography
#   - Network access between stacks (default: localhost with different ports)
#
# Usage:
#   ./bootstrap.sh                    # local single-machine (all on localhost)
#   ./bootstrap.sh --broker-host IP   # multi-VM (broker on specific IP)
# ============================================================================

set -euo pipefail

RESET="\033[0m"
BOLD="\033[1m"
GREEN="\033[32m"
CYAN="\033[36m"
YELLOW="\033[33m"
RED="\033[31m"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

BROKER_HOST="${1:-localhost}"
BROKER_URL="https://${BROKER_HOST}:8443"
BROKER_HTTP="http://${BROKER_HOST}:8000"
ERPNEXT_URL="http://localhost:8080"
ODOO_URL="http://localhost:8069"

ATN_ADMIN_SECRET="${ATN_ADMIN_SECRET:-trustlink-admin-2026}"

header() { echo -e "\n${BOLD}${CYAN}═══ $1 ═══${RESET}\n"; }
ok()     { echo -e "  ${GREEN}✓${RESET}  $1"; }
warn()   { echo -e "  ${YELLOW}!${RESET}  $1"; }
fail()   { echo -e "  ${RED}✗${RESET}  $1"; }

# ============================================================================
header "Step 1: Start VM1 — ATN Broker"
# ============================================================================

cd "$SCRIPT_DIR/vm1-broker"

# Generate broker PKI if needed
if [ ! -f "$PROJECT_ROOT/certs/broker/broker.pem" ]; then
    echo "  Generating broker PKI..."
    cd "$PROJECT_ROOT"
    python generate_certs.py 2>/dev/null || true
    cd "$SCRIPT_DIR/vm1-broker"
fi

# Generate TLS cert for nginx if needed
if [ ! -f "$PROJECT_ROOT/certs/broker/tls.crt" ]; then
    echo "  Generating TLS certificate..."
    mkdir -p "$PROJECT_ROOT/certs/broker"
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$PROJECT_ROOT/certs/broker/tls.key" \
        -out "$PROJECT_ROOT/certs/broker/tls.crt" \
        -days 365 -subj "/CN=${BROKER_HOST}" 2>/dev/null
    ok "TLS certificate generated"
fi

export ATN_ADMIN_SECRET BROKER_HOST
docker compose up -d
ok "VM1 broker stack started"

# Wait for broker health
echo -e "  Waiting for broker..."
for i in $(seq 1 30); do
    if curl -sk "${BROKER_URL}/healthz" >/dev/null 2>&1; then
        ok "Broker healthy at ${BROKER_URL}"
        break
    fi
    sleep 2
done

# ============================================================================
header "Step 2: Start VM2 — Enterprise A (ERPNext + OPA)"
# ============================================================================

cd "$SCRIPT_DIR/vm2-buyer"
docker compose up -d
ok "VM2 stack started (ERPNext + OPA)"
warn "ERPNext takes 2-3 minutes for first startup..."

# ============================================================================
header "Step 3: Start VM3 — Enterprise B (Odoo + OPA)"
# ============================================================================

cd "$SCRIPT_DIR/vm3-supplier"
mkdir -p addons  # empty addons dir for Odoo
docker compose up -d
ok "VM3 stack started (Odoo + OPA)"

# ============================================================================
header "Step 4: Generate org & agent certificates"
# ============================================================================

cd "$PROJECT_ROOT"
python demo/generate_org_certs.py --org electrostore --broker "$BROKER_URL"
python demo/generate_org_certs.py --org chipfactory --broker "$BROKER_URL"

python demo/generate_org_certs.py \
    --agent electrostore::buyer-agent \
    --secret electrostore \
    --broker "$BROKER_URL"

python demo/generate_org_certs.py \
    --agent chipfactory::supplier-agent \
    --secret chipfactory \
    --broker "$BROKER_URL"

ok "Certificates generated"

# ============================================================================
header "Step 5: Onboard organizations in ATN"
# ============================================================================

ES_CA=$(cat certs/electrostore/ca.pem)
CF_CA=$(cat certs/chipfactory/ca.pem)

# Register orgs via API
for ORG_ID in electrostore chipfactory; do
    SECRET="$ORG_ID"
    DISPLAY=$(echo "$ORG_ID" | sed 's/electrostore/ElectroStore S.r.l./;s/chipfactory/ChipFactory S.p.A./')

    curl -sk -X POST "${BROKER_HTTP}/v1/registry/orgs" \
        -H "Content-Type: application/json" \
        -H "x-admin-secret: ${ATN_ADMIN_SECRET}" \
        -d "{\"org_id\":\"${ORG_ID}\",\"display_name\":\"${DISPLAY}\",\"secret\":\"${SECRET}\"}" \
        >/dev/null 2>&1 && ok "Registered org: ${ORG_ID}" || warn "Org ${ORG_ID} may already exist"
done

# Upload CA certificates
curl -sk -X POST "${BROKER_HTTP}/v1/registry/orgs/electrostore/certificate" \
    -H "Content-Type: application/json" \
    -H "x-org-id: electrostore" -H "x-org-secret: electrostore" \
    -d "{\"ca_certificate\":$(echo "$ES_CA" | python -c 'import sys,json; print(json.dumps(sys.stdin.read()))')}" \
    >/dev/null 2>&1 && ok "CA uploaded: electrostore" || warn "CA electrostore may exist"

curl -sk -X POST "${BROKER_HTTP}/v1/registry/orgs/chipfactory/certificate" \
    -H "Content-Type: application/json" \
    -H "x-org-id: chipfactory" -H "x-org-secret: chipfactory" \
    -d "{\"ca_certificate\":$(echo "$CF_CA" | python -c 'import sys,json; print(json.dumps(sys.stdin.read()))')}" \
    >/dev/null 2>&1 && ok "CA uploaded: chipfactory" || warn "CA chipfactory may exist"

# ============================================================================
header "Step 6: Register agents & approve bindings"
# ============================================================================

for AGENT in "electrostore::buyer-agent electrostore" "chipfactory::supplier-agent chipfactory"; do
    set -- $AGENT
    AGENT_ID="$1"
    ORG="$2"

    curl -sk -X POST "${BROKER_HTTP}/v1/registry/agents" \
        -H "Content-Type: application/json" \
        -H "x-org-id: ${ORG}" -H "x-org-secret: ${ORG}" \
        -d "{\"agent_id\":\"${AGENT_ID}\",\"org_id\":\"${ORG}\",\"display_name\":\"${AGENT_ID}\",\"capabilities\":[\"order.read\",\"order.write\"]}" \
        >/dev/null 2>&1

    # Create and approve binding
    BINDING_ID=$(curl -sk -X POST "${BROKER_HTTP}/v1/registry/bindings" \
        -H "Content-Type: application/json" \
        -H "x-org-id: ${ORG}" -H "x-org-secret: ${ORG}" \
        -d "{\"org_id\":\"${ORG}\",\"agent_id\":\"${AGENT_ID}\",\"scope\":[\"order.read\",\"order.write\"]}" \
        2>/dev/null | python -c 'import sys,json; print(json.loads(sys.stdin.read()).get("id",""))' 2>/dev/null || echo "")

    if [ -n "$BINDING_ID" ] && [ "$BINDING_ID" != "" ]; then
        curl -sk -X POST "${BROKER_HTTP}/v1/registry/bindings/${BINDING_ID}/approve" \
            -H "x-org-id: ${ORG}" -H "x-org-secret: ${ORG}" \
            >/dev/null 2>&1
        ok "Agent registered & bound: ${AGENT_ID}"
    else
        warn "Agent ${AGENT_ID} may already exist"
    fi
done

# ============================================================================
header "Step 7: Create session policies"
# ============================================================================

cd "$PROJECT_ROOT"
python demo/create_policies.py || warn "Policies may already exist"

# ============================================================================
header "Step 8: Configure OPA webhook URLs"
# ============================================================================

# Set OPA URLs for each org (broker calls these for policy decisions)
# VM2 OPA (electrostore): localhost:8181 from broker's perspective
# VM3 OPA (chipfactory): localhost:8181 from broker's perspective
# In multi-VM: replace with actual IPs

warn "OPA webhook URLs must be configured manually for multi-VM setups."
warn "For single-machine: OPA runs on the same host, webhook URLs use host.docker.internal."

# ============================================================================
header "Step 9: Seed ERP & CRM data"
# ============================================================================

warn "ERPNext and Odoo need manual first-time setup (create site/database)."
echo ""
echo -e "  ${BOLD}ERPNext (VM2):${RESET}"
echo "    docker compose -f vm2-buyer/docker-compose.yml exec erpnext bench new-site erp.localhost --mariadb-root-password changeit --admin-password admin"
echo "    docker compose -f vm2-buyer/docker-compose.yml exec erpnext bench --site erp.localhost install-app erpnext"
echo "    python vm2-buyer/seed_erpnext.py --wait"
echo ""
echo -e "  ${BOLD}Odoo (VM3):${RESET}"
echo "    Open http://localhost:8069, create database 'odoo' with admin password 'admin'"
echo "    Install 'Sales' and 'Inventory' modules from the Apps menu"
echo "    python vm3-supplier/seed_odoo.py --wait"

# ============================================================================
header "Setup Complete"
# ============================================================================

echo -e "  ${BOLD}Services:${RESET}"
echo -e "    ATN Dashboard:  ${CYAN}${BROKER_URL}/dashboard${RESET}"
echo -e "    ATN Broker:     ${CYAN}${BROKER_HTTP}${RESET}"
echo -e "    ERPNext:        ${CYAN}${ERPNEXT_URL}${RESET}"
echo -e "    Odoo:           ${CYAN}${ODOO_URL}${RESET}"
echo -e "    Jaeger:         ${CYAN}http://localhost:16686${RESET}"
echo ""
echo -e "  ${BOLD}Run the agents:${RESET}"
echo -e "    ${CYAN}# Terminal 1 — Supplier (always listening)${RESET}"
echo "    python enterprise-lab/vm3-supplier/supplier_agent.py --config certs/chipfactory/chipfactory__supplier-agent.env"
echo ""
echo -e "    ${CYAN}# Terminal 2 — Buyer (checks ERPNext, negotiates)${RESET}"
echo "    python enterprise-lab/vm2-buyer/buyer_agent.py --config certs/electrostore/electrostore__buyer-agent.env"
echo ""
