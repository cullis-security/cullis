#!/usr/bin/env bash
# Agent Trust Network — One-click setup
# Generates PKI, TLS cert, starts all containers, runs bootstrap.
#
# Usage:
#   ./setup.sh            # first run or full reset
#   ./setup.sh --no-build # skip docker build (containers already built)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

GREEN='\033[32m'; BOLD='\033[1m'; RESET='\033[0m'; RED='\033[31m'; GRAY='\033[90m'

# Use venv Python if available, otherwise fall back to python3/python
if [ -f "$SCRIPT_DIR/.venv/bin/python" ]; then
    PYTHON="$SCRIPT_DIR/.venv/bin/python"
elif command -v python3 &>/dev/null; then
    PYTHON="python3"
elif command -v python &>/dev/null; then
    PYTHON="python"
else
    fail "Python not found — activate your venv or nix-shell first"
fi
log()  { echo -e "${BOLD}[setup]${RESET} $1"; }
ok()   { echo -e "  ${GREEN}✓${RESET}  $1"; }
fail() { echo -e "  ${RED}✗${RESET}  $1"; exit 1; }

NO_BUILD=0
for arg in "$@"; do
  [[ "$arg" == "--no-build" ]] && NO_BUILD=1
done

# ── 1. PKI ───────────────────────────────────────────────────────────────────
log "Generating broker PKI..."
$PYTHON generate_certs.py

# ── 2. TLS cert for nginx ────────────────────────────────────────────────────
log "Generating TLS certificate for nginx..."
bash nginx/generate_tls_cert.sh

# ── 3. Containers ─────────────────────────────────────────────────────────────
if [ "$NO_BUILD" -eq 0 ]; then
    log "Building and starting containers..."
    docker compose up -d --build
else
    log "Starting containers (no build)..."
    docker compose up -d
fi

# ── 4. Wait for Vault and load broker key ─────────────────────────────────────
VAULT_ADDR="${VAULT_ADDR:-http://localhost:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-dev-root-token}"
VAULT_SECRET_PATH="${VAULT_SECRET_PATH:-secret/data/broker}"

log "Waiting for Vault to be ready..."
ATTEMPTS=0
until curl -sf "${VAULT_ADDR}/v1/sys/health" > /dev/null 2>&1; do
    ATTEMPTS=$((ATTEMPTS + 1))
    if [ "$ATTEMPTS" -ge 20 ]; then
        fail "Vault did not start after 40s — check logs: docker compose logs vault"
    fi
    sleep 2
done
ok "Vault is ready (${VAULT_ADDR})"

log "Loading broker CA key into Vault..."
BROKER_KEY_PEM=$(cat certs/broker-ca-key.pem | awk '{printf "%s\\n", $0}')
BROKER_CERT_PEM=$(cat certs/broker-ca.pem | awk '{printf "%s\\n", $0}')
VAULT_PAYLOAD=$(printf '{"data":{"private_key_pem":"%s","ca_cert_pem":"%s"}}' \
    "$BROKER_KEY_PEM" "$BROKER_CERT_PEM")

HTTP_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" \
    -X POST "${VAULT_ADDR}/v1/${VAULT_SECRET_PATH}" \
    -H "X-Vault-Token: ${VAULT_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "$VAULT_PAYLOAD" 2>&1)

if [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "204" ]; then
    ok "Broker CA key stored in Vault at ${VAULT_SECRET_PATH}"
else
    fail "Failed to store broker key in Vault (HTTP ${HTTP_STATUS})"
fi

# ── 5. Wait for broker ────────────────────────────────────────────────────────
log "Waiting for broker to be ready..."
ATTEMPTS=0
until curl -sf http://localhost:8000/health > /dev/null 2>&1; do
    ATTEMPTS=$((ATTEMPTS + 1))
    if [ "$ATTEMPTS" -ge 30 ]; then
        fail "Broker did not start after 60s — check logs: docker compose logs broker"
    fi
    sleep 2
done
ok "Broker is ready"

# ── 6. Wait for nginx ────────────────────────────────────────────────────────
log "Waiting for nginx (HTTPS)..."
ATTEMPTS=0
until curl -sfk https://localhost:8443/health > /dev/null 2>&1; do
    ATTEMPTS=$((ATTEMPTS + 1))
    if [ "$ATTEMPTS" -ge 15 ]; then
        fail "Nginx did not start — check logs: docker compose logs nginx"
    fi
    sleep 2
done
ok "HTTPS ready (https://localhost:8443)"

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}Setup complete!${RESET}"
echo ""
echo -e "  Dashboard ${GRAY}https://localhost:8443/dashboard${RESET}"
echo -e "  Broker    ${GRAY}https://localhost:8443  (also http://localhost:8000 direct)${RESET}"
echo -e "  Vault     ${GRAY}http://localhost:8200  (token: ${VAULT_TOKEN})${RESET}"
echo -e "  Postgres  ${GRAY}localhost:5432  (user: atn / pass: atn / db: agent_trust)${RESET}"
echo -e "  Redis     ${GRAY}localhost:6379${RESET}"
echo -e "  Mock PDP  ${GRAY}localhost:9000 (manufacturer), localhost:9001 (buyer)${RESET}"
echo ""
echo "  Next: generate org certs and onboard via dashboard"
echo "    python demo/generate_org_certs.py --org chipfactory"
echo "    python demo/generate_org_certs.py --org electrostore"
echo ""
echo "  Tear down:"
echo "    docker compose down -v"
echo ""
