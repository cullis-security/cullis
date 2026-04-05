#!/usr/bin/env bash
# ============================================================================
# Enterprise Lab — Verification Script
#
# Checks that all components are running and reachable.
# Run this after bootstrap.sh to verify the setup.
# ============================================================================

set -euo pipefail

RESET="\033[0m"
BOLD="\033[1m"
GREEN="\033[32m"
RED="\033[31m"
YELLOW="\033[33m"
CYAN="\033[36m"

BROKER_HOST="${1:-localhost}"
BROKER_HTTPS="https://${BROKER_HOST}:8443"
BROKER_HTTP="http://${BROKER_HOST}:8000"
ERPNEXT_URL="http://localhost:8080"
ODOO_URL="http://localhost:8069"
OPA_VM2_URL="http://localhost:8181"  # VM2 OPA
OPA_VM3_URL="http://localhost:8182"  # VM3 OPA (different port if same host)
JAEGER_URL="http://localhost:16686"

PASS=0
FAIL=0

check() {
    local name="$1"
    local url="$2"
    local expect="${3:-200}"

    STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")
    if [ "$STATUS" = "$expect" ]; then
        echo -e "  ${GREEN}✓${RESET}  ${name} — ${url} (HTTP ${STATUS})"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}✗${RESET}  ${name} — ${url} (HTTP ${STATUS}, expected ${expect})"
        FAIL=$((FAIL + 1))
    fi
}

echo -e "\n${BOLD}${CYAN}Enterprise Lab — Verification${RESET}\n"

# VM1 — Broker
echo -e "${BOLD}VM1 — ATN Broker${RESET}"
check "Broker healthz"     "${BROKER_HTTP}/healthz"
check "Broker readyz"      "${BROKER_HTTP}/readyz"
check "Broker HTTPS"       "${BROKER_HTTPS}/healthz"
check "Jaeger UI"          "${JAEGER_URL}/"

echo ""

# VM2 — Enterprise A
echo -e "${BOLD}VM2 — Enterprise A (ERPNext + OPA)${RESET}"
check "ERPNext"            "${ERPNEXT_URL}/"                    "200"
check "OPA VM2"            "${OPA_VM2_URL}/v1/data/atn/session" "200"

echo ""

# VM3 — Enterprise B
echo -e "${BOLD}VM3 — Enterprise B (Odoo + OPA)${RESET}"
check "Odoo"               "${ODOO_URL}/web/login"              "200"
# OPA on VM3 — if running on same host, may use different port
check "OPA VM3"            "${OPA_VM3_URL}/v1/data/atn/session" "200"

echo ""

# ATN-specific checks
echo -e "${BOLD}ATN Configuration${RESET}"

# Check orgs exist
for ORG in electrostore chipfactory; do
    STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "${BROKER_HTTP}/v1/registry/orgs/${ORG}" 2>/dev/null || echo "000")
    if [ "$STATUS" = "200" ]; then
        echo -e "  ${GREEN}✓${RESET}  Org '${ORG}' registered"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}✗${RESET}  Org '${ORG}' not found (HTTP ${STATUS})"
        FAIL=$((FAIL + 1))
    fi
done

# Check JWKS endpoint
check "JWKS endpoint"      "${BROKER_HTTP}/.well-known/jwks.json"

echo ""

# Summary
echo -e "${BOLD}Results: ${GREEN}${PASS} passed${RESET}, ${RED}${FAIL} failed${RESET}"

if [ "$FAIL" -gt 0 ]; then
    echo -e "\n${YELLOW}Some checks failed. Ensure all services are running.${RESET}"
    exit 1
else
    echo -e "\n${GREEN}${BOLD}All checks passed. Lab is ready.${RESET}"
fi
