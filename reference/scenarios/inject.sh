#!/usr/bin/env bash
# Cullis Reference — inject fresh traffic into a running stack
#
# One-line entry point for live demos. Sends a mix of intra-org and
# cross-org messages across the six agents to keep the Grafana
# dashboard alive while the audience watches.
#
# Usage:
#   bash reference/scenarios/inject.sh                 # one mixed burst
#   bash reference/scenarios/inject.sh -n 5            # five mixed bursts
#   bash reference/scenarios/inject.sh --loop          # forever, ~every 8s (Ctrl-C to stop)
#   bash reference/scenarios/inject.sh --cross-org     # only cross-org messages
#
# Requires the reference stack to be already up
# (`bash reference/scenarios/widget-hunt.sh`).

set -euo pipefail
cd "$(dirname "$0")/.."

COUNT=1
LOOP=0
ONLY_CROSS=0

while [ $# -gt 0 ]; do
    case "$1" in
        -n)            COUNT="$2"; shift 2 ;;
        --loop)        LOOP=1; shift ;;
        -c|--cross-org) ONLY_CROSS=1; shift ;;
        -h|--help)
            sed -n '2,15p' "$0" | sed 's/^# *//'
            exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

GREEN='\033[32m'
CYAN='\033[36m'
GRAY='\033[90m'
RESET='\033[0m'

# Each helper builds a CullisClient inside an agent container using
# ADR-014 mTLS identity material (agent.pem + agent-key.pem + dpop.jwk
# under /state/<org>/agents/<name>/). Mirrors reference/agent/agent.py
# ``_auth_identity_dir``. The /scenarios dir is NOT mounted into the
# agent containers so the credential-load block is inlined per helper
# instead of importing the shared _identity helper.

_inject_intra_orga() {
    local sku="$1"
    docker compose --profile full exec -T alice-byoca python - <<PY 2>&1 | grep -v "^\[sdk\]" | tail -1
import pathlib
from cullis_sdk import CullisClient
ID = pathlib.Path("/state/orga/agents/alice-byoca")
c = CullisClient.from_identity_dir("https://mastio-nginx-a:9443",
    cert_path=ID/"agent.pem", key_path=ID/"agent-key.pem",
    dpop_key_path=ID/"dpop.jwk",
    agent_id="orga::alice-byoca", org_id="orga", verify_tls=False)
c.login_via_proxy()
c._signing_key_pem = (ID/"agent-key.pem").read_text()
r = c.send_oneshot("orga::alice-spiffe",
    {"content": "do you have ${sku}?", "from": "orga::alice-byoca", "hops": 1})
print("intra-orga ${sku}: msg_id=" + r.get("msg_id", "?")[:12])
PY
}

_inject_intra_orgb() {
    local sku="$1"
    docker compose --profile full exec -T bob-byoca python - <<PY 2>&1 | grep -v "^\[sdk\]" | tail -1
import pathlib
from cullis_sdk import CullisClient
ID = pathlib.Path("/state/orgb/agents/bob-byoca")
c = CullisClient.from_identity_dir("https://mastio-nginx-b:9443",
    cert_path=ID/"agent.pem", key_path=ID/"agent-key.pem",
    dpop_key_path=ID/"dpop.jwk",
    agent_id="orgb::bob-byoca", org_id="orgb", verify_tls=False)
c.login_via_proxy()
c._signing_key_pem = (ID/"agent-key.pem").read_text()
r = c.send_oneshot("orgb::bob-spiffe",
    {"content": "do you have ${sku}?", "from": "orgb::bob-byoca", "hops": 1})
print("intra-orgb ${sku}: msg_id=" + r.get("msg_id", "?")[:12])
PY
}

_inject_cross_org() {
    local sku="$1"
    docker compose --profile full exec -T alice-connector python - <<PY 2>&1 | grep -v "^\[sdk\]" | tail -1
import pathlib
from cullis_sdk import CullisClient
ID = pathlib.Path("/state/orga/agents/alice-connector")
c = CullisClient.from_identity_dir("https://mastio-nginx-a:9443",
    cert_path=ID/"agent.pem", key_path=ID/"agent-key.pem",
    dpop_key_path=ID/"dpop.jwk",
    agent_id="orga::alice-connector", org_id="orga", verify_tls=False)
c.login_via_proxy()
c._signing_key_pem = (ID/"agent-key.pem").read_text()
r = c.send_oneshot("orgb::bob-connector",
    {"content": "request from orga: source 50 ${sku} cross-org",
     "from": "orga::alice-connector", "hops": 1})
print("cross-org ${sku}: msg_id=" + r.get("msg_id", "?")[:12])
PY
}

_one_burst() {
    local skus=("widget-X" "gear-Y" "bolt-Z")
    local sku=${skus[$((RANDOM % 3))]}
    if [ "$ONLY_CROSS" = "1" ]; then
        echo -e "  ${CYAN}→${RESET} $(_inject_cross_org "$sku")"
    else
        # mix: 60% intra-orga, 25% intra-orgb, 15% cross-org
        local r=$((RANDOM % 100))
        if [ $r -lt 60 ]; then
            echo -e "  ${GREEN}→${RESET} $(_inject_intra_orga "$sku")"
        elif [ $r -lt 85 ]; then
            echo -e "  ${GREEN}→${RESET} $(_inject_intra_orgb "$sku")"
        else
            echo -e "  ${CYAN}→${RESET} $(_inject_cross_org "$sku")"
        fi
    fi
}

if [ "$LOOP" = "1" ]; then
    echo -e "${GRAY}Looping (Ctrl-C to stop)…${RESET}"
    while true; do
        _one_burst
        sleep 8
    done
else
    for i in $(seq 1 "$COUNT"); do
        _one_burst
    done
fi
