#!/usr/bin/env bash
# ADR-029 Phase F, policy-granular end-to-end demo.
#
# Exercises the tool-level PDP gate (Phase C) + cross-org federation
# (Phase D-2) against the running sandbox. Configures tool_rules on
# both Mastios, then walks through a sequence of allow / deny calls
# and tails the audit chain.
#
# Prerequisites:
#   1. `./demo.sh full` has been run.
#   2. MCP_PROXY_TOOL_PDP_ENABLED=true is set on proxy-a and proxy-b
#      (the sandbox docker-compose.yml ships this on by default for
#      the full profile after ADR-029 Phase F).
#
# Designed to read well on screen for the YC video: each scenario
# prints the verdict and reason inline, the final audit dump shows
# the hash-chained trail.
set -euo pipefail

cd "$(dirname "$0")/.."

BOLD='\033[1m'
GREEN='\033[32m'
RED='\033[31m'
YELLOW='\033[33m'
CYAN='\033[36m'
DIM='\033[2m'
RESET='\033[0m'

ALLOW_EMOJI=$'✅'
DENY_EMOJI=$'❌'

_step() { echo -e "\n${BOLD}${CYAN}── $1 ──${RESET}"; }
_note() { echo -e "  ${DIM}$1${RESET}"; }


_have_jq() { command -v jq >/dev/null 2>&1; }

# proxy-a is mounted on host port 9100, proxy-b on 9200.
PROXY_A_URL="http://localhost:9100"
PROXY_B_URL="http://localhost:9200"


# ── 0. Sanity check ───────────────────────────────────────────────────
_step "0. Sanity check: both Mastios alive + tool PDP gate on"

if ! curl -sf "${PROXY_A_URL}/readyz" >/dev/null; then
    echo -e "${RED}proxy-a is not reachable at ${PROXY_A_URL}. Run ./demo.sh full first.${RESET}"
    exit 1
fi
if ! curl -sf "${PROXY_B_URL}/readyz" >/dev/null; then
    echo -e "${RED}proxy-b is not reachable at ${PROXY_B_URL}. Run ./demo.sh full first.${RESET}"
    exit 1
fi

probe_a=$(curl -s -o /dev/null -w '%{http_code}' \
    -X POST "${PROXY_A_URL}/v1/policy/tool-call" \
    -H 'Content-Type: application/json' \
    -d '{"principal":{"id":"probe","type":"user"},"invocation":{"tool_name":"probe"}}')
if [ "${probe_a}" = "404" ]; then
    echo -e "${RED}proxy-a tool PDP gate is OFF.${RESET}"
    echo -e "${YELLOW}Restart the sandbox after the ADR-029 Phase F merge so MCP_PROXY_TOOL_PDP_ENABLED=true is picked up:${RESET}"
    echo -e "  ./demo.sh down && ./demo.sh full"
    exit 1
fi

_note "proxy-a tool PDP gate: ON (probe returned HTTP ${probe_a})"


# ── 1. Configure tool_rules on both Mastios ───────────────────────────
_step "1. Write tool_rules on proxy-a (orga) and proxy-b (orgb)"

# proxy-a (orga) policy:
#   acme.catalog.search   allowed for mario, denied for anna,
#                         restricted to claude-haiku-4-5
#   orgb.catalog.search   allowed for mario, no model lock (will federate
#                         to proxy-b on call)
docker compose exec -T proxy-a python - <<'PY'
import asyncio, json
from mcp_proxy.db import set_config
async def main():
    rules = {
        "tool_rules": {
            "acme.catalog.search": {
                "allowed_principals": ["orga::user::mario"],
                "denied_principals":  ["orga::user::anna"],
                "allowed_models":     ["claude-haiku-4-5"],
            },
            "orgb.catalog.search": {
                "allowed_principals": ["orga::user::mario"],
            },
        }
    }
    await set_config("policy_rules", json.dumps(rules, indent=2, sort_keys=True))
    print("[proxy-a] policy_rules.tool_rules written")
asyncio.run(main())
PY

# proxy-b (orgb) policy:
#   orgb.catalog.search   open: any cross-org user that proxy-a
#                         clears reaches the data.
#   orgb.private.tool     listed but with empty allowed_principals,
#                         so any incoming request is denied at the
#                         target side (proxy-a's local allow gets
#                         intersected with proxy-b's deny → final deny).
docker compose exec -T proxy-b python - <<'PY'
import asyncio, json
from mcp_proxy.db import set_config
async def main():
    rules = {
        "tool_rules": {
            "orgb.catalog.search": {
                # Empty allowlist → any principal accepted (legacy
                # default-allow on this axis once tool_rules is non-empty).
                # Phase D-2 expects the target Mastio to gate on its OWN
                # policy; here we just open the door for the federation
                # demo.
            },
            "orgb.private.tool": {
                "allowed_principals": ["orgb::user::ceo"],
            },
        }
    }
    await set_config("policy_rules", json.dumps(rules, indent=2, sort_keys=True))
    print("[proxy-b] policy_rules.tool_rules written")
asyncio.run(main())
PY


# ── helper: pretty-call the gate + print verdict ──────────────────────
call_gate() {
    local label="$1"
    local proxy_url="$2"
    local payload="$3"

    local resp http_code body decision reason
    resp=$(curl -s -o /tmp/policy-resp.json -w '%{http_code}' \
        -X POST "${proxy_url}/v1/policy/tool-call" \
        -H 'Content-Type: application/json' \
        -d "${payload}")
    http_code="${resp}"
    body=$(cat /tmp/policy-resp.json)
    if _have_jq; then
        decision=$(echo "${body}" | jq -r '.decision // "?"')
        reason=$(echo "${body}" | jq -r '.reason // ""')
    else
        decision=$(echo "${body}" | grep -o '"decision":"[^"]*"' | head -1 | cut -d'"' -f4)
        reason=$(echo "${body}" | sed -n 's/.*"reason":"\([^"]*\)".*/\1/p' | head -1)
    fi
    local emoji color
    if [ "${decision}" = "allow" ]; then
        emoji="${ALLOW_EMOJI}"
        color="${GREEN}"
    else
        emoji="${DENY_EMOJI}"
        color="${RED}"
    fi
    printf "  ${BOLD}%-58s${RESET} %s ${color}%-5s${RESET}  ${DIM}%s${RESET}\n" \
        "${label}" "${emoji}" "${decision}" "${reason}"
}


# ── 2. Local Mastio gate (proxy-a) ────────────────────────────────────
_step "2. proxy-a local gate: principal + model + tool"

call_gate "mario + haiku → acme.catalog.search" "${PROXY_A_URL}" '{
    "principal": {"id": "orga::user::mario", "type": "user", "org": "orga"},
    "model":     {"id": "claude-haiku-4-5"},
    "target":    {"id": "orga::workload::catalog", "type": "workload", "org": "orga"},
    "invocation":{"kind": "session_tool_call", "tool_name": "acme.catalog.search"}
}'

call_gate "anna  + haiku → acme.catalog.search" "${PROXY_A_URL}" '{
    "principal": {"id": "orga::user::anna", "type": "user", "org": "orga"},
    "model":     {"id": "claude-haiku-4-5"},
    "target":    {"id": "orga::workload::catalog", "type": "workload", "org": "orga"},
    "invocation":{"kind": "session_tool_call", "tool_name": "acme.catalog.search"}
}'

call_gate "mario + opus  → acme.catalog.search" "${PROXY_A_URL}" '{
    "principal": {"id": "orga::user::mario", "type": "user", "org": "orga"},
    "model":     {"id": "claude-opus-4-7"},
    "target":    {"id": "orga::workload::catalog", "type": "workload", "org": "orga"},
    "invocation":{"kind": "session_tool_call", "tool_name": "acme.catalog.search"}
}'

call_gate "mario + haiku → acme.unlisted.tool   " "${PROXY_A_URL}" '{
    "principal": {"id": "orga::user::mario", "type": "user", "org": "orga"},
    "model":     {"id": "claude-haiku-4-5"},
    "target":    {"id": "orga::workload::catalog", "type": "workload", "org": "orga"},
    "invocation":{"kind": "session_tool_call", "tool_name": "acme.unlisted.tool"}
}'


# ── 3. Cross-org federation: proxy-a ↔ proxy-b ────────────────────────
_step "3. Cross-org federation: proxy-a asks proxy-b"

call_gate "mario → orgb.catalog.search          " "${PROXY_A_URL}" '{
    "principal": {"id": "orga::user::mario", "type": "user", "org": "orga"},
    "model":     {"id": "claude-haiku-4-5"},
    "target":    {"id": "orgb::workload::catalog", "type": "workload", "org": "orgb"},
    "invocation":{"kind": "session_tool_call", "tool_name": "orgb.catalog.search"}
}'

call_gate "mario → orgb.private.tool            " "${PROXY_A_URL}" '{
    "principal": {"id": "orga::user::mario", "type": "user", "org": "orga"},
    "model":     {"id": "claude-haiku-4-5"},
    "target":    {"id": "orgb::workload::secret", "type": "workload", "org": "orgb"},
    "invocation":{"kind": "session_tool_call", "tool_name": "orgb.private.tool"}
}'

call_gate "mario → stranger.tool (no fed URL)    " "${PROXY_A_URL}" '{
    "principal": {"id": "orga::user::mario", "type": "user", "org": "orga"},
    "model":     {"id": "claude-haiku-4-5"},
    "target":    {"id": "stranger::workload::x", "type": "workload", "org": "stranger"},
    "invocation":{"kind": "session_tool_call", "tool_name": "stranger.tool"}
}'


# ── 4. Audit chain ────────────────────────────────────────────────────
_step "4. Hash-chained audit on proxy-a (last 8 rows, action=policy.tool_call)"

docker compose exec -T proxy-a python - <<'PY'
import asyncio, json
from sqlalchemy import text
from mcp_proxy.db import get_db
async def main():
    async with get_db() as conn:
        rows = (await conn.execute(text(
            "SELECT chain_seq, agent_id, status, tool_name, detail "
            "FROM audit_log WHERE action='policy.tool_call' "
            "ORDER BY chain_seq DESC LIMIT 8"
        ))).fetchall()
    for r in reversed(rows):
        d = json.loads(r.detail or "{}")
        tail = " ".join(
            f"{k}={d[k]}" for k in ("model", "target", "federated") if k in d
        )
        print(f"  #{r.chain_seq:<3}  {r.status:<5}  {r.agent_id:<32}  {r.tool_name:<24}  {tail}")
asyncio.run(main())
PY


# ── 5. Wrap-up ───────────────────────────────────────────────────────
_step "5. Demo complete"

cat <<EOF
  ${BOLD}Recap${RESET}

  Local gate (proxy-a, orga):
    mario + haiku  → acme.catalog.search  allow  (in allowed_principals + allowed_models)
    anna  + haiku  → acme.catalog.search  deny   (denied_principals beats allow)
    mario + opus   → acme.catalog.search  deny   (model not in allowed_models)
    mario + haiku  → acme.unlisted.tool   deny   (tool not in tool_rules: explicit-allow)

  Cross-org federation (proxy-a → proxy-b):
    mario → orgb.catalog.search           allow  (proxy-a allow ∩ proxy-b allow)
    mario → orgb.private.tool             deny   (proxy-b explicit-allow refuses; final deny)
    mario → stranger.tool                 deny   (no federation URL for that org)

  ${BOLD}What this proves${RESET}
  - PDP discriminates on principal + model + tool + target org, all on a
    single uniform shape (ADR-029 §Decision).
  - Cross-org calls are dual-allow: source AND target Mastio must agree.
  - Default-deny when an org is not in the federation map; an admin
    cannot bypass a peer by omission.
  - Every decision lands hash-chained in audit_log; allow and deny
    rows side by side make forensic queries trivial.

  ${BOLD}Dashboard${RESET}
  Open http://localhost:9100/proxy/policies/tool-rules to edit the rules
  through the new authoring matrix (ADR-029 Phase E).
EOF
