#!/usr/bin/env bash
# Cullis Reference Deployment — `widget-hunt` scenario
#
# Kicks off the multi-hop demo by injecting an INITIAL_PROMPT into
# alice-byoca (BUYER, orga). She'll ask alice-spiffe (INVENTORY) for
# widget-X, find none, ask alice-connector (BROKER) to source it
# cross-org, who in turn discovers + messages bob-connector (BROKER,
# orgb), who routes to bob-spiffe (SUPPLIER), who checks bob-byoca
# (INVENTORY), then walks the answer back. Every hop is a real LLM
# decision via Ollama + a real Cullis send.
#
# Usage:
#   bash reference/scenarios/widget-hunt.sh                # run with defaults
#   PROMPT="Need 50 gear-Y" bash reference/scenarios/widget-hunt.sh
#
# Prerequisites:
#   - reference stack DOWN (we restart it with the env injected)
#   - sandbox stack DOWN (mutually exclusive — same ports)
#   - Ollama up on host with gemma3:1b loaded
#   - Container → host:11434 reachable (NixOS: br-* in firewall whitelist)

set -euo pipefail

cd "$(dirname "$0")/.."

PROMPT="${PROMPT:-Source 100 units of widget-X from anywhere in the federation, including cross-org suppliers if our orga inventory is empty.}"

BOLD='\033[1m'
GREEN='\033[32m'
CYAN='\033[36m'
YELLOW='\033[33m'
GRAY='\033[90m'
RESET='\033[0m'

_h()    { echo -e "\n${BOLD}${CYAN}═══ $1 ═══${RESET}\n"; }
_ok()   { echo -e "  ${GREEN}✓${RESET} $1"; }
_note() { echo -e "  ${YELLOW}•${RESET} $1"; }
_dim()  { echo -e "  ${GRAY}…${RESET} $1"; }

_h "Cullis Reference — widget-hunt scenario"

_note "Bringing reference stack down (clean slate)"
docker compose --profile full down -v --remove-orphans >/dev/null 2>&1 || true

_note "Bringing reference stack up with INITIAL_PROMPT on alice-byoca"
echo "  ${GRAY}prompt:${RESET} ${PROMPT}"
# BOOTSTRAP_SCOPE=full forces the outer bootstrap to register orga too
# (its default in the compose file is "up", which leaves orga out for
# the sandbox's guided onboarding flow). The reference deployment needs
# both orgs because the cross-org demo is the whole point.
BOOTSTRAP_SCOPE=full \
ALICE_BYOCA_INITIAL_PROMPT="${PROMPT}" \
  docker compose --profile full up -d --build --wait --quiet-pull >/dev/null

_ok "stack ready"

echo
echo "  ${BOLD}${CYAN}┌─────────────────────────────────────────────────────────┐${RESET}"
echo "  ${BOLD}${CYAN}│  📊 Grafana dashboard:  http://localhost:3000           │${RESET}"
echo "  ${BOLD}${CYAN}│      → Live LLM decisions + enrollment + audit events   │${RESET}"
echo "  ${BOLD}${CYAN}└─────────────────────────────────────────────────────────┘${RESET}"
echo

_note "Tail the conversation across all six agents (Ctrl-C to stop)"
echo
echo -e "  ${GRAY}docker compose --profile full logs -f \\${RESET}"
echo -e "  ${GRAY}    alice-byoca alice-spiffe alice-connector \\${RESET}"
echo -e "  ${GRAY}    bob-byoca bob-spiffe bob-connector${RESET}"
echo

# Filter to just the relevant agent log lines (drop httpx noise) so the
# multi-hop story is readable. Each agent prefixes its lines with
# `[orga::alice-byoca|buyer]` etc., so this grep keeps the Cullis +
# LLM events and drops the polling noise.
docker compose --profile full logs -f \
    alice-byoca alice-spiffe alice-connector \
    bob-byoca bob-spiffe bob-connector \
  | grep --line-buffered -E "kick-off|inbox.recv|llm.decide|tool\.|max_hops|FAILED|ERROR|identity loaded" \
  | grep --line-buffered -v "HTTP Request"
