#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# Cullis — Generate proxy.env with secure random secrets (MCP Proxy)
# ═══════════════════════════════════════════════════════════════════════════════
#
# Usage:
#   ./scripts/generate-proxy-env.sh              # Interactive
#   ./scripts/generate-proxy-env.sh --defaults   # Same-host localhost defaults
#   ./scripts/generate-proxy-env.sh --prod       # Needs BROKER_URL + PROXY_PUBLIC_URL env vars
#   ./scripts/generate-proxy-env.sh --force      # Overwrite existing proxy.env
#
# Environment variables (optional):
#   BROKER_URL         — required with --prod (e.g. https://broker.example.com)
#   PROXY_PUBLIC_URL   — required with --prod (e.g. https://proxy.myorg.example.com)
#   ORG_ADMIN_EMAIL    — informational, stored in MCP_PROXY_ALLOWED_ORIGINS hint
#   PROJECT_DIR        — override project root (default: parent of scripts/)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="${PROJECT_DIR:-$(dirname "$SCRIPT_DIR")}"

GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RED=$'\033[31m'
BOLD=$'\033[1m'; GRAY=$'\033[90m'; RESET=$'\033[0m'
ok()   { echo -e "  ${GREEN}✓${RESET}  $1"; }
warn() { echo -e "  ${YELLOW}!${RESET}  $1"; }
err()  { echo -e "  ${RED}✗${RESET}  $1"; }
die()  { err "$1"; exit 1; }

MODE="interactive"
FORCE=0
for arg in "$@"; do
    case "$arg" in
        --defaults) MODE="defaults" ;;
        --prod)     MODE="prod" ;;
        --force)    FORCE=1 ;;
        --help|-h)
            echo "Usage: $0 [--defaults|--prod] [--force]"
            exit 0
            ;;
        *) die "Unknown argument: $arg (use --help)" ;;
    esac
done

OUT="$PROJECT_DIR/proxy.env"
if [[ -f "$OUT" && "$FORCE" -eq 0 ]]; then
    if [[ "$MODE" != "interactive" ]]; then
        ok "Keeping existing proxy.env (use --force to overwrite)"
        exit 0
    fi
    warn "proxy.env already exists"
    read -rp "  Overwrite with fresh secrets? [y/N]: " reply
    [[ "$reply" =~ ^[Yy] ]] || { ok "Keeping existing proxy.env"; exit 0; }
fi

command -v openssl >/dev/null || die "openssl is required"
[[ -f "$PROJECT_DIR/proxy.env.example" ]] || die "proxy.env.example not found"

if [[ "$MODE" == "prod" ]]; then
    [[ -n "${BROKER_URL:-}" ]]       || die "--prod requires BROKER_URL env var"
    [[ -n "${PROXY_PUBLIC_URL:-}" ]] || die "--prod requires PROXY_PUBLIC_URL env var"
fi

gen_secret() { openssl rand -base64 32 | tr -d '/+=' | head -c 32; }

ADMIN_SECRET="$(gen_secret)"
SIGNING_KEY="$(gen_secret)"

ok "Generated random admin secret + signing key"

case "$MODE" in
    prod)
        BROKER="${BROKER_URL}"
        PUBLIC="${PROXY_PUBLIC_URL}"
        JWKS="${BROKER_URL%/}/.well-known/jwks.json"
        ENVIRONMENT="production"
        ;;
    defaults)
        BROKER="${BROKER_URL:-http://broker:8000}"
        PUBLIC="${PROXY_PUBLIC_URL:-http://localhost:9100}"
        JWKS="${BROKER%/}/.well-known/jwks.json"
        ENVIRONMENT="development"
        ;;
    interactive)
        echo ""
        read -rp "  Broker URL [http://broker:8000]: " BROKER
        BROKER="${BROKER:-http://broker:8000}"
        read -rp "  Proxy public URL [http://localhost:9100]: " PUBLIC
        PUBLIC="${PUBLIC:-http://localhost:9100}"
        JWKS="${BROKER%/}/.well-known/jwks.json"
        ENVIRONMENT="development"
        ;;
esac

cp "$PROJECT_DIR/proxy.env.example" "$OUT"
sed -i "s|^MCP_PROXY_ENVIRONMENT=.*|MCP_PROXY_ENVIRONMENT=${ENVIRONMENT}|"           "$OUT"
sed -i "s|^MCP_PROXY_ADMIN_SECRET=.*|MCP_PROXY_ADMIN_SECRET=${ADMIN_SECRET}|"        "$OUT"
sed -i "s|^MCP_PROXY_DASHBOARD_SIGNING_KEY=.*|MCP_PROXY_DASHBOARD_SIGNING_KEY=${SIGNING_KEY}|" "$OUT"
sed -i "s|^MCP_PROXY_BROKER_URL=.*|MCP_PROXY_BROKER_URL=${BROKER}|"                  "$OUT"
sed -i "s|^MCP_PROXY_BROKER_JWKS_URL=.*|MCP_PROXY_BROKER_JWKS_URL=${JWKS}|"          "$OUT"
sed -i "s|^MCP_PROXY_PROXY_PUBLIC_URL=.*|MCP_PROXY_PROXY_PUBLIC_URL=${PUBLIC}|"      "$OUT"

ok "Wrote ${OUT}"
echo ""
echo -e "  ${BOLD}MCP_PROXY_ADMIN_SECRET${RESET}      ${GRAY}${ADMIN_SECRET:0:8}...${RESET}"
echo -e "  ${BOLD}MCP_PROXY_BROKER_URL${RESET}        ${GRAY}${BROKER}${RESET}"
echo -e "  ${BOLD}MCP_PROXY_PROXY_PUBLIC_URL${RESET}  ${GRAY}${PUBLIC}${RESET}"
echo -e "  ${BOLD}MCP_PROXY_ENVIRONMENT${RESET}       ${GRAY}${ENVIRONMENT}${RESET}"
echo ""
