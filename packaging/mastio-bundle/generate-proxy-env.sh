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
# Bundle layout — script lives at the bundle root next to
# proxy.env.example. The repo-side copy in scripts/ keeps its original
# parent-of-scripts default; PROJECT_DIR can still be overridden via env.
PROJECT_DIR="${PROJECT_DIR:-$SCRIPT_DIR}"

GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RED=$'\033[31m'
BOLD=$'\033[1m'; GRAY=$'\033[90m'; RESET=$'\033[0m'
ok()   { echo -e "  ${GREEN}✓${RESET}  $1"; }
warn() { echo -e "  ${YELLOW}!${RESET}  $1"; }
err()  { echo -e "  ${RED}✗${RESET}  $1"; }
die()  { err "$1"; exit 1; }

MODE="interactive"
FORCE=0
# Opt-in to auto-seed the first-boot admin password. Default behavior
# (off) leaves ``admin_password_hash`` NULL on first boot so the
# operator picks the password interactively at ``/proxy/register``.
# Power users who script the install (Ansible / Terraform / CI smoke)
# pass ``--auto-admin-pwd`` to retain the legacy seed-in-env flow.
# Memory-wise: the dashboard is never publicly exposed on Cullis's
# threat model (operator behind VPN / internal segment), so the
# /register race-window is not a concern; the gain is one fewer
# random-string-on-stdout to handle.
AUTO_ADMIN_PWD="${MASTIO_AUTO_ADMIN_PWD:-0}"
for arg in "$@"; do
    case "$arg" in
        --defaults)        MODE="defaults" ;;
        --prod)            MODE="prod" ;;
        --force)           FORCE=1 ;;
        --auto-admin-pwd)  AUTO_ADMIN_PWD=1 ;;
        --help|-h)
            cat <<'USAGE'
Usage: ./generate-proxy-env.sh [--defaults|--prod] [--force] [--auto-admin-pwd]

  --defaults         Same-host localhost defaults (no prompts).
  --prod             Needs BROKER_URL + PROXY_PUBLIC_URL env vars.
  --force            Overwrite existing proxy.env.
  --auto-admin-pwd   Auto-generate the first-boot admin password and
                     write it to MCP_PROXY_INITIAL_ADMIN_PASSWORD.
                     Default (without this flag) leaves the hash NULL
                     so the operator chooses the password at
                     /proxy/register on first sign-in.
                     Equivalent env: MASTIO_AUTO_ADMIN_PWD=1
USAGE
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

[[ -f "$PROJECT_DIR/proxy.env.example" ]] || die "proxy.env.example not found"

if [[ "$MODE" == "prod" ]]; then
    [[ -n "${BROKER_URL:-}" ]]       || die "--prod requires BROKER_URL env var"
    [[ -n "${PROXY_PUBLIC_URL:-}" ]] || die "--prod requires PROXY_PUBLIC_URL env var"
fi

# Prefer openssl when available (well-tested, fast); fall back to
# /dev/urandom + coreutils on hosts that ship without openssl —
# minimal NixOS, Alpine, distroless, WSL2 trimmed Ubuntu, etc. Issue
# #638: a customer on a Linux host without openssl pre-installed
# previously hit ``openssl is required`` on the very first deploy.
gen_secret() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -base64 32 | tr -d '/+=' | head -c 32
    else
        # 64 random bytes → base64 → strip non-alphanum → take 32 chars.
        # /dev/urandom + base64 + tr are coreutils, present on every
        # Linux a docker host can boot on.
        head -c 64 /dev/urandom | base64 | tr -d '/+=\n' | head -c 32
    fi
}

ADMIN_SECRET="$(gen_secret)"
SIGNING_KEY="$(gen_secret)"
# First-boot admin password.
#
# Default (AUTO_ADMIN_PWD=0): leave INITIAL_ADMIN_PASSWORD empty so
# ``proxy.env`` does not seed the bcrypt hash at boot. The operator
# hits ``/proxy/login`` on first sign-in, the dashboard redirects to
# ``/proxy/register``, and the operator picks the password interactively
# (typed once, never on stdout). Threat model: dashboard is never
# publicly exposed (operator behind VPN / internal segment), so the
# first-POST-wins race on /register is bounded by network access
# control rather than internet exposure.
#
# Opt-in (--auto-admin-pwd | MASTIO_AUTO_ADMIN_PWD=1): keep the legacy
# behavior — generate a random secret, write it into proxy.env, the
# Mastio lifespan reads + hashes it on first boot. Use this for
# scripted provisioning (Ansible / Terraform / CI smoke) where a
# /register browser hop is not feasible.
if [[ "$AUTO_ADMIN_PWD" -eq 1 ]]; then
    INITIAL_ADMIN_PASSWORD="$(gen_secret)"
    ok "Generated random admin secret + signing key + first-boot password (--auto-admin-pwd)"
else
    INITIAL_ADMIN_PASSWORD=""
    ok "Generated random admin secret + signing key (admin password chosen interactively at /proxy/register on first sign-in)"
fi

case "$MODE" in
    prod)
        BROKER="${BROKER_URL}"
        PUBLIC="${PROXY_PUBLIC_URL}"
        JWKS="${BROKER_URL%/}/.well-known/jwks.json"
        ENVIRONMENT="production"
        ;;
    defaults)
        BROKER="${BROKER_URL:-http://broker:8000}"
        # Default ``https://host.docker.internal:9443`` matches the
        # docker-compose.yml fallback and the deploy.sh interactive
        # prompt default. This is the same URL the interactive flow
        # writes when the operator presses Enter at the public-URL
        # prompt. Emitting it explicitly keeps ``--defaults`` self-
        # contained for CI / Ansible / quick-laptop boot: the resulting
        # proxy.env survives standalone (no extra deploy.sh post-fix)
        # and the operator never hits 401 ``htu mismatch`` because the
        # field was empty. Operators fronting the Mastio with a stable
        # public hostname override via ``PROXY_PUBLIC_URL=...`` env or
        # by editing proxy.env after generation.
        PUBLIC="${PROXY_PUBLIC_URL:-https://host.docker.internal:9443}"
        JWKS="${BROKER%/}/.well-known/jwks.json"
        ENVIRONMENT="development"
        ;;
    interactive)
        echo ""
        read -rp "  Broker URL [http://broker:8000]: " BROKER
        BROKER="${BROKER:-http://broker:8000}"
        # Same default the deploy.sh interactive prompt offers (line ~611):
        # covers host browser + sibling containers in the laptop / single
        # VM scenario. Empty input → laptop default, never the empty
        # string (MINOR-F: empty triggers 401 htu mismatch on every agent
        # enrollment because the docker-compose ${VAR:-...} fallback does
        # NOT apply uniformly across all consumers of proxy.env).
        read -rp "  Proxy public URL [https://host.docker.internal:9443]: " PUBLIC
        PUBLIC="${PUBLIC:-https://host.docker.internal:9443}"
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

# MCP_PROXY_PROXY_PUBLIC_URL ships COMMENTED in proxy.env.example (the
# example carries a placeholder production hostname so operators see
# the shape, not a usable default). A plain sed-substitution on
# ``^MCP_PROXY_PROXY_PUBLIC_URL=`` therefore silently no-ops and the
# generated proxy.env ends up without an uncommented line, exactly
# the dogfood breakage MINOR-F pins (CI / Ansible / laptop boot with
# --defaults then ./deploy.sh up: every agent enrollment fails 401
# htu mismatch). Strip any pre-existing line (commented or not) and
# append the resolved value so the field always lands uncommented.
sed -i.bak '/^#*[[:space:]]*MCP_PROXY_PROXY_PUBLIC_URL=/d' "$OUT"
rm -f "${OUT}.bak"
echo "MCP_PROXY_PROXY_PUBLIC_URL=${PUBLIC}" >> "$OUT"

# ADR-030 — the bundle bind-mount paths default to ./data and ./nginx-certs.
# proxy.env.example ships them already, so no sed required here. The block
# is intentionally idempotent: re-running this script never clobbers an
# operator's custom path because the example carries the canonical value
# and any override survives via --force-only overwrite.
# proxy.env.example does not ship the seed line. Append only when the
# operator asked for the auto-seed path; otherwise omit so the Mastio
# main.py boot path correctly leaves the hash NULL and routes
# /proxy/login → /proxy/register for interactive setup.
if [[ -n "$INITIAL_ADMIN_PASSWORD" ]]; then
    echo "MCP_PROXY_INITIAL_ADMIN_PASSWORD=${INITIAL_ADMIN_PASSWORD}" >> "$OUT"
fi

ok "Wrote ${OUT}"
echo ""
echo -e "  ${BOLD}MCP_PROXY_ADMIN_SECRET${RESET}            ${GRAY}${ADMIN_SECRET:0:8}…${RESET}"
if [[ -n "$INITIAL_ADMIN_PASSWORD" ]]; then
    echo -e "  ${BOLD}MCP_PROXY_INITIAL_ADMIN_PASSWORD${RESET}  ${GRAY}${INITIAL_ADMIN_PASSWORD}${RESET}"
    echo -e "                                  ${GRAY}(login at /proxy/login as ``admin`` with this password, then rotate)${RESET}"
else
    echo -e "  ${BOLD}MCP_PROXY_INITIAL_ADMIN_PASSWORD${RESET}  ${GRAY}(unset — pick interactively at /proxy/register on first sign-in)${RESET}"
fi
echo -e "  ${BOLD}MCP_PROXY_BROKER_URL${RESET}              ${GRAY}${BROKER}${RESET}"
echo -e "  ${BOLD}MCP_PROXY_PROXY_PUBLIC_URL${RESET}        ${GRAY}${PUBLIC}${RESET}"
echo -e "  ${BOLD}MCP_PROXY_ENVIRONMENT${RESET}             ${GRAY}${ENVIRONMENT}${RESET}"
echo ""
