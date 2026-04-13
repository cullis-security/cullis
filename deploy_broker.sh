#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# Cullis — Broker deployment (broker + postgres + redis + vault + nginx + jaeger)
# ═══════════════════════════════════════════════════════════════════════════════
#
# Deploys the Cullis trust broker. Each organization then deploys their own
# MCP Proxy using deploy_proxy.sh.
#
# Three TLS profiles, all driven by the same script:
#
#   --dev                              Self-signed cert on https://localhost:8443
#                                      (default — runs entirely offline)
#
#   --prod-acme --domain X --email Y   Real cert from Let's Encrypt via certbot.
#                                      Requires public DNS pointing to the host
#                                      and ports 80/443 reachable from the
#                                      internet for the HTTP-01 challenge.
#
#   --prod-byoca --domain X            Bring Your Own CA: provide a cert and
#         --cert /path/to/fullchain.pem  key already issued by your enterprise
#         --key  /path/to/privkey.pem    CA. The script copies them into nginx
#                                      and writes the matching nginx.conf.
#
# Interactive fallback: running without flags asks the same questions.
# Backwards-compatible aliases: --prod is treated as the interactive prod path.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Colors ───────────────────────────────────────────────────────────────────
GREEN='\033[32m'
YELLOW='\033[33m'
RED='\033[31m'
BOLD='\033[1m'
GRAY='\033[90m'
RESET='\033[0m'

ok()   { echo -e "  ${GREEN}✓${RESET}  $1"; }
warn() { echo -e "  ${YELLOW}!${RESET}  $1"; }
err()  { echo -e "  ${RED}✗${RESET}  $1"; }
die()  { err "$1"; exit 1; }
log()  { echo -e "${BOLD}[$2]${RESET} $1"; }
step() { echo -e "\n${BOLD}── $1 ──${RESET}"; }

ask_yn() {
    local prompt="$1" default="${2:-n}"
    local reply
    if [[ "$default" == "y" ]]; then
        read -rp "  $prompt [Y/n]: " reply
        reply="${reply:-y}"
    else
        read -rp "  $prompt [y/N]: " reply
        reply="${reply:-n}"
    fi
    [[ "$reply" =~ ^[Yy] ]]
}

# ── Parse CLI args ───────────────────────────────────────────────────────────
MODE=""
TLS_PROFILE=""           # "" | "selfsigned" | "acme" | "byoca"
ARG_DOMAIN=""
ARG_EMAIL=""
ARG_CERT=""
ARG_KEY=""

print_help() {
    cat <<EOF
Usage: $0 [PROFILE] [OPTIONS]

Profiles (mutually exclusive):
  --dev                       Development: self-signed cert on https://localhost:8443
  --prod                      Production (interactive): asks for domain + TLS choice
  --prod-acme                 Production with Let's Encrypt (HTTP-01)
                              Requires --domain and --email
  --prod-byoca                Production with Bring Your Own CA cert
                              Requires --domain, --cert, --key

Options:
  --domain <name>             FQDN for production deployment
  --email  <addr>             Email for Let's Encrypt notifications (--prod-acme only)
  --cert   <path>             Path to TLS certificate PEM (--prod-byoca only)
  --key    <path>             Path to TLS private key PEM (--prod-byoca only)
  --help, -h                  Show this help and exit

Examples:
  $0 --dev
  $0 --prod-acme  --domain broker.example.com --email ops@example.com
  $0 --prod-byoca --domain broker.example.com \\
                  --cert /etc/ssl/cullis/fullchain.pem \\
                  --key  /etc/ssl/cullis/privkey.pem

When no profile is given, the script runs in interactive mode (legacy).
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dev)         MODE="development"; TLS_PROFILE="selfsigned"; shift ;;
        --prod)        MODE="production"; shift ;;
        --prod-acme)   MODE="production"; TLS_PROFILE="acme"; shift ;;
        --prod-byoca)  MODE="production"; TLS_PROFILE="byoca"; shift ;;
        --domain)      ARG_DOMAIN="${2:-}"; shift 2 ;;
        --email)       ARG_EMAIL="${2:-}"; shift 2 ;;
        --cert)        ARG_CERT="${2:-}"; shift 2 ;;
        --key)         ARG_KEY="${2:-}"; shift 2 ;;
        --help|-h)     print_help; exit 0 ;;
        *)             die "Unknown argument: $1 (use --help)" ;;
    esac
done

# Validate non-interactive profile combinations
if [[ "$TLS_PROFILE" == "acme" ]]; then
    [[ -z "$ARG_DOMAIN" ]] && die "--prod-acme requires --domain"
    [[ -z "$ARG_EMAIL"  ]] && die "--prod-acme requires --email"
fi
if [[ "$TLS_PROFILE" == "byoca" ]]; then
    [[ -z "$ARG_DOMAIN" ]] && die "--prod-byoca requires --domain"
    [[ -z "$ARG_CERT"   ]] && die "--prod-byoca requires --cert"
    [[ -z "$ARG_KEY"    ]] && die "--prod-byoca requires --key"
    [[ ! -f "$ARG_CERT" ]] && die "Certificate file not found: $ARG_CERT"
    [[ ! -f "$ARG_KEY"  ]] && die "Key file not found: $ARG_KEY"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# 1. Prerequisites
# ═══════════════════════════════════════════════════════════════════════════════
step "Checking prerequisites"

command -v docker &>/dev/null   || die "docker is not installed"
ok "docker found"

# Accept either 'docker compose' (plugin) or 'docker-compose' (standalone)
if docker compose version &>/dev/null 2>&1; then
    COMPOSE="docker compose"
    ok "docker compose (plugin) found"
elif command -v docker-compose &>/dev/null; then
    COMPOSE="docker-compose"
    ok "docker-compose (standalone) found"
else
    die "docker compose is not installed (need plugin or standalone)"
fi

command -v openssl &>/dev/null  || die "openssl is not installed"
ok "openssl found"

# ═══════════════════════════════════════════════════════════════════════════════
# 2. Interactive mode selection
# ═══════════════════════════════════════════════════════════════════════════════
step "Deployment mode"

DOMAIN="localhost"
USE_LETSENCRYPT="n"
CERT_PATH=""
KEY_PATH=""

if [[ -z "$MODE" ]]; then
    echo "  1) Development (self-signed cert, localhost)"
    echo "  2) Production (real domain, TLS)"
    read -rp "  Choose [1/2]: " mode_choice
    case "$mode_choice" in
        2|prod|production) MODE="production" ;;
        *) MODE="development" ;;
    esac
fi

if [[ "$MODE" == "production" ]]; then
    ok "Production mode selected"

    # Non-interactive: --prod-acme / --prod-byoca already supplied everything.
    if [[ "$TLS_PROFILE" == "acme" ]]; then
        DOMAIN="$ARG_DOMAIN"
        USE_LETSENCRYPT="y"
        LE_EMAIL="$ARG_EMAIL"
        ok "Profile: --prod-acme  domain=$DOMAIN  email=$LE_EMAIL"
    elif [[ "$TLS_PROFILE" == "byoca" ]]; then
        DOMAIN="$ARG_DOMAIN"
        USE_LETSENCRYPT="n"
        CERT_PATH="$ARG_CERT"
        KEY_PATH="$ARG_KEY"
        ok "Profile: --prod-byoca  domain=$DOMAIN  cert=$CERT_PATH"
    else
        # Interactive legacy path (--prod alone or no flag)
        read -rp "  Domain name (e.g. broker.example.com): " DOMAIN
        [[ -z "$DOMAIN" ]] && die "Domain name is required for production mode"

        if ask_yn "Use Let's Encrypt for TLS?"; then
            USE_LETSENCRYPT="y"
            ok "Will configure Let's Encrypt (certbot)"
        else
            USE_LETSENCRYPT="n"
            read -rp "  Path to TLS certificate (PEM): " CERT_PATH
            read -rp "  Path to TLS private key (PEM): " KEY_PATH
            [[ ! -f "$CERT_PATH" ]] && die "Certificate file not found: $CERT_PATH"
            [[ ! -f "$KEY_PATH" ]]  && die "Key file not found: $KEY_PATH"
            ok "Will use enterprise CA certificates"
        fi
    fi
else
    ok "Development mode selected"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# 3. Generate .env if needed
# ═══════════════════════════════════════════════════════════════════════════════
step "Environment configuration (.env)"

if [[ "$MODE" == "production" ]]; then
    DOMAIN="${DOMAIN}" bash "$SCRIPT_DIR/scripts/generate-env.sh" --prod
else
    bash "$SCRIPT_DIR/scripts/generate-env.sh"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# 4. Broker PKI (CA + broker cert)
# ═══════════════════════════════════════════════════════════════════════════════
step "Broker PKI"

CERTS_DIR="$SCRIPT_DIR/certs"
mkdir -p "$CERTS_DIR"

if [[ -f "$CERTS_DIR/broker-ca.pem" && -f "$CERTS_DIR/broker-ca-key.pem" ]]; then
    warn "Broker CA already exists"
    if ask_yn "Regenerate broker CA? (will invalidate all existing agent certs)"; then
        rm -f "$CERTS_DIR/broker-ca.pem" "$CERTS_DIR/broker-ca-key.pem"
        _REGEN_CA=1
    else
        ok "Keeping existing broker CA"
    fi
else
    _REGEN_CA=1
fi

if [[ "${_REGEN_CA:-0}" == "1" ]]; then
    # Use Python generate_certs.py if available, otherwise use openssl directly
    if [[ -f "$SCRIPT_DIR/generate_certs.py" ]]; then
        PYTHON=""
        if [[ -f "$SCRIPT_DIR/.venv/bin/python" ]]; then
            PYTHON="$SCRIPT_DIR/.venv/bin/python"
        elif command -v python3 &>/dev/null; then
            PYTHON="python3"
        elif command -v python &>/dev/null; then
            PYTHON="python"
        fi

        if [[ -n "$PYTHON" ]]; then
            $PYTHON "$SCRIPT_DIR/generate_certs.py"
            ok "Broker CA generated (via generate_certs.py)"
        else
            warn "Python not found, generating CA with openssl"
            _USE_OPENSSL_CA=1
        fi
    else
        _USE_OPENSSL_CA=1
    fi

    if [[ "${_USE_OPENSSL_CA:-0}" == "1" ]]; then
        openssl req -x509 -newkey rsa:4096 -nodes \
            -keyout "$CERTS_DIR/broker-ca-key.pem" \
            -out "$CERTS_DIR/broker-ca.pem" \
            -days 3650 \
            -subj "/CN=Cullis Root CA/O=Cullis" \
            2>/dev/null
        chmod 600 "$CERTS_DIR/broker-ca-key.pem"
        ok "Broker CA generated (via openssl)"
    fi
fi

# ═══════════════════════════════════════════════════════════════════════════════
# 5. TLS certificates
# ═══════════════════════════════════════════════════════════════════════════════
step "TLS certificates"

NGINX_CERTS="$SCRIPT_DIR/nginx/certs"
mkdir -p "$NGINX_CERTS"

if [[ "$MODE" == "development" ]]; then
    # Self-signed cert for dev
    if [[ -f "$NGINX_CERTS/server.pem" && -f "$NGINX_CERTS/server-key.pem" ]]; then
        warn "Self-signed TLS cert already exists"
        if ! ask_yn "Regenerate self-signed TLS cert?"; then
            ok "Keeping existing TLS cert"
        else
            _REGEN_TLS=1
        fi
    else
        _REGEN_TLS=1
    fi

    if [[ "${_REGEN_TLS:-0}" == "1" ]]; then
        openssl req -x509 -newkey rsa:2048 -nodes \
            -keyout "$NGINX_CERTS/server-key.pem" \
            -out "$NGINX_CERTS/server.pem" \
            -days 365 \
            -subj "/CN=localhost/O=ATN Dev" \
            -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
            2>/dev/null
        ok "Self-signed TLS cert generated"
    fi

elif [[ "$USE_LETSENCRYPT" == "y" ]]; then
    # Let's Encrypt: we start with a temporary self-signed cert so nginx can boot,
    # then certbot replaces it after the ACME challenge.
    ok "Will obtain Let's Encrypt cert after containers start"

    # Generate temporary self-signed cert for initial nginx startup
    if [[ ! -f "$NGINX_CERTS/server.pem" ]]; then
        openssl req -x509 -newkey rsa:2048 -nodes \
            -keyout "$NGINX_CERTS/server-key.pem" \
            -out "$NGINX_CERTS/server.pem" \
            -days 1 \
            -subj "/CN=${DOMAIN}/O=ATN Temp" \
            2>/dev/null
        ok "Temporary TLS cert generated (will be replaced by Let's Encrypt)"
    fi

    # Generate nginx config with ACME challenge location
    cat > "$SCRIPT_DIR/nginx/nginx-letsencrypt.conf" <<NGINXEOF
# ACME challenge server (HTTP)
server {
    listen 80;
    server_name ${DOMAIN};

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    location / {
        return 301 https://\$host\$request_uri;
    }
}

# HTTPS server
server {
    listen 443 ssl;
    server_name ${DOMAIN};

    ssl_certificate     /etc/nginx/certs/server.pem;
    ssl_certificate_key /etc/nginx/certs/server-key.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5:!RC4;
    ssl_prefer_server_ciphers on;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;

    client_max_body_size 2m;

    # WebSocket support
    location /v1/broker/ws {
        proxy_pass http://broker:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 86400;
    }

    location /broker/ws {
        proxy_pass http://broker:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 86400;
    }

    location / {
        proxy_pass http://broker:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
NGINXEOF
    ok "Generated nginx config for Let's Encrypt"

    # Generate docker-compose.letsencrypt.yml
    cat > "$SCRIPT_DIR/docker-compose.letsencrypt.yml" <<COMPOSEEOF
# Let's Encrypt / certbot override
# Auto-generated by deploy.sh — do not edit manually.

services:
  nginx:
    volumes:
      - ./nginx/nginx-letsencrypt.conf:/etc/nginx/conf.d/default.conf:ro
      - ./nginx/certs:/etc/nginx/certs:ro
      - certbot-webroot:/var/www/certbot:ro
      - certbot-certs:/etc/letsencrypt:ro
    ports:
      - "443:443"
      - "80:80"

  certbot:
    image: certbot/certbot:latest
    volumes:
      - certbot-webroot:/var/www/certbot
      - certbot-certs:/etc/letsencrypt
    entrypoint: "/bin/sh -c 'trap exit TERM; while :; do sleep 12h & wait \$\${!}; certbot renew --quiet; done'"

volumes:
  certbot-webroot:
  certbot-certs:
COMPOSEEOF
    ok "Generated docker-compose.letsencrypt.yml"

else
    # Enterprise CA: copy provided certs
    cp "$CERT_PATH" "$NGINX_CERTS/server.pem"
    cp "$KEY_PATH" "$NGINX_CERTS/server-key.pem"
    chmod 600 "$NGINX_CERTS/server-key.pem"
    ok "Enterprise TLS cert installed"

    # Update nginx config for the production domain
    cat > "$SCRIPT_DIR/nginx/nginx.conf" <<NGINXEOF
server {
    listen 443 ssl;
    server_name ${DOMAIN};

    ssl_certificate     /etc/nginx/certs/server.pem;
    ssl_certificate_key /etc/nginx/certs/server-key.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5:!RC4;
    ssl_prefer_server_ciphers on;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;

    client_max_body_size 2m;

    # WebSocket support
    location /v1/broker/ws {
        proxy_pass http://broker:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 86400;
    }

    location /broker/ws {
        proxy_pass http://broker:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 86400;
    }

    location / {
        proxy_pass http://broker:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name ${DOMAIN};
    return 301 https://\$host\$request_uri;
}
NGINXEOF
    ok "Updated nginx.conf for domain: ${DOMAIN}"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# 6. Build and start containers
# ═══════════════════════════════════════════════════════════════════════════════
step "Starting Docker containers"

# ── Pre-flight checks for production ────────────────────────────────────────
# Catches the #1 ops mistake: running deploy_broker.sh --prod-* with a stale
# .env that still has development defaults. docker-compose.prod.yml uses :?
# to fail loudly, but catching it here lets us print the *specific* fix.
if [[ "$MODE" == "production" ]]; then
    _errors=()
    _load_env() { grep -E "^$1=" "$SCRIPT_DIR/.env" 2>/dev/null | head -1 | cut -d= -f2- || true; }

    _admin="$(_load_env ADMIN_SECRET)"
    if [[ -z "$_admin" || "$_admin" == "change-me-in-production" ]]; then
        _errors+=("ADMIN_SECRET is empty or default — run scripts/generate-env.sh --prod --force")
    fi

    _signing="$(_load_env DASHBOARD_SIGNING_KEY)"
    if [[ -z "$_signing" ]]; then
        _errors+=("DASHBOARD_SIGNING_KEY is empty — admin sessions will break on every broker restart. Run scripts/generate-env.sh --prod --force")
    fi

    _vtok="$(_load_env VAULT_TOKEN)"
    if [[ -z "$_vtok" || "$_vtok" == "dev-root-token" ]]; then
        _errors+=("VAULT_TOKEN is empty or still the dev default — run ./vault/init-vault.sh and paste the printed scoped token into .env")
    fi

    _pgpw="$(_load_env POSTGRES_PASSWORD)"
    if [[ -z "$_pgpw" || "$_pgpw" == "atn" ]]; then
        _errors+=("POSTGRES_PASSWORD is empty or default — regenerate .env with scripts/generate-env.sh --prod --force")
    fi

    if [[ ${#_errors[@]} -gt 0 ]]; then
        echo ""
        err "Production .env is not safe to deploy:"
        for e in "${_errors[@]}"; do
            echo -e "    ${RED}✗${RESET} $e"
        done
        echo ""
        die "Fix the issues above and rerun. Aborting before docker compose up to prevent insecure deploy."
    fi
    ok "Production .env validated (ADMIN_SECRET, DASHBOARD_SIGNING_KEY, VAULT_TOKEN, POSTGRES_PASSWORD set)"
fi

if [[ "$MODE" == "production" ]]; then
    COMPOSE_FILES="-f docker-compose.yml -f docker-compose.prod.yml"
    if [[ "$USE_LETSENCRYPT" == "y" ]]; then
        COMPOSE_FILES="$COMPOSE_FILES -f docker-compose.letsencrypt.yml"
    fi
    echo -e "  ${GRAY}${COMPOSE} ${COMPOSE_FILES} up --build -d${RESET}"
    $COMPOSE $COMPOSE_FILES up --build -d
else
    echo -e "  ${GRAY}${COMPOSE} up --build -d${RESET}"
    $COMPOSE up --build -d
fi

ok "Containers started"

# ═══════════════════════════════════════════════════════════════════════════════
# 7. Let's Encrypt: obtain certificate
# ═══════════════════════════════════════════════════════════════════════════════
if [[ "$USE_LETSENCRYPT" == "y" ]]; then
    step "Obtaining Let's Encrypt certificate"

    echo "  Waiting for nginx to be ready..."
    ATTEMPTS=0
    until curl -sf "http://${DOMAIN}/.well-known/acme-challenge/" -o /dev/null 2>&1 || [[ $ATTEMPTS -ge 15 ]]; do
        ATTEMPTS=$((ATTEMPTS + 1))
        sleep 2
    done

    if [[ -z "${LE_EMAIL:-}" ]]; then
        read -rp "  Email for Let's Encrypt notifications: " LE_EMAIL
    fi
    [[ -z "$LE_EMAIL" ]] && die "Email is required for Let's Encrypt"

    echo "  Running certbot..."
    $COMPOSE $COMPOSE_FILES run --rm certbot certonly \
        --webroot \
        --webroot-path=/var/www/certbot \
        --email "$LE_EMAIL" \
        --agree-tos \
        --no-eff-email \
        -d "$DOMAIN"

    if [[ $? -eq 0 ]]; then
        ok "Let's Encrypt certificate obtained"

        # Update nginx config to use the real cert
        sed -i "s|/etc/nginx/certs/server.pem|/etc/letsencrypt/live/${DOMAIN}/fullchain.pem|g" \
            "$SCRIPT_DIR/nginx/nginx-letsencrypt.conf"
        sed -i "s|/etc/nginx/certs/server-key.pem|/etc/letsencrypt/live/${DOMAIN}/privkey.pem|g" \
            "$SCRIPT_DIR/nginx/nginx-letsencrypt.conf"

        # Reload nginx with the real cert
        $COMPOSE $COMPOSE_FILES exec nginx nginx -s reload
        ok "Nginx reloaded with Let's Encrypt cert"

        echo ""
        warn "IMPORTANT: Set up automatic renewal with a cron job:"
        echo -e "  ${GRAY}# Add to crontab (crontab -e):${RESET}"
        echo -e "  ${GRAY}0 3 * * * cd ${SCRIPT_DIR} && ${COMPOSE} ${COMPOSE_FILES} run --rm certbot renew --quiet && ${COMPOSE} ${COMPOSE_FILES} exec nginx nginx -s reload${RESET}"
    else
        err "certbot failed — check DNS and firewall (port 80 must be reachable)"
        warn "You can retry manually:"
        echo -e "  ${GRAY}${COMPOSE} ${COMPOSE_FILES} run --rm certbot certonly --webroot --webroot-path=/var/www/certbot -d ${DOMAIN}${RESET}"
    fi
fi

# ═══════════════════════════════════════════════════════════════════════════════
# 7b. Load broker CA key into Vault
# ═══════════════════════════════════════════════════════════════════════════════
step "Loading broker key into Vault"

VAULT_ADDR="${VAULT_ADDR:-http://localhost:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-dev-root-token}"
VAULT_SECRET_PATH="${VAULT_SECRET_PATH:-secret/data/broker}"

echo "  Waiting for Vault to be ready..."
_VAULT_ATTEMPTS=0
until curl -sf "${VAULT_ADDR}/v1/sys/health" > /dev/null 2>&1; do
    _VAULT_ATTEMPTS=$((_VAULT_ATTEMPTS + 1))
    if [[ $_VAULT_ATTEMPTS -ge 20 ]]; then
        die "Vault did not start after 40s — check logs: $COMPOSE logs vault"
    fi
    sleep 2
done
ok "Vault is ready"

if [[ -f "$CERTS_DIR/broker-ca-key.pem" && -f "$CERTS_DIR/broker-ca.pem" ]]; then
    BROKER_KEY_PEM=$(cat "$CERTS_DIR/broker-ca-key.pem" | awk '{printf "%s\\n", $0}')
    BROKER_CERT_PEM=$(cat "$CERTS_DIR/broker-ca.pem" | awk '{printf "%s\\n", $0}')
    VAULT_PAYLOAD=$(printf '{"data":{"private_key_pem":"%s","ca_cert_pem":"%s"}}' \
        "$BROKER_KEY_PEM" "$BROKER_CERT_PEM")

    HTTP_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" \
        -X POST "${VAULT_ADDR}/v1/${VAULT_SECRET_PATH}" \
        -H "X-Vault-Token: ${VAULT_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "$VAULT_PAYLOAD" 2>&1)

    if [[ "$HTTP_STATUS" == "200" || "$HTTP_STATUS" == "204" ]]; then
        ok "Broker CA key stored in Vault at ${VAULT_SECRET_PATH}"
    else
        err "Failed to store broker key in Vault (HTTP ${HTTP_STATUS})"
        warn "Re-run this script (idempotent) or load the key manually with the Vault CLI"
    fi
else
    warn "Broker CA key not found at $CERTS_DIR/broker-ca-key.pem — skipping Vault load"
    warn "Generate it first: python generate_certs.py"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# 8. Wait for health check
# ═══════════════════════════════════════════════════════════════════════════════
step "Waiting for services"

# Wait for broker health
echo "  Waiting for broker..."
ATTEMPTS=0
until curl -sf http://localhost:8000/health > /dev/null 2>&1; do
    ATTEMPTS=$((ATTEMPTS + 1))
    if [[ $ATTEMPTS -ge 30 ]]; then
        die "Broker did not start after 60s — check logs: $COMPOSE logs broker"
    fi
    sleep 2
done
ok "Broker is healthy"

# Wait for nginx/HTTPS
echo "  Waiting for HTTPS..."
ATTEMPTS=0
if [[ "$MODE" == "development" ]]; then
    HEALTH_URL="https://localhost:8443/health"
    CURL_OPTS="-sfk"
else
    HEALTH_URL="https://${DOMAIN}/health"
    CURL_OPTS="-sf"
    # If using self-signed temp cert (pre-LE), allow insecure
    [[ "$USE_LETSENCRYPT" == "y" ]] || CURL_OPTS="-sf"
fi
until curl $CURL_OPTS "$HEALTH_URL" > /dev/null 2>&1; do
    ATTEMPTS=$((ATTEMPTS + 1))
    if [[ $ATTEMPTS -ge 15 ]]; then
        warn "HTTPS health check timed out — nginx may still be starting"
        break
    fi
    sleep 2
done
if [[ $ATTEMPTS -lt 15 ]]; then
    ok "HTTPS is ready"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# 9. Run Alembic migrations
# ═══════════════════════════════════════════════════════════════════════════════
step "Running database migrations"

BROKER_CONTAINER=$($COMPOSE ps -q broker 2>/dev/null || true)
if [[ -n "$BROKER_CONTAINER" ]]; then
    echo -e "  ${GRAY}alembic upgrade head${RESET}"
    if docker exec "$BROKER_CONTAINER" alembic upgrade head 2>&1; then
        ok "Migrations applied"
    else
        warn "Alembic migration failed — the broker may have applied them on startup"
    fi
else
    warn "Could not find broker container for migrations"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# 10. Summary
# ═══════════════════════════════════════════════════════════════════════════════
echo ""
echo -e "${GREEN}${BOLD}Deployment complete!${RESET}"
echo ""

if [[ "$MODE" == "development" ]]; then
    echo -e "  ${BOLD}Mode${RESET}        Development"
    echo -e "  ${BOLD}Dashboard${RESET}   ${GRAY}https://localhost:8443/dashboard${RESET}"
    echo -e "  ${BOLD}Broker${RESET}      ${GRAY}https://localhost:8443  (also http://localhost:8000 direct)${RESET}"
    echo -e "  ${BOLD}Vault${RESET}       ${GRAY}http://localhost:8200${RESET}"
    echo -e "  ${BOLD}Jaeger${RESET}      ${GRAY}http://localhost:16686${RESET}"
    echo ""
    echo "  Next steps:"
    echo "    1. Open the broker dashboard and log in with ADMIN_SECRET from .env"
    echo "    2. Generate an invite token for each organization"
    echo "    3. Deploy the MCP Proxy for each org:"
    echo "       ./deploy_proxy.sh"
    echo "    4. Each org opens their proxy dashboard, enters broker URL + invite token"
    echo ""
else
    echo -e "  ${BOLD}Mode${RESET}        Production"
    echo -e "  ${BOLD}Domain${RESET}      ${DOMAIN}"
    echo -e "  ${BOLD}Dashboard${RESET}   ${GRAY}https://${DOMAIN}/dashboard${RESET}"
    echo -e "  ${BOLD}Broker API${RESET}  ${GRAY}https://${DOMAIN}/v1/${RESET}"
    if [[ "$USE_LETSENCRYPT" == "y" ]]; then
        echo -e "  ${BOLD}TLS${RESET}         Let's Encrypt (auto-renew via cron)"
    else
        echo -e "  ${BOLD}TLS${RESET}         Enterprise CA"
    fi
    echo ""
    echo "  Next steps:"
    echo "    1. Verify dashboard login at https://${DOMAIN}/dashboard"
    echo "    2. Set up monitoring and log aggregation"
    echo "    3. Configure Vault for production (disable dev mode)"
    echo "    4. Set up backup for PostgreSQL data"
    if [[ "$USE_LETSENCRYPT" == "y" ]]; then
        echo "    5. Add certbot renewal cron job (see above)"
    fi
    echo ""
fi

echo "  Useful commands:"
echo "    $COMPOSE logs -f broker     # Follow broker logs"
echo "    $COMPOSE ps                 # Show container status"
echo "    $COMPOSE down               # Stop all containers"
echo "    $COMPOSE down -v            # Stop and remove volumes (data loss!)"
echo ""
