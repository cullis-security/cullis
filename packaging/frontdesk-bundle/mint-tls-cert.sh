#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# Cullis Frontdesk — Mint self-signed TLS cert for the nginx sidecar
# ═══════════════════════════════════════════════════════════════════════════════
#
# Generates a self-signed CA + server cert under ``./tls/``, used by
# the frontdesk-nginx sidecar to terminate TLS on port 8443. Runs
# inside a transient ``nginx:1.27-alpine`` container so the host needs
# no openssl install (same dependency-free posture as the Mastio
# bundle's ADR-014 cert lifecycle).
#
# Idempotent: if the cert already exists AND covers every SAN passed
# in, do nothing. SAN drift triggers a fresh mint.
#
# Usage:
#   ./mint-tls-cert.sh                              # uses default SAN
#   ./mint-tls-cert.sh --san "vps.example.com,1.2.3.4"
#   ./mint-tls-cert.sh --force                      # always remint
#
# Output (under ``./tls/``):
#   frontdesk-ca.crt   trust anchor (operator imports into browser to
#                      remove the self-signed warning, or just clicks
#                      through once and accepts the cert exception)
#   frontdesk-ca.key   CA private key (chmod 600, never published)
#   frontdesk-server.crt  leaf cert nginx serves on 8443
#   frontdesk-server.key  leaf private key (chmod 600)
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RED=$'\033[31m'
BOLD=$'\033[1m'; GRAY=$'\033[90m'; RESET=$'\033[0m'
ok()   { echo -e "  ${GREEN}\xe2\x9c\x93${RESET}  $1"; }
warn() { echo -e "  ${YELLOW}!${RESET}  $1"; }
err()  { echo -e "  ${RED}\xe2\x9c\x97${RESET}  $1"; }
die()  { err "$1"; exit 1; }

EXTRA_SAN=""
FORCE=0
NGINX_IMAGE="nginx:1.27-alpine"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --san)
            shift
            [[ $# -gt 0 && "$1" != --* ]] || die "--san requires a comma-separated list"
            EXTRA_SAN="$1"; shift ;;
        --san=*)   EXTRA_SAN="${1#--san=}"; shift ;;
        --force)   FORCE=1; shift ;;
        --help|-h)
            cat <<EOF
Usage: $0 [--san "host1,host2,1.2.3.4"] [--force]

Mints a self-signed TLS cert under ./tls/ for the frontdesk-nginx
sidecar to terminate HTTPS on port 8443.

  --san LIST    Comma-separated extra SAN entries (DNS names + IP
                literals). Default SANs always included:
                localhost, host.docker.internal, frontdesk.local,
                cullis-frontdesk-nginx, 127.0.0.1, ::1.
  --force       Regenerate even if cert already exists.

The cert is generated inside a transient ${NGINX_IMAGE} container
so the host needs no openssl install. Run by ./deploy.sh as part
of the standard bring-up when FRONTDESK_TLS=enabled (default).
EOF
            exit 0
            ;;
        *) die "Unknown argument: $1 (use --help)" ;;
    esac
done

TLS_DIR="$SCRIPT_DIR/tls"
CRT="$TLS_DIR/frontdesk-server.crt"
KEY="$TLS_DIR/frontdesk-server.key"
CA_CRT="$TLS_DIR/frontdesk-ca.crt"
CA_KEY="$TLS_DIR/frontdesk-ca.key"

# Build the SAN block. Default SANs cover every name a browser /
# Connector / sibling container may reach this sidecar at on a
# typical single-host deploy. EXTRA_SAN appended verbatim (operator
# adds their public hostname, VPS IP, etc).
DEFAULT_DNS="localhost host.docker.internal frontdesk.local cullis-frontdesk-nginx"
# IPv4 loopback only. openssl normalises ``::1`` to the expanded
# ``0:0:0:0:0:0:0:1`` form when reading the cert back, which breaks
# the SAN-drift idempotence check below if we write the shorthand.
# IPv6 loopback is rare on customer hosts; operators who need it
# pass it via --tls-san "::1" and that round-trip stays stable
# (--tls-san already classifies on ``*:*``).
DEFAULT_IP="127.0.0.1"

san_lines=""
for dns in $DEFAULT_DNS; do
    san_lines+="DNS:${dns},"
done
for ip in $DEFAULT_IP; do
    san_lines+="IP:${ip},"
done
if [[ -n "$EXTRA_SAN" ]]; then
    # Split on commas; each entry is classified as IP (parseable
    # numeric IPv4/IPv6) or DNS name. Same logic the Mastio's
    # agent_manager.emit_nginx_server_cert uses (RFC 5280: IP literals
    # MUST go in iPAddress SAN, not dNSName, or Python's ssl module
    # rejects them silently).
    IFS=',' read -ra extras <<< "$EXTRA_SAN"
    for raw in "${extras[@]}"; do
        entry="$(echo "$raw" | xargs)"  # trim whitespace
        [[ -z "$entry" ]] && continue
        # crude ipv4/ipv6 detection — good enough for SAN classification
        if [[ "$entry" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || [[ "$entry" == *:* ]]; then
            san_lines+="IP:${entry},"
        else
            san_lines+="DNS:${entry},"
        fi
    done
fi
san_lines="${san_lines%,}"

# Idempotence: if the cert exists, parse the SANs it carries and skip
# the mint when they already cover everything we'd write. ``--force``
# bypasses this. Runs openssl in the same nginx:alpine + apk-add path
# the mint step uses (host openssl is optional; the customer-real
# install path doesn't assume one).
if [[ $FORCE -eq 0 && -f "$CRT" && -f "$KEY" && -f "$CA_CRT" ]]; then
    existing_sans="$(
        docker run --rm -v "$TLS_DIR:/tls:ro" --entrypoint sh "$NGINX_IMAGE" -c '
            command -v openssl >/dev/null 2>&1 || apk add --no-cache openssl >/dev/null 2>&1
            openssl x509 -in /tls/frontdesk-server.crt -noout -ext subjectAltName 2>/dev/null | tail -n +2
        ' 2>/dev/null || true
    )"
    # openssl emits ``IP Address:`` but we write ``IP:`` in the
    # extfile. Normalise both sides to the same shape (drop spaces,
    # collapse ``IP Address:`` -> ``IP:``) so the comparison is
    # apples-to-apples.
    normalise() { echo "$1" | tr -d ' \n' | sed 's/IPAddress:/IP:/g'; }
    want="$(normalise "$san_lines")"
    have="$(normalise "$existing_sans")"
    # Every entry from the requested list must already appear in the
    # cert's SAN list. The cert may carry additional SANs from a past
    # mint that requested more — that's a no-op, not a drift.
    all_present=1
    IFS=',' read -ra want_parts <<< "$want"
    for part in "${want_parts[@]}"; do
        [[ -z "$part" ]] && continue
        case ",${have}," in
            *",${part},"*) ;;
            *) all_present=0; break ;;
        esac
    done
    if [[ -n "$existing_sans" && $all_present -eq 1 ]]; then
        ok "TLS cert already covers requested SANs, reusing ${CRT}"
        exit 0
    fi
    warn "Existing TLS cert SAN list differs from request, regenerating"
fi

mkdir -p "$TLS_DIR"

# Run openssl in nginx:alpine (already pulled by the bundle, has
# openssl 3.x baked in). The container writes into the bind-mounted
# /tls dir; chmod 0600 on the keys to satisfy nginx's strict-perm
# warnings on hostpath mounts.
#
# Quoting note: the inner sh -c body is wrapped in single quotes so
# the OUTER bash (which runs with set -u) does NOT try to expand
# ``$SAN_LINES`` — that variable only exists inside the container, set
# via ``-e``. The cert extension file is then rendered from a heredoc
# expanded by the inner sh, which DOES see SAN_LINES.
docker run --rm \
    -v "$TLS_DIR:/tls" \
    -e SAN_LINES="$san_lines" \
    --entrypoint sh \
    "$NGINX_IMAGE" -c '
        set -e
        # nginx:1.27-alpine ships busybox ssl_client only, not the
        # full openssl binary we need for x509 + CSR signing. ``apk
        # add openssl`` lands ~5 MB in the ephemeral container layer
        # (gone the moment the --rm container exits). On a customer
        # host with no openssl this is the same as installing it on
        # the host, only without polluting /usr/bin.
        if ! command -v openssl >/dev/null 2>&1; then
            apk add --no-cache openssl >/dev/null 2>&1 \
                || { echo "apk add openssl failed inside nginx:alpine"; exit 1; }
        fi
        cd /tls

        # ── 1. Self-signed CA (10 years; not in any browser trust
        #       store, the operator clicks through once or imports
        #       frontdesk-ca.crt). ──
        if [ ! -f frontdesk-ca.crt ] || [ ! -f frontdesk-ca.key ]; then
            openssl req -x509 -nodes -newkey rsa:4096 -days 3650 \
                -subj "/CN=Cullis Frontdesk Local CA" \
                -keyout frontdesk-ca.key \
                -out    frontdesk-ca.crt >/dev/null 2>&1
        fi

        # ── 2. Server CSR + leaf cert signed by the CA, 825 days
        #       (Apple Safari rejects leaf certs with longer
        #       validity since iOS 13). ──
        openssl req -new -nodes -newkey rsa:2048 \
            -subj "/CN=cullis-frontdesk" \
            -keyout frontdesk-server.key \
            -out    frontdesk-server.csr >/dev/null 2>&1

        # Heredoc expands $SAN_LINES inside the container (env var
        # passed via -e to docker run above). Unquoted EOF == expand.
        cat > server-ext.cnf <<EOF
authorityKeyIdentifier = keyid,issuer
basicConstraints = critical,CA:FALSE
keyUsage = digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = ${SAN_LINES}
EOF

        openssl x509 -req -in frontdesk-server.csr \
            -CA  frontdesk-ca.crt \
            -CAkey frontdesk-ca.key \
            -CAcreateserial \
            -days 825 \
            -extfile server-ext.cnf \
            -out frontdesk-server.crt >/dev/null 2>&1

        rm -f frontdesk-server.csr frontdesk-ca.srl server-ext.cnf

        chmod 0644 frontdesk-server.crt frontdesk-ca.crt
        chmod 0600 frontdesk-server.key frontdesk-ca.key
    ' || die "TLS cert generation failed inside ${NGINX_IMAGE} container"

ok "Minted TLS cert under ${TLS_DIR}/"
echo -e "    ${GRAY}frontdesk-server.crt    leaf cert (SAN: ${san_lines//,/, })${RESET}"
echo -e "    ${GRAY}frontdesk-server.key    leaf key (chmod 600)${RESET}"
echo -e "    ${GRAY}frontdesk-ca.crt        local CA — import into browser to silence the warning${RESET}"
