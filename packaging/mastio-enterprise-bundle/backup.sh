#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# Cullis Mastio Enterprise — backup
# ═══════════════════════════════════════════════════════════════════════════════
#
# Produces an encrypted tarball of all per-deploy state:
#
#   - SQLite DB (data/mcp_proxy.db) via hot `.backup` so the live
#     proxy does not need to stop. Snapshot is consistent.
#   - Org CA + nginx server cert (nginx-certs/), the trust root for
#     every agent + Connector user issued under this Mastio.
#   - SAML SP signing keypair (saml-keys/), if the saml_sso plugin is
#     active.
#   - proxy.env with the CULLIS_LICENSE_KEY value REDACTED (the JWT
#     itself is recoverable from Cullis Security; what we want to
#     preserve here is the operator-side config: PUBLIC_URL,
#     plugin envs, secret refs, custom MCP_PROXY_* tuning).
#
# Output: a single `.tar.gz.gpg` file encrypted with a symmetric
# passphrase prompted from the operator (AES256). The file is safe
# to copy off-host (S3, rsync, USB) — without the passphrase it is
# opaque ciphertext.
#
# Usage:
#   ./backup.sh                              # interactive, output ./backups/
#   ./backup.sh --out /path/to/dir           # custom output dir
#   ./backup.sh --passphrase-file path       # non-interactive (cron)
#
# Restore: ./restore.sh path/to/backup.tar.gz.gpg
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── colour helpers ──────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    BOLD="\033[1m"; RED="\033[31m"; GREEN="\033[32m"; YELLOW="\033[33m"; RESET="\033[0m"
else
    BOLD=""; RED=""; GREEN=""; YELLOW=""; RESET=""
fi
ok()   { echo -e "  ${GREEN}✓${RESET}  $1"; }
warn() { echo -e "  ${YELLOW}!${RESET}  $1"; }
err()  { echo -e "  ${RED}✗${RESET}  $1"; }
die()  { err "$1"; exit 1; }
step() { echo -e "\n${BOLD}── $1 ──${RESET}"; }

OUT_DIR="$SCRIPT_DIR/backups"
PASSPHRASE_FILE=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --out)              OUT_DIR="$2"; shift 2 ;;
        --out=*)            OUT_DIR="${1#--out=}"; shift ;;
        --passphrase-file)  PASSPHRASE_FILE="$2"; shift 2 ;;
        --passphrase-file=*) PASSPHRASE_FILE="${1#--passphrase-file=}"; shift ;;
        -h|--help)
            sed -n '2,30p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *) die "unknown arg: $1 (use --help)" ;;
    esac
done

# ── pre-flight ──────────────────────────────────────────────────────────────
step "pre-flight"
command -v gpg >/dev/null    || die "gpg not in PATH. Install: nix-shell -p gnupg"
command -v sqlite3 >/dev/null || warn "sqlite3 not in PATH; falling back to file copy (still consistent if proxy is idle)"
command -v tar >/dev/null    || die "tar not in PATH"

[[ -f proxy.env ]] || die "proxy.env missing in $SCRIPT_DIR"
[[ -d data ]]      || die "./data/ missing (bundle never deployed?)"
[[ -d nginx-certs ]] || die "./nginx-certs/ missing"

mkdir -p "$OUT_DIR"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
WORK_DIR="$(mktemp -d -t cullis-backup-XXXXXX)"
trap 'rm -rf "$WORK_DIR"' EXIT
ok "work dir: $WORK_DIR"

# ── snapshot SQLite (hot) ───────────────────────────────────────────────────
step "snapshot mcp_proxy.db (hot via sqlite3 .backup)"
STAGE="$WORK_DIR/stage"
mkdir -p "$STAGE/data"
if command -v sqlite3 >/dev/null && [[ -f data/mcp_proxy.db ]]; then
    sqlite3 "data/mcp_proxy.db" ".backup '$STAGE/data/mcp_proxy.db'"
    ok "SQLite hot backup OK ($(du -h "$STAGE/data/mcp_proxy.db" | cut -f1))"
elif [[ -f data/mcp_proxy.db ]]; then
    # No sqlite3 on host? Cold copy. Best-effort; warn operator.
    warn "sqlite3 unavailable, falling back to cp; ensure low write activity"
    cp data/mcp_proxy.db "$STAGE/data/mcp_proxy.db"
    ok "cold copy OK"
else
    warn "data/mcp_proxy.db missing (proxy never booted?) — skipping DB"
fi

# ── stage certs + saml + redacted config ───────────────────────────────────
step "stage certs + saml keys + redacted proxy.env"
cp -r nginx-certs "$STAGE/nginx-certs"
ok "nginx-certs/ staged ($(du -sh "$STAGE/nginx-certs" | cut -f1))"

if [[ -d saml-keys ]]; then
    cp -r saml-keys "$STAGE/saml-keys"
    ok "saml-keys/ staged"
else
    warn "saml-keys/ absent (saml_sso plugin not enabled, OK to skip)"
fi

# Redact CULLIS_LICENSE_KEY before archiving; preserve everything else.
# The license JWT itself comes back from Cullis Security at restore time
# (it is the customer's contract artefact, re-issuable). We do NOT want
# to bake the JWT into the backup; if backup is exfiltrated the licensee
# secret stays protected.
sed -E 's|^(CULLIS_LICENSE_KEY=).*|\1<REDACTED-RECOVER-FROM-CULLIS-SECURITY>|' proxy.env > "$STAGE/proxy.env"
ok "proxy.env redacted + staged (license JWT removed)"

# ── manifest with metadata + integrity ──────────────────────────────────────
step "manifest"
MANIFEST="$STAGE/MANIFEST.txt"
{
    echo "Cullis Mastio Enterprise backup"
    echo "Bundle path:    $SCRIPT_DIR"
    echo "Backup taken:   $TIMESTAMP"
    echo "Bundle version: $(grep -E '^CULLIS_MASTIO_VERSION=' proxy.env | cut -d= -f2 || echo 'unknown')"
    echo "Host:           $(hostname -f 2>/dev/null || hostname)"
    echo ""
    echo "Contents:"
    (cd "$STAGE" && find . -type f -printf '  %p  (%s bytes)\n' | sort)
    echo ""
    echo "SHA256 checksums:"
    (cd "$STAGE" && find . -type f -not -name MANIFEST.txt -print0 | xargs -0 sha256sum)
} > "$MANIFEST"
ok "manifest written ($(wc -l < "$MANIFEST") lines)"

# ── pack ────────────────────────────────────────────────────────────────────
step "pack tar.gz"
TARBALL="$WORK_DIR/backup.tar.gz"
tar -czf "$TARBALL" -C "$STAGE" .
ok "tarball $(du -h "$TARBALL" | cut -f1)"

# ── encrypt gpg --symmetric AES256 ──────────────────────────────────────────
step "encrypt (gpg --symmetric AES256)"
OUT_FILE="$OUT_DIR/cullis-mastio-enterprise-backup-${TIMESTAMP}.tar.gz.gpg"

if [[ -n "$PASSPHRASE_FILE" ]]; then
    [[ -r "$PASSPHRASE_FILE" ]] || die "passphrase file unreadable: $PASSPHRASE_FILE"
    gpg --batch --yes --pinentry-mode loopback \
        --passphrase-file "$PASSPHRASE_FILE" \
        --symmetric --cipher-algo AES256 \
        --output "$OUT_FILE" \
        "$TARBALL"
else
    echo "  Enter passphrase to encrypt the backup (will be prompted twice)."
    echo "  Store it somewhere safe — without it the backup is unrecoverable."
    gpg --symmetric --cipher-algo AES256 \
        --output "$OUT_FILE" \
        "$TARBALL"
fi
chmod 600 "$OUT_FILE"
ok "encrypted: $OUT_FILE ($(du -h "$OUT_FILE" | cut -f1))"

# ── final report ────────────────────────────────────────────────────────────
echo
echo -e "${BOLD}Backup complete${RESET}"
echo "  File:     $OUT_FILE"
echo "  Mode:     $(stat -c '%a' "$OUT_FILE")"
echo "  Restore:  ./restore.sh \"$OUT_FILE\""
echo
echo -e "${YELLOW}Off-host copy recommended:${RESET}"
echo "  Examples (pick one):"
echo "    rsync -a \"$OUT_FILE\" backup-target:/var/backups/cullis/"
echo "    aws s3 cp \"$OUT_FILE\" s3://your-backup-bucket/cullis/"
echo "    scp \"$OUT_FILE\" your.usb.mount:/path/"
echo
echo "  The encrypted file is safe to transmit. The passphrase is the"
echo "  ONLY secret — store it apart from the backup (1Password,"
echo "  Bitwarden, etc.). Both lost = backup unrecoverable."
