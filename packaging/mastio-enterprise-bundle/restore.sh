#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# Cullis Mastio Enterprise — restore from backup.sh output
# ═══════════════════════════════════════════════════════════════════════════════
#
# Reverses backup.sh: decrypts the .tar.gz.gpg archive, verifies SHA256
# checksums against the manifest, stops the running stack (if any),
# replaces ./data + ./nginx-certs + ./saml-keys with the snapshot,
# restores proxy.env (with license JWT marked REDACTED — operator must
# re-paste the JWT before bringing the stack up), and prints next steps.
#
# Usage:
#   ./restore.sh /path/to/cullis-mastio-enterprise-backup-*.tar.gz.gpg
#   ./restore.sh /path/to/... --passphrase-file /path/to/pass
#
# Safety: refuses to clobber an existing data/ dir unless --force is
# explicit (avoids accidental overwrite of a running production
# deploy).
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

BACKUP_FILE=""
PASSPHRASE_FILE=""
FORCE=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --passphrase-file)  PASSPHRASE_FILE="$2"; shift 2 ;;
        --passphrase-file=*) PASSPHRASE_FILE="${1#--passphrase-file=}"; shift ;;
        --force)            FORCE=1; shift ;;
        -h|--help)
            sed -n '2,25p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *)
            if [[ -z "$BACKUP_FILE" ]]; then
                BACKUP_FILE="$1"
            fi
            shift
            ;;
    esac
done

[[ -n "$BACKUP_FILE" ]] || die "usage: $0 <backup.tar.gz.gpg> [--passphrase-file PATH] [--force]"
[[ -f "$BACKUP_FILE" ]] || die "backup file not found: $BACKUP_FILE"

# ── pre-flight ──────────────────────────────────────────────────────────────
step "pre-flight"
command -v gpg >/dev/null || die "gpg not in PATH. Install: nix-shell -p gnupg"
command -v tar >/dev/null || die "tar not in PATH"
command -v sha256sum >/dev/null || die "sha256sum not in PATH"

WORK_DIR="$(mktemp -d -t cullis-restore-XXXXXX)"
trap 'rm -rf "$WORK_DIR"' EXIT
ok "work dir: $WORK_DIR"

# ── decrypt ─────────────────────────────────────────────────────────────────
step "decrypt"
TARBALL="$WORK_DIR/backup.tar.gz"
if [[ -n "$PASSPHRASE_FILE" ]]; then
    [[ -r "$PASSPHRASE_FILE" ]] || die "passphrase file unreadable: $PASSPHRASE_FILE"
    gpg --batch --yes --pinentry-mode loopback \
        --passphrase-file "$PASSPHRASE_FILE" \
        --decrypt --output "$TARBALL" \
        "$BACKUP_FILE" 2>/dev/null \
        || die "decryption failed (wrong passphrase or corrupt file)"
else
    echo "  Enter passphrase to decrypt the backup."
    gpg --decrypt --output "$TARBALL" "$BACKUP_FILE" 2>/dev/null \
        || die "decryption failed (wrong passphrase or corrupt file)"
fi
ok "decrypted"

# ── extract ─────────────────────────────────────────────────────────────────
step "extract"
EXTRACT="$WORK_DIR/extract"
mkdir -p "$EXTRACT"
tar -xzf "$TARBALL" -C "$EXTRACT"
ok "extracted to $EXTRACT"

[[ -f "$EXTRACT/MANIFEST.txt" ]] || die "MANIFEST.txt missing — not a Cullis backup"

# ── verify integrity ────────────────────────────────────────────────────────
step "verify SHA256 checksums against MANIFEST"
cd "$EXTRACT"
if grep -A 9999 '^SHA256 checksums:$' MANIFEST.txt | tail -n +2 | grep -E '^[0-9a-f]{64}' \
   | sha256sum -c --strict --quiet; then
    ok "all checksums verified"
else
    die "checksum mismatch — backup tampered or corrupt"
fi
cd "$SCRIPT_DIR"

# ── safety: existing state ──────────────────────────────────────────────────
step "safety check"
if [[ -d data && -n "$(ls -A data 2>/dev/null || true)" ]] && [[ "$FORCE" != "1" ]]; then
    err "./data/ is not empty (live deploy?). Refusing to overwrite without --force."
    err "Inspect with: ls -la data/ nginx-certs/ saml-keys/"
    err "If safe to proceed: ./restore.sh \"$BACKUP_FILE\" --force"
    exit 1
fi

# ── stop stack if running ───────────────────────────────────────────────────
step "stop stack (if running)"
if docker compose -p cullis-mastio-enterprise ps --quiet 2>/dev/null | grep -q .; then
    docker compose --env-file proxy.env -p cullis-mastio-enterprise down 2>&1 | tail -3
    ok "stack stopped"
else
    ok "no stack running"
fi

# ── restore files into bind mounts ──────────────────────────────────────────
step "restore bind-mount contents"
# Clean (only if --force AND state exists), then copy
[[ -d data ]] && rm -rf data
[[ -d nginx-certs ]] && rm -rf nginx-certs
[[ -d saml-keys ]] && rm -rf saml-keys

cp -r "$EXTRACT/data" ./data 2>/dev/null || warn "no data/ in backup (clean restore on fresh host)"
cp -r "$EXTRACT/nginx-certs" ./nginx-certs
[[ -d "$EXTRACT/saml-keys" ]] && cp -r "$EXTRACT/saml-keys" ./saml-keys
ok "bind-mount contents restored"

# proxy.env handling: never auto-overwrite, since license JWT is REDACTED
# in the backup and the operator's local copy may already have the
# correct JWT. Provide as side-file for inspection.
if [[ -f proxy.env ]]; then
    cp "$EXTRACT/proxy.env" proxy.env.restored
    warn "proxy.env preserved; backup copy written to proxy.env.restored for diff"
    warn "If you want to use the backup version, run:"
    warn "  diff proxy.env proxy.env.restored"
    warn "  mv proxy.env.restored proxy.env  # if you want to adopt"
    warn "  then re-paste CULLIS_LICENSE_KEY (the JWT is REDACTED in backup)"
else
    cp "$EXTRACT/proxy.env" proxy.env
    warn "proxy.env restored from backup."
    warn "CRITICAL: CULLIS_LICENSE_KEY is REDACTED. Edit proxy.env and paste"
    warn "the JWT from your Bitwarden / 1Password / etc. before ./deploy.sh."
fi

# ── final ───────────────────────────────────────────────────────────────────
echo
echo -e "${BOLD}Restore complete${RESET}"
echo "  Backup:  $BACKUP_FILE"
echo "  Manifest entries: $(wc -l < "$EXTRACT/MANIFEST.txt") lines"
echo
echo "Next steps:"
echo "  1. Verify CULLIS_LICENSE_KEY in proxy.env is a valid JWT (not REDACTED)"
echo "  2. ./deploy.sh"
echo "  3. Verify post-boot:  docker compose -p cullis-mastio-enterprise logs mcp-proxy | grep license:"
echo
echo -e "${YELLOW}If JWT was issued more than 90 days before the backup, request a fresh one from hello@cullis.io.${RESET}"
