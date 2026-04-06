#!/usr/bin/env bash
# pg-restore.sh — Restore PostgreSQL backup for Agent Trust Network
# Usage: ./scripts/pg-restore.sh backups/atn_2026-04-06_030000.sql.gz
#
# Accepts a .sql.gz or .sql backup file and restores it into the
# running postgres container.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Postgres credentials — reads from .env or falls back to compose defaults
if [ -f "${PROJECT_DIR}/.env" ]; then
    # shellcheck disable=SC1091
    set -a; source "${PROJECT_DIR}/.env"; set +a
fi
PG_USER="${POSTGRES_USER:-atn}"
PG_DB="${POSTGRES_DB:-agent_trust}"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

if [ $# -lt 1 ]; then
    echo "Usage: $0 <backup-file>"
    echo "  e.g. $0 backups/atn_2026-04-06_030000.sql.gz"
    exit 1
fi

BACKUP_FILE="$1"

if [ ! -f "${BACKUP_FILE}" ]; then
    log "ERROR: File not found: ${BACKUP_FILE}"
    exit 1
fi

log "WARNING: This will drop and recreate all tables in '${PG_DB}'."
read -r -p "Continue? [y/N] " confirm
if [[ ! "${confirm}" =~ ^[Yy]$ ]]; then
    log "Aborted."
    exit 0
fi

# Determine if compressed
if [[ "${BACKUP_FILE}" == *.gz ]]; then
    log "Restoring from compressed backup: ${BACKUP_FILE}"
    gunzip -c "${BACKUP_FILE}" | docker compose -f "${PROJECT_DIR}/docker-compose.yml" \
        exec -T postgres psql -U "${PG_USER}" -d "${PG_DB}" --single-transaction
else
    log "Restoring from backup: ${BACKUP_FILE}"
    docker compose -f "${PROJECT_DIR}/docker-compose.yml" \
        exec -T postgres psql -U "${PG_USER}" -d "${PG_DB}" --single-transaction < "${BACKUP_FILE}"
fi

if [ $? -eq 0 ]; then
    log "Restore successful."
else
    log "ERROR: Restore failed!"
    exit 1
fi
