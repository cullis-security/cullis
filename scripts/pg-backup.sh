#!/usr/bin/env bash
# pg-backup.sh — Automated PostgreSQL backup for Agent Trust Network
# Usage: ./scripts/pg-backup.sh
#
# Runs pg_dump via the postgres container, compresses with gzip,
# saves to backups/ with a timestamp, and prunes backups older than 30.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BACKUP_DIR="${PROJECT_DIR}/backups"
TIMESTAMP="$(date +%Y-%m-%d_%H%M%S)"
BACKUP_FILE="atn_${TIMESTAMP}.sql.gz"
KEEP_COUNT=30

# Postgres credentials — reads from .env or falls back to compose defaults
if [ -f "${PROJECT_DIR}/.env" ]; then
    # shellcheck disable=SC1091
    set -a; source "${PROJECT_DIR}/.env"; set +a
fi
PG_USER="${POSTGRES_USER:-atn}"
PG_DB="${POSTGRES_DB:-agent_trust}"

# Ensure backup directory exists
mkdir -p "${BACKUP_DIR}"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

# Run pg_dump inside the postgres container, compress, save to host
log "Starting backup: ${BACKUP_FILE}"
if docker compose -f "${PROJECT_DIR}/docker-compose.yml" exec -T postgres \
    pg_dump -U "${PG_USER}" "${PG_DB}" | gzip > "${BACKUP_DIR}/${BACKUP_FILE}"; then
    SIZE=$(du -h "${BACKUP_DIR}/${BACKUP_FILE}" | cut -f1)
    log "Backup successful: ${BACKUP_FILE} (${SIZE})"
else
    log "ERROR: Backup failed!"
    rm -f "${BACKUP_DIR}/${BACKUP_FILE}"
    exit 1
fi

# Verify the backup is not empty
if [ ! -s "${BACKUP_DIR}/${BACKUP_FILE}" ]; then
    log "ERROR: Backup file is empty, removing"
    rm -f "${BACKUP_DIR}/${BACKUP_FILE}"
    exit 1
fi

# Prune old backups — keep only the most recent $KEEP_COUNT
BACKUP_COUNT=$(find "${BACKUP_DIR}" -maxdepth 1 -name 'atn_*.sql.gz' -type f | wc -l)
if [ "${BACKUP_COUNT}" -gt "${KEEP_COUNT}" ]; then
    DELETE_COUNT=$((BACKUP_COUNT - KEEP_COUNT))
    log "Pruning ${DELETE_COUNT} old backup(s) (keeping ${KEEP_COUNT})"
    find "${BACKUP_DIR}" -maxdepth 1 -name 'atn_*.sql.gz' -type f -printf '%T+ %p\n' \
        | sort | head -n "${DELETE_COUNT}" | awk '{print $2}' \
        | xargs rm -f
fi

log "Done. ${BACKUP_COUNT} backup(s) in ${BACKUP_DIR}"
