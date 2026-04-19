#!/usr/bin/env bash
# Generates a per-org Broker CA (RSA-4096) used by Cullis to sign organization
# subordinate CAs. One CA per org (orga/orgb). Idempotent: skip if valid cert
# already present with >30d validity.
set -euo pipefail

ORG_ID="${ORG_ID:?ORG_ID env required}"
OUT="${OUT_DIR:-/broker-certs}"
mkdir -p "$OUT"

CERT="$OUT/broker-ca.pem"
KEY="$OUT/broker-ca-key.pem"

if [[ -f "$CERT" && -f "$KEY" ]] && openssl x509 -in "$CERT" -noout -checkend $((30*24*3600)) >/dev/null 2>&1; then
    echo "[broker-ca-init:$ORG_ID] existing CA valid, skipping"
    exit 0
fi

umask 077

openssl genrsa -out "$KEY" 4096 2>/dev/null
openssl req -x509 -new -nodes -key "$KEY" -sha256 -days 3650 \
    -subj "/CN=Cullis Broker CA ($ORG_ID)/O=$ORG_ID" \
    -out "$CERT"

chmod 644 "$CERT"
# Broker runs as non-root; local KMS derives encryption key from this PEM
# and needs read access. World-readable is acceptable in sandbox since the
# CA is ephemeral test material (not a real production key).
chmod 644 "$KEY"

echo "[broker-ca-init:$ORG_ID] generated broker CA"
openssl x509 -in "$CERT" -noout -subject -dates
