#!/usr/bin/env bash
# Generate self-signed TLS certificate for nginx (demo/dev only)
set -e

DIR="$(cd "$(dirname "$0")" && pwd)/certs"
mkdir -p "$DIR"

if [ -f "$DIR/server.pem" ] && [ -f "$DIR/server-key.pem" ]; then
    echo "  TLS cert already exists — skip"
    exit 0
fi

openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$DIR/server-key.pem" \
    -out "$DIR/server.pem" \
    -days 365 \
    -subj "/CN=localhost/O=ATN Dev" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
    2>/dev/null

echo "  TLS cert generated: $DIR/server.pem"
