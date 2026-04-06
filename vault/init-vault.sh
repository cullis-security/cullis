#!/usr/bin/env bash
# =============================================================================
# Vault Production Initialization Script
# =============================================================================
#
# Run ONCE after the first production deploy to initialize and unseal Vault.
#
# Usage:
#   ./vault/init-vault.sh
#
# Prerequisites:
#   - Vault container running in production mode (not dev)
#   - VAULT_ADDR set (default: http://127.0.0.1:8200)
#   - vault CLI and jq installed
#
set -euo pipefail

VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
export VAULT_ADDR

KEYS_FILE="$(dirname "$0")/vault-keys.json"

echo "==> Vault address: ${VAULT_ADDR}"

# ── Wait for Vault to be reachable ──────────────────────────────────────────
echo "==> Waiting for Vault to be ready..."
for i in $(seq 1 30); do
    if vault status -address="${VAULT_ADDR}" >/dev/null 2>&1; then
        break
    fi
    # Vault returns exit code 2 when sealed but reachable — that's fine
    if vault status -address="${VAULT_ADDR}" 2>&1 | grep -q "Seal Type"; then
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "ERROR: Vault not reachable after 30 attempts"
        exit 1
    fi
    sleep 2
done
echo "==> Vault is reachable."

# ── Check if already initialized ────────────────────────────────────────────
if vault status -address="${VAULT_ADDR}" 2>&1 | grep -q '"initialized": true\|Initialized.*true'; then
    echo "==> Vault is already initialized."

    # If sealed, try to unseal with existing keys file
    if vault status -address="${VAULT_ADDR}" 2>&1 | grep -q '"sealed": true\|Sealed.*true'; then
        if [ -f "${KEYS_FILE}" ]; then
            echo "==> Vault is sealed — unsealing with saved keys..."
            for i in 0 1 2; do
                KEY=$(jq -r ".unseal_keys_b64[$i]" "${KEYS_FILE}")
                vault operator unseal -address="${VAULT_ADDR}" "${KEY}" >/dev/null
            done
            echo "==> Vault unsealed successfully."
        else
            echo "ERROR: Vault is sealed but no keys file found at ${KEYS_FILE}"
            echo "       Provide unseal keys manually: vault operator unseal"
            exit 1
        fi
    else
        echo "==> Vault is already unsealed. Nothing to do."
    fi
    exit 0
fi

# ── Initialize Vault ────────────────────────────────────────────────────────
echo "==> Initializing Vault (5 key shares, threshold 3)..."
vault operator init \
    -address="${VAULT_ADDR}" \
    -key-shares=5 \
    -key-threshold=3 \
    -format=json > "${KEYS_FILE}"

chmod 600 "${KEYS_FILE}"
echo "==> Keys saved to ${KEYS_FILE} (mode 600)"

# ── Unseal with 3 of 5 keys ────────────────────────────────────────────────
echo "==> Unsealing Vault..."
for i in 0 1 2; do
    KEY=$(jq -r ".unseal_keys_b64[$i]" "${KEYS_FILE}")
    vault operator unseal -address="${VAULT_ADDR}" "${KEY}" >/dev/null
done
echo "==> Vault unsealed successfully."

# ── Authenticate with root token ────────────────────────────────────────────
ROOT_TOKEN=$(jq -r ".root_token" "${KEYS_FILE}")
export VAULT_TOKEN="${ROOT_TOKEN}"

# ── Enable KV v2 secrets engine ─────────────────────────────────────────────
echo "==> Enabling KV v2 secrets engine at secret/..."
vault secrets enable -address="${VAULT_ADDR}" -path=secret kv-v2 2>/dev/null || \
    echo "    (secret/ engine already enabled)"

echo ""
echo "============================================================"
echo "  Vault initialized and unsealed successfully!"
echo "============================================================"
echo ""
echo "  Root token: ${ROOT_TOKEN}"
echo ""
echo "  Set this in your .env file:"
echo "    VAULT_TOKEN=${ROOT_TOKEN}"
echo ""
echo "  WARNING: Store the unseal keys and root token securely!"
echo "  Consider using a password manager, HSM, or cloud KMS."
echo "  DELETE ${KEYS_FILE} after securely backing up the keys."
echo ""
echo "  Next steps:"
echo "    1. Store the broker CA key in Vault:"
echo "       vault kv put secret/broker \\"
echo "         private_key_pem=@certs/broker-ca-key.pem \\"
echo "         ca_cert_pem=@certs/broker-ca.pem"
echo ""
echo "    2. Revoke the root token after creating limited-scope tokens:"
echo "       vault token revoke \${VAULT_TOKEN}"
echo "============================================================"
