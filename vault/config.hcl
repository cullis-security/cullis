# =============================================================================
# HashiCorp Vault — Production Server Configuration
# =============================================================================
#
# Used by docker-compose.prod.yml to run Vault in production mode
# (replacing the default dev-mode server).
#
# Initialize Vault after first start:
#   ./vault/init-vault.sh
#

storage "file" {
  path = "/vault/data"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true   # TLS terminated by nginx reverse proxy in the same Docker network
}

ui = true

max_lease_ttl     = "768h"
default_lease_ttl = "768h"

# Disable mlock warning — IPC_LOCK capability is added via docker-compose
disable_mlock = false
