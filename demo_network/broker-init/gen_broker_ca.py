"""
Minimal broker-CA bootstrap for the demo network.

Generates a self-signed broker root CA (RSA-4096, 10y) at
/broker-certs/broker-ca.pem + broker-ca-key.pem, idempotent.
The broker container mounts this volume read-only.

If VAULT_ADDR + VAULT_TOKEN are set we also push the private key PEM and
the public key PEM into Vault at VAULT_SECRET_PATH, because the broker
with KMS_BACKEND=vault reads them from there at startup (smoke runs in
prod-like mode with Vault enabled).

Deliberately standalone — avoids pulling the full app package into the
init container, so this service has a tiny image and no app-code churn
risk.
"""
import datetime
import os
import pathlib
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

# PKI_KEY_TYPE=rsa (default) | ec → drives the broker CA key algorithm.
# Lets the smoke-all-ecc CI variant bootstrap a fully-ECC demo stack
# without rebuilding images.
PKI_KEY_TYPE = os.environ.get("PKI_KEY_TYPE", "rsa").strip().lower()

OUT = pathlib.Path("/broker-certs")
OUT.mkdir(parents=True, exist_ok=True)
KEY = OUT / "broker-ca-key.pem"
CRT = OUT / "broker-ca.pem"


def _maybe_push_to_vault(priv_pem: bytes, pub_pem: bytes) -> None:
    """Push broker keys to Vault at VAULT_SECRET_PATH if Vault is configured.

    The Vault token is read from VAULT_TOKEN_FILE (preferred) or VAULT_TOKEN
    env. The file path comes from vault-init which wrote a broker-scoped
    token, so the root token never enters this container.
    """
    vault_addr = os.environ.get("VAULT_ADDR", "")
    token_file = os.environ.get("VAULT_TOKEN_FILE", "")
    vault_token = ""
    if token_file and pathlib.Path(token_file).exists():
        vault_token = pathlib.Path(token_file).read_text().strip()
    else:
        vault_token = os.environ.get("VAULT_TOKEN", "")

    secret_path = os.environ.get("VAULT_SECRET_PATH", "secret/data/broker")
    if not vault_addr or not vault_token:
        print("broker-init: VAULT_ADDR/VAULT_TOKEN(_FILE) not set, skipping Vault push")
        return

    import httpx
    import time

    url = f"{vault_addr.rstrip('/')}/v1/{secret_path}"
    data_fields = {
        "private_key_pem": priv_pem.decode(),
        "public_key_pem":  pub_pem.decode(),
    }
    # Pre-seed the admin password so the broker skips /dashboard/setup on
    # first boot. The smoke logs in programmatically with curl — this keeps
    # it single-shot after the setup-first-no-login flow landed. Tied to
    # ADMIN_SECRET via an env var so demo/prod deployments stay aligned.
    seed_pw = os.environ.get("SEED_BROKER_ADMIN_PASSWORD", "")
    if seed_pw:
        import bcrypt
        pw_hash = bcrypt.hashpw(
            seed_pw.encode(), bcrypt.gensalt(rounds=10)
        ).decode()
        data_fields["admin_secret_hash"] = pw_hash
        data_fields["admin_password_user_set"] = "true"
    body = {"data": data_fields}
    # Respect a caller-supplied CA bundle (test CA + Vault CA merged).
    ca_bundle = os.environ.get("SSL_CERT_FILE") or True
    last_exc: Exception | None = None
    for attempt in range(20):
        try:
            r = httpx.post(url, json=body,
                           headers={"X-Vault-Token": vault_token},
                           verify=ca_bundle,
                           timeout=5.0)
            if r.status_code in (200, 204):
                print(f"broker-init: pushed broker keys to Vault at {secret_path}")
                return
            last_exc = RuntimeError(f"HTTP {r.status_code}: {r.text[:200]}")
        except Exception as exc:
            last_exc = exc
        time.sleep(1)
    raise SystemExit(f"broker-init: Vault push failed after retries: {last_exc}")


if KEY.exists() and CRT.exists():
    print(f"broker-init: CA already present at {OUT}, re-using for Vault push")
    priv_existing = KEY.read_bytes()
    cert_existing = CRT.read_bytes()
    cert_obj = x509.load_pem_x509_certificate(cert_existing)
    pub_existing = cert_obj.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    _maybe_push_to_vault(priv_existing, pub_existing)
    sys.exit(0)

if PKI_KEY_TYPE == "ec":
    print("broker-init: generating broker root CA (ECDSA P-256)")
    key = ec.generate_private_key(ec.SECP256R1())
elif PKI_KEY_TYPE == "rsa":
    print("broker-init: generating broker root CA (RSA-4096)")
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
else:
    raise SystemExit(f"broker-init: unsupported PKI_KEY_TYPE={PKI_KEY_TYPE!r}")
name = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "Cullis Demo Broker CA"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Cullis Demo"),
])
now = datetime.datetime.now(datetime.timezone.utc)
cert = (
    x509.CertificateBuilder()
    .subject_name(name)
    .issuer_name(name)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now)
    .not_valid_after(now + datetime.timedelta(days=365 * 10))
    .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
    .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    .sign(key, hashes.SHA256())
)

priv_pem = key.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
)
cert_pem = cert.public_bytes(serialization.Encoding.PEM)
pub_pem = key.public_key().public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo,
)

KEY.write_bytes(priv_pem)
CRT.write_bytes(cert_pem)

# Broker runs as non-root 'appuser' — make files world-readable.
KEY.chmod(0o644)
CRT.chmod(0o644)

print(f"broker-init: wrote {CRT} + {KEY}")

_maybe_push_to_vault(priv_pem, pub_pem)
