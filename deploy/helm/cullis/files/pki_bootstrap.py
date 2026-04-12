"""Helm-chart PKI bootstrap — runs as a post-install Job.

Generates a self-signed broker root CA, writes it into a Kubernetes
Secret (so the broker Deployment can mount it at /app/certs), and
optionally pushes the same PEMs into Vault at VAULT_SECRET_PATH so the
broker's KMS_BACKEND=vault path resolves on first boot.

Idempotent: if the target Secret already has both PEMs, skip
regeneration and only refresh the Vault copy when PUSH_TO_VAULT=true.

Uses the in-cluster Kubernetes API via the pod's projected ServiceAccount
token (no extra dependencies — the broker image already ships
cryptography + httpx).

Required env:
  - TARGET_NAMESPACE     (k8s namespace where the Secret lives)
  - TARGET_SECRET_NAME   (name of the Secret to create/update)
  - PKI_KEY_TYPE         ("rsa" | "ec", default "rsa")
  - PUSH_TO_VAULT        ("true" | "false", default "false")

Vault-only env (when PUSH_TO_VAULT=true):
  - VAULT_ADDR
  - VAULT_TOKEN          (via env or file at VAULT_TOKEN_FILE)
  - VAULT_SECRET_PATH    (default "secret/data/broker")
"""
import base64
import datetime
import os
import pathlib
import sys
import time

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

NAMESPACE = os.environ["TARGET_NAMESPACE"]
SECRET_NAME = os.environ["TARGET_SECRET_NAME"]
KEY_TYPE = os.environ.get("PKI_KEY_TYPE", "rsa").strip().lower()
PUSH_TO_VAULT = os.environ.get("PUSH_TO_VAULT", "false").strip().lower() == "true"

SA_TOKEN = pathlib.Path(
    "/var/run/secrets/kubernetes.io/serviceaccount/token"
).read_text().strip()
SA_CA = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
K8S_HOST = os.environ.get("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc")
K8S_PORT = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
K8S_API = f"https://{K8S_HOST}:{K8S_PORT}"
K8S_HEADERS = {"Authorization": f"Bearer {SA_TOKEN}"}


def _k8s_get_secret() -> dict | None:
    r = httpx.get(
        f"{K8S_API}/api/v1/namespaces/{NAMESPACE}/secrets/{SECRET_NAME}",
        headers=K8S_HEADERS, verify=SA_CA, timeout=10.0,
    )
    if r.status_code == 404:
        return None
    r.raise_for_status()
    return r.json()


def _k8s_upsert_secret(data: dict[str, bytes]) -> None:
    body = {
        "apiVersion": "v1",
        "kind": "Secret",
        "type": "Opaque",
        "metadata": {
            "name": SECRET_NAME,
            "namespace": NAMESPACE,
            "labels": {
                "app.kubernetes.io/managed-by": "cullis-pki-bootstrap",
            },
        },
        "data": {k: base64.b64encode(v).decode() for k, v in data.items()},
    }
    existing = _k8s_get_secret()
    if existing is None:
        r = httpx.post(
            f"{K8S_API}/api/v1/namespaces/{NAMESPACE}/secrets",
            json=body, headers=K8S_HEADERS, verify=SA_CA, timeout=10.0,
        )
    else:
        r = httpx.put(
            f"{K8S_API}/api/v1/namespaces/{NAMESPACE}/secrets/{SECRET_NAME}",
            json=body, headers=K8S_HEADERS, verify=SA_CA, timeout=10.0,
        )
    if r.status_code >= 300:
        raise SystemExit(
            f"pki-bootstrap: failed to write Secret {SECRET_NAME}: "
            f"HTTP {r.status_code} {r.text[:300]}"
        )


def _generate_ca() -> tuple[bytes, bytes, bytes]:
    if KEY_TYPE == "ec":
        print("pki-bootstrap: generating broker root CA (ECDSA P-256)")
        key = ec.generate_private_key(ec.SECP256R1())
    elif KEY_TYPE == "rsa":
        print("pki-bootstrap: generating broker root CA (RSA-4096)")
        key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    else:
        raise SystemExit(f"pki-bootstrap: unsupported PKI_KEY_TYPE={KEY_TYPE!r}")

    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Cullis Broker CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Cullis"),
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
    return priv_pem, cert_pem, pub_pem


def _push_to_vault(priv_pem: bytes, pub_pem: bytes, cert_pem: bytes) -> None:
    vault_addr = os.environ.get("VAULT_ADDR", "")
    token_file = os.environ.get("VAULT_TOKEN_FILE", "")
    vault_token = ""
    if token_file and pathlib.Path(token_file).exists():
        vault_token = pathlib.Path(token_file).read_text().strip()
    else:
        vault_token = os.environ.get("VAULT_TOKEN", "")

    secret_path = os.environ.get("VAULT_SECRET_PATH", "secret/data/broker")
    if not vault_addr or not vault_token:
        raise SystemExit(
            "pki-bootstrap: PUSH_TO_VAULT=true but VAULT_ADDR/VAULT_TOKEN missing"
        )

    url = f"{vault_addr.rstrip('/')}/v1/{secret_path}"
    body = {
        "data": {
            "private_key_pem": priv_pem.decode(),
            "public_key_pem":  pub_pem.decode(),
            "ca_cert_pem":     cert_pem.decode(),
        }
    }
    ca_bundle = os.environ.get("SSL_CERT_FILE") or True
    last_exc: Exception | None = None
    for attempt in range(60):
        try:
            r = httpx.post(
                url, json=body,
                headers={"X-Vault-Token": vault_token},
                verify=ca_bundle, timeout=5.0,
            )
            if r.status_code in (200, 204):
                print(f"pki-bootstrap: pushed broker keys to Vault at {secret_path}")
                return
            last_exc = RuntimeError(f"HTTP {r.status_code}: {r.text[:200]}")
        except Exception as exc:
            last_exc = exc
        time.sleep(2)
    raise SystemExit(f"pki-bootstrap: Vault push failed after retries: {last_exc}")


def main() -> None:
    existing = _k8s_get_secret()
    if existing and all(
        k in existing.get("data", {}) for k in ("broker-ca.pem", "broker-ca-key.pem")
    ):
        print(f"pki-bootstrap: Secret {SECRET_NAME} already populated, reusing")
        priv_pem = base64.b64decode(existing["data"]["broker-ca-key.pem"])
        cert_pem = base64.b64decode(existing["data"]["broker-ca.pem"])
        cert_obj = x509.load_pem_x509_certificate(cert_pem)
        pub_pem = cert_obj.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    else:
        priv_pem, cert_pem, pub_pem = _generate_ca()
        _k8s_upsert_secret({
            "broker-ca.pem":     cert_pem,
            "broker-ca-key.pem": priv_pem,
        })
        print(f"pki-bootstrap: wrote Secret {NAMESPACE}/{SECRET_NAME}")

    if PUSH_TO_VAULT:
        _push_to_vault(priv_pem, pub_pem, cert_pem)
    else:
        print("pki-bootstrap: PUSH_TO_VAULT=false, skipping Vault")


if __name__ == "__main__":
    sys.exit(main())
