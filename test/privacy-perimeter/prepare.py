"""Prepare fresh private evaluation state from an already downloaded Ollama model."""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--models", type=Path, required=True)
    parser.add_argument("--model", default="qwen2.5:0.5b")
    args = parser.parse_args()
    # Model paths are operator inputs, not arbitrary paths outside the cache.
    name, tag = args.model.split(":", 1)
    if any("/" in part or ".." in part for part in (name, tag)):
        parser.error("Use a library model name:tag without path components")
    source = args.models / "manifests/registry.ollama.ai/library" / name / tag
    manifest_bytes = source.read_bytes()
    manifest = json.loads(manifest_bytes)
    entries = [manifest["config"], *manifest["layers"]]
    for entry in entries:
        digest = entry["digest"]
        if not digest.startswith("sha256:") or len(digest) != 71:
            raise ValueError("Invalid model digest")
        int(digest[7:], 16)
        if not (args.models / "blobs" / digest.replace(":", "-")).is_file():
            raise FileNotFoundError("Model is not completely cached")
    os.umask(0o077)
    state = args.state.resolve()
    state.mkdir(parents=True, exist_ok=False)
    for directory in ("data", "certs", "evidence", "fixture-tls", "models/blobs"):
        (state / directory).mkdir(parents=True)
    target = state / "models/manifests/registry.ollama.ai/library" / name / tag
    target.parent.mkdir(parents=True)
    target.write_bytes(manifest_bytes)
    for entry in entries:
        filename = entry["digest"].replace(":", "-")
        destination = state / "models/blobs" / filename
        shutil.copyfile(args.models / "blobs" / filename, destination)
        with destination.open("rb") as stream:
            actual = hashlib.file_digest(stream, "sha256").hexdigest()
        if actual != entry["digest"][7:]:
            raise ValueError("Cached model digest mismatch")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = dt.datetime.now(dt.timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Cullis synthetic perimeter CA")])
    ca = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
          .public_key(key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=2))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .sign(key, hashes.SHA256()))
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = (x509.CertificateBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "fixture")])).issuer_name(subject)
        .public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=2))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("fixture")]), critical=False)
        .sign(key, hashes.SHA256()))
    tls = state / "fixture-tls"
    for filename, certificate in (("ca.pem", ca), ("server.pem", cert)):
        (tls / filename).write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        (tls / filename).chmod(0o644)
    (tls / "server.key").write_bytes(leaf_key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    settings = {
        "MCP_PROXY_ENVIRONMENT": "development",  # local KMS; not a production qualification
        "MCP_PROXY_STANDALONE": "true",
        "MCP_PROXY_ADMIN_SECRET": secrets.token_hex(32),
        "MCP_PROXY_DASHBOARD_SIGNING_KEY": secrets.token_hex(32),
        "MCP_PROXY_DPOP_NONCE_SECRET": secrets.token_hex(32),
        "MCP_PROXY_INITIAL_ADMIN_PASSWORD": secrets.token_urlsafe(32),
        "MCP_PROXY_INTEGRATIONS_HMAC_SECRET": secrets.token_hex(32),
        "MCP_PROXY_DATABASE_URL": "sqlite+aiosqlite:////data/mcp_proxy.db",
        "MCP_PROXY_LOCAL_AUTH_ENABLED": "true",
        "MCP_PROXY_PROXY_PUBLIC_URL": "https://mastio-nginx:9443",
        "MCP_PROXY_NGINX_CERT_DIR": "/var/lib/mastio/nginx-certs",
        "MCP_PROXY_NGINX_SAN": "mastio-nginx,localhost",
        "MCP_PROXY_REDIS_URL": "redis://redis:6379/0",
        "MCP_PROXY_EGRESS_DPOP_MODE": "required",
        "MCP_PROXY_INTERNAL_HOST_ALLOWLIST": "ollama,fixture,mcp-proxy",
        "MCP_PROXY_POLICY_WEBHOOK_ALLOW_PRIVATE_IPS": "false",
        "MCP_PROXY_PDP_URL": "http://mcp-proxy:9100/pdp/policy",
        "MCP_PROXY_AI_GATEWAY_BACKEND": "cullis_native",
        "MCP_PROXY_AI_GATEWAY_REQUEST_TIMEOUT_S": "120",
        "MCP_PROXY_AUDIT_CAPTURE_TOOL_PARAMETERS": "false",
        "MCP_PROXY_AUDIT_CAPTURE_TOOL_RESULT": "false",
        "MCP_PROXY_AUDIT_CHAIN_DURABLE": "true",
        "MCP_PROXY_AUDIT_FAIL_DENY": "true",
        # Isolated evaluation has no independent TSA; never claim external provenance.
        "MCP_PROXY_AUDIT_ANCHOR_ENABLED": "false",
        "MCP_PROXY_AUDIT_MERKLE_TSA_ENABLED": "false",
        "SSL_CERT_FILE": "/test-ca.pem",
        "REQUESTS_CA_BUNDLE": "/test-ca.pem",
        "OTEL_SDK_DISABLED": "true",
        "PERIMETER_MODEL": args.model,
    }
    (state / "runtime.env").write_text("".join(f"{k}={v}\n" for k, v in settings.items()))
    (state / "evidence/model.json").write_text(json.dumps({
        "model": args.model, "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "blobs": entries, "source": "previously cached local weights; digests checked",
    }, indent=2) + "\n")
    print(f"Prepared fresh evaluation state at {state}; secrets are in runtime.env")


if __name__ == "__main__":
    main()
