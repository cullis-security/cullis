"""In-container payload for ``bulk_enroll_agents.py``.

Streamed via stdin to ``docker exec -i ... python -`` on the Mastio
container. Reads config from env, writes the agents into
``internal_agents`` in one transaction, emits a JSON document with all
per-agent material to stdout (private keys ride the encrypted SSH
transport back to the operator's host).
"""
from __future__ import annotations

import base64
import datetime
import hashlib
import json
import os
import sqlite3
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

DB_PATH = os.environ["DB_PATH"]
N = int(os.environ["N_AGENTS"])
PREFIX = os.environ["PREFIX"]
TRUST_DOMAIN = os.environ.get("TRUST_DOMAIN", "cullis.local")
WIPE = os.environ.get("WIPE_PREFIX", "0") == "1"
SET_CAPS = os.environ.get("AGENT_CAPABILITIES", "")
# Bind across DB writers (Mastio + this script) without hammering each
# other. 30s busy timeout is the standard SQLite advice for WAL
# multi-writer setups.
BUSY_TIMEOUT_MS = int(os.environ.get("BUSY_TIMEOUT_MS", "30000"))

conn = sqlite3.connect(DB_PATH, timeout=BUSY_TIMEOUT_MS / 1000)
conn.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")


def cfg(key):
    row = conn.execute(
        "SELECT value FROM proxy_config WHERE key = ?", (key,),
    ).fetchone()
    return row[0] if row else None


org_id = cfg("org_id")
org_ca_key_pem = cfg("org_ca_key")
org_ca_cert_pem = cfg("org_ca_cert")
if not org_id or not org_ca_key_pem or not org_ca_cert_pem:
    sys.exit("ERR: proxy_config missing org_id/org_ca_key/org_ca_cert")

ca_key = serialization.load_pem_private_key(
    org_ca_key_pem.encode(), password=None,
)
ca_cert = x509.load_pem_x509_certificate(org_ca_cert_pem.encode())

if WIPE:
    cur = conn.execute(
        "DELETE FROM internal_agents WHERE agent_id LIKE ?",
        (f"{org_id}::{PREFIX}-%",),
    )
    print(
        f"WIPE: removed {cur.rowcount} prior {PREFIX}-* agents",
        file=sys.stderr,
    )

now = datetime.datetime.now(datetime.timezone.utc)
now_iso = now.isoformat(timespec="seconds")


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def jwk_for(pub):
    nums = pub.public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": b64url(nums.x.to_bytes(32, "big")),
        "y": b64url(nums.y.to_bytes(32, "big")),
    }


def rfc7638_thumbprint(jwk: dict) -> str:
    canonical = json.dumps(
        {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return b64url(hashlib.sha256(canonical).digest())


capabilities_json = json.dumps(
    [c for c in SET_CAPS.split(",") if c]
)

rows = []
agents_out = []
for i in range(N):
    agent_name = f"{PREFIX}-{i:05d}"
    agent_id = f"{org_id}::{agent_name}"
    spiffe = f"spiffe://{TRUST_DOMAIN}/{org_id}/{agent_name}"

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, agent_id),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_id),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.UniformResourceIdentifier(spiffe),
            ]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    leaf_pkcs8 = leaf_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()

    dpop_key = ec.generate_private_key(ec.SECP256R1())
    dpop_jwk_pub = jwk_for(dpop_key.public_key())
    dpop_jkt = rfc7638_thumbprint(dpop_jwk_pub)
    dpop_pkcs8 = dpop_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()

    rows.append((
        agent_id, agent_name, capabilities_json, cert_pem, now_iso,
        1, None, dpop_jkt, "stress", now_iso, spiffe, 1, now_iso,
        "both", 1,
    ))
    agents_out.append({
        "agent_id": agent_id,
        "agent_name": agent_name,
        "leaf_priv_pkcs8_pem": leaf_pkcs8,
        "cert_pem": cert_pem,
        "dpop_priv_pkcs8_pem": dpop_pkcs8,
        "dpop_jwk_pub": dpop_jwk_pub,
        "dpop_jkt": dpop_jkt,
    })

INSERT_SQL = (
    "INSERT OR REPLACE INTO internal_agents "
    "(agent_id, display_name, capabilities, cert_pem, created_at, "
    "is_active, device_info, dpop_jkt, enrollment_method, enrolled_at, "
    "spiffe_id, federated, federated_at, reach, federation_revision) "
    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
)
conn.executemany(INSERT_SQL, rows)
conn.commit()

count = conn.execute(
    "SELECT COUNT(*) FROM internal_agents WHERE agent_id LIKE ?",
    (f"{org_id}::{PREFIX}-%",),
).fetchone()[0]

result = {
    "org_id": org_id,
    "trust_domain": TRUST_DOMAIN,
    "prefix": PREFIX,
    "requested": N,
    "after_count": count,
    "agents": agents_out,
}
sys.stdout.write(json.dumps(result))
sys.stdout.flush()
print(f"OK: {count} {PREFIX}-* agents in internal_agents", file=sys.stderr)
