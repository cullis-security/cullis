"""Postgres variant of ``_bulk_inject.py`` for the A.1b Run 2 stress test.

Streams via ``docker exec -i cullis-mastio-mcp-proxy-1 python -`` exactly
like the SQLite payload, but talks to the Mastio's Postgres backend
through asyncpg (already pinned in the Mastio image). Reads org CA from
``proxy_config`` and writes per-agent rows into ``internal_agents``.

ENV:
  DSN              postgresql://user:pass@host:5432/db (defaults to the
                   intra-cluster URL the Mastio container uses)
  N_AGENTS         row count to seed
  PREFIX           agent name prefix
  TRUST_DOMAIN     spiffe trust domain (default cullis.local)
  WIPE_PREFIX      1 to delete prior <prefix>-* rows first
  AGENT_CAPABILITIES   comma-separated capability list
"""
from __future__ import annotations

import asyncio
import base64
import datetime
import hashlib
import json
import os
import sys

import asyncpg
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


DSN = os.environ.get(
    "DSN",
    "postgres://cullis_proxy:cullis_proxy_dev@postgres:5432/proxy_a",
)
N = int(os.environ["N_AGENTS"])
PREFIX = os.environ["PREFIX"]
TRUST_DOMAIN = os.environ.get("TRUST_DOMAIN", "cullis.local")
WIPE = os.environ.get("WIPE_PREFIX", "0") == "1"
SET_CAPS = os.environ.get("AGENT_CAPABILITIES", "")


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def jwk_for(pub):
    nums = pub.public_numbers()
    return {
        "kty": "EC", "crv": "P-256",
        "x": b64url(nums.x.to_bytes(32, "big")),
        "y": b64url(nums.y.to_bytes(32, "big")),
    }


def rfc7638_thumbprint(jwk):
    canonical = json.dumps(
        {"crv": jwk["crv"], "kty": jwk["kty"],
         "x": jwk["x"], "y": jwk["y"]},
        separators=(",", ":"), sort_keys=True,
    ).encode()
    return b64url(hashlib.sha256(canonical).digest())


async def main():
    conn = await asyncpg.connect(DSN)
    org_id = await conn.fetchval(
        "SELECT value FROM proxy_config WHERE key = $1", "org_id",
    )
    org_ca_key_pem = await conn.fetchval(
        "SELECT value FROM proxy_config WHERE key = $1", "org_ca_key",
    )
    org_ca_cert_pem = await conn.fetchval(
        "SELECT value FROM proxy_config WHERE key = $1", "org_ca_cert",
    )
    if not (org_id and org_ca_key_pem and org_ca_cert_pem):
        sys.exit("proxy_config missing org material")

    ca_key = serialization.load_pem_private_key(
        org_ca_key_pem.encode(), password=None,
    )
    ca_cert = x509.load_pem_x509_certificate(org_ca_cert_pem.encode())

    if WIPE:
        deleted = await conn.execute(
            "DELETE FROM internal_agents WHERE agent_id LIKE $1",
            f"{org_id}::{PREFIX}-%",
        )
        print(f"WIPE: {deleted}", file=sys.stderr)

    now = datetime.datetime.now(datetime.timezone.utc)
    now_iso = now.isoformat(timespec="seconds")
    caps_json = json.dumps([c for c in SET_CAPS.split(",") if c])

    rows = []
    agents_out = []
    for i in range(N):
        agent_name = f"{PREFIX}-{i:05d}"
        agent_id = f"{org_id}::{agent_name}"
        spiffe = f"spiffe://{TRUST_DOMAIN}/{org_id}/{agent_name}"

        leaf_key = ec.generate_private_key(ec.SECP256R1())
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, agent_id),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_id),
            ]))
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

        # federated_at column is TIMESTAMPTZ in Postgres (TEXT in SQLite).
        # is_active is INTEGER, federated is BOOLEAN. created_at and
        # enrolled_at are TEXT in both backends.
        rows.append((
            agent_id, agent_name, caps_json, cert_pem, now_iso,
            1, None, dpop_jkt, "stress", now_iso, spiffe,
            True, now, "both", 1,
        ))
        agents_out.append({
            "agent_id": agent_id, "agent_name": agent_name,
            "leaf_priv_pkcs8_pem": leaf_pkcs8, "cert_pem": cert_pem,
            "dpop_priv_pkcs8_pem": dpop_pkcs8,
            "dpop_jwk_pub": dpop_jwk_pub, "dpop_jkt": dpop_jkt,
        })

    # Bulk INSERT — Postgres COPY would be faster but executemany via
    # asyncpg is plenty quick for 5000 rows.
    await conn.executemany(
        """INSERT INTO internal_agents
           (agent_id, display_name, capabilities, cert_pem, created_at,
            is_active, device_info, dpop_jkt, enrollment_method, enrolled_at,
            spiffe_id, federated, federated_at, reach, federation_revision)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
           ON CONFLICT (agent_id) DO UPDATE SET
             cert_pem = EXCLUDED.cert_pem,
             dpop_jkt = EXCLUDED.dpop_jkt,
             enrolled_at = EXCLUDED.enrolled_at""",
        rows,
    )
    count = await conn.fetchval(
        "SELECT COUNT(*) FROM internal_agents WHERE agent_id LIKE $1",
        f"{org_id}::{PREFIX}-%",
    )

    result = {
        "org_id": org_id, "trust_domain": TRUST_DOMAIN,
        "prefix": PREFIX, "requested": N, "after_count": count,
        "agents": agents_out,
    }
    sys.stdout.write(json.dumps(result))
    sys.stdout.flush()
    print(f"OK: {count} {PREFIX}-* in postgres", file=sys.stderr)
    await conn.close()


asyncio.run(main())
