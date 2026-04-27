"""Test helpers for ADR-014 mTLS-fronted Mastio routes.

Unit tests in this suite hit the FastAPI app directly via
``ASGITransport`` — there's no nginx in the loop. After PR-B the
egress + agents/search dependencies authenticate against the headers
nginx forwards (``X-SSL-Client-Cert``, ``X-SSL-Client-Verify``), so
tests have to synthesize what nginx would have injected.

This module provides three primitives:

  * ``mint_agent_cert`` — mint a cert+key signed by a session-cached
    test Org CA. SAN matches the production
    ``agent_manager._generate_agent_cert`` shape, so the SPIFFE-URI
    parsing path in ``get_agent_from_client_cert`` is exercised
    exactly as in production.

  * ``mtls_headers`` — pack a cert PEM into the two headers nginx
    forwards on the mTLS-required locations. URL-escaping mirrors
    nginx's ``$ssl_client_escaped_cert``.

  * ``provision_internal_agent`` — insert an active row into
    ``internal_agents`` with the freshly-minted cert + return the
    nginx-shaped headers ready to drop into ``client.request(...)``.

Tests that previously did ``api_key = await _provision_caller()`` +
``headers={"X-API-Key": api_key}`` now do ``headers = await
provision_internal_agent("caller-bot")`` + ``headers=headers`` (or
``{**headers, "DPoP": ...}`` when also exercising the DPoP layer).
"""
from __future__ import annotations

import json
import urllib.parse
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

# Cache the Org CA across the test session — minting a fresh CA for
# every fixture call would dwarf the actual test runtime (RSA-2048
# keygen is ~150 ms each).
_CA_CACHE: tuple = ()


def _build_test_ca() -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    global _CA_CACHE
    if _CA_CACHE:
        return _CA_CACHE
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Cullis Test Org CA"),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=1), critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    _CA_CACHE = (key, cert)
    return _CA_CACHE


def mint_agent_cert(
    *,
    org_id: str,
    agent_name: str,
    trust_domain: str = "cullis.local",
) -> tuple[str, str]:
    """Mint a Connector-shaped cert+key signed by the test Org CA.

    Returns ``(cert_pem, key_pem)``. The SAN includes the SPIFFE URI
    shape the production cert minting emits.
    """
    ca_key, ca_cert = _build_test_ca()
    agent_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, f"{org_id}::{agent_name}"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_id),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(agent_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.UniformResourceIdentifier(
                    f"spiffe://{trust_domain}/{org_id}/{agent_name}"
                ),
            ]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = agent_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return cert_pem, key_pem


def mtls_headers(cert_pem: str) -> dict[str, str]:
    """Build the headers nginx forwards on mTLS-required locations.

    Tests hit FastAPI directly so this synthesizes what nginx would
    inject:
      - ``X-SSL-Client-Cert``: URL-escaped PEM (mirrors nginx's
        ``$ssl_client_escaped_cert``).
      - ``X-SSL-Client-Verify``: ``SUCCESS`` (nginx-set on a chain
        validation pass).
    """
    return {
        "X-SSL-Client-Cert": urllib.parse.quote(cert_pem, safe=""),
        "X-SSL-Client-Verify": "SUCCESS",
    }


def _split_id(identifier: str, default_org: str) -> tuple[str, str, str]:
    """Resolve ``("acme::alice", "acme")`` → ``("acme", "alice", "acme::alice")``.

    Tests pass either a bare agent name (``"caller-bot"``) or the
    canonical ``org::name``; both shapes round-trip to the same row.
    """
    if "::" in identifier:
        org, _, name = identifier.partition("::")
        return org, name, f"{org}::{name}"
    return default_org, identifier, f"{default_org}::{identifier}"


async def provision_internal_agent(
    agent_id_or_name: str = "caller-bot",
    *,
    org_id: str = "acme",
    capabilities: list[str] | None = None,
    display_name: str | None = None,
    is_active: bool = True,
    trust_domain: str = "cullis.local",
    dpop_jkt: str | None = None,
) -> dict[str, str]:
    """Insert an active agent with a freshly-minted cert + return headers.

    Drop-in replacement for the legacy ``_provision_caller`` shape:
    instead of returning a raw API key, returns the headers a real
    Connector would have caused nginx to forward.

    The ``api_key_hash`` column is populated with a placeholder so
    legacy code paths that inspect the row don't crash; the cert dep
    never reads it. PR-C drops the column entirely.
    """
    from sqlalchemy import text
    from mcp_proxy.db import get_db

    org, name, full_id = _split_id(agent_id_or_name, org_id)
    cert_pem, _key_pem = mint_agent_cert(
        org_id=org, agent_name=name, trust_domain=trust_domain,
    )

    caps = capabilities if capabilities is not None else ["cap.read"]
    display = display_name or full_id

    async with get_db() as conn:
        row = {
            "agent_id": full_id,
            "display_name": display,
            "capabilities": json.dumps(caps),
            "cert_pem": cert_pem,
            "api_key_hash": "$2b$12$placeholder",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "is_active": 1 if is_active else 0,
        }
        if dpop_jkt is not None:
            await conn.execute(
                text(
                    "INSERT INTO internal_agents "
                    "(agent_id, display_name, capabilities, cert_pem, "
                    " api_key_hash, created_at, is_active, dpop_jkt) "
                    "VALUES (:agent_id, :display_name, :capabilities, "
                    " :cert_pem, :api_key_hash, :created_at, :is_active, "
                    " :dpop_jkt)"
                ),
                {**row, "dpop_jkt": dpop_jkt},
            )
        else:
            await conn.execute(
                text(
                    "INSERT INTO internal_agents "
                    "(agent_id, display_name, capabilities, cert_pem, "
                    " api_key_hash, created_at, is_active) "
                    "VALUES (:agent_id, :display_name, :capabilities, "
                    " :cert_pem, :api_key_hash, :created_at, :is_active)"
                ),
                row,
            )

    return mtls_headers(cert_pem)
