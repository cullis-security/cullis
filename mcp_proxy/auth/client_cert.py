"""mTLS client-cert authentication for intra-org egress (ADR-014).

The Mastio's nginx sidecar terminates TLS on 9443 and validates the
client cert against the Org CA. Verified cert PEM is forwarded to
``mcp-proxy`` in two headers:

  * ``X-SSL-Client-Cert``   — the leaf cert PEM, URL-escaped per nginx's
    ``$ssl_client_escaped_cert`` variable (newlines → ``%0A`` etc.).
  * ``X-SSL-Client-Verify`` — equals ``SUCCESS`` when nginx's verification
    passed; on the routes that require mTLS, nginx returns 401 outright
    when verification fails, so mcp-proxy normally only sees ``SUCCESS``
    here. We re-check anyway as defence-in-depth.

The new ``get_agent_from_client_cert`` dependency replaces the
``X-API-Key`` bearer path on routes that carry agent identity at the
TLS layer — the cert IS the credential; api_key disappears in PR-C.

Threat model — header spoofing
------------------------------
``X-SSL-Client-Cert`` is a textbook header-injection target. The
defences, layered:

  1. nginx always overwrites the header with ``$ssl_client_escaped_cert``
     (``proxy_set_header`` semantics) on the mTLS-required locations,
     and explicitly clears it (``""``) on every other location. A
     client can never have the value it set survive into mcp-proxy.

  2. ``mcp-proxy`` listens only on the internal docker network. The
     host port is unpublished, so an attacker outside the broker_net
     cannot reach :9100 directly to bypass nginx and inject a forged
     header.

  3. This dep pins the parsed cert's DER digest against the stored
     ``internal_agents.cert_pem`` digest. A cert that chains to the
     Org CA but isn't the one we issued for *this* agent (e.g. a
     rotated cert that we deactivated, or a cert minted off-band by
     a compromised CA backup) fails pinning even if nginx accepts it.

A shared-secret edge header (``X-Mastio-Edge``) is deferred — the
network binding plus the cert pin are the layers that matter. We add
the shared secret only when a deploy ever has to publish :9100.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import re
import urllib.parse
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization  # noqa: F401  (kept for future)
from cryptography.x509.oid import NameOID
from fastapi import HTTPException, Request, status

from mcp_proxy.auth.rate_limit import get_agent_rate_limiter
from mcp_proxy.config import get_settings
from mcp_proxy.db import get_agent
from mcp_proxy.models import InternalAgent

_log = logging.getLogger("mcp_proxy")

# nginx's ``$ssl_client_verify`` returns ``SUCCESS`` on a verified
# client cert and ``FAILED:<reason>`` / ``NONE`` otherwise. On the
# mTLS-required locations nginx already short-circuits to 401 when
# verification fails, but the route can also be reached without
# nginx in the loop (e.g. inside the docker network during dev), so
# we re-check.
_VERIFY_SUCCESS = "SUCCESS"


# ─────────────────────────────────────────────────────────────────────────────
# PEM extraction + identity parsing
# ─────────────────────────────────────────────────────────────────────────────


def _decode_escaped_pem(escaped: str) -> str:
    """Reverse ``$ssl_client_escaped_cert`` to a parseable PEM string.

    nginx URL-encodes the cert (newlines, spaces, etc.) so it survives
    HTTP header transport. ``urllib.parse.unquote`` recovers the
    original PEM. We do not validate structure here — the PEM parser
    in ``cryptography`` produces a precise error if the bytes aren't a
    cert.
    """
    return urllib.parse.unquote(escaped)


def _parse_spiffe_uri(uri: str) -> Optional[tuple[str, str]]:
    """Return ``(org_id, agent_name)`` for a Cullis SPIFFE URI.

    Cullis cert SAN format (see
    ``mcp_proxy.egress.agent_manager._generate_agent_cert``):
        ``spiffe://<trust_domain>/<org_id>/<agent_name>``

    The trust_domain is informational here — the org_id we trust is
    fixed by the Mastio's own configuration; we extract it from the
    URI only to assemble the canonical agent_id and let the DB lookup
    do the actual authority check.
    """
    if not uri.startswith("spiffe://"):
        return None
    rest = uri[len("spiffe://"):]
    # ADR-020 — accept both legacy 2-component (``<td>/<org>/<name>``)
    # and typed 3-component (``<td>/<org>/<type>/<name>``) paths.
    parts = rest.split("/")
    if len(parts) == 3:
        _td, org_id, agent_name = parts
    elif len(parts) == 4:
        _td, org_id, ptype, name = parts
        if ptype not in ("agent", "user", "workload"):
            return None
        if ptype == "agent":
            agent_name = name
        else:
            # Encode the typed identity into the canonical agent_id form
            # used as the registry key (``{org}::{type}::{name}``). The
            # caller will look this up in ``internal_agents`` directly.
            agent_name = f"{ptype}::{name}"
    else:
        return None
    if not org_id or not agent_name:
        return None
    return org_id, agent_name


def _parse_cn(cn: str) -> Optional[tuple[str, str]]:
    """Fallback: parse the canonical ``{org_id}::{agent_name}`` from CN.

    The cert subject CN equals the canonical agent_id by convention
    (see ``_generate_agent_cert``). We split on the literal ``::`` so
    org_ids that contain a single colon (``acme:eu``) round-trip.
    """
    if "::" not in cn:
        return None
    org_id, _, agent_name = cn.partition("::")
    if not org_id or not agent_name:
        return None
    return org_id, agent_name


def _identity_from_cert(cert: x509.Certificate) -> tuple[str, str]:
    """Extract ``(org_id, agent_name)`` from a Cullis-issued cert.

    Preference order:
      1. SPIFFE URI in SubjectAlternativeName — the canonical identity
         marker since :pr:`agent_manager._generate_agent_cert` started
         emitting it. Survives renames in CN.
      2. CN (``<org_id>::<agent_name>``) — fallback for legacy certs
         that pre-date the SAN URI extension. Same parsing rules as
         the canonical agent_id.

    Raises 401 if neither yields a usable identity. The error
    deliberately doesn't echo the cert bytes back — keeps the dep
    diagnostic-quiet for would-be enumerators.
    """
    try:
        san_ext = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
        for uri in san_ext.value.get_values_for_type(
            x509.UniformResourceIdentifier
        ):
            parsed = _parse_spiffe_uri(uri)
            if parsed:
                return parsed
    except x509.ExtensionNotFound:
        pass

    cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if cn_attrs:
        parsed = _parse_cn(cn_attrs[0].value)
        if parsed:
            return parsed

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="client cert has no parseable SPIFFE SAN or CN identity",
    )


def _cert_der_digest(cert: x509.Certificate) -> bytes:
    """SHA-256 of a cert's DER encoding — the pin we compare on lookup."""
    der = cert.public_bytes(serialization.Encoding.DER)
    return hashlib.sha256(der).digest()


def _pem_der_digest(pem: str) -> bytes | None:
    """SHA-256 of a PEM-encoded cert's DER bytes.

    Robust to whitespace and the ``-----BEGIN/END-----`` markers — we
    decode the base64 body directly so the comparison doesn't break
    on ``\\r\\n`` vs ``\\n`` line endings the cert went through on its
    way into the database.
    """
    if not pem:
        return None
    try:
        body = re.sub(r"-----.*?-----|\s", "", pem)
        return hashlib.sha256(base64.b64decode(body)).digest()
    except (ValueError, TypeError):
        return None


# ─────────────────────────────────────────────────────────────────────────────
# FastAPI dependency
# ─────────────────────────────────────────────────────────────────────────────


def _expected_org_id() -> str:
    """The org_id this Mastio will accept on the mTLS path.

    Single-org-per-instance is an ADR-006 invariant; we read it from
    settings rather than inferring from each cert (which would let a
    cert minted by a compromised CA backup pose as an arbitrary org).
    """
    return (get_settings().org_id or "").strip()


async def get_agent_from_client_cert(request: Request) -> InternalAgent:
    """Authenticate an internal agent by its TLS client cert (ADR-014).

    Steps:
      1. Verify ``X-SSL-Client-Verify == SUCCESS`` (nginx-validated).
      2. URL-decode + parse the leaf cert from ``X-SSL-Client-Cert``.
      3. Extract identity (SPIFFE SAN preferred, CN fallback).
      4. Reject if the cert claims a different org_id than this
         Mastio's configured one.
      5. Look up ``internal_agents`` by canonical agent_id.
      6. Pin leaf DER digest against stored ``cert_pem`` digest.
      7. Rate-limit per agent_id (shared bucket with the legacy path
         until PR-C removes that path).
      8. Record traffic for the ADR-013 anomaly detector.

    Returns the populated :class:`InternalAgent`, or raises 401/429.
    """
    verify = request.headers.get("X-SSL-Client-Verify") or ""
    if verify != _VERIFY_SUCCESS:
        # Defence-in-depth — nginx normally returns 401 itself when
        # verification fails on an mTLS-required location, but a caller
        # that reaches mcp-proxy bypassing nginx wouldn't have nginx's
        # gate. Fail closed.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="client cert not verified",
        )

    escaped_pem = request.headers.get("X-SSL-Client-Cert") or ""
    if not escaped_pem:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="client cert header missing",
        )

    pem = _decode_escaped_pem(escaped_pem)
    try:
        cert = x509.load_pem_x509_certificate(pem.encode())
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="client cert is not valid PEM",
        )

    org_id_from_cert, agent_name = _identity_from_cert(cert)

    expected_org = _expected_org_id()
    if expected_org and org_id_from_cert != expected_org:
        # A cert that chains to *some* CA we trust but claims a foreign
        # org_id at the application layer. This shouldn't happen — the
        # Org CA is single-org — but we fail closed in case a future
        # multi-tenant deploy ever shares a CA.
        _log.warning(
            "client cert org mismatch (cert=%s, expected=%s, agent=%s)",
            org_id_from_cert, expected_org, agent_name,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="client cert org mismatch",
        )

    canonical_id = f"{org_id_from_cert}::{agent_name}"

    agent_data = await get_agent(canonical_id)
    if agent_data is None or not agent_data.get("is_active"):
        _log.warning(
            "client cert authentication: no active agent for %s",
            canonical_id,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="agent unknown or inactive",
        )

    # ADR-020 — typed principals (user / workload) skip the cert-pin step.
    # Their certs rotate every ~1h via ``/v1/principals/csr`` and are not
    # persisted in ``internal_agents`` (the registry is a *workload*
    # registry; user principals live in their own table). Identity is
    # already gated upstream by the nginx mTLS chain walk + the SPIFFE
    # SAN match the chain enforces, so re-pinning the rotating leaf
    # would force every fresh login through a registry write the
    # provisioner doesn't issue.
    is_typed_principal = "::user::" in canonical_id or "::workload::" in canonical_id
    if not is_typed_principal:
        # Pin the presented cert against the stored one. A renewal that
        # rotated cert_pem in the DB but left the old cert in the wild
        # would fail this — that's the desired behaviour: revocation by
        # row-level update propagates to the next request without waiting
        # for CA rotation.
        stored_digest = _pem_der_digest(agent_data.get("cert_pem"))
        if not stored_digest:
            _log.error(
                "internal_agents.cert_pem unparseable for %s — refusing auth",
                canonical_id,
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="agent cert pin unavailable",
            )
        if not hmac.compare_digest(_cert_der_digest(cert), stored_digest):
            _log.warning(
                "client cert pin mismatch for %s — presented cert is not "
                "the one this Mastio issued.",
                canonical_id,
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="client cert does not match the registered identity",
            )

    settings = get_settings()
    if not await get_agent_rate_limiter().check(
        canonical_id, settings.rate_limit_per_minute
    ):
        _log.warning("rate limit exceeded for agent: %s", canonical_id)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded",
            headers={"Retry-After": "60"},
        )

    _log.debug("client cert authenticated agent: %s", canonical_id)
    # ADR-013 Phase 4 — same recorder the api_key path feeds.
    from mcp_proxy.observability.traffic_recorder import record_agent_request
    record_agent_request(request, canonical_id)

    return InternalAgent(
        agent_id=agent_data["agent_id"],
        display_name=agent_data["display_name"],
        capabilities=agent_data["capabilities"],
        created_at=agent_data["created_at"],
        is_active=agent_data["is_active"],
        cert_pem=agent_data.get("cert_pem"),
        dpop_jkt=agent_data.get("dpop_jkt"),
        reach=agent_data.get("reach") or "both",
    )
