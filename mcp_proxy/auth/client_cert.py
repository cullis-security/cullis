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

# P3 MAJOR-C — structured 401 detail bodies. Mirrors the
# ``denied_reason_code`` token vocabulary from PR #751: SDK consumers,
# dashboard banners, and admins reading raw 401 bodies all dispatch on
# the stable ``reason`` token instead of substring-matching prose.
# Only public-by-design fields (cert SAN, configured org_id) are
# echoed back; cert PEM bytes / pubkey thumbprints / DB pins stay in
# the warning log. See ``feedback_sqlalchemy_exc_leaks_bound_params``
# for the controlled-disclosure principle.
_REASON_CERT_NOT_VERIFIED = "client_cert_not_verified"
_REASON_CERT_HEADER_MISSING = "client_cert_header_missing"
_REASON_CERT_INVALID_PEM = "client_cert_invalid_pem"
_REASON_CERT_NO_IDENTITY = "client_cert_no_parseable_identity"
_REASON_ORG_MISMATCH = "client_cert_org_mismatch"
_REASON_AGENT_UNKNOWN = "agent_unknown_or_inactive"
_REASON_AGENT_PIN_UNAVAILABLE = "agent_cert_pin_unavailable"
_REASON_CERT_PIN_MISMATCH = "client_cert_pin_mismatch"
_REASON_TYPED_PRINCIPAL_UNKNOWN = "typed_principal_unknown"
_REASON_TYPED_PRINCIPAL_NOT_ENROLLED = "typed_principal_not_yet_enrolled"
_REASON_TYPED_PUBKEY_NOT_BOUND = "client_cert_pubkey_not_bound_to_principal"

# Single docs anchor across all hints — one doc rewrite moves all
# error messages without code churn.
_DOCS_ANCHOR = "https://docs.cullis.io/runbook/mastio-mtls-auth"


def _err(reason: str, hint: str, **extra: str) -> dict[str, str]:
    """Build the structured ``HTTPException.detail`` body. Body shape:
    ``{reason, hint, docs, **extra}``. ``extra`` is per-call-site
    public context (expected_org, presented_org, principal_id, ...).
    """
    body: dict[str, str] = {"reason": reason, "hint": hint, "docs": _DOCS_ANCHOR}
    body.update(extra)
    return body


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

    Raises 401 if neither yields a usable identity. The error body
    includes the cert's first SAN URI + serial (both public-by-design
    identifiers on every X.509 leaf) so an operator can match the
    rejected cert against the ``/v1/principals/csr`` audit row, but
    never echoes the cert DER / pubkey thumbprint / DB internals.
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
        detail=_err(
            _REASON_CERT_NO_IDENTITY,
            "Cert has no SPIFFE URI SAN and no '<org>::<agent>' CN; "
            "re-mint via the Connector enroll wizard or /v1/principals/csr.",
            cert_san=_cert_first_spiffe(cert),
            cert_serial=_cert_serial_hex(cert),
        ),
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


def _cert_serial_hex(cert: x509.Certificate) -> str:
    """Return the cert's serial as lowercase hex, or ``"?"`` if unreadable.

    Used only in warning logs for forensic correlation against the
    ``/v1/principals/csr`` audit row that minted the cert — the serial
    is a public identifier present in every X.509 leaf.
    """
    try:
        return f"{cert.serial_number:x}"
    except Exception:  # noqa: BLE001 — diagnostic only
        return "?"


def _cert_first_spiffe(cert: x509.Certificate) -> str:
    """Return the first SAN URI in the cert (kept name for blame
    history), or ``"?"`` when no URI SAN is present.

    Despite the legacy name this helper does NOT filter on the
    ``spiffe://`` scheme — it returns the first
    :class:`x509.UniformResourceIdentifier` value in the SAN regardless
    of scheme. That is deliberate: when the diagnostic fires
    (``client_cert.py`` pubkey-pin warnings) the operator wants to see
    a wrong-scheme URI such as ``https://attacker.example`` rather
    than ``"?"``. The :func:`_identity_from_cert` flow is the one that
    enforces SPIFFE structure.

    CR / LF / NUL in the returned value are escaped before logging so a
    cert with an attacker-controlled SAN cannot inject extra newlines
    into structured-log ingestion (Datadog / Sentry / Loki). nginx
    validates the cert chain but does not sanitize SAN content, and
    while most JSON-encoded loggers escape control chars defensively,
    this strip is a low-cost belt-and-braces against any future
    plain-text log sink.
    """
    try:
        san_ext = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName,
        )
        for uri in san_ext.value.get_values_for_type(
            x509.UniformResourceIdentifier,
        ):
            return _strip_log_controls(str(uri))
    except x509.ExtensionNotFound:
        pass
    except Exception:  # noqa: BLE001 — diagnostic only
        pass
    return "?"


def _strip_log_controls(value: str) -> str:
    """Escape control characters that could break structured log lines.

    Used by :func:`_cert_first_spiffe`. Replaces CR / LF with their
    escaped two-character form so a single log line stays single, and
    drops NUL bytes outright (they terminate strings in some log
    consumers and cannot be escaped safely).
    """
    return (
        value
        .replace("\r", "\\r")
        .replace("\n", "\\n")
        .replace("\x00", "")
    )


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
            detail=_err(
                _REASON_CERT_NOT_VERIFIED,
                "nginx did not stamp X-SSL-Client-Verify=SUCCESS — "
                "request bypassed the mTLS sidecar or the cert chain "
                "failed validation; check the Mastio nginx access log.",
                presented_verify=_strip_log_controls(verify) or "<empty>",
            ),
        )

    escaped_pem = request.headers.get("X-SSL-Client-Cert") or ""
    if not escaped_pem:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=_err(
                _REASON_CERT_HEADER_MISSING,
                "X-SSL-Client-Cert header is empty — request reached "
                "mcp-proxy without traversing the mTLS sidecar.",
            ),
        )

    pem = _decode_escaped_pem(escaped_pem)
    try:
        cert = x509.load_pem_x509_certificate(pem.encode())
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=_err(
                _REASON_CERT_INVALID_PEM,
                "X-SSL-Client-Cert payload is not a valid X.509 PEM — "
                "check the nginx ``proxy_set_header $ssl_client_escaped_cert``"
                " directive.",
            ),
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
            detail=_err(
                _REASON_ORG_MISMATCH,
                "The Connector cert was issued by a different Mastio "
                "Org. Re-run the enroll wizard against the Mastio whose "
                "org_id matches ``expected_org``, or correct "
                "``MCP_PROXY_ORG_ID`` if the Mastio config drifted.",
                expected_org=expected_org,
                presented_org=org_id_from_cert,
                agent_name=agent_name,
            ),
        )

    canonical_id = f"{org_id_from_cert}::{agent_name}"

    # ADR-020 — typed principals (user / workload) authenticate via the
    # cert chain (validated upstream by nginx mTLS) plus the SPIFFE SAN
    # baked into the cert. They live in ``local_user_principals`` /
    # ``local_workload_principals``, NOT in ``internal_agents`` (that
    # registry is for service agents). The rotating ~1h leaf the
    # ``/v1/principals/csr`` provisioner mints rotates the cert
    # thumbprint, but the principal's keypair (and therefore its SPKI
    # SHA-256 ``pubkey_thumbprint``) is stable across refreshes.
    #
    # CRIT-1 defence (audit T2-C1 / Track 2 CRIT-1, 2026-05-11):
    # the previous version of this branch skipped registry lookup AND
    # cert-pin step entirely for typed principals, on the rationale
    # that the chain walk + SPIFFE SAN was sufficient. It was not. Any
    # Mastio-bound JWT could POST a CSR for ``<org>::user::<arbitrary>``
    # via ``/v1/principals/csr``, get the Org CA to sign a 1h cert
    # bound to the attacker's keypair, then present that cert here and
    # be accepted as that arbitrary user. We now require the principal
    # row to exist AND the cert's SPKI SHA-256 to match the row's
    # ``pubkey_thumbprint`` (TOFU set on first CSR signature).
    is_typed_principal = "::user::" in canonical_id or "::workload::" in canonical_id

    if is_typed_principal:
        if "::user::" in canonical_id:
            from mcp_proxy.db import get_user_principal_pubkey_thumbprint
            exists, stored_pubkey = await get_user_principal_pubkey_thumbprint(
                canonical_id,
            )
            kind = "user"
        else:  # ::workload::
            from mcp_proxy.db import get_workload_principal_pubkey_thumbprint
            exists, stored_pubkey = await get_workload_principal_pubkey_thumbprint(
                canonical_id,
            )
            kind = "workload"
        if not exists:
            _log.warning(
                "client cert auth: typed principal not registered: %s",
                canonical_id,
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=_err(
                    _REASON_TYPED_PRINCIPAL_UNKNOWN,
                    f"No row exists for ``{canonical_id}`` in "
                    f"``local_{kind}_principals``; pre-create via "
                    f"``POST /v1/admin/{kind}s`` (admin dashboard) "
                    "before the first /v1/principals/csr.",
                    principal_id=canonical_id,
                    principal_kind=kind,
                ),
            )
        if stored_pubkey is None:
            # Row exists (e.g. admin pre-created via /v1/admin/users)
            # but no CSR has been signed yet — there is no pubkey to
            # pin against. Refuse rather than admit on the strength of
            # the cert chain alone, otherwise CRIT-1 is back in play.
            _log.warning(
                "client cert auth: typed principal has no pubkey pin: "
                "principal=%s cert_serial=%s cert_san=%s — admin "
                "pre-created the row but no /v1/principals/csr has been "
                "signed yet for this principal.",
                canonical_id,
                _cert_serial_hex(cert),
                _cert_first_spiffe(cert),
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=_err(
                    _REASON_TYPED_PRINCIPAL_NOT_ENROLLED,
                    f"Principal ``{canonical_id}`` exists but no CSR has "
                    "been signed yet (no pubkey to pin against); have "
                    "the end-user complete the Connector enroll flow "
                    "before retrying.",
                    principal_id=canonical_id,
                    principal_kind=kind,
                ),
            )
        from mcp_proxy.registry.principals_csr import pubkey_thumbprint_sha256
        presented_pubkey = pubkey_thumbprint_sha256(cert.public_key())
        if not hmac.compare_digest(presented_pubkey, stored_pubkey):
            # Both values are SHA-256 hex of the SubjectPublicKeyInfo DER
            # — public identifiers, not secrets — log them in full so an
            # operator can correlate against the on-disk Connector key
            # (``cullis_connector/ambassador/shared/keystore.py``: hash
            # the PEM at ``<config_dir>/user_keys/<sha256(principal_id)>.key.pem``
            # and compare). Also log the cert serial + SPIFFE SAN so the
            # mismatched cert can be traced back to the specific
            # ``/v1/principals/csr`` mint it came from.
            _log.warning(
                "client cert pubkey pin mismatch: principal=%s "
                "presented_spki_sha256=%s stored_spki_sha256=%s "
                "cert_serial=%s cert_san=%s — presented cert is not "
                "bound to this principal's TOFU pubkey. Compare "
                "presented_spki_sha256 against "
                "sha256(SPKI(<config_dir>/user_keys/sha256(principal_id))).",
                canonical_id,
                presented_pubkey,
                stored_pubkey,
                _cert_serial_hex(cert),
                _cert_first_spiffe(cert),
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=_err(
                    _REASON_TYPED_PUBKEY_NOT_BOUND,
                    "Cert's SPKI SHA-256 does not match the TOFU pin "
                    f"stored for ``{canonical_id}``. Rotate the pin via "
                    "the admin dashboard if the key rotation was "
                    "legitimate; otherwise treat as a forged-cert "
                    "incident.",
                    principal_id=canonical_id,
                    principal_kind=kind,
                    cert_serial=_cert_serial_hex(cert),
                    cert_san=_cert_first_spiffe(cert),
                ),
            )
        agent_data = None
    else:
        agent_data = await get_agent(canonical_id)
        if agent_data is None or not agent_data.get("is_active"):
            _log.warning(
                "client cert authentication: no active agent for %s",
                canonical_id,
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=_err(
                    _REASON_AGENT_UNKNOWN,
                    "No active ``internal_agents`` row for "
                    f"``{canonical_id}``; re-enroll via the Connector "
                    "or re-activate from the admin dashboard.",
                    agent_id=canonical_id,
                ),
            )

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
                detail=_err(
                    _REASON_AGENT_PIN_UNAVAILABLE,
                    f"Stored ``cert_pem`` for ``{canonical_id}`` is "
                    "unparseable; inspect the row and re-issue the "
                    "cert if the PEM is truncated.",
                    agent_id=canonical_id,
                ),
            )
        presented_digest = _cert_der_digest(cert)
        if not hmac.compare_digest(presented_digest, stored_digest):
            # Wave 2 fix 7+8 — fall back to ``previous_cert_pem`` when
            # the row carries an active grace window. Pre-fix, the
            # rotation writers swapped ``cert_pem`` in place and every
            # mid-flight request signed with the OLD keypair 401'd
            # against the fresh pin. Now, requests signed with the
            # previous cert keep working until
            # ``previous_grace_period_expires_at`` passes. Logged as a
            # warning + audited so operators can see how many
            # rotations land mid-flight and tune the grace window.
            from mcp_proxy.auth.cert_grace import is_grace_active
            prev_pem = agent_data.get("previous_cert_pem")
            grace_expires = agent_data.get("previous_grace_period_expires_at")
            prev_digest = _pem_der_digest(prev_pem) if prev_pem else None
            if (
                prev_digest is not None
                and is_grace_active(grace_expires)
                and hmac.compare_digest(presented_digest, prev_digest)
            ):
                _log.warning(
                    "client cert pin grace match for %s — presented the "
                    "PREVIOUS cert (post-rotation grace, expires=%s). "
                    "Connector should re-enroll to pick up the new cert "
                    "before the grace window closes.",
                    canonical_id, grace_expires,
                )
                # Best-effort audit; mirror the writer's audit shape so
                # ``agent.cert_rotated`` + ``agent.cert_pinning_grace_match``
                # join cleanly on agent_id + thumbprint in forensic queries.
                try:
                    from mcp_proxy.db import log_audit
                    await log_audit(
                        agent_id=canonical_id,
                        action="agent.cert_pinning_grace_match",
                        status="success",
                        detail=(
                            f"grace_expires_at={grace_expires} "
                            f"presented_thumbprint={presented_digest.hex()}"
                        ),
                    )
                except Exception as exc:  # noqa: BLE001 — best-effort
                    _log.debug(
                        "agent.cert_pinning_grace_match audit emit failed: %s",
                        exc,
                    )
                # Drop through to the rate-limit + traffic-recorder steps
                # below as if the pin matched. ``agent_data`` already
                # carries the active credentials for the InternalAgent
                # envelope returned to the caller.
            else:
                _log.warning(
                    "client cert pin mismatch for %s — presented cert is not "
                    "the one this Mastio issued.",
                    canonical_id,
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=_err(
                        _REASON_CERT_PIN_MISMATCH,
                        "Presented cert's DER digest does not match the "
                        f"one stored for ``{canonical_id}`` (likely a stale "
                        "cert post-rotation); re-enroll the Connector, or "
                        "treat as forged if the caller insists their cert "
                        "is current.",
                        agent_id=canonical_id,
                        cert_serial=_cert_serial_hex(cert),
                        cert_san=_cert_first_spiffe(cert),
                    ),
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

    if is_typed_principal:
        # Build the InternalAgent envelope from the cert + canonical id.
        # Typed principals are not pinned in ``internal_agents``, so
        # there's no display_name / capabilities / created_at to read
        # back; downstream consumers (audit, rate-limit) only need
        # ``agent_id`` and ``principal_type`` to attribute correctly.
        # The SPIFFE id pattern is ``<org>::user::<name>`` /
        # ``<org>::workload::<name>``; the ``principal_type`` mirror
        # is what audit aggregations key on (see models.py:78).
        principal_type = "user" if "::user::" in canonical_id else "workload"
        from datetime import datetime, timezone
        return InternalAgent(
            agent_id=canonical_id,
            display_name=agent_name,
            capabilities=[],
            created_at=datetime.now(timezone.utc).isoformat(),
            is_active=True,
            cert_pem=None,
            dpop_jkt=None,
            reach="intra",
            principal_type=principal_type,
        )

    return InternalAgent(
        agent_id=agent_data["agent_id"],
        display_name=agent_data["display_name"],
        capabilities=agent_data["capabilities"],
        created_at=agent_data["created_at"],
        is_active=agent_data["is_active"],
        cert_pem=agent_data.get("cert_pem"),
        dpop_jkt=agent_data.get("dpop_jkt"),
        reach=agent_data.get("reach") or "both",
        previous_cert_pem=agent_data.get("previous_cert_pem"),
        previous_dpop_jkt=agent_data.get("previous_dpop_jkt"),
        previous_grace_period_expires_at=agent_data.get(
            "previous_grace_period_expires_at"
        ),
        # ADR-034 §2 — DB column is authoritative for enrolled rows.
        # Migration 0041 backfills existing rows to ``agent``, so a
        # row missing the field is impossible after upgrade; the
        # ``or "agent"`` guard is belt-and-braces for any synthetic
        # dict that omits it in tests.
        principal_type=agent_data.get("principal_type") or "agent",
    )
