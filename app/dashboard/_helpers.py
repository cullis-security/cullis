"""Shared helpers for the Court dashboard router (audit F-B-202 PR-1).

Sprint 2 / F-B-202 modularization PR-1 of 10. Extracts the pure-helper
functions that ``app/dashboard/router.py`` accumulated alongside its
67 route handlers, with the goal of letting future PRs (one per
feature area) move endpoints to per-feature sub-routers without
having to drag the helpers along.

What lives here:

  - ``_safe_redirect`` — open-redirect guard (audit H-IO-1) used by
    login / logout / OIDC / form-post handlers.
  - ``_ctx`` — Jinja2 template context builder, threads
    session, csrf_token, jaeger_url into every render.
  - sealed-org mutation guard: ``_is_sealed``, ``_require_sealed_reauth``,
    ``_sealed_mutation_details``, plus the ``_SEALED_DETAIL`` constant
    (audit F-B-2).
  - input validators: ``_validate_id``, ``_validate_webhook_url``,
    plus the ``_ID_PATTERN`` regex.
  - audit rendering: ``_build_audit_event_dict`` (projects
    ``AuditLog`` rows for the audit template).
  - HTMX nav chip: ``_count_chip``.
  - URL builder: ``_broker_url_from_request``.
  - dev cert generator: ``_generate_agent_cert`` (used by the
    download-bundle endpoint).

No router decorators here — the helpers are imported from
``app.dashboard.router`` (and from future sub-routers as the split
progresses).

Module-level imports are intentionally kept lean: only the symbols
every helper actually needs. Heavier deps (``cryptography``,
``json``) are imported lazily inside their consumer to keep
import-time cheap for sub-routers that only need a subset.
"""
from __future__ import annotations

import datetime
import re
from urllib.parse import urlparse

from fastapi import HTTPException, Request

from app.dashboard.session import DashboardSession, get_session
from app.registry.org_store import OrganizationRecord


# ── Open-redirect guard (audit H-IO-1) ────────────────────────────


def _safe_redirect(next_url: object, fallback: str = "/dashboard") -> str:
    """Validate a caller-supplied redirect target and return a safe local path.

    Rejects anything that could cause an open-redirect (H-IO-1):
    - non-string values
    - absolute URLs  (``https://...``)
    - protocol-relative URLs  (``//evil.example/x``)
    - backslash-relative URLs  (``/\\evil``)
    - empty / whitespace-only strings

    Only accepts paths that start with ``/`` and whose parsed ``netloc``
    is empty (i.e., no host component), which is the standard urllib test
    for relative-same-origin URLs.
    """
    if not isinstance(next_url, str) or not next_url.strip():
        return fallback
    # Block protocol-relative (//host) and backslash variants (/\host)
    if next_url.startswith("//") or next_url.startswith("/\\"):
        return fallback
    # Must start with a single slash (no scheme, no authority)
    if not next_url.startswith("/"):
        return fallback
    # Belt-and-suspenders: urlparse must see no scheme and no netloc
    parsed = urlparse(next_url)
    if parsed.scheme or parsed.netloc:
        return fallback
    return next_url


# ── Template context ──────────────────────────────────────────────


def _ctx(request: Request, session: DashboardSession, **kwargs) -> dict:
    """Build template context with session info, CSRF token, and the
    Jaeger UI link derived from the OTLP endpoint."""
    from app.config import get_settings

    _s = get_settings()
    _parsed = urlparse(_s.otel_exporter_otlp_endpoint or "http://localhost:4317")
    _jaeger_host = _parsed.hostname or "localhost"
    _jaeger_scheme = _parsed.scheme or "http"
    jaeger_url = f"{_jaeger_scheme}://{_jaeger_host}:16686"
    return {
        "request": request,
        "session": session,
        "csrf_token": session.csrf_token,
        "jaeger_url": jaeger_url,
        **kwargs,
    }


# ── Sealed-org mutation guard (audit F-B-2) ───────────────────────
#
# Rationale: the broker dashboard authenticates a single ``admin`` session
# cookie. Without further scoping, that cookie lets the network operator
# mutate any tenant's identity plane (CA, bindings, agents, certs) with
# no cross-check that they actually represent the tenant. The ``sealed``
# flag on ``organizations`` marks orgs whose proxy claimed ownership via
# the attach-ca flow; mutations on those orgs require a per-org re-auth
# challenge stamped on the session cookie within the last
# ``REAUTH_TTL_SECONDS`` seconds.
#
# Guard pattern to apply on every state-changing endpoint scoped to an org:
#
#     await _require_sealed_reauth(request, org)  # raises 403 if missing
#
# The helper is a no-op for unsealed orgs (legacy behavior preserved).

_SEALED_DETAIL = (
    "Organization is tenant-sealed. Complete the per-org re-auth challenge "
    "before retrying this action."
)


def _is_sealed(org: OrganizationRecord | None) -> bool:
    """Return True iff the org exists and its ``sealed`` flag is True."""
    return bool(getattr(org, "sealed", False)) if org is not None else False


async def _require_sealed_reauth(
    request: Request, org: OrganizationRecord | None,
) -> None:
    """Raise 403 if the org is sealed and the admin session lacks a scope.

    Safe to call with ``org=None`` (treated as unsealed — the caller's
    existence check handles the not-found case on its own).
    """
    if not _is_sealed(org):
        return
    session = get_session(request)
    if not session.is_admin:
        raise HTTPException(status_code=403, detail=_SEALED_DETAIL)
    if not session.has_reauth_scope(org.org_id):
        raise HTTPException(status_code=403, detail=_SEALED_DETAIL)


def _sealed_mutation_details(
    org: OrganizationRecord | None, extra: dict | None = None,
) -> dict:
    """Standardize audit log details for sealed-org mutations."""
    base: dict = {"source": "dashboard_admin"}
    if _is_sealed(org):
        base["source"] = "dashboard_admin_with_reauth"
        base["sealed"] = True
    if extra:
        base.update(extra)
    return base


# ── Input validators ──────────────────────────────────────────────


# Alphanumeric, hyphens, underscores, colons, dots — max 128 chars
_ID_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._:@\-]{0,127}$")


def _validate_id(value: str, field_name: str) -> str | None:
    """Return an error message if the ID is invalid, else None."""
    if not value:
        return None  # emptiness checked elsewhere
    if not _ID_PATTERN.match(value):
        return (
            f"{field_name} must be alphanumeric (hyphens, underscores, colons, "
            "dots allowed), max 128 characters."
        )
    return None


def _validate_webhook_url(url: str) -> str | None:
    """Return an error message if the webhook URL is invalid, else None."""
    if not url:
        return None
    parsed = urlparse(url)
    if parsed.scheme not in ("https", "http"):
        return "Webhook URL must use https:// or http:// scheme."
    if not parsed.hostname:
        return "Webhook URL must have a valid hostname."
    return None


# ── Audit rendering ───────────────────────────────────────────────


def _build_audit_event_dict(e) -> dict:
    """Project an ``AuditLog`` row into the dict shape the audit template
    consumes, adding a pretty-printed ``details`` string plus a parsed
    ``recipient`` hint for oneshot/forwarded events so the UI can show
    who was on the receiving end of the traffic.

    ``details_pretty`` is ``None`` when the original column was empty;
    non-JSON legacy strings pass through verbatim so nothing is lost.
    """
    import json as _json
    raw = e.details
    recipient = None
    details_pretty: str | None = None
    if raw:
        try:
            parsed = _json.loads(raw)
            details_pretty = _json.dumps(parsed, indent=2, sort_keys=True)
            if isinstance(parsed, dict):
                recipient = (
                    parsed.get("recipient_agent_id")
                    or parsed.get("target_agent_id")
                    or parsed.get("recipient")
                )
        except (ValueError, TypeError):
            details_pretty = raw
    return {
        "event_type": e.event_type,
        "result": e.result,
        "agent_id": e.agent_id,
        "org_id": e.org_id,
        "details": e.details,
        "details_pretty": details_pretty,
        "recipient": recipient,
        "created_at": e.timestamp,
        "entry_hash": e.entry_hash,
    }


# ── HTMX nav chip ─────────────────────────────────────────────────


def _count_chip(count: int) -> str:
    """Neutral count chip used in the principal-type nav badges."""
    if count <= 0:
        return ""
    return (
        '<span class="px-1.5 py-0.5 rounded-full text-[10px] font-mono '
        f'bg-gray-700/40 text-gray-400">{count}</span>'
    )


# ── Broker URL builder ────────────────────────────────────────────


def _broker_url_from_request(request: Request) -> str:
    """Compute the broker public URL from request headers."""
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host", request.url.hostname)
    port = request.url.port
    if scheme == "https" and port and port != 443:
        return f"{scheme}://{host}:{port}"
    elif scheme == "http" and port and port != 80:
        return f"{scheme}://{host}:{port}"
    return f"{scheme}://{host}"


# ── Dev agent cert generator (used by /agents/<id>/bundle) ────────


def _generate_agent_cert(agent_id: str, org_id: str, org_ca_key, org_ca_cert):
    """Generate agent cert + key in memory. Returns (key_pem, cert_pem).

    Used by the dashboard's deploy-bundle download endpoint. Mints a
    1-year RSA-2048 leaf cert signed by ``org_ca_key`` with a SPIFFE
    SAN derived from the agent id. The caller is responsible for
    persisting the thumbprint pin in the registry.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    now = datetime.datetime.now(datetime.timezone.utc)
    _, agent_name = agent_id.split("::", 1)
    spiffe_id = f"spiffe://cullis.local/{org_id}/{agent_name}"

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, agent_id),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_id),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(org_ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName([
                x509.UniformResourceIdentifier(spiffe_id),
            ]),
            critical=False,
        )
        .sign(org_ca_key, hashes.SHA256())
    )

    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    return key_pem, cert_pem


__all__ = [
    "_safe_redirect",
    "_ctx",
    "_SEALED_DETAIL",
    "_is_sealed",
    "_require_sealed_reauth",
    "_sealed_mutation_details",
    "_ID_PATTERN",
    "_validate_id",
    "_validate_webhook_url",
    "_build_audit_event_dict",
    "_count_chip",
    "_broker_url_from_request",
    "_generate_agent_cert",
]
