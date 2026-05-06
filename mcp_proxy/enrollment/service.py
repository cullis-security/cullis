"""Business logic for the Connector enrollment flow.

Thin helpers that take an ``AsyncConnection`` (the proxy's only DB primitive,
see ``mcp_proxy.db.get_db``) and manipulate the ``pending_enrollments``
table via raw SQL. Cert signing is delegated to :class:`AgentManager` so CA
material stays owned by the module that already loads it from Vault/disk.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

from cryptography.hazmat.primitives import serialization
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

if TYPE_CHECKING:
    from mcp_proxy.egress.agent_manager import AgentManager


ENROLLMENT_TTL = timedelta(minutes=30)
POLL_INTERVAL_S = 5


class EnrollmentError(Exception):
    """Raised for user-facing enrollment failures. The router maps the
    ``http_status`` to the HTTP response code (400/404/409/503)."""

    def __init__(self, message: str, http_status: int = 400) -> None:
        super().__init__(message)
        self.http_status = http_status


@dataclass
class StartedEnrollment:
    session_id: str
    expires_at: datetime


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(ts: datetime) -> str:
    return ts.isoformat(timespec="seconds")


def _pubkey_fingerprint(pubkey_pem: str) -> str:
    """SHA-256 of the DER SubjectPublicKeyInfo — matches standard CLI output.

    Gives the admin a stable string to compare against what the Connector
    prints locally on enrollment start.
    """
    try:
        public_key = serialization.load_pem_public_key(pubkey_pem.encode())
    except Exception as exc:
        raise EnrollmentError(f"Invalid public key PEM: {exc}", http_status=400) from exc
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def _row_to_dict(row: Any) -> dict[str, Any]:
    return dict(row)


# ── Reads ────────────────────────────────────────────────────────────────


async def get_record(conn: AsyncConnection, session_id: str) -> dict[str, Any]:
    """Fetch a record. Lazily marks it expired when the TTL has lapsed."""
    result = await conn.execute(
        text("SELECT * FROM pending_enrollments WHERE session_id = :sid"),
        {"sid": session_id},
    )
    row = result.mappings().first()
    if row is None:
        raise EnrollmentError("Enrollment session not found", http_status=404)
    record = _row_to_dict(row)

    if record["status"] == "pending":
        expires_at = datetime.fromisoformat(record["expires_at"])
        if expires_at < _now():
            await conn.execute(
                text(
                    "UPDATE pending_enrollments SET status = 'expired' "
                    "WHERE session_id = :sid"
                ),
                {"sid": session_id},
            )
            record["status"] = "expired"
    return record


async def list_pending(conn: AsyncConnection) -> list[dict[str, Any]]:
    """Return pending records (newest first), flipping any whose TTL lapsed."""
    now_iso = _iso(_now())
    await conn.execute(
        text(
            "UPDATE pending_enrollments "
            "SET status = 'expired' "
            "WHERE status = 'pending' AND expires_at < :now"
        ),
        {"now": now_iso},
    )
    result = await conn.execute(
        text(
            "SELECT * FROM pending_enrollments "
            "WHERE status = 'pending' "
            "ORDER BY created_at DESC"
        )
    )
    return [_row_to_dict(r) for r in result.mappings().all()]


# ── Writes ───────────────────────────────────────────────────────────────


def _validate_and_compute_dpop_jkt(dpop_jwk: dict | None) -> str | None:
    """Audit F-B-11 Phase 3b — validate a client-submitted public JWK and
    return its RFC 7638 thumbprint.

    Refuses private key material (``d``), unsupported kty, malformed
    coordinates. Returns None when the caller supplied nothing — backwards
    compat with pre-Phase-3c SDKs.
    """
    if dpop_jwk is None:
        return None
    if not isinstance(dpop_jwk, dict) or not dpop_jwk:
        raise EnrollmentError(
            "dpop_jwk must be a non-empty object", http_status=400,
        )
    if "d" in dpop_jwk:
        raise EnrollmentError(
            "dpop_jwk must be the public JWK — private material ('d') rejected",
            http_status=400,
        )
    kty = dpop_jwk.get("kty")
    if kty not in ("EC", "RSA"):
        raise EnrollmentError(
            f"dpop_jwk kty {kty!r} unsupported — expected 'EC' (P-256) or 'RSA'",
            http_status=400,
        )
    try:
        from mcp_proxy.auth.dpop import compute_jkt
        return compute_jkt(dpop_jwk)
    except (ValueError, KeyError) as exc:
        raise EnrollmentError(
            f"dpop_jwk is malformed: {exc}", http_status=400,
        ) from exc


_ENROLLMENT_POP_DOMAIN = "enrollment-pop:v1"


def _verify_pop_signature(
    pubkey_pem: str, fingerprint: str, signature_b64: str,
) -> bool:
    """H-csr-pop audit — proof of possession over the enrollment keypair.

    The Connector signs ``"enrollment-pop:v1|<fingerprint>"`` with
    its private key and submits the signature in ``pop_signature``.
    The server verifies before persisting the row. A failed verify
    raises ``EnrollmentError`` (400). Domain-separated by the
    ``enrollment-pop:v1`` prefix and bound to the pubkey fingerprint
    so the proof is non-replayable across keys.
    """
    import base64 as _b64

    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes as _hashes
    from cryptography.hazmat.primitives.asymmetric import (
        ec as _ec,
        padding as _padding,
        rsa as _rsa,
    )

    try:
        sig = _b64.urlsafe_b64decode(
            signature_b64 + "=" * (-len(signature_b64) % 4),
        )
    except Exception:
        return False
    try:
        pub_key = serialization.load_pem_public_key(pubkey_pem.encode())
    except Exception:
        return False
    canonical = (
        f"{_ENROLLMENT_POP_DOMAIN}|{fingerprint}".encode("utf-8")
    )
    try:
        if isinstance(pub_key, _rsa.RSAPublicKey):
            pub_key.verify(
                sig, canonical,
                _padding.PSS(
                    mgf=_padding.MGF1(_hashes.SHA256()),
                    salt_length=_padding.PSS.MAX_LENGTH,
                ),
                _hashes.SHA256(),
            )
        elif isinstance(pub_key, _ec.EllipticCurvePublicKey):
            pub_key.verify(sig, canonical, _ec.ECDSA(_hashes.SHA256()))
        else:
            return False
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


async def start_enrollment(
    conn: AsyncConnection,
    *,
    pubkey_pem: str,
    requester_name: str,
    requester_email: str,
    reason: str | None,
    device_info: str | None,
    dpop_jwk: dict | None = None,
    pop_signature: str | None = None,
) -> StartedEnrollment:
    """Create a new pending enrollment.

    The session_id is a 128-bit URL-safe random token — unguessable so only
    the client that started the flow can poll it.

    ADR-014 PR-C — the agent's TLS client cert is the credential. No
    api_key is minted; ``approve()`` writes only ``cert_pem`` (signed by
    the Org CA on approval) to ``internal_agents``. The Connector
    presents that cert at the TLS handshake on subsequent calls and
    ``get_agent_from_client_cert`` resolves the agent identity.

    ``dpop_jwk`` (F-B-11 Phase 3b) is the optional public JWK of the
    Connector's DPoP keypair. When supplied the server computes its RFC
    7638 thumbprint and persists it on the pending row; ``approve`` then
    copies it to ``internal_agents.dpop_jkt`` so the egress dep can
    enforce proof binding from the first request. Omitting it leaves the
    agent on the mode=optional grace path until the admin endpoint
    (#206) populates it manually or a re-enrollment with a DPoP-aware
    SDK supplies one.
    """
    dpop_jkt = _validate_and_compute_dpop_jkt(dpop_jwk)

    fingerprint = _pubkey_fingerprint(pubkey_pem)

    # H-csr-pop audit fix — verify proof-of-possession over the
    # submitted public key. A pre-fix Connector that doesn't ship
    # ``pop_signature`` is allowed through with a WARNING during the
    # transition window so existing fleets keep working; a follow-up
    # PR makes it required once Connector rollout is confirmed.
    if pop_signature:
        if not _verify_pop_signature(pubkey_pem, fingerprint, pop_signature):
            raise EnrollmentError(
                "pop_signature does not verify against pubkey_pem — "
                "the submitter does not control the corresponding "
                "private key (H-csr-pop audit).",
                http_status=400,
            )
    else:
        import logging
        logging.getLogger("mcp_proxy.enrollment").warning(
            "start_enrollment: legacy Connector submitted pubkey_pem "
            "without pop_signature (fingerprint=%s). Accepted under "
            "the transition window; a future release will make the "
            "PoP signature required.",
            fingerprint,
        )

    session_id = secrets.token_urlsafe(24)
    now = _now()
    expires_at = now + ENROLLMENT_TTL

    await conn.execute(
        text(
            """INSERT INTO pending_enrollments (
                session_id, pubkey_pem, pubkey_fingerprint,
                requester_name, requester_email, reason, device_info,
                status, created_at, expires_at, dpop_jkt
            ) VALUES (
                :sid, :pk, :fp,
                :name, :email, :reason, :device,
                'pending', :created, :expires, :dpop_jkt
            )"""
        ),
        {
            "sid": session_id,
            "pk": pubkey_pem,
            "fp": fingerprint,
            "name": requester_name,
            "email": requester_email,
            "reason": reason,
            "device": device_info,
            "created": _iso(now),
            "expires": _iso(expires_at),
            "dpop_jkt": dpop_jkt,
        },
    )
    return StartedEnrollment(session_id=session_id, expires_at=expires_at)


async def approve(
    conn: AsyncConnection,
    *,
    session_id: str,
    agent_id: str,
    capabilities: list[str],
    groups: list[str],
    admin_name: str,
    agent_manager: "AgentManager",
) -> dict[str, Any]:
    """Approve a pending enrollment — admin decides agent_id/caps/groups.

    The requester has no influence on these values; their only input was the
    public key and the self-declared name/email/reason that the admin used
    when deciding.
    """
    record = await get_record(conn, session_id)
    if record["status"] != "pending":
        raise EnrollmentError(
            f"Cannot approve an enrollment in status '{record['status']}'",
            http_status=409,
        )

    if not agent_manager.ca_loaded:
        raise EnrollmentError(
            "Org CA is not loaded — complete broker setup first.",
            http_status=503,
        )

    cert_pem = agent_manager.sign_external_pubkey(
        pubkey_pem=record["pubkey_pem"],
        agent_name=agent_id,
    )

    # ADR-014 — ``get_agent_from_client_cert`` parses the cert SAN
    # (``spiffe://<trust_domain>/<org_id>/<agent_name>``) and looks up
    # ``internal_agents.agent_id`` by the canonical ``{org_id}::{agent_name}``
    # form. Store the canonical form so the cert-auth dep finds the row.
    # Accept both shapes from the admin form: short ``agent-x`` (treated
    # as the agent name within this org) and pre-canonical ``acme::agent-x``
    # (kept as-is, idempotent — the dashboard happens to ship both
    # depending on which page builds the request).
    canonical_id = (
        agent_id if "::" in agent_id else f"{agent_manager.org_id}::{agent_id}"
    )

    now = _iso(_now())
    await conn.execute(
        text(
            """UPDATE pending_enrollments
               SET status = 'approved',
                   decided_at = :decided,
                   decided_by = :admin,
                   agent_id_assigned = :agent_id,
                   capabilities_assigned = :caps,
                   groups_assigned = :groups,
                   cert_pem = :cert
               WHERE session_id = :sid"""
        ),
        {
            "decided": now,
            "admin": admin_name,
            "agent_id": canonical_id,
            "caps": json.dumps(capabilities),
            "groups": json.dumps(groups),
            "cert": cert_pem,
            "sid": session_id,
        },
    )

    # Register the approved agent in the main internal_agents registry so it
    # shows up in the dashboard and can authenticate via mTLS client cert
    # (ADR-014) against /v1/egress/*. The cert ``cert_pem`` we just signed
    # on the line above is the credential — no api_key is minted.
    existing = await conn.execute(
        text("SELECT 1 FROM internal_agents WHERE agent_id = :aid"),
        {"aid": canonical_id},
    )
    # SPIFFE URI ``sign_external_pubkey`` just embedded into the cert SAN
    # — store it on the row so the Court's CSR auth dep
    # (``app.registry.user_principals_router.sign_csr`` /
    # ``app.auth.x509_verifier``) can match the assertion's cert SAN to
    # ``agents.spiffe_id`` after federation propagation. Without this,
    # device-code-enrolled Connectors hit ``SPIFFE ID in SAN does not
    # match the registered agent`` on every cross-org call.
    name_part = canonical_id.split("::", 1)[1]
    spiffe_id = (
        f"spiffe://{agent_manager.trust_domain}/"
        f"{agent_manager.org_id}/{name_part}"
    )

    if existing.first() is None:
        # ADR-010 D1 left ``federated`` opt-in (admin flips manually) so
        # an org could onboard local-only agents without leaking them
        # cross-org. ``connector``-method enrollments are the opposite
        # case: the user has just gone through the dashboard approval
        # ritual, the admin has set capabilities, and the agent's whole
        # purpose is to talk to the user (and, in shared-mode Frontdesk,
        # to the Court for ``/v1/principals/csr``). Auto-flip the flag
        # so the federation publisher pushes the row on the next tick.
        # Production deployments that want stricter gating can revoke
        # via the dashboard's admin-only ``federated=0`` toggle.
        await conn.execute(
            text(
                """INSERT INTO internal_agents
                   (agent_id, display_name, capabilities,
                    cert_pem, created_at, is_active, device_info, dpop_jkt,
                    enrollment_method, enrolled_at, spiffe_id,
                    federated, federated_at, reach, federation_revision)
                   VALUES (:aid, :dn, :caps, :cert, :created, 1,
                           :device, :dpop_jkt, 'connector', :created,
                           :spiffe_id,
                           1, :created, 'both', 1)"""
            ),
            {
                "aid": canonical_id,
                "dn": agent_id,
                "caps": json.dumps(capabilities),
                "cert": cert_pem,
                "created": now,
                # Free-form JSON carried from the Connector at start_enrollment
                # and kept through approval. We store it verbatim — the
                # dashboard parses it via a Jinja filter for display.
                "device": record.get("device_info"),
                # F-B-11 Phase 3b (#181) — JWK thumbprint the SDK pinned
                # at start_enrollment. NULL for pre-Phase-3c clients; the
                # egress dep's grace path accepts them until operators
                # flip to required mode (Phase 6).
                "dpop_jkt": record.get("dpop_jkt"),
                "spiffe_id": spiffe_id,
            },
        )
        await conn.execute(
            text(
                """INSERT INTO audit_log
                   (timestamp, agent_id, action, status, detail)
                   VALUES (:ts, :aid, 'agent.create', 'success', :detail)"""
            ),
            {
                "ts": now,
                "aid": canonical_id,
                "detail": json.dumps({
                    "source": "device_code_enrollment",
                    "session_id": session_id,
                    "admin": admin_name,
                    "capabilities": capabilities,
                }),
            },
        )

    # ADR-021 PR4d follow-up: schedule a baseline binding on the Court so
    # the freshly enrolled agent can pass ``login_via_proxy_with_local_key``
    # without an extra manual step. The publisher needs ~1 tick to push
    # the agent first, so we run this as a fire-and-forget task with
    # retry/backoff. Production deployments that want explicit per-agent
    # binding decisions can disable this via
    # ``MCP_PROXY_AUTO_BASELINE_BINDING=false`` (see config).
    #
    # Shared-mode skip (Frontdesk container): when the Connector declares
    # ``ambassador_mode=shared`` in ``device_info`` it is a *workload* that
    # signs CSRs for end-user principals — capabilities scoped to MCP
    # resources belong on those user principals, not on the container
    # (see memory/feedback_frontdesk_shared_mode_capability_model.md).
    # Skipping auto-binding keeps the container's permission surface to
    # ``principals.sign`` and prevents bogus baseline bindings from being
    # pushed to the Court for a workload that never calls MCP tools itself.
    import logging as _logging
    from mcp_proxy.config import get_settings as _get_settings
    _bind_log = _logging.getLogger("mcp_proxy.enrollment.binding")
    ambassador_mode = _ambassador_mode_from_device_info(record.get("device_info"))
    if ambassador_mode == "shared":
        _bind_log.info(
            "auto-binding skipped agent=%s reason=shared-mode-workload caps=%s",
            canonical_id, capabilities,
        )
    elif _get_settings().auto_baseline_binding and capabilities:
        _bind_log.info(
            "scheduling auto-binding agent=%s caps=%s",
            canonical_id, capabilities,
        )
        task = asyncio.create_task(_create_baseline_binding(
            agent_id=canonical_id,
            capabilities=capabilities,
        ))
        # Log unhandled exceptions so the task does not die silently.
        def _log_task_exc(t: asyncio.Task) -> None:
            try:
                exc = t.exception()
            except asyncio.CancelledError:
                return
            if exc is not None:
                _bind_log.exception(
                    "auto-binding task crashed for %s", canonical_id,
                    exc_info=exc,
                )
        task.add_done_callback(_log_task_exc)
    else:
        _bind_log.info(
            "auto-binding skipped agent=%s enabled=%s caps=%s",
            canonical_id, _get_settings().auto_baseline_binding, capabilities,
        )

    return await get_record(conn, session_id)


def _ambassador_mode_from_device_info(device_info: str | None) -> str | None:
    """Best-effort parse of ``ambassador_mode`` out of ``device_info``.

    ``device_info`` is the free-form JSON the Connector ships at
    ``start_enrollment``. The Frontdesk shared-mode Connector adds an
    ``ambassador_mode: "shared"`` key so the proxy can tell, at approval
    time, that the agent is a workload (no per-resource capabilities).

    Returns ``None`` for any malformed / missing / non-JSON payload —
    callers must treat ``None`` as ``single`` (the default).
    """
    if not device_info:
        return None
    try:
        parsed = json.loads(device_info)
    except (TypeError, ValueError):
        return None
    if not isinstance(parsed, dict):
        return None
    mode = parsed.get("ambassador_mode")
    if isinstance(mode, str):
        return mode
    return None


async def _create_baseline_binding(
    *,
    agent_id: str,
    capabilities: list[str],
    max_attempts: int = 30,
    initial_delay_s: float = 2.0,
) -> None:
    """Create + approve a baseline binding for a freshly enrolled agent.

    Runs on the proxy's event loop after ``approve()`` returns. The
    publisher needs a tick or two to push the agent into the Court's
    ``agents`` table; until that lands, ``POST /v1/registry/bindings``
    404s with ``no such agent``. We retry with linear backoff until the
    agent shows up or ``max_attempts * initial_delay_s`` (=60s default)
    elapses, whichever comes first.

    Failure to bind is logged but does not roll back the enrollment —
    operators can still create the binding manually from the dashboard.
    """
    import logging
    import httpx
    from mcp_proxy.config import get_settings
    from mcp_proxy.db import get_config

    log = logging.getLogger("mcp_proxy.enrollment.binding")
    settings = get_settings()
    org_id = settings.org_id
    broker_url = settings.broker_url
    if not broker_url:
        log.info(
            "auto-binding skipped for %s: standalone proxy (no broker_url)",
            agent_id,
        )
        return

    org_secret = await get_config("org_secret")
    if not org_secret:
        log.warning(
            "auto-binding skipped for %s: org_secret not in proxy_config",
            agent_id,
        )
        return

    headers = {"X-Org-Id": org_id, "X-Org-Secret": org_secret}
    body = {
        "org_id": org_id,
        "agent_id": agent_id,
        "scope": list(capabilities),
    }

    binding_id: int | str | None = None
    async with httpx.AsyncClient(timeout=httpx.Timeout(10.0)) as client:
        for attempt in range(max_attempts):
            try:
                r = await client.post(
                    f"{broker_url.rstrip('/')}/v1/registry/bindings",
                    json=body, headers=headers,
                )
            except httpx.HTTPError as exc:
                log.warning(
                    "auto-binding attempt %d failed for %s: %s",
                    attempt + 1, agent_id, exc,
                )
                await asyncio.sleep(initial_delay_s)
                continue

            if r.status_code == 201:
                binding_id = r.json().get("id")
                break
            if r.status_code == 409:
                # Already bound; look up the existing id.
                lr = await client.get(
                    f"{broker_url.rstrip('/')}/v1/registry/bindings",
                    params={"org_id": org_id}, headers=headers,
                )
                if lr.status_code == 200:
                    binding_id = next(
                        (b["id"] for b in lr.json()
                         if b.get("agent_id") == agent_id),
                        None,
                    )
                    if binding_id is not None:
                        break
            # 404 = publisher hasn't pushed yet; 400 = caps not on Court yet.
            await asyncio.sleep(initial_delay_s)

        if binding_id is None:
            log.warning(
                "auto-binding gave up after %d attempts for %s; "
                "operator can create+approve manually via dashboard",
                max_attempts, agent_id,
            )
            return

        try:
            ar = await client.post(
                f"{broker_url.rstrip('/')}/v1/registry/bindings/"
                f"{binding_id}/approve",
                headers=headers,
            )
        except httpx.HTTPError as exc:
            log.warning(
                "auto-binding approve failed for %s (id=%s): %s",
                agent_id, binding_id, exc,
            )
            return

        if ar.status_code in (200, 204):
            log.info(
                "auto-binding ok agent=%s binding_id=%s scope=%s",
                agent_id, binding_id, capabilities,
            )
        else:
            log.warning(
                "auto-binding approve returned %d for %s: %s",
                ar.status_code, agent_id, ar.text[:200],
            )


async def reject(
    conn: AsyncConnection,
    *,
    session_id: str,
    reason: str,
    admin_name: str,
) -> dict[str, Any]:
    record = await get_record(conn, session_id)
    if record["status"] != "pending":
        raise EnrollmentError(
            f"Cannot reject an enrollment in status '{record['status']}'",
            http_status=409,
        )
    now = _iso(_now())
    await conn.execute(
        text(
            """UPDATE pending_enrollments
               SET status = 'rejected',
                   decided_at = :decided,
                   decided_by = :admin,
                   rejection_reason = :reason
               WHERE session_id = :sid"""
        ),
        {"decided": now, "admin": admin_name, "reason": reason, "sid": session_id},
    )
    return await get_record(conn, session_id)


async def sweep_expired(conn: AsyncConnection) -> int:
    """Flip all pending records past their TTL to ``expired``. Returns count."""
    now_iso = _iso(_now())
    result = await conn.execute(
        text(
            "UPDATE pending_enrollments "
            "SET status = 'expired' "
            "WHERE status = 'pending' AND expires_at < :now"
        ),
        {"now": now_iso},
    )
    return int(result.rowcount or 0)
