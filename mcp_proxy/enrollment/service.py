"""Business logic for the Connector enrollment flow.

Thin helpers that take an ``AsyncConnection`` (the proxy's only DB primitive,
see ``mcp_proxy.db.get_db``) and manipulate the ``pending_enrollments``
table via raw SQL. Cert signing is delegated to :class:`AgentManager` so CA
material stays owned by the module that already loads it from Vault/disk.
"""
from __future__ import annotations

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


async def start_enrollment(
    conn: AsyncConnection,
    *,
    pubkey_pem: str,
    requester_name: str,
    requester_email: str,
    reason: str | None,
    device_info: str | None,
) -> StartedEnrollment:
    """Create a new pending enrollment.

    The session_id is a 128-bit URL-safe random token — unguessable so only
    the client that started the flow can poll it.
    """
    fingerprint = _pubkey_fingerprint(pubkey_pem)
    session_id = secrets.token_urlsafe(24)
    now = _now()
    expires_at = now + ENROLLMENT_TTL

    await conn.execute(
        text(
            """INSERT INTO pending_enrollments (
                session_id, pubkey_pem, pubkey_fingerprint,
                requester_name, requester_email, reason, device_info,
                status, created_at, expires_at
            ) VALUES (
                :sid, :pk, :fp,
                :name, :email, :reason, :device,
                'pending', :created, :expires
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
            "agent_id": agent_id,
            "caps": json.dumps(capabilities),
            "groups": json.dumps(groups),
            "cert": cert_pem,
            "sid": session_id,
        },
    )

    # Register the approved agent in the main internal_agents registry so it
    # shows up in the dashboard and can authenticate via X-API-Key against
    # /v1/egress/*. The connector does not use the API key (it authenticates
    # via cert + DPoP), but it is surfaced on the dashboard for admin rotation
    # and optional SDK paths. Without this step a device-code enrollment left
    # the agent invisible in the UI — see the history of this function.
    from mcp_proxy.auth.api_key import generate_api_key, hash_api_key

    raw_api_key = generate_api_key(agent_id)
    api_key_hash = hash_api_key(raw_api_key)
    existing = await conn.execute(
        text("SELECT 1 FROM internal_agents WHERE agent_id = :aid"),
        {"aid": agent_id},
    )
    if existing.first() is None:
        await conn.execute(
            text(
                """INSERT INTO internal_agents
                   (agent_id, display_name, capabilities, api_key_hash,
                    cert_pem, created_at, is_active)
                   VALUES (:aid, :dn, :caps, :hash, :cert, :created, 1)"""
            ),
            {
                "aid": agent_id,
                "dn": agent_id,
                "caps": json.dumps(capabilities),
                "hash": api_key_hash,
                "cert": cert_pem,
                "created": now,
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
                "aid": agent_id,
                "detail": json.dumps({
                    "source": "device_code_enrollment",
                    "session_id": session_id,
                    "admin": admin_name,
                    "capabilities": capabilities,
                }),
            },
        )

    return await get_record(conn, session_id)


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
