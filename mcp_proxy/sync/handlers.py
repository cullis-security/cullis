"""Dispatch federation event types to cache upserts/deletes.

Each handler is an `async def h(conn, payload, ts)` that mutates the
proxy cache under the caller's transaction. The `apply_event` function
picks the right handler from the event type.

Handlers intentionally do not re-raise on "row not found" (for removals
and revocations), so the subscriber makes progress even when a proxy
restored from backup misses intermediate state: the next event type
that creates/updates the row recovers consistency.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

_log = logging.getLogger("mcp_proxy.sync.handlers")


# Event type constants (mirror app/broker/federation.py so the subscriber
# does not import from the broker package).
EVENT_AGENT_REGISTERED = "agent.registered"
EVENT_AGENT_REVOKED = "agent.revoked"
EVENT_AGENT_ROTATED = "agent.rotated"
EVENT_POLICY_UPDATED = "org.policy.updated"
EVENT_POLICY_REMOVED = "org.policy.removed"
EVENT_BINDING_GRANTED = "binding.granted"
EVENT_BINDING_REVOKED = "binding.revoked"


Handler = Callable[[AsyncConnection, str, dict[str, Any], str], Awaitable[None]]


async def _agent_registered(
    conn: AsyncConnection, org_id: str, payload: dict[str, Any], ts: str,
) -> None:
    await conn.execute(
        text(
            """INSERT INTO cached_federated_agents
                 (agent_id, org_id, display_name, capabilities, revoked, updated_at)
               VALUES (:agent_id, :org_id, :display_name, :capabilities, 0, :ts)
               ON CONFLICT (agent_id) DO UPDATE SET
                 org_id=excluded.org_id,
                 display_name=excluded.display_name,
                 capabilities=excluded.capabilities,
                 revoked=0,
                 updated_at=excluded.updated_at"""
        ),
        {
            "agent_id": payload["agent_id"],
            "org_id": org_id,
            "display_name": payload.get("display_name"),
            "capabilities": json.dumps(payload.get("capabilities", [])),
            "ts": ts,
        },
    )


async def _agent_revoked(
    conn: AsyncConnection, org_id: str, payload: dict[str, Any], ts: str,
) -> None:
    # Revoked events carry only {agent_id, serial_hex, reason} — we may
    # not have seen a prior register event (e.g. proxy enabled after
    # the agent was registered long ago). UPSERT with revoked=1 so the
    # cache reflects reality either way.
    agent_id = payload.get("agent_id")
    if not agent_id:
        _log.debug("agent.revoked without agent_id — skipping")
        return
    await conn.execute(
        text(
            """INSERT INTO cached_federated_agents
                 (agent_id, org_id, capabilities, revoked, updated_at)
               VALUES (:agent_id, :org_id, '[]', 1, :ts)
               ON CONFLICT (agent_id) DO UPDATE SET
                 revoked=1,
                 updated_at=excluded.updated_at"""
        ),
        {"agent_id": agent_id, "org_id": org_id, "ts": ts},
    )


async def _agent_rotated(
    conn: AsyncConnection, org_id: str, payload: dict[str, Any], ts: str,
) -> None:
    await conn.execute(
        text(
            """UPDATE cached_federated_agents
               SET thumbprint=:thumbprint, updated_at=:ts
               WHERE agent_id=:agent_id"""
        ),
        {
            "agent_id": payload["agent_id"],
            "thumbprint": payload.get("thumbprint"),
            "ts": ts,
        },
    )


async def _policy_updated(
    conn: AsyncConnection, org_id: str, payload: dict[str, Any], ts: str,
) -> None:
    await conn.execute(
        text(
            """INSERT INTO cached_policies
                 (policy_id, org_id, policy_type, is_active, updated_at)
               VALUES (:policy_id, :org_id, :policy_type, 1, :ts)
               ON CONFLICT (policy_id) DO UPDATE SET
                 policy_type=excluded.policy_type,
                 is_active=1,
                 updated_at=excluded.updated_at"""
        ),
        {
            "policy_id": payload["policy_id"],
            "org_id": org_id,
            "policy_type": payload.get("policy_type"),
            "ts": ts,
        },
    )


async def _policy_removed(
    conn: AsyncConnection, org_id: str, payload: dict[str, Any], ts: str,
) -> None:
    await conn.execute(
        text(
            """UPDATE cached_policies
               SET is_active=0, updated_at=:ts
               WHERE policy_id=:policy_id"""
        ),
        {"policy_id": payload["policy_id"], "ts": ts},
    )


async def _binding_granted(
    conn: AsyncConnection, org_id: str, payload: dict[str, Any], ts: str,
) -> None:
    await conn.execute(
        text(
            """INSERT INTO cached_bindings
                 (binding_id, org_id, agent_id, scope, status, updated_at)
               VALUES (:binding_id, :org_id, :agent_id, :scope, 'approved', :ts)
               ON CONFLICT (binding_id) DO UPDATE SET
                 org_id=excluded.org_id,
                 agent_id=excluded.agent_id,
                 scope=excluded.scope,
                 status='approved',
                 updated_at=excluded.updated_at"""
        ),
        {
            "binding_id": payload["binding_id"],
            "org_id": org_id,
            "agent_id": payload["agent_id"],
            "scope": json.dumps(payload.get("scope", [])),
            "ts": ts,
        },
    )


async def _binding_revoked(
    conn: AsyncConnection, org_id: str, payload: dict[str, Any], ts: str,
) -> None:
    await conn.execute(
        text(
            """UPDATE cached_bindings
               SET status='revoked', updated_at=:ts
               WHERE binding_id=:binding_id"""
        ),
        {"binding_id": payload["binding_id"], "ts": ts},
    )


_HANDLERS: dict[str, Handler] = {
    EVENT_AGENT_REGISTERED: _agent_registered,
    EVENT_AGENT_REVOKED: _agent_revoked,
    EVENT_AGENT_ROTATED: _agent_rotated,
    EVENT_POLICY_UPDATED: _policy_updated,
    EVENT_POLICY_REMOVED: _policy_removed,
    EVENT_BINDING_GRANTED: _binding_granted,
    EVENT_BINDING_REVOKED: _binding_revoked,
}


async def apply_event(
    conn: AsyncConnection,
    *,
    org_id: str,
    seq: int,
    event_type: str,
    payload: dict[str, Any],
) -> None:
    """Apply a single federation event to the proxy cache and bump the
    cursor. All writes go through the same transaction so a mid-apply
    crash cannot leave the cache ahead of the cursor (or vice versa).
    """
    handler = _HANDLERS.get(event_type)
    ts = datetime.now(timezone.utc).isoformat()
    if handler is None:
        # Unknown event type: log and advance the cursor anyway. A newer
        # broker may introduce event types this proxy version doesn't
        # handle; rather than wedging the subscriber, we skip and rely
        # on the rebuild-cache fallback for full consistency.
        _log.info("unknown federation event type %s — cursor advanced", event_type)
    else:
        await handler(conn, org_id, payload, ts)

    await conn.execute(
        text(
            """INSERT INTO federation_cursor (org_id, last_seq, updated_at)
               VALUES (:org_id, :seq, :ts)
               ON CONFLICT (org_id) DO UPDATE SET
                 last_seq=excluded.last_seq,
                 updated_at=excluded.updated_at"""
        ),
        {"org_id": org_id, "seq": seq, "ts": ts},
    )


async def get_cursor(conn: AsyncConnection, org_id: str) -> int:
    """Read last-applied seq for `org_id`, returning 0 if the subscriber
    has never run before for this org."""
    row = (
        await conn.execute(
            text("SELECT last_seq FROM federation_cursor WHERE org_id = :org_id"),
            {"org_id": org_id},
        )
    ).first()
    return int(row[0]) if row else 0
