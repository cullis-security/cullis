"""Active-binding lookup for ``local_agent_resource_bindings`` (ADR-020).

Shared by:
  * ``mcp_proxy.ingress.mcp_aggregator`` — JSON-RPC ``tools/call`` path.
  * ``mcp_proxy.tools.executor`` — REST ``POST /v1/ingress/execute``
    path (CRIT-2 fix, audit T3-F1).

Pre-CRIT-2 the executor short-circuited the binding check entirely for
``principal_type != "agent"``; user / workload tokens hit MCP-resource
tools without any per-resource grant. The fix wires this same lookup
into the executor so both surfaces enforce the binding gate.

The query is keyed on ``(agent_id, principal_type, resource_id)`` so a
user named "daniele" never inherits an agent named "daniele"'s
bindings (or vice versa).
"""
from __future__ import annotations

from sqlalchemy import text

from mcp_proxy.db import get_db


async def bound_resource_ids(
    principal_id: str, principal_type: str,
) -> set[str]:
    """Set of resource_ids this principal currently has active bindings for."""
    async with get_db() as conn:
        result = await conn.execute(
            text(
                """
                SELECT resource_id
                  FROM local_agent_resource_bindings
                 WHERE agent_id = :a
                   AND principal_type = :pt
                   AND revoked_at IS NULL
                """
            ),
            {"a": principal_id, "pt": principal_type},
        )
        return {row[0] for row in result.all()}


async def has_active_binding(
    principal_id: str, principal_type: str, resource_id: str,
) -> bool:
    """True iff an unrevoked binding exists for this triple."""
    async with get_db() as conn:
        row = (await conn.execute(
            text(
                """
                SELECT 1 FROM local_agent_resource_bindings
                 WHERE agent_id = :a
                   AND principal_type = :pt
                   AND resource_id = :r
                   AND revoked_at IS NULL
                 LIMIT 1
                """
            ),
            {"a": principal_id, "pt": principal_type, "r": resource_id},
        )).first()
        return row is not None
