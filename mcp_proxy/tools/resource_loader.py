"""
MCP resource loader — populate the tool registry from ``local_mcp_resources``.

ADR-007 Phase 1 PR #2. Reads enabled rows out of the DB at startup and
registers each one as a ``ToolDefinition`` with ``resource_id`` and
``endpoint_url`` set. The handler is a placeholder that raises
``NotImplementedError`` — real forwarding lands in PR-3.

Conflict policy: if a name collides with an already-registered tool
(typically a builtin loaded from tools.yaml), the DB entry is SKIPPED
with a warning. Builtin YAML wins — rationale in ADR-007 issue #140.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from sqlalchemy import text

from mcp_proxy.db import get_db
from mcp_proxy.tools.context import ToolContext
from mcp_proxy.tools.registry import ToolDefinition, ToolRegistry

_log = logging.getLogger("mcp_proxy.tools.resource_loader")


async def _unwired_handler(ctx: ToolContext) -> Any:
    """Placeholder handler for DB-loaded resources.

    PR-2 registers the definition so discovery and metadata lookups
    work. PR-3 replaces this with a forwarder that proxies the call
    to ``tool_def.endpoint_url`` honouring binding and capability
    checks.
    """
    raise NotImplementedError(
        "MCP resource forwarding not wired yet — landing in ADR-007 Phase 1 PR #3"
    )


def _parse_allowed_domains(raw: str | None) -> list[str]:
    """Decode the JSON-encoded allowed_domains column.

    Schema stores a JSON array text (``"[]"`` default). Malformed
    payload degrades to an empty whitelist so a single bad row cannot
    break startup — defense in depth; ``WhitelistedTransport`` still
    validates at call-time.
    """
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        _log.warning("allowed_domains not valid JSON: %r — using []", raw)
        return []
    if not isinstance(parsed, list):
        _log.warning(
            "allowed_domains is not a JSON list: %r — using []", raw
        )
        return []
    return [str(d) for d in parsed]


async def load_resources_into_registry(registry: ToolRegistry) -> int:
    """Load every enabled row from ``local_mcp_resources`` into ``registry``.

    Returns the count of resources actually registered; rows skipped
    because of a name collision with a builtin are not counted.

    Must be called AFTER ``init_db`` has completed (Alembic upgrade head
    is responsible for creating the table). Safe to call multiple times:
    re-registering a resource the loader already knows about updates the
    existing entry (last-writer-wins).
    """
    loaded = 0
    skipped_conflict = 0

    async with get_db() as conn:
        result = await conn.execute(
            text(
                """
                SELECT resource_id, org_id, name, description,
                       endpoint_url, required_capability,
                       allowed_domains, enabled
                  FROM local_mcp_resources
                 WHERE enabled = 1
                """
            )
        )
        rows = list(result.mappings())

    for row in rows:
        name = row["name"]

        existing = registry.get(name)
        if existing is not None and not existing.is_mcp_resource:
            _log.warning(
                "Resource '%s' (resource_id=%s) collides with builtin "
                "tool — DB entry skipped. Rename the DB resource to "
                "resolve.",
                name,
                row["resource_id"],
            )
            skipped_conflict += 1
            continue

        tool_def = ToolDefinition(
            name=name,
            description=row["description"] or "",
            required_capability=row["required_capability"] or "",
            allowed_domains=_parse_allowed_domains(row["allowed_domains"]),
            handler=_unwired_handler,
            parameters_schema=None,
            resource_id=row["resource_id"],
            endpoint_url=row["endpoint_url"],
        )
        registry.register_definition(tool_def)
        loaded += 1

    _log.info(
        "MCP resource loader: %d loaded, %d skipped (conflict with builtin)",
        loaded,
        skipped_conflict,
    )
    return loaded
