"""
MCP resource loader — populate the tool registry from ``local_mcp_resources``.

ADR-007 Phase 1 PR #2 (schema + placeholder) + PR #3 (real forwarder).

Conflict policy: if a name collides with an already-registered tool
(typically a builtin loaded from tools.yaml), the DB entry is SKIPPED
with a warning. Builtin YAML wins — rationale in ADR-007 issue #140.
"""
from __future__ import annotations

import json
import logging

from sqlalchemy import text

from mcp_proxy.db import get_db
from mcp_proxy.tools.mcp_resource_forwarder import forward_to_mcp_resource
from mcp_proxy.tools.registry import ToolDefinition, ToolRegistry

_log = logging.getLogger("mcp_proxy.tools.resource_loader")


async def reload_resources(registry: ToolRegistry) -> int:
    """Drop every MCP-resource ToolDefinition and reload from the DB.

    Called by the dashboard CRUD after any mutation to
    ``local_mcp_resources`` so the live registry reflects the new state
    without a proxy restart. Builtin tools (``is_mcp_resource is False``)
    are untouched.

    Returns the count of resources re-registered.
    """
    stale = [
        name for name, td in registry._tools.items()
        if td.is_mcp_resource
    ]
    for name in stale:
        registry._tools.pop(name, None)
    return await load_resources_into_registry(registry)


async def _noop_placeholder(ctx):
    """Unreachable placeholder — real handler is attached via closure below.

    Exists only because :class:`ToolDefinition` requires a non-null
    ``handler`` at construction and we bind the closure-ified forwarder
    immediately after. If this function ever runs, the binding step
    was skipped — log loudly.
    """
    raise RuntimeError(
        "resource_loader bug: forwarder closure not bound for this ToolDefinition"
    )


def _make_handler(tool_def: ToolDefinition):
    """Bind the forwarder to its ToolDefinition via closure.

    The executor invokes ``tool_def.handler(ctx)`` with a single
    positional ``ctx``; the forwarder needs the definition too for
    endpoint_url / auth metadata, so we pre-bind here.
    """
    async def _h(ctx):
        return await forward_to_mcp_resource(ctx, tool_def=tool_def)
    return _h


async def _fetch_upstream_schema(endpoint_url: str, tool_name: str) -> dict | None:
    """Best-effort fetch of the upstream MCP server's inputSchema for ``tool_name``.

    The DB stores only the resource description + endpoint; the actual
    tool signature lives on the upstream MCP server (e.g. postgres-mcp
    advertises ``{sql: string}``). Without this, the proxy aggregator
    advertises an empty inputSchema and the LLM has no idea how to
    invoke the tool.
    """
    import httpx as _httpx
    try:
        async with _httpx.AsyncClient(timeout=3.0) as client:
            r = await client.post(
                endpoint_url,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                },
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            )
            if r.status_code != 200:
                _log.warning(
                    "upstream tools/list returned %d for %s",
                    r.status_code, endpoint_url,
                )
                return None
            data = r.json()
            for t in (data.get("result", {}) or {}).get("tools", []):
                if t.get("name") == tool_name:
                    return t.get("inputSchema")
            return None
    except Exception as exc:
        _log.warning(
            "upstream schema fetch failed for %s: %s", endpoint_url, exc,
        )
        return None


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
                       endpoint_url, auth_type, auth_secret_ref,
                       required_capability, allowed_domains, enabled
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

        # Fetch upstream input schema so the LLM sees the real tool
        # signature (sql / SQL string / etc.) instead of an empty object.
        # Best-effort: if the upstream MCP server is not yet up at boot,
        # fall back to None and the LLM gets the empty schema. Future PR:
        # lazy + cached refresh on demand.
        upstream_schema = await _fetch_upstream_schema(
            row["endpoint_url"], name,
        )
        tool_def = ToolDefinition(
            name=name,
            description=row["description"] or "",
            required_capability=row["required_capability"] or "",
            allowed_domains=_parse_allowed_domains(row["allowed_domains"]),
            handler=_noop_placeholder,  # replaced below; must be a callable
            parameters_schema=upstream_schema,
            resource_id=row["resource_id"],
            endpoint_url=row["endpoint_url"],
        )
        # Stash auth config as private attrs (avoids widening the public
        # dataclass schema for backend-specific metadata the forwarder
        # alone consumes).
        tool_def._auth_type = row["auth_type"]
        tool_def._auth_secret_ref = row["auth_secret_ref"]
        # Bind the real handler with the def in its closure.
        tool_def.handler = _make_handler(tool_def)
        registry.register_definition(tool_def)
        loaded += 1

    _log.info(
        "MCP resource loader: %d loaded, %d skipped (conflict with builtin)",
        loaded,
        skipped_conflict,
    )
    return loaded
