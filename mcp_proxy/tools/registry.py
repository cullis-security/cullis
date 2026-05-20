"""
ToolRegistry — singleton registry of all available tools.

Tools register themselves via the ``@tool_registry.register(...)`` decorator
which is evaluated at import time.  The registry can also load tool
definitions from a YAML file, dynamically importing their handler modules.
"""
from __future__ import annotations

import importlib
import logging
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

import yaml

from mcp_proxy.tools.context import ToolContext

_log = logging.getLogger("mcp_proxy.tools.registry")


@dataclass
class ToolDefinition:
    """Complete definition of a registered tool."""

    name: str
    description: str
    required_capability: str
    allowed_domains: list[str]
    handler: Callable[[ToolContext], Awaitable[Any]]
    parameters_schema: dict | None = None
    # ADR-007 Phase 1 — MCP resource metadata. Populated when the entry
    # was loaded from ``local_mcp_resources`` instead of the builtin YAML.
    # PR-3 reads these to forward calls; builtins keep both as None.
    resource_id: str | None = None
    endpoint_url: str | None = None

    @property
    def is_mcp_resource(self) -> bool:
        """True when this definition backs an external MCP resource."""
        return self.resource_id is not None


class ToolRegistry:
    """Central registry for all proxy tools.

    Usage::

        @tool_registry.register(
            name="my_tool",
            capability="my.cap",
            allowed_domains=["api.example.com"],
            description="Does something",
        )
        async def my_tool(ctx: ToolContext) -> dict:
            ...
    """

    def __init__(self) -> None:
        self._tools: dict[str, ToolDefinition] = {}

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(
        self,
        name: str,
        capability: str,
        allowed_domains: list[str] | None = None,
        description: str = "",
        parameters_schema: dict | None = None,
    ) -> Callable:
        """Decorator to register a builtin tool handler function.

        F-A-304 fail-closed contract (audit 2026-05-20): ``capability``
        must be a non-empty string. Builtins have no binding row in
        ``local_agent_resource_bindings``, so an empty capability would
        collapse the executor's capability gate into a silent allow
        for every authenticated principal. Refuse at registration so
        the regression is caught at import time, not in production.

        MCP resources loaded from ``local_mcp_resources`` go through
        :meth:`register_definition` instead, where empty capability is
        permitted (the binding table is the authoritative authz path
        per ADR-007). The executor emits an explicit audit subtype
        when an MCP resource with empty capability is invoked so SOC
        can detect misconfigured rows.
        """
        if not isinstance(capability, str) or not capability.strip():
            raise ValueError(
                f"Tool '{name}' registered without a non-empty "
                "required_capability. Builtins must declare a "
                "capability; an empty value would silently bypass "
                "the capability gate for every authenticated "
                "principal (F-A-304, ADR-007)."
            )

        def decorator(fn: Callable[[ToolContext], Awaitable[Any]]) -> Callable:
            if name in self._tools:
                _log.warning("Tool '%s' registered twice — overwriting", name)
            self._tools[name] = ToolDefinition(
                name=name,
                description=description,
                required_capability=capability,
                allowed_domains=allowed_domains or [],
                handler=fn,
                parameters_schema=parameters_schema,
            )
            _log.info("Registered tool '%s' (capability=%s)", name, capability)
            return fn

        return decorator

    def register_definition(self, tool_def: ToolDefinition) -> None:
        """Register a pre-built ToolDefinition.

        Used by the DB resource loader (ADR-007) which constructs the
        definition from a ``local_mcp_resources`` row. Unlike the
        ``@register`` decorator (which wraps a handler function), this
        path accepts the full object so callers can attach a placeholder
        handler until PR-3 wires real forwarding.

        Last-writer-wins with a warning — same semantics as ``register``.
        """
        if tool_def.name in self._tools:
            _log.warning(
                "Tool '%s' registered twice — overwriting", tool_def.name
            )
        self._tools[tool_def.name] = tool_def
        _log.info(
            "Registered tool '%s' (capability=%s, resource_id=%s)",
            tool_def.name,
            tool_def.required_capability,
            tool_def.resource_id,
        )

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def get(self, name: str) -> ToolDefinition | None:
        """Return the tool definition, or None if not registered."""
        return self._tools.get(name)

    def list_tools(self) -> list[ToolDefinition]:
        """Return all registered tool definitions."""
        return list(self._tools.values())

    def has_capability(self, tool_name: str, agent_capabilities: list[str]) -> bool:
        """Check whether the agent has the capability required by the tool.

        Semantics (F-A-304 fail-closed contract, audit 2026-05-20):

        * Unknown tool name → ``False``.
        * Builtin (``is_mcp_resource is False``) with empty
          ``required_capability`` → ``False``. Registration-time guard
          should prevent this state from existing in the first place;
          treating it as fail-closed here is defense-in-depth for any
          callsite that bypassed the decorator (e.g. direct
          :meth:`register_definition` from tests or future migrations).
        * MCP resource with empty ``required_capability`` → ``True``.
          The binding table is the authoritative authz path per
          ADR-007; capability stays optional discovery metadata.
        * Tool with declared capability → membership check.

        Note: the executor (``mcp_proxy/tools/executor.py``) is the
        runtime enforcement point. This helper exists for
        discovery-time filtering and is exercised by aggregator code
        paths; the executor must independently enforce the same
        contract.
        """
        tool = self._tools.get(tool_name)
        if tool is None:
            return False
        if not tool.required_capability:
            return bool(tool.is_mcp_resource)
        return tool.required_capability in agent_capabilities

    # ------------------------------------------------------------------
    # YAML loading
    # ------------------------------------------------------------------

    def load_from_yaml(self, yaml_path: str) -> None:
        """Load tool definitions from a YAML config file.

        Each entry must specify a ``module`` key.  The module is imported
        dynamically, which triggers the ``@register`` decorator.  If a
        tool in the YAML is already registered (e.g. via direct import),
        the YAML metadata (description, capability, allowed_domains) is
        merged as an override.
        """
        try:
            with open(yaml_path, "r") as fh:
                data = yaml.safe_load(fh)
        except FileNotFoundError:
            _log.warning("Tools config file not found: %s — no tools loaded", yaml_path)
            return
        except yaml.YAMLError:
            _log.exception("Failed to parse tools YAML: %s", yaml_path)
            return

        if not data or "tools" not in data:
            _log.warning("No 'tools' key in %s", yaml_path)
            return

        for tool_name, spec in data["tools"].items():
            module_path = spec.get("module")
            if not module_path:
                _log.warning("Tool '%s' in YAML has no 'module' — skipping", tool_name)
                continue

            # Dynamic import triggers @register decorator
            try:
                importlib.import_module(module_path)
            except Exception:
                _log.exception(
                    "Failed to import tool module '%s' for tool '%s'",
                    module_path,
                    tool_name,
                )
                continue

            # Merge YAML overrides into the registered definition
            existing = self._tools.get(tool_name)
            if existing is not None:
                if "description" in spec and spec["description"]:
                    existing.description = spec["description"]
                if "capability" in spec:
                    # F-A-304: refuse YAML overrides that blank out the
                    # capability on a builtin. ``is_mcp_resource`` is False
                    # for everything loaded via YAML (MCP resources come
                    # from the DB), so the gate would collapse silently.
                    new_cap = spec["capability"]
                    if (
                        not existing.is_mcp_resource
                        and (
                            not isinstance(new_cap, str)
                            or not new_cap.strip()
                        )
                    ):
                        _log.error(
                            "Tool '%s' YAML override sets empty "
                            "required_capability — ignored (F-A-304 "
                            "fail-closed). Existing capability '%s' kept.",
                            tool_name, existing.required_capability,
                        )
                    else:
                        existing.required_capability = new_cap
                if "allowed_domains" in spec:
                    existing.allowed_domains = spec["allowed_domains"]
            else:
                _log.warning(
                    "Tool '%s' was not registered after importing '%s'",
                    tool_name,
                    module_path,
                )

        _log.info(
            "Tool registry loaded from %s: %d tool(s) registered",
            yaml_path,
            len(self._tools),
        )

    def __len__(self) -> int:
        return len(self._tools)

    def __contains__(self, name: str) -> bool:
        return name in self._tools


# Singleton instance — import this everywhere
tool_registry = ToolRegistry()
