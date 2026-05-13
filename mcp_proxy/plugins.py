"""Mastio plugin registry — extension point for the cullis-enterprise package.

Discovers plugins via Python entry points (group ``cullis.mastio_plugins``)
and exposes 7 hook surfaces. Empty registry is the supported default: when
no entry points are installed (community deploys) the proxy boots
identically to a no-plugin build.

Hook surfaces:
  * ``routers()``                 — list[APIRouter] mounted after core routers.
  * ``middlewares()``             — list[(cls, kwargs)] added to the FastAPI app.
  * ``kms_factory(name)``         — optional callable for a KMS provider name; the
                                    first plugin that returns non-None wins.
  * ``startup(app)``              — coroutine awaited at lifespan startup, after
                                    core init has placed services on ``app.state``.
  * ``shutdown(app)``             — coroutine awaited at lifespan shutdown, before
                                    core teardown disposes the engine + redis pool.
  * ``approval_required(action)`` — return True if the plugin wants to gate the
                                    given action_type (e.g. ``policies.save``)
                                    behind its own approval workflow. The first
                                    plugin that returns True wins.
  * ``submit_approval(...)``      — coroutine that persists a pending approval
                                    and returns its identifier. Called by core
                                    endpoint handlers after ``approval_required``
                                    returned True.
  * ``is_internal_replay(...)``   — coroutine returning True when the incoming
                                    request is a post-quorum replay the plugin
                                    itself issued. When True the approval hook
                                    steps aside and the endpoint runs normally.

Plugins override only the hooks they need; defaults are no-ops. Each plugin
may declare ``requires_feature``: when set, ``filter_by_license`` drops the
plugin from the active registry if the running license does not grant that
feature.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from importlib.metadata import entry_points
from typing import Any, Callable, Optional, Sequence

from fastapi import APIRouter, FastAPI

_log = logging.getLogger("mcp_proxy.plugins")

ENTRY_POINT_GROUP = "cullis.mastio_plugins"


class Plugin:
    """Base class for Mastio enterprise plugins.

    Subclasses override only the hooks they implement. ``name`` is used in
    log lines; ``requires_feature`` (when set) gates the plugin on a license
    flag.
    """

    name: str = "unnamed"
    requires_feature: str | None = None

    def routers(self) -> Sequence[APIRouter]:
        return ()

    def middlewares(self) -> Sequence[tuple[type, dict]]:
        return ()

    def kms_factory(self, provider: str) -> Optional[Callable[..., Any]]:
        return None

    async def startup(self, app: FastAPI) -> None:
        return None

    async def shutdown(self, app: FastAPI) -> None:
        return None

    def approval_required(self, action_type: str) -> bool:
        """Whether this plugin gates ``action_type`` behind its approval flow.

        Called by core endpoint handlers (policies.save, pki.rotate_ca, etc.)
        before executing the action. The first plugin in registry order that
        returns True wins; the action is intercepted and ``submit_approval``
        is invoked instead of normal execution.

        Default is False: community deploys without any plugin observe
        unchanged behavior.
        """
        return False

    async def submit_approval(
        self,
        action_type: str,
        payload: dict[str, Any],
        submitter_id: str,
    ) -> str:
        """Persist a pending approval and return its identifier (ULID).

        The plugin is responsible for storage, quorum tracking, expiry, and
        eventual execution of the action when quorum is reached. The core
        endpoint that called this returns a redirect to the plugin-managed
        approval detail page, e.g. ``/dashboard/approvals/{id}``.
        """
        raise NotImplementedError(
            f"plugin {self.name} declared approval_required for "
            f"{action_type!r} but did not implement submit_approval"
        )

    async def is_internal_replay(
        self,
        request: Any,
        action_type: str,
    ) -> bool:
        """Whether ``request`` is a post-quorum replay this plugin issued itself.

        Called by the approval hook BEFORE ``submit_approval`` so a plugin
        that has already collected enough signoffs and is now replaying
        the original mutation against its own endpoint can bypass the
        gating loop. The plugin proves authenticity its own way: a
        signed header, a server-only shared secret, a DB lookup against
        the approval row, etc. The hook trusts the boolean.

        Default is False: plugins that do not implement replay leave
        every request subject to normal interception.
        """
        return False


@dataclass
class PluginRegistry:
    plugins: list[Plugin] = field(default_factory=list)

    @classmethod
    def discover(cls, group: str = ENTRY_POINT_GROUP) -> "PluginRegistry":
        registry = cls()
        try:
            eps = entry_points().select(group=group)
        except Exception as exc:
            _log.warning("plugin discovery failed: %s", exc)
            return registry

        for ep in eps:
            try:
                obj = ep.load()
            except Exception as exc:
                _log.error("failed to load plugin entry-point %s: %s", ep.name, exc)
                continue
            try:
                plugin = obj() if isinstance(obj, type) else obj
            except Exception as exc:
                _log.error("failed to instantiate plugin %s: %s", ep.name, exc)
                continue
            if not isinstance(plugin, Plugin):
                _log.error(
                    "entry-point %s did not return a Plugin instance (got %r) — skipping",
                    ep.name, type(plugin),
                )
                continue
            registry.plugins.append(plugin)
            _log.info(
                "plugin loaded: %s (requires_feature=%s)",
                plugin.name, plugin.requires_feature,
            )
        return registry

    def filter_by_license(
        self, has_feature: Callable[[str], bool],
    ) -> "PluginRegistry":
        kept: list[Plugin] = []
        for plugin in self.plugins:
            if plugin.requires_feature is None or has_feature(plugin.requires_feature):
                kept.append(plugin)
            else:
                _log.warning(
                    "plugin %s skipped: feature %s not in license",
                    plugin.name, plugin.requires_feature,
                )
        return PluginRegistry(plugins=kept)

    def mount_routers(self, app: FastAPI) -> None:
        for plugin in self.plugins:
            for router in plugin.routers():
                app.include_router(router)

    def add_middlewares(self, app: FastAPI) -> None:
        for plugin in self.plugins:
            for cls_, kwargs in plugin.middlewares():
                app.add_middleware(cls_, **kwargs)

    def kms_factory(self, provider: str) -> Optional[Callable[..., Any]]:
        for plugin in self.plugins:
            factory = plugin.kms_factory(provider)
            if factory is not None:
                return factory
        return None

    async def run_startup(self, app: FastAPI) -> None:
        for plugin in self.plugins:
            try:
                await plugin.startup(app)
            except Exception as exc:
                _log.error("plugin %s startup failed: %s", plugin.name, exc)

    async def run_shutdown(self, app: FastAPI) -> None:
        for plugin in reversed(self.plugins):
            try:
                await plugin.shutdown(app)
            except Exception as exc:
                _log.warning("plugin %s shutdown raised: %s", plugin.name, exc)

    def approval_required_for(self, action_type: str) -> Optional[Plugin]:
        """First plugin that wants to gate ``action_type``, or None.

        Endpoint handlers can use this to skip the body fully when no plugin
        opts in (community deploy fast path).
        """
        for plugin in self.plugins:
            try:
                if plugin.approval_required(action_type):
                    return plugin
            except Exception as exc:
                _log.warning(
                    "plugin %s approval_required(%s) raised: %s",
                    plugin.name, action_type, exc,
                )
        return None


_registry: PluginRegistry | None = None


def get_registry() -> PluginRegistry:
    """Return the discovered + license-filtered plugin registry.

    First call discovers entry points and applies the license gate;
    subsequent calls reuse the cached instance. Tests may use
    :func:`reset_registry` to force re-discovery.
    """
    global _registry
    if _registry is None:
        from mcp_proxy.license import has_feature
        _registry = PluginRegistry.discover().filter_by_license(has_feature)
    return _registry


def reset_registry() -> None:
    global _registry
    _registry = None
