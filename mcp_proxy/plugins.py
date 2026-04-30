"""Mastio plugin registry — extension point for the cullis-enterprise package.

Discovers plugins via Python entry points (group ``cullis.mastio_plugins``)
and exposes 5 hook surfaces. Empty registry is the supported default: when
no entry points are installed (community deploys) the proxy boots
identically to a no-plugin build.

Hook surfaces:
  * ``routers()``         — list[APIRouter] mounted after core routers.
  * ``middlewares()``     — list[(cls, kwargs)] added to the FastAPI app.
  * ``kms_factory(name)`` — optional callable for a KMS provider name; the
                            first plugin that returns non-None wins.
  * ``startup(app)``      — coroutine awaited at lifespan startup, after
                            core init has placed services on ``app.state``.
  * ``shutdown(app)``     — coroutine awaited at lifespan shutdown, before
                            core teardown disposes the engine + redis pool.

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
