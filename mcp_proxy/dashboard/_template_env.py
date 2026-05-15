"""Shared Jinja2Templates factory for dashboard sub-routers.

Every dashboard module renders templates that ``{% extends "base.html" %}``.
``base.html`` calls globals introduced for cross-cutting concerns
(today: ``has_feature``; in the future: other plugin-aware gates).
A sub-router that builds its ``Jinja2Templates`` directly with
``Jinja2Templates(directory=...)`` would have an env *without* those
globals, and any template that touches them would 500.

This factory threads every dashboard sub-router through one
registration path, so a new global landed here takes effect across
the whole dashboard in one place.
"""
from __future__ import annotations

import json
import pathlib
from typing import Callable

from fastapi.templating import Jinja2Templates


def _parse_device_info(raw):
    """Filter mirrored from router.py — kept here so a sub-router that
    builds its env via this factory gets the same filters available."""
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None

    def _pick(*keys):
        for k in keys:
            v = data.get(k)
            if v:
                return str(v)
        return None

    return {
        "os": _pick("os", "platform", "system"),
        "hostname": _pick("hostname", "host", "node"),
        "version": _pick("version", "connector_version", "client_version"),
    }


def _register_globals(templates: Jinja2Templates) -> None:
    """Attach the dashboard-wide Jinja2 globals + filters to ``templates``.

    Bound through the module (``mcp_proxy.license.has_feature(...)``)
    rather than capturing the function at import time so test-time
    ``monkeypatch.setattr(mcp_proxy.license, "has_feature", ...)``
    lands on subsequent renders.
    """
    from mcp_proxy import license as _license

    def _has_feature(feature: str) -> bool:
        return _license.has_feature(feature)

    templates.env.globals["has_feature"] = _has_feature
    templates.env.filters.setdefault("parse_device", _parse_device_info)


def build_templates(
    template_dir: pathlib.Path | str,
    *,
    extra: Callable[[Jinja2Templates], None] | None = None,
) -> Jinja2Templates:
    """Construct a ``Jinja2Templates`` with the shared dashboard env.

    ``extra`` is an optional callback that lets a sub-router add its
    own filters / globals on top of the shared baseline without
    duplicating the baseline itself.
    """
    templates = Jinja2Templates(directory=str(template_dir))
    _register_globals(templates)
    if extra is not None:
        extra(templates)
    return templates
