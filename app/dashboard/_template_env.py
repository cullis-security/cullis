"""Shared Jinja2Templates factory for Court dashboard sub-routers.

Sprint 2 / F-B-202 PR-1. Mirror of ``mcp_proxy/dashboard/_template_env.py``
on the Mastio side. The Court dashboard router has historically lived
as a single 3125-LOC file with templates built inline via
``Jinja2Templates(directory=...)``. The modularization sprint (10 PR,
~22h) splits the router into per-feature sub-routers, and every sub-
router that renders templates must thread through this factory so
cross-cutting Jinja2 globals (today: none on the Court side; in the
future: license gates, feature flags) land in one place.

The current implementation is intentionally minimal — no globals are
registered yet. Future PRs add them here without touching every
sub-router.
"""
from __future__ import annotations

import pathlib
from typing import Callable

from fastapi.templating import Jinja2Templates


def _register_globals(templates: Jinja2Templates) -> None:
    """Attach Court-wide Jinja2 globals + filters to ``templates``.

    Currently a no-op — the Court dashboard does not need cross-cutting
    template globals yet (the Mastio side has ``has_feature`` for
    license gates, but those plugin gates are Mastio-only). The hook
    is here so a future cross-cutting feature lands in one place.
    """
    return


def build_templates(
    template_dir: pathlib.Path | str,
    *,
    extra: Callable[[Jinja2Templates], None] | None = None,
) -> Jinja2Templates:
    """Construct a ``Jinja2Templates`` with the shared Court dashboard env.

    ``extra`` is an optional callback so a sub-router can add its own
    filters / globals on top of the shared baseline without duplicating
    the baseline itself.
    """
    templates = Jinja2Templates(directory=str(template_dir))
    _register_globals(templates)
    if extra is not None:
        extra(templates)
    return templates
