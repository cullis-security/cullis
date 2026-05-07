"""Slow-path hook registry.

Phase 1 (foundation) shipped the contract; the actual slow-path
dispatcher lives in the enterprise ``llm_guardian`` plugin. The public
core stays adapter-agnostic by exposing a single ``set_slow_path_hook``
setter that the plugin calls during ``startup()``. The
``/v1/guardian/inspect`` endpoint then enqueues a copy of the payload
non-blocking; if no hook is registered, the call is a no-op.

This pattern keeps the public repo from importing anything from the
enterprise repo (open-core boundary).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Protocol

_log = logging.getLogger("mcp_proxy.guardian.slow_path")


@dataclass
class SlowPathPayload:
    """Subset of the inspect request that the slow path needs.

    The endpoint never hands the original ``InspectRequest`` to the
    hook so the plugin author cannot accidentally couple to the
    public Pydantic schema; the dataclass is a stable wire shape.
    """

    audit_id: str
    direction: str
    agent_id: str
    peer_agent_id: str
    msg_id: str
    payload: bytes


class SlowPathHook(Protocol):
    def __call__(self, task: SlowPathPayload) -> bool:  # pragma: no cover
        ...


_hook: SlowPathHook | None = None


def set_slow_path_hook(hook: SlowPathHook | None) -> None:
    """Register the slow-path enqueue callable. ``None`` clears it.

    Idempotent: re-registering replaces the existing hook. The plugin
    sets it on startup and clears on shutdown so a partial reload
    leaves no dangling reference.
    """
    global _hook
    _hook = hook
    if hook is None:
        _log.info("guardian slow-path hook cleared")
    else:
        _log.info("guardian slow-path hook registered")


def get_slow_path_hook() -> SlowPathHook | None:
    return _hook


def enqueue_slow_path(task: SlowPathPayload) -> bool:
    """Enqueue the payload non-blocking. Returns False on no-op or drop.

    Endpoint callers MUST treat False as best-effort observation lost,
    not a hard failure: the fast-path decision has already been
    computed and returned to the client.
    """
    hook = _hook
    if hook is None:
        return False
    try:
        return hook(task)
    except Exception as exc:
        _log.warning("guardian slow-path enqueue failed: %s", exc)
        return False
