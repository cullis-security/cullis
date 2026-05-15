"""
ToolContext — runtime context injected into every tool handler.

The context carries parameters, identity, secrets, and a pre-configured
httpx client whose transport enforces the tool's domain whitelist.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import httpx


@dataclass(frozen=True)
class ToolContext:
    """Immutable execution context passed to tool handlers."""

    parameters: dict[str, Any]
    agent_id: str
    org_id: str
    capabilities: list[str]
    secrets: dict[str, str]
    http_client: httpx.AsyncClient
    request_id: str
    # ADR-007 Phase 1 PR #3 — forwarder handler needs SecretProvider to
    # resolve ``auth_secret_ref`` (env://... or vault://...). Optional so
    # builtin handlers don't have to care.
    secret_provider: Any | None = None
    # Scope #5 (session 2026-05-15) — handlers that need to call into
    # other Mastio subsystems (broker bridge, local WS manager, audit
    # chain) can pull them from the FastAPI app state. Populated by
    # ``executor.run`` when invoked through a route that has a
    # ``Request`` object; ``None`` when the executor was invoked
    # without one (eg. CLI / tests). Builtin handlers that touch
    # ``app_state`` must tolerate ``None`` for that test path.
    app_state: Any | None = None
