"""Process-global state for the connector.

The MCP stdio server is single-process, single-instance. Tools share state
(active session, current client) via this module rather than via globals
scattered across files. Phase 2 will extend this with the loaded identity
material; Phase 1 keeps it minimal.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cullis_sdk import CullisClient

    from cullis_connector.config import ConnectorConfig


@dataclass
class ConnectorState:
    """Mutable state shared across MCP tool invocations."""

    config: "ConnectorConfig | None" = None
    client: "CullisClient | None" = None
    agent_id: str = ""
    active_session: str | None = None
    active_peer: str | None = None
    last_correlation_id: str | None = None
    extra: dict[str, object] = field(default_factory=dict)


_state = ConnectorState()


def get_state() -> ConnectorState:
    return _state


def reset_state() -> None:
    """Clear process-global state. Tests use this between cases."""
    global _state
    _state = ConnectorState()
