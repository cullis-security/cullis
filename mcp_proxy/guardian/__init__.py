"""ADR-016 Guardian — bidirectional content inspection on Mastio.

Phase 1 (foundation) shipped the contract: endpoint, ticket signing,
registry hook for plugin tools, audit row writer. Phase 2 (this module
extension) adds the fast-path dispatch loop in the endpoint and the
slow-path hook the enterprise ``llm_guardian`` plugin sets at startup.

Public surface:
    record_inspection — write a guardian decision to local_audit
    register_tool, registered_tools, Tool, ToolResult — plugin contract
    sign_ticket, verify_ticket, GuardianTicketError — JWT helpers
    set_slow_path_hook, SlowPathPayload — slow-path enqueue contract
"""
from __future__ import annotations

from mcp_proxy.guardian.audit import record_inspection
from mcp_proxy.guardian.registry import (
    Tool,
    ToolResult,
    register_tool,
    registered_tools,
)
from mcp_proxy.guardian.slow_path import (
    SlowPathHook,
    SlowPathPayload,
    enqueue_slow_path,
    get_slow_path_hook,
    set_slow_path_hook,
)
from mcp_proxy.guardian.ticket import (
    GuardianTicketError,
    sign_ticket,
    verify_ticket,
)

__all__ = [
    "GuardianTicketError",
    "SlowPathHook",
    "SlowPathPayload",
    "Tool",
    "ToolResult",
    "enqueue_slow_path",
    "get_slow_path_hook",
    "record_inspection",
    "register_tool",
    "registered_tools",
    "set_slow_path_hook",
    "sign_ticket",
    "verify_ticket",
]
