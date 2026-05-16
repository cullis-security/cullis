"""MDM integrations — device attestation Layer 1 (ADR-032).

Phase 1 ships Intune only. Jamf and Workspace ONE are deferred until
pilot signal validates the MDM-cert path for the regulated customers
driving the requirement (DORA, NIS2, PSD2).

The exported surface is intentionally narrow:

* :class:`IntuneClient` — async Microsoft Graph client (token cache +
  delta paging).
* :func:`intune_poll_loop` — long-running task wired into the proxy
  lifespan when ``MCP_PROXY_MDM_INTUNE_ENABLED=true``.

Both call sites live next to each other so a future Jamf/WS1 module
can mirror the same shape without bleeding into the rest of the
proxy.
"""
from mcp_proxy.mdm.intune import IntuneClient, IntuneGraphError
from mcp_proxy.mdm.poller import intune_poll_loop

__all__ = ["IntuneClient", "IntuneGraphError", "intune_poll_loop"]
