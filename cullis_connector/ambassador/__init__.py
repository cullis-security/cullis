"""Connector Ambassador (ADR-019).

OpenAI-compatible HTTP surface that translates Bearer-authenticated
requests from a chat client (Cullis Chat, Cursor, OpenWebUI, ...) into
DPoP+mTLS calls to the Cullis cloud (mcp_proxy + Mastio).

This package adds three FastAPI endpoints to the Connector dashboard
when ``config.ambassador.enabled`` is true:

  POST /v1/chat/completions    — OpenAI ChatCompletion, with tool-use
                                 loop dispatched server-side
  POST /v1/mcp                  — JSON-RPC 2.0 MCP aggregator passthrough
  GET  /v1/models               — list of models the Cullis cloud routes

The Ambassador binds to 127.0.0.1 only and rejects any request whose
``request.client.host`` is not loopback. The Bearer token is locally
generated at first start and stored at
``<config_dir>/local.token`` mode 0600. ADR-019 §6 (Security & threat
model) documents the trust boundary in detail.
"""

from cullis_connector.ambassador.router import router

__all__ = ["router"]
