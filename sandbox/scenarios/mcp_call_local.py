"""Sandbox scenario — agent calls an MCP tool on its own org's MCP server.

Executed inside a running agent container:
    docker compose exec agent-X python /app/scenarios/mcp_call_local.py

The proxy's aggregator at ``/v1/mcp`` exposes every MCP resource the
agent is bound to (ADR-007 Phase 1). This driver drives one
``tools/call`` JSON-RPC and surfaces the result. Intra-org only —
cross-org MCP has to go through A2A message wrapping, out of scope
for this walkthrough.

Auth is the ADR-011 Phase 4 unified path: the agent reuses the
API-key + DPoP credentials that ``bootstrap-mastio`` enrolled under
``/state/{org}/agents/{name}/``.

Env:
    BROKER_URL          proxy reverse-proxy URL (= the proxy the agent lives on)
    ORG_ID              this agent's org
    AGENT_NAME          this agent's short name
    MCP_TOOL_NAME       e.g. 'get_catalog' or 'check_inventory' — required
    MCP_TOOL_ARGS       JSON-encoded arguments object (default: '{}')
    IDENTITY_ROOT       where bootstrap-mastio wrote credentials (default /state)
"""
from __future__ import annotations

import json
import os
import sys

from cullis_sdk import CullisClient

from _identity import load_enrolled_client


RESET = "\033[0m"
BOLD  = "\033[1m"
GREEN = "\033[32m"
CYAN  = "\033[36m"
YELLOW = "\033[33m"
GRAY  = "\033[90m"


def _step(n: int, title: str) -> None:
    print(f"\n{BOLD}{CYAN}▶ Step {n} — {title}{RESET}", flush=True)


def _ok(msg: str) -> None:
    print(f"  {GREEN}✓{RESET} {msg}", flush=True)


def _info(msg: str) -> None:
    print(f"  {GRAY}…{RESET} {msg}", flush=True)


def _fail(msg: str) -> None:
    print(f"  {YELLOW}✗{RESET} {msg}", flush=True)


def _rpc(client: CullisClient, method: str, params: dict | None = None) -> dict:
    """POST a single JSON-RPC request to the proxy's /v1/mcp aggregator.

    Uses the SDK's internal ``_authed_request`` so DPoP nonce rotation
    is handled automatically (the proxy issues ``use_dpop_nonce`` on the
    first call of every new session — plain ``httpx.post`` would eat a
    spurious 401 otherwise).
    """
    resp = client._authed_request(
        "POST", "/v1/mcp",
        json={
            "jsonrpc": "2.0",
            "id": "1",
            "method": method,
            "params": params or {},
        },
    )
    resp.raise_for_status()
    return resp.json()


def main() -> int:
    tool_name = os.environ.get("MCP_TOOL_NAME")
    if not tool_name:
        _fail("MCP_TOOL_NAME is required (e.g. get_catalog)")
        return 2
    try:
        tool_args = json.loads(os.environ.get("MCP_TOOL_ARGS", "{}"))
    except json.JSONDecodeError as exc:
        _fail(f"MCP_TOOL_ARGS is not valid JSON: {exc}")
        return 2

    broker = os.environ["BROKER_URL"].rstrip("/")
    org_id = os.environ["ORG_ID"]
    agent_name = os.environ["AGENT_NAME"]
    identity_root = os.environ.get("IDENTITY_ROOT", "/state")
    sender = f"{org_id}::{agent_name}"

    print(
        f"\n{BOLD}═══ MCP tool call — {sender} → {tool_name}"
        f"({json.dumps(tool_args)}) ═══{RESET}",
        flush=True,
    )

    _step(1, "Load enrolled identity and authenticate to the local Mastio")
    _info(
        f"reading api-key + dpop.jwk from {identity_root}/{org_id}/agents/{agent_name}/"
    )
    try:
        client = load_enrolled_client(broker, org_id, agent_name, identity_root)
    except Exception as exc:
        _fail(f"auth failed: {exc!r}")
        return 1
    _ok(f"ready as {sender}")

    _step(2, "Discover available tools (MCP tools/list)")
    try:
        listing = _rpc(client, "tools/list")
    except Exception as exc:
        _fail(f"tools/list failed: {exc!r}")
        return 1
    tools = (listing.get("result") or {}).get("tools") or []
    _ok(f"{len(tools)} tool(s) visible to {sender} after binding filter")
    for t in tools:
        _info(f"  • {t.get('name')}")

    if not any(t.get("name") == tool_name for t in tools):
        _fail(
            f"tool '{tool_name}' not visible — check the MCP resource "
            f"binding for {sender}"
        )
        return 1

    _step(3, f"Call {tool_name}")
    _info(f"arguments = {json.dumps(tool_args)}")
    try:
        resp = _rpc(client, "tools/call", {
            "name": tool_name, "arguments": tool_args,
        })
    except Exception as exc:
        _fail(f"tools/call failed: {exc!r}")
        return 1

    if "error" in resp:
        err = resp["error"]
        _fail(f"server error {err.get('code')} — {err.get('message')}")
        return 1

    result = resp.get("result") or {}
    content = result.get("content") or []
    for entry in content:
        text = entry.get("text", "")
        _ok(f"response: {text}")

    print(
        f"\n{BOLD}{GREEN}✓ MCP aggregator exercised end-to-end "
        f"(auth + tools/list + tools/call forwarded to the MCP server){RESET}",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
