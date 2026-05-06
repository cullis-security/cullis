# Mock LLM + Mock MCP backend for the Tier 1 demo path.
#
# Real Anthropic / Postgres connections are out of scope for the
# nixosTest sandbox (offline by design, no API keys in the closure).
# Instead we stand up two tiny FastAPI services that play the role
# of the upstream backends:
#
#   cullis-mock-llm        port 11434, OpenAI-compat
#                          /v1/chat/completions returns a tool_use
#                          call on the ``query`` tool first, then a
#                          natural-language wrap-up once the
#                          ``role=tool`` reply lands.
#
#   cullis-mock-mcp-postgres  port 11435, MCP HTTP transport
#                             tools/list returns ``[{query}]``,
#                             tools/call name=query echoes back
#                             ``Mario Rossi: gdpr_training_completed=true``.
#
# The pair is what lets the testScript exercise the same daniele@user
# → litellm → tool_use → MCP postgres flow PR #445 verified live on
# the docker compose sandbox, but inside a kernel-isolated VM with no
# outbound network.
{ config, pkgs, lib, ... }:

let
  py = pkgs.python311;

  mockLlmScript = pkgs.writeText "cullis-mock-llm.py" ''
    """Mock LLM that mimics the slice of the OpenAI Chat Completions
    API the Cullis litellm pipeline drives.

    State machine (per request):
      - First call (no tool messages) → return ``tool_calls`` with a
        single ``query`` invocation against the Postgres MCP. This
        triggers the tool_use loop in Cullis Chat / our test
        harness.
      - Follow-up call (has ``role=tool`` reply) → return a plain
        text completion that quotes the tool result so the
        testScript can assert on a deterministic payload.

    Listens on 127.0.0.1:11434. No auth — the VM only exposes it
    on loopback, the Mastio's litellm reaches it as a sibling
    systemd unit.
    """
    from __future__ import annotations
    import json
    import os
    import time
    import uuid
    from fastapi import FastAPI, Request

    app = FastAPI(title="cullis-mock-llm")

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.post("/v1/chat/completions")
    async def chat(request: Request):
        body = await request.json()
        messages = body.get("messages", [])
        # Detect whether we are on the second call (tool result has
        # come back). The Cullis loop emits ``role=tool`` messages
        # carrying the MCP output.
        has_tool_reply = any(m.get("role") == "tool" for m in messages)
        now = int(time.time())
        cid = "chatcmpl-" + uuid.uuid4().hex[:16]

        if has_tool_reply:
            # Pull the last tool message and quote it so the
            # testScript's assertion is deterministic.
            tool_msgs = [m for m in messages if m.get("role") == "tool"]
            tool_text = ""
            for m in tool_msgs:
                content = m.get("content")
                if isinstance(content, str):
                    tool_text = content
                elif isinstance(content, list):
                    for block in content:
                        if isinstance(block, dict) and block.get("type") == "text":
                            tool_text = block.get("text", "")
                            break
            return {
                "id": cid,
                "object": "chat.completion",
                "created": now,
                "model": body.get("model", "claude-haiku-4-5"),
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": (
                            "Result from the compliance database: "
                            + tool_text
                        ),
                    },
                    "finish_reason": "stop",
                }],
                "usage": {
                    "prompt_tokens": 100,
                    "completion_tokens": 20,
                    "total_tokens": 120,
                },
            }

        # First call → emit a tool_calls message asking for the
        # ``query`` tool. The arguments JSON mirrors what a real
        # Haiku would emit when asked about Mario Rossi.
        return {
            "id": cid,
            "object": "chat.completion",
            "created": now,
            "model": body.get("model", "claude-haiku-4-5"),
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [{
                        "id": "call_" + uuid.uuid4().hex[:12],
                        "type": "function",
                        "function": {
                            "name": "query",
                            "arguments": json.dumps({
                                "sql": (
                                    "SELECT name, gdpr_training_completed "
                                    "FROM compliance_status "
                                    "WHERE name = 'Mario Rossi'"
                                ),
                            }),
                        },
                    }],
                },
                "finish_reason": "tool_calls",
            }],
            "usage": {
                "prompt_tokens": 50,
                "completion_tokens": 30,
                "total_tokens": 80,
            },
        }


    if __name__ == "__main__":
        import uvicorn
        uvicorn.run(
            "__main__:app",
            host="127.0.0.1",
            port=int(os.environ.get("PORT", "11434")),
        )
  '';

  mockMcpScript = pkgs.writeText "cullis-mock-mcp-postgres.py" ''
    """Mock MCP HTTP backend for the Postgres ``query`` tool.

    Implements the slice of the Streamable-HTTP MCP transport the
    proxy reverse-proxy forwarder hits in production:

      POST /mcp   JSON-RPC 2.0
        method=initialize    → server info + protocolVersion
        method=tools/list    → [{name:"query", inputSchema:{...}}]
        method=tools/call    → name=query → text echo of the
                               compliance row daniele@user is
                               authorised to read.

    Listens on 127.0.0.1:11435. The Mastio's local registration
    points at this URL via the seed step in cullis-mastio.nix.
    """
    from __future__ import annotations
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse

    app = FastAPI(title="cullis-mock-mcp-postgres")

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.post("/mcp")
    async def mcp(request: Request):
        body = await request.json()
        method = body.get("method")
        rid = body.get("id")
        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": rid,
                "result": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {"tools": {}},
                    "serverInfo": {
                        "name": "mock-postgres",
                        "version": "0.1.0",
                    },
                },
            }
        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": rid,
                "result": {
                    "tools": [{
                        "name": "query",
                        "description": (
                            "Run a read-only SQL query against the "
                            "compliance_status demo table."
                        ),
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "sql": {"type": "string"},
                            },
                            "required": ["sql"],
                        },
                    }],
                },
            }
        if method == "tools/call":
            params = body.get("params", {}) or {}
            name = params.get("name")
            if name != "query":
                return JSONResponse({
                    "jsonrpc": "2.0",
                    "id": rid,
                    "error": {
                        "code": -32601,
                        "message": f"Tool {name!r} not found",
                    },
                })
            return {
                "jsonrpc": "2.0",
                "id": rid,
                "result": {
                    "content": [{
                        "type": "text",
                        "text": (
                            "name=Mario Rossi, "
                            "gdpr_training_completed=true"
                        ),
                    }],
                    "isError": False,
                },
            }
        return JSONResponse({
            "jsonrpc": "2.0",
            "id": rid,
            "error": {
                "code": -32601,
                "message": f"Method {method!r} not supported",
            },
        })


    if __name__ == "__main__":
        import os
        import uvicorn
        uvicorn.run(
            "__main__:app",
            host="127.0.0.1",
            port=int(os.environ.get("PORT", "11435")),
        )
  '';

in
{
  options.cullis.mockServices = with lib; {
    enable = mkEnableOption "Cullis mock LLM + mock MCP postgres";

    pythonEnv = mkOption {
      type = types.package;
      description = ''
        Python interpreter that already has fastapi + uvicorn in its
        site-packages. The cullis.mastio module passes its
        ``pythonEnv`` here so we don't double-build the closure.
      '';
    };

    llmPort = mkOption {
      type = types.port;
      default = 11434;
    };

    mcpPort = mkOption {
      type = types.port;
      default = 11435;
    };
  };

  config = lib.mkIf config.cullis.mockServices.enable (
    let
      cfg = config.cullis.mockServices;
      pyBin = "${cfg.pythonEnv}/bin/python";
    in
    {
      systemd.services.cullis-mock-llm = {
        description = "Cullis mock LLM (OpenAI-compat /v1/chat/completions)";
        wantedBy = [ "multi-user.target" ];
        after = [ "network.target" ];
        environment.PORT = toString cfg.llmPort;
        serviceConfig = {
          Type = "simple";
          # Each script's ``__main__`` block hands itself to
          # ``uvicorn.run("__main__:app", ...)``. Avoids the
          # ``--app-dir`` + module-name dance that the Nix-store
          # filename (``<hash>-cullis-mock-llm.py``, hyphens not
          # legal in Python module names) makes painful.
          ExecStart = "${pyBin} ${mockLlmScript}";
          DynamicUser = true;
          Restart = "on-failure";
          RestartSec = "2s";
        };
      };

      systemd.services.cullis-mock-mcp-postgres = {
        description = "Cullis mock MCP HTTP backend (Postgres ``query``)";
        wantedBy = [ "multi-user.target" ];
        after = [ "network.target" ];
        environment.PORT = toString cfg.mcpPort;
        serviceConfig = {
          Type = "simple";
          ExecStart = "${pyBin} ${mockMcpScript}";
          DynamicUser = true;
          Restart = "on-failure";
          RestartSec = "2s";
        };
      };
    }
  );
}
