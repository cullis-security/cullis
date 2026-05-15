"""AI gateway + MCP aggregator + tool-call PDP support extracted from
:mod:`cullis_sdk.client`.

Single public symbol:

* :class:`_AiGatewayMixin` — mixin folded into ``CullisClient`` that
  exposes the three Mastio-side surfaces:

    1. **AI gateway egress (ADR-017)** — ``chat_completion``,
       ``chat_completion_stream`` and ``list_models`` talk to the
       Mastio's embedded LiteLLM proxy.
    2. **MCP aggregator (ADR-007, proxy-side only)** —
       ``list_mcp_tools`` and ``call_mcp_tool`` invoke JSON-RPC against
       ``/v1/mcp`` on the local proxy.
    3. **Tool-call PDP (ADR-029 Phase D)** —
       ``evaluate_tool_call_policy`` asks the Mastio whether a tool
       call is permitted, returning a boring fail-safe dict.

The mixin assumes the host class exposes ``_authed_request`` and the
raw ``_http`` httpx client + ``_headers`` helper (for the streaming
path that cannot use the auto-retry wrapper).
"""
from __future__ import annotations

from typing import Iterator


class _AiGatewayMixin:
    """AI gateway egress, MCP aggregator and tool-call PDP on
    ``CullisClient``."""

    # ── ADR-017 — AI gateway egress ────────────────────────────────
    def chat_completion(self, request: dict) -> dict:
        """Forward an OpenAI-compatible chat completion to Mastio's
        ``/v1/llm/chat`` endpoint, which dispatches to the configured
        AI gateway (Phase 1: Portkey).

        ``request`` is the OpenAI ChatCompletion body (model, messages,
        max_tokens, temperature). Returns the parsed response dict
        including ``cullis_trace_id`` injected by Mastio.

        Raises ``httpx.HTTPStatusError`` on non-2xx with the upstream
        body intact so callers can distinguish 401 (unauth), 502
        (gateway upstream), 504 (timeout), 501 (not implemented).
        """
        resp = self._authed_request("POST", "/v1/llm/chat", json=request)
        resp.raise_for_status()
        return resp.json()

    def chat_completion_stream(self, request: dict) -> Iterator[str]:
        """Streaming variant of :meth:`chat_completion`.

        Forces ``stream=True`` on the request and yields SSE frame
        strings exactly as they arrive from the Mastio, including
        named events (``event: tool_call_start`` etc., see
        ``mcp_proxy/egress/llm_chat_router.py`` P1 emit) and the
        terminal ``data: [DONE]\\n\\n``. The caller is responsible
        for SSE framing semantics — this iterator just hands over
        complete frames split on ``\\n\\n``.

        Bypasses :meth:`_authed_request` because the wrapper retries
        the whole call on a token-expiry 401, which is incompatible
        with a streaming response that has already started flushing
        bytes. The trade-off: no auto-relogin / DPoP nonce retry on
        the stream path. Callers that need that resilience must
        catch the 401 themselves and re-invoke after refreshing the
        token via the normal sync surface.
        """
        body = dict(request)
        body["stream"] = True
        path = "/v1/llm/chat"
        with self._http.stream(
            "POST", f"{self.base}{path}",
            headers=self._headers("POST", path),
            json=body,
        ) as resp:
            resp.raise_for_status()
            buf = ""
            # iter_text decodes UTF-8 chunks from the upstream socket.
            # Concatenate into a buffer and slice on \n\n so partial
            # frames split across TCP packets land in a single yield.
            for raw in resp.iter_text():
                if not raw:
                    continue
                buf += raw
                while "\n\n" in buf:
                    frame, buf = buf.split("\n\n", 1)
                    if frame:
                        yield frame + "\n\n"
            tail = buf.strip()
            if tail:
                # Upstream closed without a trailing blank line —
                # surface what we have so the caller can detect
                # ``[DONE]`` even on a slightly malformed stream.
                yield tail

    def list_models(self) -> list[dict]:
        """Return the OpenAI-compatible model list from Mastio.

        Hits ``GET /v1/egress/models`` (with ``/v1/models`` as a back-
        compat alias). The Mastio enumerates the providers configured
        in the ``ai_provider_credentials`` table, surfaces only those
        whose ``enabled`` is ``True`` and whose required credentials
        are present, then fans out the static model catalog (Anthropic,
        OpenAI, Gemini, Bedrock, Vertex) plus a live ``ollama/api/tags``
        fetch when an Ollama row is configured.

        Returns the ``data`` array verbatim so the Connector Ambassador
        can pass it straight through to the SPA's ``ModelPicker``.
        """
        resp = self._authed_request("GET", "/v1/egress/models")
        resp.raise_for_status()
        body = resp.json()
        return body.get("data", [])

    # ── ADR-007 — MCP aggregator (proxy-side only) ─────────────────
    def list_mcp_tools(self) -> list[dict]:
        """List the MCP tools the authenticated agent can call.

        Calls ``POST /v1/mcp`` JSON-RPC ``tools/list`` on the proxy.
        The proxy filters to backends the agent has an active binding
        for, so the returned list is already authorization-scoped.

        Requires ``self.base`` to point at the **mcp_proxy** (not
        Mastio directly): the aggregator endpoint lives there. Returns
        the raw ``tools`` array from the JSON-RPC ``result``.
        """
        resp = self._authed_request(
            "POST", "/v1/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        )
        resp.raise_for_status()
        body = resp.json()
        if "error" in body:
            raise RuntimeError(f"tools/list error: {body['error']}")
        return body.get("result", {}).get("tools", [])

    def call_mcp_tool(self, name: str, arguments: dict | None = None) -> dict:
        """Invoke an MCP tool by name through the proxy aggregator.

        The proxy validates the caller's binding, audits the call,
        injects the configured auth header from the SecretProvider
        and forwards JSON-RPC ``tools/call`` to the upstream MCP
        server. Returns the raw ``result`` object (typically with
        ``content`` array and ``isError`` flag).

        Raises ``RuntimeError`` on JSON-RPC error (binding missing,
        upstream unreachable, schema mismatch).
        """
        resp = self._authed_request(
            "POST", "/v1/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments or {}},
            },
        )
        resp.raise_for_status()
        body = resp.json()
        if "error" in body:
            err = body["error"]
            raise RuntimeError(
                f"tools/call error code={err.get('code')} "
                f"message={err.get('message')!r}"
            )
        return body.get("result", {})

    def evaluate_tool_call_policy(
        self,
        *,
        principal_id: str,
        principal_type: str = "user",
        org: str | None = None,
        model_id: str | None = None,
        model_provider: str | None = None,
        tool_name: str,
        mcp_server_id: str | None = None,
        session_id: str | None = None,
        target_id: str | None = None,
        target_type: str | None = None,
        target_org: str | None = None,
    ) -> dict:
        """ADR-029 Phase D, ask the Mastio whether a tool call is allowed.

        Wraps ``POST /v1/policy/tool-call`` on the configured Mastio.
        Returns a dict with at least ``allowed: bool`` and ``reason: str``;
        when the Mastio echoes them, optional ``scope`` / ``rate_limit``
        / ``obligations`` dicts are passed through.

        Behaviour on edge cases (kept boring on purpose so callers in
        hot paths can rely on a small surface):

          - HTTP 404, the Mastio has ``MCP_PROXY_TOOL_PDP_ENABLED=false``,
            we treat the gate as disabled and return ``{"allowed": True,
            "reason": "tool-level PDP disabled (404 from Mastio)"}``.
            That keeps legacy Mastios working when an upgraded Connector
            enables its side first.
          - HTTP 401 / 403, signature or auth problem; deny, the reason
            string carries the upstream code so audits are useful.
          - HTTP 5xx or transport error, deny, fail-safe.
          - HTTP 200 with malformed JSON, deny.
        """
        payload: dict = {
            "principal": {
                "id": principal_id,
                "type": principal_type,
            },
            "invocation": {
                "kind": "session_tool_call",
                "tool_name": tool_name,
            },
        }
        if org:
            payload["principal"]["org"] = org
        if model_id or model_provider:
            payload["model"] = {}
            if model_id:
                payload["model"]["id"] = model_id
            if model_provider:
                payload["model"]["provider"] = model_provider
        if mcp_server_id:
            payload["invocation"]["mcp_server_id"] = mcp_server_id
        if target_id or target_type or target_org:
            payload["target"] = {}
            if target_id:
                payload["target"]["id"] = target_id
            if target_type:
                payload["target"]["type"] = target_type
            if target_org:
                payload["target"]["org"] = target_org
        if session_id:
            payload["context"] = {"session_id": session_id}

        try:
            resp = self._authed_request(
                "POST", "/v1/policy/tool-call", json=payload,
            )
        except Exception as exc:  # transport-level failure
            return {
                "allowed": False,
                "reason": f"PDP transport error: {exc}",
            }

        if resp.status_code == 404:
            return {
                "allowed": True,
                "reason": "tool-level PDP disabled (404 from Mastio)",
            }
        if resp.status_code in (401, 403):
            return {
                "allowed": False,
                "reason": f"PDP rejected: HTTP {resp.status_code}",
            }
        if resp.status_code >= 500 or resp.status_code != 200:
            return {
                "allowed": False,
                "reason": f"PDP unexpected status: HTTP {resp.status_code}",
            }

        try:
            body = resp.json()
        except Exception:
            return {
                "allowed": False,
                "reason": "PDP returned non-JSON body",
            }

        decision = str(body.get("decision", "deny")).lower()
        out: dict = {
            "allowed": decision == "allow",
            "reason": str(body.get("reason", ""))[:512],
        }
        for k in ("scope", "rate_limit", "obligations"):
            v = body.get(k)
            if isinstance(v, dict):
                out[k] = v
        return out
