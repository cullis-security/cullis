"""DEPRECATED ADR-017 — AI gateway egress moved to Mastio.

Historical: Court used to forward authenticated LLM calls to a managed
gateway here. As of PR #435 the AI gateway is a Mastio responsibility
(``mcp_proxy/egress/``), so that calls from agents traverse Mastio's
DPoP + mTLS + policy + audit gates before reaching the gateway.

This package now only mounts a ``410 Gone`` handler at
``POST /v1/llm/chat`` (see ``app.egress.router``). The dispatch logic,
backend clients, and OpenAI-compat schemas live in
``mcp_proxy/egress/`` going forward.
"""
