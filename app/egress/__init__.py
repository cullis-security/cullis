"""ADR-017 Phase 1 — AI gateway egress.

Mastio forwards authenticated LLM calls to a managed AI gateway
(Portkey / LiteLLM / Kong) and stamps the call with the trusted
agent identity reconstructed from the DPoP-bound client cert. The
gateway never sees the raw Mastio token; the agent never sees the
provider API key. Audit chain captures latency + token usage.
"""
