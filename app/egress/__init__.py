"""ADR-017 — AI gateway egress.

Mastio forwards authenticated LLM calls to one of several pluggable
backends and stamps each call with the trusted agent identity
reconstructed from the DPoP-bound client cert. The agent never sees
the provider API key; the backend (whatever it is) never sees the
raw Mastio token.

Backends (pick via ``ai_gateway_backend`` setting):

  - ``litellm_embedded`` (default) — LiteLLM as an in-process Python
    library. Zero extra container on the customer side, single audit
    chain, lowest latency. Phase 3.
  - ``portkey`` — Portkey OSS as a separate HTTP container. Picked
    when the customer already runs Portkey Enterprise so Mastio sits
    on top of their existing investment. Phase 1.
  - ``litellm_proxy`` — placeholder for the LiteLLM Proxy server
    backend, wired only when a design partner asks for it.
  - ``kong`` — placeholder for Kong AI Gateway, same trigger.

The dispatcher in ``ai_gateway.dispatch`` routes by backend; new ones
are added as parallel branches so insulating a deployment from
breakage in one library is just a config change.
"""
