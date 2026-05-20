"""
cullis-agent-sdk — Python SDK for Cullis, the federated agent trust broker.

Connect your AI agents to the Cullis network with E2E encrypted messaging,
x509 mutual authentication, and DPoP-bound tokens.

Canonical usage (ADR-008 one-shot, ADR-014 mTLS-cert-as-credential)::

    from cullis_sdk import CullisClient

    # Connector flow (identity from ~/.cullis/identity/)
    client = CullisClient.from_connector()
    client.login_via_proxy_with_local_key()

    # Or server / BYOCA flow (cert + key on disk)
    # client = CullisClient.from_identity_dir(
    #     "https://mastio.example.com:9443",
    #     cert_path="/etc/cullis/agent/cert.pem",
    #     key_path="/etc/cullis/agent/key.pem",
    #     dpop_key_path="/etc/cullis/agent/dpop.jwk",
    # )

    resp = client.send_oneshot(
        recipient_id="acme::supplier-agent",
        payload={"text": "Quote for 1000 M8 bolts please."},
        ttl_seconds=300,
    )
    print(resp["msg_id"])

The legacy ``login()`` / ``open_session()`` / ``send()`` surface is
deprecated and will be removed in v0.5 (~2026-08-15). See the README
"Migrating from v0.3 sessions" section for the mapping.
"""

from cullis_sdk.client import CullisClient
from cullis_sdk._client._discovery import PubkeyFetchError
from cullis_sdk._client._websocket import WebSocketConnection
from cullis_sdk.dpop import DpopKey
from cullis_sdk.types import AgentInfo, SessionInfo, InboxMessage, RfqResult, RfqQuote
from cullis_sdk._logging import log, log_msg
from cullis_sdk._env import load_env_file, cfg

__all__ = [
    "CullisClient",
    "PubkeyFetchError",
    "WebSocketConnection",
    "DpopKey",
    "AgentInfo",
    "SessionInfo",
    "InboxMessage",
    "RfqResult",
    "RfqQuote",
    "load_env_file",
    "cfg",
    "log",
    "log_msg",
]

__version__ = "0.1.3"
