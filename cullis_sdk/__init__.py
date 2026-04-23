"""
cullis-agent-sdk — Python SDK for Cullis, the federated agent trust broker.

Connect your AI agents to the Cullis network with E2E encrypted messaging,
x509 mutual authentication, and DPoP-bound tokens.

Usage::

    from cullis_sdk import CullisClient

    with CullisClient("https://broker.example.com") as client:
        client.login("myorg::agent", "myorg", "cert.pem", "key.pem")
        agents = client.discover(capabilities=["order.write"])
        session_id = client.open_session(agents[0].agent_id, agents[0].org_id, ["order.write"])
        client.send(session_id, "myorg::agent", {"text": "Hello"}, agents[0].agent_id)
"""

from cullis_sdk.client import CullisClient, PubkeyFetchError, WebSocketConnection
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

__version__ = "0.1.0"
