"""Shared helper — load a CullisClient using the credentials that
``bootstrap-mastio`` enrolled for each reference agent (ADR-014).

Mirrors the runtime auth used by ``reference/agent/agent.py``: read
``agent.pem`` + ``agent-key.pem`` + ``dpop.jwk`` from
``/state/{org}/agents/{name}/`` and hand them to
``CullisClient.from_identity_dir``. The TLS client cert presented at
the per-org nginx sidecar's handshake IS the agent credential.
"""
from __future__ import annotations

from pathlib import Path

from cullis_sdk import CullisClient


def load_enrolled_client(
    mastio_url: str,
    org_id: str,
    agent_name: str,
    identity_root: str | Path = "/state",
    verify_tls: bool = False,
) -> CullisClient:
    identity_dir = Path(identity_root) / org_id / "agents" / agent_name
    cert_path = identity_dir / "agent.pem"
    key_path = identity_dir / "agent-key.pem"
    dpop_key_path = identity_dir / "dpop.jwk"
    if not cert_path.exists() or not key_path.exists() or not dpop_key_path.exists():
        raise RuntimeError(
            f"enrolled identity missing under {identity_dir} "
            f"(expected agent.pem + agent-key.pem + dpop.jwk) — "
            "is bootstrap-mastio done?"
        )
    client = CullisClient.from_identity_dir(
        mastio_url,
        cert_path=cert_path,
        key_path=key_path,
        dpop_key_path=dpop_key_path,
        agent_id=f"{org_id}::{agent_name}",
        org_id=org_id,
        verify_tls=verify_tls,
    )
    # Mirror the runtime wiring in agent.py ``_auth_identity_dir``:
    #   • ``login_via_proxy`` mints a broker JWT so ``_authed_request``
    #     works (needed by the /v1/mcp aggregator and any session API).
    #   • ``_signing_key_pem`` feeds the outer-envelope signature for
    #     ``send_oneshot`` non-repudiation.
    client.login_via_proxy()
    client._signing_key_pem = key_path.read_text()
    return client
