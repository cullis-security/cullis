"""Shared helper — load a CullisClient using the credentials that
``bootstrap-mastio`` enrolled for each sandbox agent (ADR-011 Phase 4).

Mirrors the runtime auth used by ``sandbox/agent/agent.py``:
read ``api-key`` + ``dpop.jwk`` from ``/state/{org}/agents/{name}/`` and
hand them to ``CullisClient.from_api_key_file``. That is the same API-key
+ DPoP identity the egress surface expects for ``send_oneshot`` and the
``/v1/mcp`` aggregator.
"""
from __future__ import annotations

from pathlib import Path

from cullis_sdk import CullisClient


def load_enrolled_client(
    mastio_url: str,
    org_id: str,
    agent_name: str,
    identity_root: str | Path = "/state",
) -> CullisClient:
    identity_dir = Path(identity_root) / org_id / "agents" / agent_name
    api_key_path = identity_dir / "api-key"
    dpop_key_path = identity_dir / "dpop.jwk"
    if not api_key_path.exists() or not dpop_key_path.exists():
        raise RuntimeError(
            f"enrolled identity missing under {identity_dir} "
            f"(expected api-key + dpop.jwk) — is bootstrap-mastio done?"
        )
    client = CullisClient.from_api_key_file(
        mastio_url,
        api_key_path=api_key_path,
        dpop_key_path=dpop_key_path,
        agent_id=f"{org_id}::{agent_name}",
        org_id=org_id,
    )
    # Mirror the runtime wiring in agent.py ``_auth_api_key_file``:
    #   • ``login_via_proxy`` mints a broker JWT so ``_authed_request``
    #     works (needed by the /v1/mcp aggregator and any session API).
    #   • ``_signing_key_pem`` feeds the outer-envelope signature for
    #     ``send_oneshot`` non-repudiation.
    client.login_via_proxy()
    key_path = identity_dir / "agent-key.pem"
    if key_path.exists():
        client._signing_key_pem = key_path.read_text()
    return client
