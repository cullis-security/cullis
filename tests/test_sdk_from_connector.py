"""SDK CullisClient.from_connector() — loads identity from Connector dir.

Matches the layout written by ``cullis_connector.identity.store.save_identity``:
    <config_dir>/identity/agent.crt
    <config_dir>/identity/agent.key
    <config_dir>/identity/metadata.json
    <config_dir>/identity/api_key
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from cullis_sdk.client import CullisClient
from tests._mtls_helpers import mint_agent_cert


def _write_identity(
    tmp_path: Path,
    *,
    agent_id: str = "demo-org::alice",
    site_url: str = "http://mastio.test",
    api_key: str = "sk_local_test_deadbeef",
    cert_pem: str | None = None,
    key_pem: str | None = None,
) -> Path:
    identity_dir = tmp_path / "identity"
    identity_dir.mkdir(parents=True, exist_ok=True)

    # ADR-014: ``from_connector`` builds the runtime httpx.Client with
    # ``cert=(cert_path, key_path)`` so the agent presents its cert at
    # the TLS handshake to nginx. Hand a real cert+key pair signed by
    # the test Org CA — the placeholder PEMs the fixture used pre-PR-B
    # explode at httpx ssl context construction.
    if cert_pem is None or key_pem is None:
        org_id, _, agent_name = agent_id.partition("::")
        if not agent_name:
            org_id, agent_name = "demo-org", agent_id
        cert_pem, key_pem = mint_agent_cert(
            org_id=org_id, agent_name=agent_name,
        )

    (identity_dir / "agent.crt").write_text(cert_pem)
    (identity_dir / "agent.key").write_text(key_pem)
    (identity_dir / "metadata.json").write_text(json.dumps({
        "agent_id": agent_id,
        "capabilities": ["oneshot.message"],
        "site_url": site_url,
        "issued_at": "2026-04-17T00:00:00+00:00",
    }))
    (identity_dir / "api_key").write_text(api_key)
    return tmp_path


def test_from_connector_loads_identity(tmp_path):
    cfg = _write_identity(tmp_path)
    client = CullisClient.from_connector(config_dir=cfg)

    assert client.base == "http://mastio.test"
    assert client._proxy_agent_id == "demo-org::alice"
    assert client._proxy_org_id == "demo-org"
    assert client._proxy_api_key == "sk_local_test_deadbeef"
    assert client._verify_tls is False  # http → verify_tls defaults off
    assert client.token is None  # login_via_proxy not invoked yet


def test_from_connector_https_defaults_verify_tls_true(tmp_path):
    cfg = _write_identity(tmp_path, site_url="https://mastio.test")
    client = CullisClient.from_connector(config_dir=cfg)
    assert client._verify_tls is True


def test_from_connector_missing_identity_dir(tmp_path):
    with pytest.raises(FileNotFoundError, match="identity not found"):
        CullisClient.from_connector(config_dir=tmp_path)


def test_from_connector_missing_api_key(tmp_path):
    cfg = _write_identity(tmp_path)
    (cfg / "identity" / "api_key").unlink()
    with pytest.raises(FileNotFoundError, match="api_key missing"):
        CullisClient.from_connector(config_dir=cfg)


def test_from_connector_malformed_metadata(tmp_path):
    cfg = _write_identity(tmp_path)
    (cfg / "identity" / "metadata.json").write_text(json.dumps({
        "capabilities": [],
    }))
    with pytest.raises(RuntimeError, match="agent_id or site_url"):
        CullisClient.from_connector(config_dir=cfg)


def test_from_connector_trims_api_key_whitespace(tmp_path):
    cfg = _write_identity(tmp_path, api_key="sk_local_test_abcdef\n")
    client = CullisClient.from_connector(config_dir=cfg)
    assert client._proxy_api_key == "sk_local_test_abcdef"


def test_from_connector_agent_without_org_prefix(tmp_path):
    """Legacy metadata where agent_id isn't ``org::name`` — org_id blank."""
    cfg = _write_identity(tmp_path, agent_id="legacy-agent-no-prefix")
    client = CullisClient.from_connector(config_dir=cfg)
    assert client._proxy_agent_id == "legacy-agent-no-prefix"
    assert client._proxy_org_id == ""
