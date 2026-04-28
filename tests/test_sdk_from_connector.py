"""SDK CullisClient.from_connector() — loads identity from Connector dir.

Matches the layout written by ``cullis_connector.identity.store.save_identity``
under ADR-014:
    <config_dir>/identity/agent.crt
    <config_dir>/identity/agent.key
    <config_dir>/identity/metadata.json
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
    cert_pem: str | None = None,
    key_pem: str | None = None,
) -> Path:
    identity_dir = tmp_path / "identity"
    identity_dir.mkdir(parents=True, exist_ok=True)

    # ADR-014: the cert IS the credential. ``from_connector`` builds the
    # runtime httpx.Client with ``cert=(cert_path, key_path)`` so the
    # agent presents its cert at the TLS handshake to nginx.
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
    return tmp_path


def test_from_connector_loads_identity(tmp_path):
    cfg = _write_identity(tmp_path)
    client = CullisClient.from_connector(config_dir=cfg)

    assert client.base == "http://mastio.test"
    assert client._proxy_agent_id == "demo-org::alice"
    assert client._proxy_org_id == "demo-org"
    assert client._verify_tls is False  # http → verify_tls defaults off
    assert client.token is None  # login_via_proxy not invoked yet


def test_from_connector_https_defaults_verify_tls_true(tmp_path):
    cfg = _write_identity(tmp_path, site_url="https://mastio.test")
    client = CullisClient.from_connector(config_dir=cfg)
    assert client._verify_tls is True


def test_from_connector_missing_identity_dir(tmp_path):
    with pytest.raises(FileNotFoundError, match="identity not found"):
        CullisClient.from_connector(config_dir=tmp_path)


def test_from_connector_malformed_metadata(tmp_path):
    cfg = _write_identity(tmp_path)
    (cfg / "identity" / "metadata.json").write_text(json.dumps({
        "capabilities": [],
    }))
    with pytest.raises(RuntimeError, match="agent_id or site_url"):
        CullisClient.from_connector(config_dir=cfg)


def test_from_connector_legacy_api_key_file_ignored(tmp_path):
    """ADR-014 PR-C: stray ``identity/api_key`` files from older
    Connectors are ignored — the cert is the credential and
    ``from_connector`` no longer reads or requires the api_key file."""
    cfg = _write_identity(tmp_path)
    (cfg / "identity" / "api_key").write_text("sk_local_legacy_abc")
    client = CullisClient.from_connector(config_dir=cfg)
    # Loads cleanly; no _proxy_api_key attribute on the instance.
    assert not hasattr(client, "_proxy_api_key") or client.__dict__.get("_proxy_api_key") is None


def test_from_connector_agent_without_org_prefix(tmp_path):
    """Legacy metadata where agent_id isn't ``org::name`` — org_id blank."""
    cfg = _write_identity(tmp_path, agent_id="legacy-agent-no-prefix")
    client = CullisClient.from_connector(config_dir=cfg)
    assert client._proxy_agent_id == "legacy-agent-no-prefix"
    assert client._proxy_org_id == ""
