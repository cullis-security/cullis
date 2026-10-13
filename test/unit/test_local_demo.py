"""Local demo boundaries: preserve state, verify cached artifacts, separate credentials."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
from unittest.mock import Mock

import pytest
import yaml

SCRIPT = Path(__file__).resolve().parents[2] / "packaging/mastio-bundle/local-demo.py"
spec = importlib.util.spec_from_file_location("local_demo", SCRIPT)
demo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(demo)


def cache_model(path, payload=b"synthetic model blob"):
    digest = hashlib.sha256(payload).hexdigest()
    blob = path / "blobs" / ("sha256-" + digest)
    blob.parent.mkdir(parents=True)
    blob.write_bytes(payload)
    manifest = path / "manifests/registry.ollama.ai/library/example/small"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(json.dumps({"config": {"digest": "sha256:" + digest}, "layers": []}))
    (path / "id_ed25519").write_text("account key must not be copied")
    return blob


def test_cache_copy_excludes_account_keys_and_rejects_corruption(tmp_path):
    source, target = tmp_path / "source", tmp_path / "target"
    blob = cache_model(source)
    result = demo.verify_model(source, "example:small", target)
    assert result["model"] == "example:small"
    assert not (target / "id_ed25519").exists()
    blob.write_bytes(b"corrupted")
    with pytest.raises(demo.SetupError, match="digest mismatch"):
        demo.verify_model(source, "example:small", tmp_path / "corrupt-copy")


@pytest.mark.parametrize("model", ["../escape:tag", "model:../tag", "/abs:model", "name", "name:tag/extra"])
def test_model_cannot_select_arbitrary_cache_paths(model):
    with pytest.raises(demo.SetupError):
        demo.model_path(model)


def test_prepare_refuses_existing_state_before_docker(tmp_path, monkeypatch):
    marker = tmp_path / "keep"
    marker.write_text("existing identity")
    docker = Mock(side_effect=AssertionError("must not call Docker"))
    monkeypatch.setattr(demo, "run", docker)
    with pytest.raises(demo.SetupError, match="already exists"):
        demo.prepare(argparse.Namespace(state=tmp_path))
    assert marker.read_text() == "existing identity"
    docker.assert_not_called()


def test_agent_has_no_admin_state_or_backend_network():
    config = yaml.safe_load((SCRIPT.parent / "docker-compose.local-demo.yml").read_text())
    services = config["services"]
    agent = services["agent"]
    assert "env_file" not in agent
    assert not any("SECRET" in key or "PASSWORD" in key for key in agent["environment"])
    assert agent["networks"] == ["clients"]
    assert set(agent["volumes"]) == {
        "./first-agent.py:/opt/first-agent.py:ro",
        "${DEMO_STATE:?}/agent:/identity", "${DEMO_STATE:?}/public:/trust:ro",
    }
    assert "clients" not in services["mcp-proxy"]["networks"]
    assert "clients" not in services["ollama"]["networks"]
    assert {name for name, value in config["networks"].items() if not value["internal"]} == {"ingress"}
    assert {name for name, service in services.items() if "ingress" in service.get("networks", [])} == {"mastio-nginx"}
    assert services["mastio-nginx"]["networks"] == ["clients", "gateway", "ingress"]
    assert services["mastio-nginx"]["cap_add"] == ["NET_ADMIN"]
    assert services["mastio-nginx"]["cap_drop"] == ["NET_RAW"]
    assert services["mastio-nginx"]["security_opt"] == ["no-new-privileges:true"]
    assert {name for name, service in services.items() if "ports" in service} == {"mastio-nginx"}
    assert services["mastio-nginx"]["ports"] == ["127.0.0.1:${DEMO_PORT:?}:9443"]
    assert services["ollama"]["environment"]["OLLAMA_NO_CLOUD"] == "1"


def test_privacy_settings_and_generated_secrets():
    first, second = demo.settings(), demo.settings()
    assert first["MCP_PROXY_EGRESS_DPOP_MODE"] == "required"
    assert first["MCP_PROXY_POLICY_WEBHOOK_ALLOW_PRIVATE_IPS"] == "false"
    for key in ("AUDIT_CAPTURE_TOOL_PARAMETERS", "AUDIT_CAPTURE_TOOL_RESULT", "AUDIT_ANCHOR_ENABLED"):
        assert first["MCP_PROXY_" + key] == "false"
    for key in ("ADMIN_SECRET", "DASHBOARD_SIGNING_KEY", "DPOP_NONCE_SECRET", "INITIAL_ADMIN_PASSWORD"):
        assert len(first["MCP_PROXY_" + key]) >= 64
        assert first["MCP_PROXY_" + key] != second["MCP_PROXY_" + key]
