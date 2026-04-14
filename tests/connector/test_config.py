"""Tests for cullis_connector.config — resolution order CLI > env > file > default."""
from __future__ import annotations

from pathlib import Path

import pytest

from cullis_connector.config import (
    DEFAULT_CONFIG_DIR,
    ConnectorConfig,
    load_config,
)


def test_defaults_when_nothing_provided(tmp_path: Path) -> None:
    cfg = load_config({"config_dir": str(tmp_path)}, env={})
    assert cfg.site_url == ""
    assert cfg.config_dir == tmp_path
    assert cfg.verify_tls is True
    assert cfg.log_level == "info"
    assert cfg.request_timeout_s == 10.0


def test_env_overrides_defaults(tmp_path: Path) -> None:
    env = {
        "CULLIS_SITE_URL": "https://site.example.com:9443",
        "CULLIS_VERIFY_TLS": "false",
        "CULLIS_LOG_LEVEL": "debug",
        "CULLIS_REQUEST_TIMEOUT_S": "5.5",
    }
    cfg = load_config({"config_dir": str(tmp_path)}, env=env)
    assert cfg.site_url == "https://site.example.com:9443"
    assert cfg.verify_tls is False
    assert cfg.log_level == "debug"
    assert cfg.request_timeout_s == 5.5


def test_cli_overrides_env(tmp_path: Path) -> None:
    env = {"CULLIS_SITE_URL": "https://from-env.example.com"}
    cli = {"config_dir": str(tmp_path), "site_url": "https://from-cli.example.com"}
    cfg = load_config(cli, env=env)
    assert cfg.site_url == "https://from-cli.example.com"


def test_yaml_file_overrides_defaults_but_not_env(tmp_path: Path) -> None:
    yaml = pytest.importorskip("yaml")
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(
        yaml.safe_dump(
            {
                "site_url": "https://from-file.example.com",
                "log_level": "warning",
                "verify_tls": False,
            }
        )
    )

    cfg = load_config({"config_dir": str(tmp_path)}, env={})
    assert cfg.site_url == "https://from-file.example.com"
    assert cfg.log_level == "warning"
    assert cfg.verify_tls is False

    env = {"CULLIS_SITE_URL": "https://env-wins.example.com"}
    cfg2 = load_config({"config_dir": str(tmp_path)}, env=env)
    assert cfg2.site_url == "https://env-wins.example.com"
    assert cfg2.log_level == "warning"


def test_trailing_slash_stripped_from_site_url(tmp_path: Path) -> None:
    cfg = load_config(
        {"config_dir": str(tmp_path), "site_url": "https://site.example.com/"},
        env={},
    )
    assert cfg.site_url == "https://site.example.com"


def test_identity_paths_derived_from_config_dir(tmp_path: Path) -> None:
    cfg = ConnectorConfig(config_dir=tmp_path)
    assert cfg.identity_dir == tmp_path / "identity"
    assert cfg.cert_path == tmp_path / "identity" / "agent.crt"
    assert cfg.key_path == tmp_path / "identity" / "agent.key"
    assert cfg.ca_chain_path == tmp_path / "identity" / "ca-chain.pem"


def test_default_config_dir_is_home_dot_cullis() -> None:
    assert DEFAULT_CONFIG_DIR == Path.home() / ".cullis"


def test_invalid_yaml_top_level_raises(tmp_path: Path) -> None:
    pytest.importorskip("yaml")
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text("- this is a list, not a mapping\n")
    with pytest.raises(ValueError, match="must be a mapping"):
        load_config({"config_dir": str(tmp_path)}, env={})
