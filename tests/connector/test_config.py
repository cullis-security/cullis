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


# ── verify_arg / verify_arg_for ────────────────────────────────────────────


_VERIFY_ENV_VARS = (
    "CULLIS_FRONTDESK_CA_BUNDLE",
    "SSL_CERT_FILE",
    "REQUESTS_CA_BUNDLE",
)


@pytest.fixture
def _no_ca_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Clear the env-CA fallbacks ``verify_arg_for`` honours so the
    "no CA anywhere" tests are deterministic regardless of the host."""
    for name in _VERIFY_ENV_VARS:
        monkeypatch.delenv(name, raising=False)


def test_verify_arg_returns_false_when_user_disabled_tls(
    tmp_path: Path, _no_ca_env: None,
) -> None:
    """Opt-out is opt-out: a pinned CA on disk does NOT silently
    re-enable verification when the operator passed --no-verify-tls."""
    ca = tmp_path / "identity" / "ca-chain.pem"
    ca.parent.mkdir(parents=True)
    ca.write_text("-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n")
    cfg = ConnectorConfig(config_dir=tmp_path, verify_tls=False)
    assert cfg.verify_arg is False


def test_verify_arg_returns_path_when_ca_pinned(
    tmp_path: Path, _no_ca_env: None,
) -> None:
    """TOFU pinning happy path: with verification on and a pinned CA
    on disk, httpx receives the absolute path so it uses the pinned
    CA as trust store instead of the system bundle."""
    ca = tmp_path / "identity" / "ca-chain.pem"
    ca.parent.mkdir(parents=True)
    ca.write_text("-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n")
    cfg = ConnectorConfig(config_dir=tmp_path, verify_tls=True)
    assert cfg.verify_arg == str(ca)


def test_verify_arg_returns_true_when_no_ca_pinned(
    tmp_path: Path, _no_ca_env: None,
) -> None:
    """First-contact / pre-TOFU state: verification on but no CA on
    disk yet → httpx uses its default CA bundle (system trust store).
    This still fails for self-signed Sites, which is the cue for the
    TOFU bootstrap UI to kick in."""
    cfg = ConnectorConfig(config_dir=tmp_path, verify_tls=True)
    assert cfg.verify_arg is True


def test_verify_arg_for_module_helper_matches_property(
    tmp_path: Path, _no_ca_env: None,
) -> None:
    """``verify_arg_for`` must produce the same result as the
    instance property when given the same inputs — callers with a
    form-supplied ``verify_tls`` rely on this equivalence."""
    from cullis_connector.config import verify_arg_for

    ca_path = tmp_path / "identity" / "ca-chain.pem"
    ca_path.parent.mkdir(parents=True)

    # No CA pinned, verify on.
    cfg = ConnectorConfig(config_dir=tmp_path, verify_tls=True)
    assert verify_arg_for(True, ca_path) == cfg.verify_arg

    # CA pinned, verify on.
    ca_path.write_text("PEM")
    cfg = ConnectorConfig(config_dir=tmp_path, verify_tls=True)
    assert verify_arg_for(True, ca_path) == cfg.verify_arg

    # CA pinned, verify off — both paths must collapse to False.
    cfg = ConnectorConfig(config_dir=tmp_path, verify_tls=False)
    assert verify_arg_for(False, ca_path) == cfg.verify_arg == False  # noqa: E712


# ── env-CA fallback (Frontdesk auto-enroll) ───────────────────────────────


def test_verify_arg_for_uses_env_bundle_when_no_pin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Headless Frontdesk auto-enroll path: the bundle ships an Org
    Root CA at a path exported via ``CULLIS_FRONTDESK_CA_BUNDLE`` and
    skips the manual ``/setup/pin-ca`` wizard. ``verify_arg_for``
    must fall back to that bundle so per-user HTTPS calls (in
    particular ``/v1/principals/csr``) don't trip
    ``CERTIFICATE_VERIFY_FAILED``."""
    from cullis_connector.config import verify_arg_for

    env_ca = tmp_path / "ca-bundle.pem"
    env_ca.write_text("PEM")
    for name in _VERIFY_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CULLIS_FRONTDESK_CA_BUNDLE", str(env_ca))

    assert verify_arg_for(True, tmp_path / "missing-pin.pem") == str(env_ca)


def test_verify_arg_for_pin_wins_over_env_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pinning is operator-controlled trust and must never be silently
    overridden by an env var. A populated per-profile ``ca-chain.pem``
    wins even when ``CULLIS_FRONTDESK_CA_BUNDLE`` points at a real
    file."""
    from cullis_connector.config import verify_arg_for

    pin = tmp_path / "ca-chain.pem"
    pin.write_text("PIN")
    env_ca = tmp_path / "env-bundle.pem"
    env_ca.write_text("ENV")
    monkeypatch.setenv("CULLIS_FRONTDESK_CA_BUNDLE", str(env_ca))

    assert verify_arg_for(True, pin) == str(pin)


@pytest.mark.parametrize(
    "env_name",
    ["CULLIS_FRONTDESK_CA_BUNDLE", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE"],
)
def test_verify_arg_for_env_fallback_priority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    env_name: str,
) -> None:
    """All three env names are honoured (Cullis-specific first, then
    the two standard Python-ecosystem fallbacks)."""
    from cullis_connector.config import verify_arg_for

    env_ca = tmp_path / "ca.pem"
    env_ca.write_text("PEM")
    for name in _VERIFY_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(env_name, str(env_ca))

    assert verify_arg_for(True, tmp_path / "missing.pem") == str(env_ca)


def test_verify_arg_for_skips_missing_env_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the env var points at a non-existent file, fall through to
    the next candidate (or system store) instead of returning a path
    httpx can't open."""
    from cullis_connector.config import verify_arg_for

    for name in _VERIFY_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CULLIS_FRONTDESK_CA_BUNDLE", str(tmp_path / "absent.pem"))

    assert verify_arg_for(True, tmp_path / "also-absent.pem") is True


def test_verify_arg_for_env_bundle_ignored_when_verify_off(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``verify_tls=False`` collapses to ``False`` even when an env CA
    bundle is set. Opt-out is opt-out."""
    from cullis_connector.config import verify_arg_for

    env_ca = tmp_path / "ca.pem"
    env_ca.write_text("PEM")
    monkeypatch.setenv("CULLIS_FRONTDESK_CA_BUNDLE", str(env_ca))

    assert verify_arg_for(False, tmp_path / "missing.pem") is False
