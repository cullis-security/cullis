"""Configuration loading for cullis-connector.

Resolution order (highest priority first):
    1. CLI flags (e.g. --site-url, --config-dir, --profile)
    2. Environment variables (CULLIS_SITE_URL, CULLIS_CONFIG_DIR,
       CULLIS_PROFILE, ...)
    3. Config file <config_dir>/config.yaml
    4. Built-in defaults

`--config-dir` always wins: an operator who points the connector at an
explicit directory knows what they're doing and we won't second-guess
them. Otherwise `--profile <name>` (or `CULLIS_PROFILE`) maps to
``~/.cullis/profiles/<name>/``. With neither flag, legacy installs
(anyone with ``~/.cullis/identity/`` predating M3.3) keep using the
flat ``~/.cullis/`` layout so in-place upgrades don't lose keys; fresh
installs land on ``~/.cullis/profiles/default/``.

A profile directory holds:
    config.yaml             — user-editable settings
    identity/agent.crt      — agent certificate (Phase 2 enrollment)
    identity/agent.key      — agent private key (chmod 600)
    identity/ca-chain.pem   — trust chain for Site/Broker verification
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Optional dependency: PyYAML. Connector ships with it but degrades gracefully
# if a user installs without it.
try:
    import yaml as _yaml
except ImportError:  # pragma: no cover - tested via integration
    _yaml = None  # type: ignore[assignment]


DEFAULT_CONFIG_ROOT = Path.home() / ".cullis"
# Back-compat alias — old tests / external integrations may import
# this name. Keep pointing at the root; the effective config_dir is
# now resolved through :func:`resolve_config_dir`.
DEFAULT_CONFIG_DIR = DEFAULT_CONFIG_ROOT
DEFAULT_CONFIG_FILENAME = "config.yaml"


@dataclass
class AmbassadorConfig:
    """Connector Ambassador (ADR-019) settings.

    The Ambassador exposes OpenAI-compatible endpoints on the same
    FastAPI app as the dashboard so local chat clients (Cullis Chat,
    Cursor, OpenWebUI, ...) can speak Bearer to localhost while
    Cullis cloud keeps requiring DPoP+mTLS.
    """

    enabled: bool = True
    """Mount /v1/chat/completions, /v1/mcp, /v1/models on the dashboard app."""

    advertised_models: list[str] = field(
        default_factory=lambda: [
            "claude-haiku-4-5",
            "claude-sonnet-4-6",
            "claude-opus-4-7",
        ]
    )
    """Models surfaced via /v1/models. Must be supported by Mastio's egress."""

    require_local_only: bool = True
    """Reject any non-loopback peer regardless of bind. Defence-in-depth
    against the operator overriding ``--host`` to 0.0.0.0."""


@dataclass
class ConnectorConfig:
    """Resolved runtime configuration for the connector process."""

    site_url: str = ""
    """Base URL of the Cullis Site (e.g. https://cullis-site.acme.local:9443).

    Phase 1 also accepts a Broker URL for backward compatibility with the
    transitional cullis_sdk path. Phase 2+ targets Site exclusively.
    """

    config_dir: Path = field(default_factory=lambda: DEFAULT_CONFIG_ROOT)
    """Directory holding identity/ and config.yaml.

    With M3.3a this is usually a profile directory under
    ``~/.cullis/profiles/<name>/`` rather than ``~/.cullis/`` itself,
    unless the operator forced ``--config-dir`` or the machine still
    holds a pre-M3.3 flat layout.
    """

    profile_name: str = ""
    """Active profile name, or empty string when running against a
    legacy flat layout / explicit --config-dir. Informational — the
    authoritative source of truth is ``config_dir``."""

    verify_tls: bool = True
    """Whether to verify TLS certificates of the Site. Disable only for dev."""

    log_level: str = "info"
    """Log level: debug, info, warning, error."""

    request_timeout_s: float = 10.0
    """HTTP request timeout for diagnostic and tool calls."""

    ambassador: AmbassadorConfig = field(default_factory=AmbassadorConfig)
    """ADR-019 — OpenAI-compatible Bearer surface for local chat clients."""

    @property
    def identity_dir(self) -> Path:
        return self.config_dir / "identity"

    @property
    def cert_path(self) -> Path:
        return self.identity_dir / "agent.crt"

    @property
    def key_path(self) -> Path:
        return self.identity_dir / "agent.key"

    @property
    def ca_chain_path(self) -> Path:
        return self.identity_dir / "ca-chain.pem"

    @property
    def verify_arg(self) -> bool | str:
        """``httpx.verify`` value with TOFU-pinned CA when available.

        See ``verify_arg_for`` — this property wires it to the
        ``ConnectorConfig`` instance.
        """
        return verify_arg_for(self.verify_tls, self.ca_chain_path)


def verify_arg_for(verify_tls: bool, ca_chain_path: Path) -> bool | str:
    """Compute ``httpx.verify`` from a form-supplied ``verify_tls`` and a
    profile's ``ca-chain.pem`` path.

    Returns the absolute path to the pinned CA when the file exists and
    verification is on, so httpx uses it as the trust store for
    verifying the Site's leaf cert end-to-end. Returns ``False`` when
    the operator has explicitly disabled verification (opt-out is
    opt-out — a pinned CA does not silently re-enable it). Falls back
    to ``True`` when verification is on but no CA has been pinned yet
    (first contact before TOFU bootstrap completes).
    """
    if not verify_tls:
        return False
    return str(ca_chain_path) if ca_chain_path.exists() else True


def _read_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    if _yaml is None:
        raise RuntimeError(
            f"PyYAML not installed but config file exists at {path}. "
            "Install with: pip install 'cullis-connector[yaml]'"
        )
    with path.open("r", encoding="utf-8") as fh:
        loaded = _yaml.safe_load(fh) or {}
    if not isinstance(loaded, dict):
        raise ValueError(f"{path}: top-level YAML must be a mapping")
    return loaded


def _coerce_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def resolve_config_dir(
    cli: dict[str, Any],
    env_map: dict[str, str],
    *,
    root: Path | None = None,
) -> tuple[Path, str]:
    """Pick the effective config_dir and (optional) profile name.

    Ordering reflects operator intent: explicit --config-dir wins
    unconditionally, then --profile / CULLIS_PROFILE, then legacy
    flat layout compatibility, then fresh-install default.

    Returns ``(config_dir, profile_name)``. ``profile_name`` is the
    empty string when no profile is in effect (legacy layout or
    explicit --config-dir override).
    """
    from cullis_connector.profile import (
        DEFAULT_PROFILE_NAME,
        has_legacy_layout,
        profile_dir,
        validate_profile_name,
    )

    config_root = (root or DEFAULT_CONFIG_ROOT).expanduser()

    # 1. Explicit override — honour it verbatim.
    if cli.get("config_dir"):
        return Path(cli["config_dir"]).expanduser(), ""
    env_override = env_map.get("CULLIS_CONFIG_DIR")
    if env_override:
        return Path(env_override).expanduser(), ""

    # 2. --profile / CULLIS_PROFILE.
    profile = cli.get("profile") or env_map.get("CULLIS_PROFILE")
    if profile:
        validate_profile_name(profile)
        return profile_dir(config_root, profile), profile

    # 3. Legacy flat layout — keep using it to preserve in-place
    # upgrades. The operator can `mv identity/ profiles/default/`
    # on their own schedule.
    if has_legacy_layout(config_root):
        return config_root, ""

    # 4. Fresh install.
    return profile_dir(config_root, DEFAULT_PROFILE_NAME), DEFAULT_PROFILE_NAME


def load_config(
    cli_overrides: dict[str, Any] | None = None,
    *,
    env: dict[str, str] | None = None,
) -> ConnectorConfig:
    """Resolve effective configuration from CLI > env > file > defaults.

    Parameters
    ----------
    cli_overrides:
        Mapping of fields explicitly set on the command line. None values are
        ignored so callers can pass argparse Namespace dicts directly.
    env:
        Environment mapping (defaults to ``os.environ``). Tests inject custom
        values via this parameter.
    """
    env_map = env if env is not None else os.environ
    cli = {k: v for k, v in (cli_overrides or {}).items() if v is not None}

    # 1. Determine config_dir (and optional profile) before anything
    #    else, so we can locate config.yaml.
    config_dir, profile_name = resolve_config_dir(cli, env_map)

    # 2. Read file (if present).
    file_data = _read_yaml(config_dir / DEFAULT_CONFIG_FILENAME)

    def _pick(key: str, env_key: str, default: Any) -> Any:
        if key in cli:
            return cli[key]
        if env_key in env_map and env_map[env_key] != "":
            return env_map[env_key]
        if key in file_data:
            return file_data[key]
        return default

    site_url = str(_pick("site_url", "CULLIS_SITE_URL", "")).rstrip("/")
    verify_tls = _coerce_bool(_pick("verify_tls", "CULLIS_VERIFY_TLS", True))
    log_level = str(_pick("log_level", "CULLIS_LOG_LEVEL", "info")).lower()
    request_timeout_s = float(_pick("request_timeout_s", "CULLIS_REQUEST_TIMEOUT_S", 10.0))

    return ConnectorConfig(
        site_url=site_url,
        config_dir=config_dir,
        profile_name=profile_name,
        verify_tls=verify_tls,
        log_level=log_level,
        request_timeout_s=request_timeout_s,
    )
