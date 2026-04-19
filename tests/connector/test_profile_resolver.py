"""Tests for the M3.3a multi-profile config resolver.

Four paths to exercise:
- explicit --config-dir wins unconditionally
- --profile / CULLIS_PROFILE maps to ~/.cullis/profiles/<name>/
- legacy flat layout (identity/ at root, no profiles/) preserved
- fresh install lands on ~/.cullis/profiles/default/

Plus the helpers in :mod:`cullis_connector.profile`:
- validate_profile_name rejects hostile inputs
- list_profiles orders ``default`` first and ignores stray files
"""
from __future__ import annotations

import pytest

from cullis_connector.config import load_config, resolve_config_dir
from cullis_connector.profile import (
    DEFAULT_PROFILE_NAME,
    has_legacy_layout,
    list_profiles,
    profile_dir,
    validate_profile_name,
)


# ── validate_profile_name ────────────────────────────────────────────


@pytest.mark.parametrize(
    "name",
    ["default", "north", "south", "org-1", "agent_01", "A1b2C3"],
)
def test_validate_profile_name_accepts_safe_names(name):
    assert validate_profile_name(name) == name


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "-leading-dash",
        "_underscore-first",
        "has space",
        "has/slash",
        "has..dot",
        "has$dollar",
        "../escape",
        "x" * 64,
    ],
)
def test_validate_profile_name_rejects_hostile(bad):
    with pytest.raises(ValueError):
        validate_profile_name(bad)


# ── has_legacy_layout ────────────────────────────────────────────────


def test_has_legacy_layout_false_on_empty_root(tmp_path):
    assert has_legacy_layout(tmp_path) is False


def test_has_legacy_layout_true_when_identity_dir_present(tmp_path):
    (tmp_path / "identity").mkdir()
    assert has_legacy_layout(tmp_path) is True


def test_has_legacy_layout_true_during_half_done_migration(tmp_path):
    # If a user has both the flat identity/ AND profiles/ we still
    # flag legacy — their flat keys are the ones actively in use.
    (tmp_path / "identity").mkdir()
    (tmp_path / "profiles").mkdir()
    assert has_legacy_layout(tmp_path) is True


# ── list_profiles ────────────────────────────────────────────────────


def test_list_profiles_empty_root_returns_nothing(tmp_path):
    assert list_profiles(tmp_path) == []


def test_list_profiles_picks_up_explicit_profiles(tmp_path):
    for name in ("south", "north", "central"):
        (tmp_path / "profiles" / name).mkdir(parents=True)
    assert list_profiles(tmp_path) == ["central", "north", "south"]


def test_list_profiles_ignores_stray_files_and_bad_names(tmp_path):
    (tmp_path / "profiles" / "valid").mkdir(parents=True)
    (tmp_path / "profiles" / "ok-name").mkdir(parents=True)
    (tmp_path / "profiles" / ".hidden").mkdir(parents=True)
    (tmp_path / "profiles" / "..escape").mkdir(parents=True)
    (tmp_path / "profiles" / "stray.txt").write_text("not a profile")
    assert list_profiles(tmp_path) == ["ok-name", "valid"]


def test_list_profiles_surfaces_legacy_as_default(tmp_path):
    # A fresh ~/.cullis/ with only the flat identity/ shows up under
    # the pseudo-name "default".
    (tmp_path / "identity").mkdir()
    assert list_profiles(tmp_path) == [DEFAULT_PROFILE_NAME]


def test_list_profiles_puts_default_first_when_mixed(tmp_path):
    (tmp_path / "identity").mkdir()
    (tmp_path / "profiles" / "north").mkdir(parents=True)
    (tmp_path / "profiles" / "south").mkdir(parents=True)
    assert list_profiles(tmp_path) == ["default", "north", "south"]


# ── resolve_config_dir ───────────────────────────────────────────────


def test_resolve_config_dir_explicit_config_dir_beats_everything(tmp_path):
    forced = tmp_path / "forced"
    cli = {"config_dir": str(forced), "profile": "north"}
    env = {"CULLIS_PROFILE": "south", "CULLIS_CONFIG_DIR": str(tmp_path / "envdir")}
    path, profile = resolve_config_dir(cli, env, root=tmp_path)
    assert path == forced
    assert profile == ""


def test_resolve_config_dir_env_config_dir_beats_profile(tmp_path):
    envdir = tmp_path / "env-forced"
    cli = {"profile": "north"}
    env = {"CULLIS_CONFIG_DIR": str(envdir)}
    path, profile = resolve_config_dir(cli, env, root=tmp_path)
    assert path == envdir
    assert profile == ""


def test_resolve_config_dir_cli_profile_maps_to_subdir(tmp_path):
    path, profile = resolve_config_dir(
        {"profile": "north"}, {}, root=tmp_path
    )
    assert path == profile_dir(tmp_path, "north")
    assert profile == "north"


def test_resolve_config_dir_env_profile_picks_up(tmp_path):
    path, profile = resolve_config_dir(
        {}, {"CULLIS_PROFILE": "south"}, root=tmp_path
    )
    assert path == profile_dir(tmp_path, "south")
    assert profile == "south"


def test_resolve_config_dir_cli_profile_beats_env_profile(tmp_path):
    path, profile = resolve_config_dir(
        {"profile": "north"},
        {"CULLIS_PROFILE": "south"},
        root=tmp_path,
    )
    assert profile == "north"
    assert path == profile_dir(tmp_path, "north")


def test_resolve_config_dir_legacy_layout_keeps_flat_root(tmp_path):
    (tmp_path / "identity").mkdir()
    path, profile = resolve_config_dir({}, {}, root=tmp_path)
    assert path == tmp_path
    assert profile == ""


def test_resolve_config_dir_fresh_install_picks_default_profile(tmp_path):
    path, profile = resolve_config_dir({}, {}, root=tmp_path)
    assert path == profile_dir(tmp_path, DEFAULT_PROFILE_NAME)
    assert profile == DEFAULT_PROFILE_NAME


def test_resolve_config_dir_rejects_hostile_profile_name(tmp_path):
    with pytest.raises(ValueError):
        resolve_config_dir({"profile": "../escape"}, {}, root=tmp_path)


# ── load_config end-to-end ───────────────────────────────────────────


def test_load_config_propagates_profile_name(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "cullis_connector.config.DEFAULT_CONFIG_ROOT", tmp_path
    )
    cfg = load_config({"profile": "north"}, env={})
    assert cfg.profile_name == "north"
    assert cfg.config_dir == tmp_path / "profiles" / "north"
    assert cfg.identity_dir == tmp_path / "profiles" / "north" / "identity"


def test_load_config_empty_profile_name_on_legacy_layout(tmp_path, monkeypatch):
    (tmp_path / "identity").mkdir()
    monkeypatch.setattr(
        "cullis_connector.config.DEFAULT_CONFIG_ROOT", tmp_path
    )
    cfg = load_config({}, env={})
    assert cfg.profile_name == ""
    assert cfg.config_dir == tmp_path
    assert cfg.identity_dir == tmp_path / "identity"


def test_load_config_explicit_config_dir_clears_profile_name(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "cullis_connector.config.DEFAULT_CONFIG_ROOT", tmp_path
    )
    custom = tmp_path / "custom"
    cfg = load_config({"config_dir": str(custom), "profile": "north"}, env={})
    # --config-dir wins → profile name cleared.
    assert cfg.profile_name == ""
    assert cfg.config_dir == custom


def test_load_config_default_profile_on_fresh_install(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "cullis_connector.config.DEFAULT_CONFIG_ROOT", tmp_path
    )
    cfg = load_config({}, env={})
    assert cfg.profile_name == DEFAULT_PROFILE_NAME
    assert cfg.config_dir == tmp_path / "profiles" / DEFAULT_PROFILE_NAME


# ── CLI plumbing sanity ──────────────────────────────────────────────


def test_cli_parser_accepts_profile_flag_on_subcommands():
    from cullis_connector.cli import _build_parser

    parser = _build_parser()
    simple = ("serve", "dashboard", "desktop")
    for cmd in simple:
        args = parser.parse_args([cmd, "--profile", "north"])
        assert args.profile == "north"

    # ``enroll`` has its own required flags; supply them so argparse
    # doesn't abort before reaching --profile.
    enroll = parser.parse_args([
        "enroll",
        "--profile", "north",
        "--requester-name", "Alice",
        "--requester-email", "alice@example.com",
    ])
    assert enroll.profile == "north"
