"""Multi-profile support for the Connector (M3.3a).

A profile is an isolated enrollment — separate identity, separate
config.yaml, separate state — living under
``~/.cullis/profiles/<name>/`` instead of the original flat
``~/.cullis/`` layout. It lets a single machine host several
identities (say ``north`` and ``south``) without the user having to
juggle distinct config dirs or shell profiles.

Resolution rules (highest priority first, handled in `config.py`):

1. Explicit ``--config-dir`` / ``CULLIS_CONFIG_DIR`` — respected as-is
   (the operator knows what they're doing).
2. ``--profile`` / ``CULLIS_PROFILE`` — maps to
   ``~/.cullis/profiles/<name>/``.
3. Legacy layout — if ``~/.cullis/identity/`` exists without a
   ``profiles/`` sibling, keep using ``~/.cullis/`` so upgrades of
   in-place installs don't break.
4. Fresh install — use ``~/.cullis/profiles/default/``.

We do NOT move the legacy identity directory automatically. The user
sees both the legacy layout and any explicit profiles in
:func:`list_profiles`; they can migrate when they want (a one-line
``mv`` documented in the README) without us silently touching
production keys.
"""
from __future__ import annotations

import re
from pathlib import Path

# RFC-friendly names: letters, digits, dash, underscore. Keeps the
# resulting directory safe on every filesystem we care about and
# avoids shell-injection surprises in docs.
_PROFILE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\-]{0,62}$")

DEFAULT_PROFILE_NAME = "default"


def validate_profile_name(name: str) -> str:
    """Return ``name`` if it's a safe profile identifier, else raise."""
    if not _PROFILE_NAME_RE.match(name):
        raise ValueError(
            f"invalid profile name {name!r}: must start with "
            "an alphanumeric character and contain only letters, "
            "digits, '-', or '_' (max 63 chars)"
        )
    return name


def profile_dir(root: Path, name: str) -> Path:
    """Return the directory holding a given profile's files."""
    return root / "profiles" / validate_profile_name(name)


def has_legacy_layout(root: Path) -> bool:
    """True when the root directory still uses the pre-M3.3 flat layout
    (identity/ sitting directly under the root, no profiles/ sibling).

    The caller can decide whether to keep using it or migrate — we
    only observe.
    """
    if not (root / "identity").is_dir():
        return False
    if (root / "profiles").is_dir():
        # The user already has profiles/ alongside a flat identity/
        # (maybe a half-done manual migration). Treat it as legacy
        # until the flat identity/ is moved out of the way; anything
        # else would hide the existing keys from the user.
        return True
    return True


def list_profiles(root: Path) -> list[str]:
    """Return the profile names known under ``root``.

    Includes the ``default`` pseudo-entry for the legacy flat layout
    if it's present. Names are returned sorted with ``default`` first
    so tray menus and dropdowns stay stable across runs.
    """
    found: set[str] = set()
    profiles_root = root / "profiles"
    if profiles_root.is_dir():
        for child in profiles_root.iterdir():
            if not child.is_dir():
                continue
            try:
                validate_profile_name(child.name)
            except ValueError:
                # Skip directories that don't look like profiles
                # (stray editor tmp files, lost+found, etc.).
                continue
            found.add(child.name)
    if has_legacy_layout(root):
        found.add(DEFAULT_PROFILE_NAME)

    ordered = sorted(found)
    if DEFAULT_PROFILE_NAME in ordered:
        ordered.remove(DEFAULT_PROFILE_NAME)
        ordered.insert(0, DEFAULT_PROFILE_NAME)
    return ordered
