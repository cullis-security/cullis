"""Capability → minimum tier lookup table.

ADR-032 Decision E / F5. Loads the operator-pinned matrix from
``enterprise-kit/policy/capability-tiers.yaml`` (override via
``MCP_PROXY_TIER_MATRIX_PATH``) and exposes a single ``lookup``
helper the executor and the policy engine share. The matrix is
hot-loadable: the caller can rebuild it via
:func:`load_default_tier_matrix` and replace the cached singleton
on ``app.state`` without restarting the proxy.

Schema reference: imp/attestation-claim-schema.md sez. 2 and
enterprise-kit/policy/capability-tiers.yaml (sample default).

Tier ordering (low → high) is mirrored verbatim from
``mcp_proxy.attestation.tier``; we re-export :data:`TIER_ORDER`
here so the wider call-graph (executor, policy engine, dashboard)
has one canonical sort vector.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from mcp_proxy.attestation.tier import (
    TIER_BYOD_ATTESTED,
    TIER_BYOD_ISOLATED,
    TIER_MANAGED,
    TIER_MANAGED_ATTESTED,
    TIER_UNTRUSTED,
)

_log = logging.getLogger("mcp_proxy.policy.tier_matrix")

# Low → high. Index = tier rank. Used by :func:`tier_meets_requirement`
# in this module and by the dashboard's CISO config view (R-future) so
# both stay aligned to the schema-doc ordering.
TIER_ORDER: tuple[str, ...] = (
    TIER_UNTRUSTED,
    TIER_BYOD_ISOLATED,
    TIER_BYOD_ATTESTED,
    TIER_MANAGED,
    TIER_MANAGED_ATTESTED,
)

_TIER_RANK: dict[str, int] = {t: i for i, t in enumerate(TIER_ORDER)}

DEFAULT_MATRIX_PATH = (
    Path(__file__).parent.parent.parent
    / "enterprise-kit"
    / "policy"
    / "capability-tiers.yaml"
)
ENV_MATRIX_PATH = "MCP_PROXY_TIER_MATRIX_PATH"

# When the bundled YAML is missing AND the env override is unset, we
# fall back to a permissive default so a customer that hasn't dropped
# a capability-tiers.yaml on disk yet doesn't break their existing
# capability flow. The fallback is intentionally identical to "tier
# enforcement disabled": every capability defaults to ``untrusted``
# and the gate is a no-op.
_FALLBACK_DEFAULT_TIER = TIER_UNTRUSTED


@dataclass(frozen=True)
class TierMatrix:
    """Cached representation of ``capability-tiers.yaml``.

    Two lookup tables — exact-name first, prefix wildcard second —
    so the lookup stays O(1) for the common case (a real capability
    name like ``mcp.transfer_money``) and degrades to O(len(prefixes))
    only when the exact name is missing.
    """

    version: str
    default_min_tier: str
    by_exact: dict[str, str]
    by_prefix: tuple[tuple[str, str], ...]
    source_path: str

    def lookup(self, capability: str | None) -> str:
        """Return the minimum tier required to invoke ``capability``.

        Lookup order:

        1. Exact match in :attr:`by_exact`.
        2. Longest matching prefix in :attr:`by_prefix` (``admin.*``
           covers ``admin.read``, ``admin.write``, ...). Longer
           prefixes win when several entries match.
        3. :attr:`default_min_tier` when nothing matches.

        ``capability`` is ``None`` (or empty) when a builtin doesn't
        declare a required capability — we treat that as the
        permissive default rather than refusing the call, because the
        gate above this layer has already decided the call is
        capability-allowed.
        """
        if not capability:
            return self.default_min_tier
        exact = self.by_exact.get(capability)
        if exact is not None:
            return exact
        best_prefix = ""
        best_tier: str | None = None
        for prefix, tier in self.by_prefix:
            if capability.startswith(prefix) and len(prefix) > len(best_prefix):
                best_prefix = prefix
                best_tier = tier
        if best_tier is not None:
            return best_tier
        return self.default_min_tier


def tier_meets_requirement(actual: str | None, required: str | None) -> bool:
    """True when ``actual`` ranks ≥ ``required`` in the schema-doc order.

    Unknown / typo'd values resolve to ``untrusted`` for the actual
    (most restrictive — a forged claim cannot raise the tier) and to
    ``managed_attested`` for the required (most restrictive — a
    typo in YAML must not silently relax the gate). Both behaviours
    are documented in schema-doc sez. 7.
    """
    if actual is None or actual not in _TIER_RANK:
        actual_rank = _TIER_RANK[TIER_UNTRUSTED]
    else:
        actual_rank = _TIER_RANK[actual]
    if required is None or required not in _TIER_RANK:
        required_rank = _TIER_RANK[TIER_MANAGED_ATTESTED]
    else:
        required_rank = _TIER_RANK[required]
    return actual_rank >= required_rank


def load_tier_matrix(path: Path | str | None = None) -> TierMatrix:
    """Read the YAML at ``path`` (or the configured default) into a
    :class:`TierMatrix`. Raises :class:`ValueError` on a malformed file.

    Resolution order for the file location:

    1. The ``path`` argument when explicitly supplied (tests).
    2. The ``MCP_PROXY_TIER_MATRIX_PATH`` env override (production
       operator override without rebuilding the bundle).
    3. The repo-bundled default at
       ``enterprise-kit/policy/capability-tiers.yaml``.

    When the resolved path does not exist the function returns a
    permissive fallback matrix (every capability → ``untrusted``)
    so a deployment without the YAML on disk does not crash the
    proxy startup. A warning is logged so the operator can spot the
    miss in the boot log.
    """
    if path is None:
        env_override = os.environ.get(ENV_MATRIX_PATH)
        path = Path(env_override) if env_override else DEFAULT_MATRIX_PATH
    path = Path(path)
    if not path.exists():
        _log.warning(
            "tier matrix YAML not found at %s — falling back to permissive "
            "default (every capability → %s). Drop a capability-tiers.yaml "
            "in place or set %s to enforce the 5-tier gate.",
            path, _FALLBACK_DEFAULT_TIER, ENV_MATRIX_PATH,
        )
        return TierMatrix(
            version="0.0-fallback",
            default_min_tier=_FALLBACK_DEFAULT_TIER,
            by_exact={},
            by_prefix=(),
            source_path=str(path),
        )

    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(
            f"{path}: top level must be a mapping (got {type(raw).__name__})",
        )

    version = str(raw.get("version") or "0.0-unversioned")
    default_min_tier = str(
        raw.get("default_min_tier") or _FALLBACK_DEFAULT_TIER,
    )
    if default_min_tier not in _TIER_RANK:
        raise ValueError(
            f"{path}: default_min_tier '{default_min_tier}' is not one of "
            f"{list(TIER_ORDER)}",
        )

    by_exact: dict[str, str] = {}
    by_prefix: list[tuple[str, str]] = []
    capabilities = raw.get("capabilities") or {}
    if not isinstance(capabilities, dict):
        raise ValueError(
            f"{path}: ``capabilities`` must be a mapping "
            f"(got {type(capabilities).__name__})",
        )

    for name, entry in capabilities.items():
        if not isinstance(entry, dict):
            raise ValueError(
                f"{path}: capability '{name}' must be a mapping",
            )
        tier = entry.get("min_tier")
        if not isinstance(tier, str) or tier not in _TIER_RANK:
            raise ValueError(
                f"{path}: capability '{name}' has invalid min_tier "
                f"'{tier}' (must be one of {list(TIER_ORDER)})",
            )
        if not isinstance(name, str) or not name:
            raise ValueError(
                f"{path}: capability name must be a non-empty string",
            )
        if name.endswith(".*"):
            # ``admin.*`` → prefix ``admin.``. The trailing dot is
            # required so ``admin.*`` matches ``admin.read`` but NOT
            # ``adminstuff``.
            by_prefix.append((name[:-1], tier))
        else:
            by_exact[name] = tier

    # Sort prefixes longest-first so the lookup-best-match loop can
    # short-circuit on the first hit when we add that optimisation
    # later. Today we still scan the whole list for clarity.
    by_prefix.sort(key=lambda kv: -len(kv[0]))

    return TierMatrix(
        version=version,
        default_min_tier=default_min_tier,
        by_exact=by_exact,
        by_prefix=tuple(by_prefix),
        source_path=str(path),
    )


def load_default_tier_matrix() -> TierMatrix:
    """Convenience for ``app.state`` boot: load from the configured
    path with no overrides. Errors during load are caught + logged so
    boot continues with the fallback matrix; an operator can fix the
    YAML and call :meth:`reload_tier_matrix` from a future admin
    endpoint without a process restart.
    """
    try:
        return load_tier_matrix(None)
    except Exception as exc:  # noqa: BLE001 — boot must not crash
        _log.error(
            "tier matrix load failed (%s) — falling back to permissive "
            "default. Fix the YAML and reload.", exc,
        )
        return TierMatrix(
            version="0.0-fallback",
            default_min_tier=_FALLBACK_DEFAULT_TIER,
            by_exact={},
            by_prefix=(),
            source_path="<load-error-fallback>",
        )


__all__ = [
    "DEFAULT_MATRIX_PATH",
    "ENV_MATRIX_PATH",
    "TIER_ORDER",
    "TierMatrix",
    "load_default_tier_matrix",
    "load_tier_matrix",
    "tier_meets_requirement",
]
