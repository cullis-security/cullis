"""Lazy importer for the third-party ``webauthn`` library.

Every call site that needs py_webauthn goes through :func:`load_lib`
so that a Mastio booted without the optional extra still imports the
WebAuthn sub-package (validators, storage helpers, error types) for
the warn-only enforcement mode. The hard ImportError surfaces only on
the code paths that actually call into the library.
"""
from __future__ import annotations

from functools import lru_cache
from typing import Any

from mcp_proxy.auth.webauthn.errors import WebAuthnLibraryMissingError


@lru_cache(maxsize=1)
def load_lib() -> Any:
    """Return the imported ``webauthn`` module, raising on absence.

    Cached so the import cost (and a potentially slow filesystem lookup
    on first call) only happens once per process. The cache also makes
    monkeypatching in tests deterministic: replace the import target
    and call ``load_lib.cache_clear()``.
    """
    try:
        import webauthn  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover - exercised by env-gated test
        raise WebAuthnLibraryMissingError(
            "py_webauthn is not installed; install the [webauthn] extra "
            "(pip install 'cullis-agent-sdk[webauthn]') to enable "
            "ADR-033 Phase 2 user assertion binding.",
        ) from exc
    return webauthn


def is_available() -> bool:
    """Return ``True`` iff the ``webauthn`` library imports cleanly.

    Useful for branches that want to skip a code path without raising,
    notably the warn-mode session emission that accepts assertion-less
    requests on purpose.
    """
    try:
        load_lib()
    except WebAuthnLibraryMissingError:
        return False
    return True
