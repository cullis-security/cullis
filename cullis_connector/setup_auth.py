"""Admin-only auth for the Connector setup wizard in shared mode.

ADR-034 §1 — when ``AMBASSADOR_MODE=shared`` the Frontdesk container
sits at the boundary between the corporate LAN and the Cullis cloud.
The ``/setup/*`` routes that enrol the workload and pin the Mastio CA
must not be reachable by every end-user who can reach the login form;
otherwise any host on the LAN can re-enrol the container under an
attacker-controlled Mastio.

This module owns the three accepted proof shapes:

* **Bootstrap Bearer** — env ``FRONTDESK_SETUP_BEARER`` (32 random
  bytes hex). If unset on first boot, the container mints one,
  prints it to stderr inside a clearly framed banner so the admin
  catches it via ``docker logs``, and persists the value in
  ``<config_dir>/setup_state.json`` so a container restart doesn't
  rotate the token under a setup-in-progress admin. The bearer is
  invalidated by ``mark_setup_completed`` (see below) so a stale
  ``docker logs`` line cannot re-grant control after enrolment.
* **HMAC signature** — env ``FRONTDESK_SETUP_HMAC_KEY``. The CI /
  automation client signs ``f"{timestamp}|{path}|{body}"`` with
  HMAC-SHA256 and sends the hex digest in
  ``X-Cullis-Setup-Sig: ts=<ms>,sig=<hex>``. Timestamps older than
  five minutes are refused (replay window).
* **Setup-grant JWT** (TBD endpoint on Mastio, deferred to a follow-up
  PR — see ADR-034 §1 Open Q "Mastio admin session validation"). Not
  implemented in this module; the warn/required knob below covers the
  transition window.

The single ``read_setup_auth_enforcement`` env value
(``FRONTDESK_SETUP_AUTH_ENFORCEMENT={warn,required}``) selects the
policy. Default ``warn`` in v0.5.0 (audit the gap, don't break
existing deployments mid-upgrade); flipped to ``required`` in v0.5.1.

Single mode (``AMBASSADOR_MODE != "shared"``) bypasses every check.
The existing ``require_local_only`` loopback gate on the ambassador
is the authoritative guard for Cullis Chat desktop.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from cullis_connector.identity.auth_mode import is_shared_mode

_log = logging.getLogger("cullis_connector.setup_auth")

ENV_BEARER = "FRONTDESK_SETUP_BEARER"
ENV_HMAC_KEY = "FRONTDESK_SETUP_HMAC_KEY"
ENV_ENFORCEMENT = "FRONTDESK_SETUP_AUTH_ENFORCEMENT"

ENFORCEMENT_WARN = "warn"
ENFORCEMENT_REQUIRED = "required"
_VALID_ENFORCEMENT = (ENFORCEMENT_WARN, ENFORCEMENT_REQUIRED)

# Replay window for HMAC signatures. Five minutes covers a slow CI
# runner without leaving a meaningful window for a leaked signature.
HMAC_REPLAY_WINDOW_S = 300

# Filename for the persistent bearer + completion state. Lives under
# the resolved config_dir so multi-profile installs stay isolated.
SETUP_STATE_FILENAME = "setup_state.json"

# 32 random bytes → 64 hex chars, comfortable headroom against
# brute-force without bloating the docker-logs banner.
_BEARER_BYTES = 32


@dataclass(frozen=True)
class SetupAuthOutcome:
    """Outcome of an admin-proof check.

    ``allowed`` is the final yes/no the caller acts on. ``reason``
    carries a short tag for audit logs (``bearer_ok``, ``hmac_ok``,
    ``no_proof_warn``, ``no_proof_refused``, ``completed_refused``,
    ``single_mode_bypass``). ``enforcement`` echoes the active knob so
    the caller can decide whether to log a warning vs raise 403.
    """

    allowed: bool
    reason: str
    enforcement: str


def read_setup_auth_enforcement(env: Optional[dict] = None) -> str:
    """Return ``warn`` or ``required``. Default ``warn``.

    A typo (``strict``, ``off``) falls back to ``warn`` with a one-time
    log line so a misconfigured operator doesn't silently disable the
    audit visibility — same pattern as ``read_auth_mode``.
    """
    e = env if env is not None else os.environ
    raw = (e.get(ENV_ENFORCEMENT) or "").strip().lower()
    if not raw:
        return ENFORCEMENT_WARN
    if raw in _VALID_ENFORCEMENT:
        return raw
    _log.warning(
        "%s=%r is not one of %s; falling back to %s",
        ENV_ENFORCEMENT, raw, _VALID_ENFORCEMENT, ENFORCEMENT_WARN,
    )
    return ENFORCEMENT_WARN


def _state_path(config_dir: Path) -> Path:
    return Path(config_dir) / SETUP_STATE_FILENAME


def _load_state(config_dir: Path) -> dict:
    path = _state_path(config_dir)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        _log.warning(
            "setup_state.json unreadable, treating as empty: %s", exc,
        )
        return {}


def _store_state(config_dir: Path, state: dict) -> None:
    path = _state_path(config_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")
    # Atomic replace so a half-written file can't poison the next boot.
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        # Windows / non-POSIX FS — best effort, the env-only path
        # still works for those deployments.
        pass


def read_or_generate_setup_bearer(
    config_dir: Path, *, env: Optional[dict] = None,
) -> Optional[str]:
    """Return the active setup bearer, generating it on first boot.

    Precedence:

      1. ``FRONTDESK_SETUP_BEARER`` env wins (CI / explicit operator
         override). The env value is NOT persisted to disk so an
         operator who rotates the env without touching the file
         immediately invalidates the previous bearer.
      2. The value persisted in ``setup_state.json`` from a prior
         boot. Same container, same bearer — restarts during an
         in-progress setup don't lock the admin out.
      3. A freshly minted random bearer (only when shared mode is
         active and no completion flag is set). Printed once to
         stderr inside a framed banner so it lands in ``docker logs``
         next to the other startup messages.

    Returns ``None`` in single mode (no bearer needed) or when setup
    is already completed (no further bearer should be served).
    """
    if not is_shared_mode(env):
        return None
    state = _load_state(config_dir)
    if state.get("setup_completed"):
        return None

    e = env if env is not None else os.environ
    bearer = (e.get(ENV_BEARER) or "").strip() or state.get("bearer")
    if bearer:
        return bearer

    bearer = secrets.token_hex(_BEARER_BYTES)
    state["bearer"] = bearer
    _store_state(config_dir, state)

    banner = (
        "\n"
        "============================================================\n"
        " Frontdesk setup bearer (shared mode)\n"
        "------------------------------------------------------------\n"
        f" {bearer}\n"
        "------------------------------------------------------------\n"
        " Pass this as ``Authorization: Bearer <token>`` or query\n"
        " param ``?setup_token=<token>`` when calling /setup/*.\n"
        " The bearer is invalidated automatically once enrollment\n"
        " completes; restart the container to mint a fresh one.\n"
        "============================================================\n"
    )
    print(banner, file=sys.stderr, flush=True)
    return bearer


def mark_setup_completed(config_dir: Path) -> None:
    """Persist a flag that disables further ``/setup/*`` access.

    Called by the wizard right after a successful enrollment. The
    next request to any ``/setup/*`` path with a valid bearer is
    still refused, so a container left running after enrolment
    cannot be re-targeted by a stale ``docker logs`` line.

    Operator escape hatch: ``docker compose down + up`` with the
    ``FRONTDESK_SETUP_BEARER`` env unset wipes the bearer; an
    operator who deletes ``setup_state.json`` explicitly resets the
    surface. Both paths are intentional admin actions.
    """
    state = _load_state(config_dir)
    state["setup_completed"] = True
    state["setup_completed_at"] = int(time.time())
    # Wipe the bearer at completion so even a memory-resident copy is
    # only good until the next read.
    state.pop("bearer", None)
    _store_state(config_dir, state)


def is_setup_completed(config_dir: Path) -> bool:
    return bool(_load_state(config_dir).get("setup_completed"))


def _verify_hmac(
    *,
    sig_header: str,
    method: str,
    path: str,
    body_bytes: bytes,
    hmac_key: str,
    now: Optional[float] = None,
) -> bool:
    """Constant-time check on the ``X-Cullis-Setup-Sig`` header.

    Header format: ``ts=<unix_ms>,sig=<hex>``. The signed payload is
    ``f"{ts}|{method}|{path}|{sha256(body_bytes).hex()}"`` so an
    attacker who learns one signature can't replay it on a different
    body or endpoint.
    """
    if not sig_header or not hmac_key:
        return False
    parts = {}
    for chunk in sig_header.split(","):
        if "=" not in chunk:
            return False
        k, v = chunk.split("=", 1)
        parts[k.strip().lower()] = v.strip()
    ts_raw = parts.get("ts")
    sig_hex = parts.get("sig")
    if not ts_raw or not sig_hex:
        return False
    try:
        ts = int(ts_raw)
    except ValueError:
        return False
    now_s = now if now is not None else time.time()
    if abs(now_s - ts / 1000.0) > HMAC_REPLAY_WINDOW_S:
        return False
    payload = (
        f"{ts}|{method.upper()}|{path}|{hashlib.sha256(body_bytes).hexdigest()}"
    )
    expected = hmac.new(
        hmac_key.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, sig_hex)


def verify_setup_request(
    *,
    config_dir: Path,
    method: str,
    path: str,
    headers: dict,
    query_params: dict,
    body_bytes: bytes,
    env: Optional[dict] = None,
) -> SetupAuthOutcome:
    """Centralised proof check for ``/setup/*`` in shared mode.

    The middleware (``cullis_connector/web.py``) calls this once per
    request. Single mode bypasses every check (returns
    ``allowed=True, reason="single_mode_bypass"``). Completed setup
    refuses regardless of proof (returns ``allowed=False,
    reason="completed_refused"``).

    Header lookup is case-insensitive — the middleware passes a
    pre-normalised dict (lowercased keys).
    """
    e = env if env is not None else os.environ
    enforcement = read_setup_auth_enforcement(e)

    if not is_shared_mode(e):
        return SetupAuthOutcome(True, "single_mode_bypass", enforcement)

    if is_setup_completed(config_dir):
        return SetupAuthOutcome(False, "completed_refused", enforcement)

    # Bearer check — header takes precedence, query param is a
    # fallback for the ``GET /setup`` browser landing where setting
    # ``Authorization`` is awkward.
    authz = (headers.get("authorization") or "").strip()
    expected_bearer = read_or_generate_setup_bearer(config_dir, env=e)
    presented_bearer: Optional[str] = None
    if authz.lower().startswith("bearer "):
        presented_bearer = authz.split(" ", 1)[1].strip()
    if presented_bearer is None:
        presented_bearer = (
            query_params.get("setup_token") or ""
        ).strip() or None
    if (
        expected_bearer
        and presented_bearer
        and hmac.compare_digest(expected_bearer, presented_bearer)
    ):
        return SetupAuthOutcome(True, "bearer_ok", enforcement)

    # HMAC check.
    sig_header = (headers.get("x-cullis-setup-sig") or "").strip()
    hmac_key = (e.get(ENV_HMAC_KEY) or "").strip()
    if sig_header and hmac_key:
        if _verify_hmac(
            sig_header=sig_header,
            method=method,
            path=path,
            body_bytes=body_bytes,
            hmac_key=hmac_key,
        ):
            return SetupAuthOutcome(True, "hmac_ok", enforcement)

    if enforcement == ENFORCEMENT_REQUIRED:
        return SetupAuthOutcome(False, "no_proof_refused", enforcement)
    return SetupAuthOutcome(True, "no_proof_warn", enforcement)


__all__ = [
    "ENFORCEMENT_REQUIRED",
    "ENFORCEMENT_WARN",
    "ENV_BEARER",
    "ENV_ENFORCEMENT",
    "ENV_HMAC_KEY",
    "HMAC_REPLAY_WINDOW_S",
    "SetupAuthOutcome",
    "SETUP_STATE_FILENAME",
    "is_setup_completed",
    "mark_setup_completed",
    "read_or_generate_setup_bearer",
    "read_setup_auth_enforcement",
    "verify_setup_request",
]
