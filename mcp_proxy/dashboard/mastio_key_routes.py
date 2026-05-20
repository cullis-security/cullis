"""Mastio dashboard, Mastio key rotation sub-router.

Sprint F-B-201 PR-10 of 13. Extracts the Mastio key rotation lifecycle
(grace-days config + rotate trigger + complete-staged finalization) from
the ``mcp_proxy/dashboard/router.py`` god-object. Four routes total.

Mounted via ``router.include_router(mastio_key_routes.router)``.

Routes (4):

  GET  /proxy/mastio-key                   rotation dashboard (active signer + grace keys)
  POST /proxy/mastio-key/grace-days        persist rotation_grace_days (CSRF)
  POST /proxy/mastio-key/rotate            mint new ES256 leaf (CSRF + approval hook + rate-limit)
  POST /proxy/mastio-key/complete-staged   resolve orphaned staged rotation (CSRF)

The CSRF gate, the ``ACTION_MASTIO_KEY_ROTATE`` approval-hook intercept,
the per-env minimum rotation interval guardrail (issue #282) and the
staged-rotation state machine (issue #281) are preserved verbatim.
"""
from __future__ import annotations

import logging
import pathlib
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from starlette.responses import RedirectResponse

from mcp_proxy.admin.approval_hook import (
    ACTION_MASTIO_KEY_ROTATE,
    maybe_intercept_for_approval,
)
from mcp_proxy.dashboard._helpers import _ctx
from mcp_proxy.dashboard._template_env import build_templates
from mcp_proxy.dashboard.session import require_login, verify_csrf

_log = logging.getLogger("mcp_proxy.dashboard")

_TEMPLATE_DIR = pathlib.Path(__file__).parent / "templates"
templates = build_templates(_TEMPLATE_DIR)

router = APIRouter(tags=["dashboard-mastio-key"])


MASTIO_ROTATION_GRACE_DAYS_DEFAULT = 7
MASTIO_ROTATION_GRACE_DAYS_MIN = 1
MASTIO_ROTATION_GRACE_DAYS_MAX = 90

# Minimum seconds between two ``/mastio-key/rotate`` calls. Configurable
# via env so sandbox integration tests (#268) can lower / disable it
# during ``./demo.sh full``, and so incident response can drop it to 0
# without code edits. Not a trust-governance knob (never goes through
# ``proxy_config``), purely an operational guardrail against burst-loop
# abuse from a stolen admin cookie. See #282.
_MASTIO_ROTATION_MIN_INTERVAL_SECONDS_DEFAULT = 30


def _mastio_rotation_min_interval_seconds() -> int:
    """Read ``CULLIS_MASTIO_ROTATION_MIN_INTERVAL_SECONDS`` from env.

    Falls back to 30s on unset / malformed. Accepts 0 to disable the
    guardrail (test environments, incident rollback).
    """
    import os
    raw = os.environ.get("CULLIS_MASTIO_ROTATION_MIN_INTERVAL_SECONDS")
    if raw is None:
        return _MASTIO_ROTATION_MIN_INTERVAL_SECONDS_DEFAULT
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return _MASTIO_ROTATION_MIN_INTERVAL_SECONDS_DEFAULT
    return max(0, value)


async def _load_rotation_grace_days() -> int:
    """Read the configured rotation grace window (days) from proxy_config.

    Falls back to the baseline default on first visit / malformed config.
    """
    from mcp_proxy.db import get_config
    raw = await get_config("rotation_grace_days")
    if raw is None:
        return MASTIO_ROTATION_GRACE_DAYS_DEFAULT
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return MASTIO_ROTATION_GRACE_DAYS_DEFAULT
    if value < MASTIO_ROTATION_GRACE_DAYS_MIN:
        return MASTIO_ROTATION_GRACE_DAYS_MIN
    if value > MASTIO_ROTATION_GRACE_DAYS_MAX:
        return MASTIO_ROTATION_GRACE_DAYS_MAX
    return value


def _mastio_key_to_view(key, *, now: datetime) -> dict:
    """Render a ``MastioKey`` into a plain dict the template can iterate over."""
    expires_at = key.expires_at
    grace_total = None
    grace_remaining = None
    grace_pct = None
    if key.deprecated_at is not None and expires_at is not None:
        grace_total_s = (expires_at - key.deprecated_at).total_seconds()
        grace_remaining_s = max(0, (expires_at - now).total_seconds())
        grace_total = max(1, int(grace_total_s))
        grace_remaining = int(grace_remaining_s)
        # 0% = just rotated, 100% = grace fully elapsed
        grace_pct = max(
            0, min(100, 100 - int(grace_remaining_s * 100 / grace_total)),
        )
    return {
        "kid": key.kid,
        "pubkey_pem": key.pubkey_pem,
        "cert_pem": key.cert_pem or "",
        "created_at": key.created_at.isoformat(),
        "activated_at": key.activated_at.isoformat() if key.activated_at else None,
        "deprecated_at": key.deprecated_at.isoformat() if key.deprecated_at else None,
        "expires_at": expires_at.isoformat() if expires_at else None,
        "is_active": key.is_active,
        "is_valid_for_verification": key.is_valid_for_verification,
        "grace_total_seconds": grace_total,
        "grace_remaining_seconds": grace_remaining,
        "grace_pct": grace_pct,
    }


@router.get("/mastio-key", response_class=HTMLResponse)
async def mastio_key_page(request: Request):
    """Signing-key rotation dashboard.

    Shows the active Mastio ES256 signer, any keys still inside the
    verifier grace window, and exposes the ``rotation_grace_days``
    configuration + a one-click rotate action.
    """
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    from mcp_proxy.auth.local_keystore import LocalKeyStore
    from mcp_proxy.db import get_config

    org_id = await get_config("org_id") or ""
    grace_days = await _load_rotation_grace_days()
    standalone = getattr(request.app.state, "broker_bridge", None) is None

    keystore = LocalKeyStore()
    now = datetime.now(timezone.utc)

    active_view = None
    try:
        active_key = await keystore.current_signer()
    except RuntimeError as exc:
        # Identity not yet provisioned, the page renders with an
        # empty-state CTA pointing at /proxy/setup.
        _log.info("mastio_key page: no active signer (%s)", exc)
        active_key = None

    if active_key is not None:
        active_view = _mastio_key_to_view(active_key, now=now)

    grace_keys = []
    try:
        valid = await keystore.all_valid_keys()
        for k in valid:
            if k.deprecated_at is None:
                continue  # that is the active one, shown above
            grace_keys.append(_mastio_key_to_view(k, now=now))
        grace_keys.sort(key=lambda k: k["expires_at"] or "")
    except Exception:
        pass

    return templates.TemplateResponse("mastio_key.html", _ctx(
        request, session,
        active="mastio_key",
        org_id=org_id,
        active_key=active_view,
        grace_keys=grace_keys,
        grace_days=grace_days,
        grace_days_min=MASTIO_ROTATION_GRACE_DAYS_MIN,
        grace_days_max=MASTIO_ROTATION_GRACE_DAYS_MAX,
        standalone=standalone,
    ))


@router.post("/mastio-key/grace-days")
async def mastio_key_save_grace(request: Request):
    """Persist the ``rotation_grace_days`` preference (clamped to 1..90)."""
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    from mcp_proxy.db import log_audit, set_config

    form = await request.form()
    raw = form.get("grace_days", "")
    try:
        value = int(raw)
    except (TypeError, ValueError):
        raise HTTPException(
            status_code=400,
            detail=f"grace_days must be an integer between {MASTIO_ROTATION_GRACE_DAYS_MIN} and {MASTIO_ROTATION_GRACE_DAYS_MAX}",
        )
    if (
        value < MASTIO_ROTATION_GRACE_DAYS_MIN
        or value > MASTIO_ROTATION_GRACE_DAYS_MAX
    ):
        raise HTTPException(
            status_code=400,
            detail=f"grace_days must be between {MASTIO_ROTATION_GRACE_DAYS_MIN} and {MASTIO_ROTATION_GRACE_DAYS_MAX}",
        )

    await set_config("rotation_grace_days", str(value))
    await log_audit(
        agent_id="admin",
        action="mastio_key.grace_days_set",
        status="success",
        detail=f"rotation_grace_days={value}",
    )
    return RedirectResponse(url="/proxy/mastio-key", status_code=303)


@router.post("/mastio-key/rotate")
async def mastio_key_rotate(request: Request):
    """Trigger a Mastio ES256 leaf rotation.

    Flow (ADR-012 Phase 2.1, issue #261):
      1. ``AgentManager.rotate_mastio_key`` mints a new leaf under the
         intermediate CA, signs a continuity proof with the current key.
      2. The ``propagator`` (wired to ``BrokerBridge`` when available)
         POSTs the proof to the Court's rotate endpoint. On Court
         rejection we raise 502 with the Court's own error.
      3. The local ``mastio_keys`` swap runs in a single DB transaction,
         the previous key is marked ``deprecated_at=now`` / ``expires_at``
         at ``now + grace_days`` and remains verifier-valid during the
         grace window.

    Standalone deploys (no broker uplink) allow rotation without
    propagation, a warning surfaces in the UI. This is a deliberate
    relaxation: a standalone Mastio has no Court pin to update.
    """
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    form = await request.form()
    payload = {k: str(v) for k, v in form.items() if k != "csrf_token"}
    intercept = await maybe_intercept_for_approval(
        session=session, action_type=ACTION_MASTIO_KEY_ROTATE, payload=payload,
        request=request,
    )
    if intercept is not None:
        return intercept

    if form.get("confirm_text") != "ROTATE":
        raise HTTPException(
            status_code=400,
            detail="Confirmation text mismatch, rotation aborted",
        )

    from mcp_proxy.db import log_audit

    agent_mgr = getattr(request.app.state, "agent_manager", None)
    if agent_mgr is None or not getattr(agent_mgr, "mastio_loaded", False):
        raise HTTPException(
            status_code=409,
            detail="Mastio identity not loaded, complete setup first",
        )

    # Issue #282, minimum rotation interval. A logged-in admin can
    # POST ``confirm_text=ROTATE`` in a tight loop and with the default
    # grace_days=7 that's thousands of keys / hour, all passing
    # ``is_valid_for_verification``; with the 90-day max cadence an
    # 8-hour session could mint ~2.5M verification-valid rows.
    # Downstream verifiers OOM, Court gets hammered. A 30-second
    # floor (configurable via env for sandbox integration tests and
    # incident-response rollback) puts a human-scale rate ceiling on
    # the operator surface without entering proxy_config as a
    # trust-governance toggle, this is an operational guardrail.
    min_interval_s = _mastio_rotation_min_interval_seconds()
    if min_interval_s > 0:
        from mcp_proxy.auth.local_keystore import LocalKeyStore
        from datetime import datetime, timezone
        ks = LocalKeyStore()
        try:
            latest_act = max(
                (k.activated_at for k in await ks.all_valid_keys()
                 if k.activated_at is not None),
                default=None,
            )
        except Exception:
            latest_act = None
        if latest_act is not None:
            delta_s = (datetime.now(timezone.utc) - latest_act).total_seconds()
            if delta_s < min_interval_s:
                await log_audit(
                    agent_id="admin",
                    action="mastio_key.rotate",
                    status="rate_limited",
                    detail=(
                        f"min_interval={min_interval_s}s, "
                        f"seconds_since_last={delta_s:.1f}s"
                    ),
                )
                retry_after = max(1, int(min_interval_s - delta_s) + 1)
                raise HTTPException(
                    status_code=429,
                    detail=(
                        f"Minimum rotation interval {min_interval_s}s, "
                        f"last rotation {delta_s:.1f}s ago. Retry in "
                        f"{retry_after}s or lower "
                        f"CULLIS_MASTIO_ROTATION_MIN_INTERVAL_SECONDS."
                    ),
                    headers={"Retry-After": str(retry_after)},
                )

    grace_days = await _load_rotation_grace_days()
    broker_bridge = getattr(request.app.state, "broker_bridge", None)
    propagator = (
        broker_bridge.propagate_mastio_key_rotation
        if broker_bridge is not None
        else None
    )

    old_kid = agent_mgr._active_key.kid if agent_mgr._active_key else None

    try:
        new_active = await agent_mgr.rotate_mastio_key(
            grace_days=grace_days,
            propagator=propagator,
        )
    except HTTPException as exc:
        await log_audit(
            agent_id="admin",
            action="mastio_key.rotate",
            status="failure",
            detail=f"old_kid={old_kid}, reason={exc.detail}",
        )
        raise
    except Exception as exc:
        # Audit H-IO-2, audit row carries the full reason; HTTP detail
        # is generic so an attacker can't probe rotation internals.
        _log.warning("mastio_key.rotate failed (old_kid=%s): %s", old_kid, exc)
        await log_audit(
            agent_id="admin",
            action="mastio_key.rotate",
            status="failure",
            detail=f"old_kid={old_kid}, reason={exc}",
        )
        raise HTTPException(
            status_code=500,
            detail="rotation failed",
        ) from exc

    # Rebuild the LocalIssuer so subsequent token mints use the new signer.
    try:
        from mcp_proxy.auth.local_issuer import build_from_keystore
        from mcp_proxy.auth.local_keystore import LocalKeyStore
        ks = getattr(request.app.state, "local_keystore", None) or LocalKeyStore()
        request.app.state.local_keystore = ks
        org_id = getattr(request.app.state, "org_id", None)
        if org_id:
            request.app.state.local_issuer = await build_from_keystore(org_id, ks)
    except Exception as exc:
        _log.warning("LocalIssuer rebuild after rotation failed: %s", exc)

    await log_audit(
        agent_id="admin",
        action="mastio_key.rotate",
        status="success",
        detail=(
            f"old_kid={old_kid}, new_kid={new_active.kid}, "
            f"grace_days={grace_days}"
        ),
    )
    # Redirect with flash-state in query string so the page can render a
    # success toast without a dedicated session flash channel.
    return RedirectResponse(
        url=(
            f"/proxy/mastio-key?rotated=1"
            f"&old_kid={old_kid or ''}"
            f"&new_kid={new_active.kid}"
        ),
        status_code=303,
    )


@router.post("/mastio-key/complete-staged")
async def mastio_key_complete_staged(request: Request):
    """Resolve an orphaned staged rotation row (issue #281 recovery).

    The form accepts ``decision=activate`` or ``decision=drop`` plus
    the standard ``confirm_text`` gate. ``activate`` completes a
    rotation whose Court-side propagation succeeded but whose local
    commit crashed; ``drop`` discards a staged row whose Court-side
    propagation never completed.

    On success, clears the sign-halt state on the AgentManager and
    rebuilds the LocalIssuer so token issuance resumes without a
    restart. Emits an audit event with the chosen branch and the
    kids involved.

    Follow-up #287 tracks the full dashboard UI (Court-pin preview
    banner, 2-button flow); this endpoint is the backend plumbing
    reachable from that UI and from ``curl`` for the current
    emergency path.
    """
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    form = await request.form()
    decision = (form.get("decision") or "").strip()
    if decision not in ("activate", "drop"):
        raise HTTPException(
            status_code=400,
            detail="decision must be 'activate' or 'drop'",
        )
    expected_confirm = "ACTIVATE" if decision == "activate" else "DROP"
    if form.get("confirm_text") != expected_confirm:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Confirmation text mismatch, type {expected_confirm} "
                f"to complete the {decision} branch"
            ),
        )

    from mcp_proxy.db import log_audit

    agent_mgr = getattr(request.app.state, "agent_manager", None)
    if agent_mgr is None:
        raise HTTPException(
            status_code=409,
            detail="AgentManager not initialized",
        )

    try:
        result = await agent_mgr.complete_staged_rotation(decision)
    except RuntimeError as exc:
        # Audit H-IO-2, audit row carries the full reason; HTTP detail
        # is generic so an attacker can't probe internal staging state.
        _log.warning(
            "mastio_key.complete_staged failed (decision=%s): %s",
            decision, exc,
        )
        await log_audit(
            agent_id="admin",
            action="mastio_key.complete_staged",
            status="failure",
            detail=f"decision={decision}, reason={exc}",
        )
        raise HTTPException(
            status_code=409,
            detail="complete-staged rotation failed",
        ) from exc

    # Rebuild LocalIssuer so local-token issuance resumes. Mirrors the
    # rebuild that runs at the end of the rotate endpoint above, the
    # halt flag has just been cleared by ``complete_staged_rotation``.
    try:
        from mcp_proxy.auth.local_issuer import build_from_keystore
        from mcp_proxy.auth.local_keystore import LocalKeyStore
        ks = getattr(request.app.state, "local_keystore", None) or LocalKeyStore()
        request.app.state.local_keystore = ks
        org_id = getattr(request.app.state, "org_id", None)
        if org_id:
            request.app.state.local_issuer = await build_from_keystore(org_id, ks)
    except Exception as exc:
        _log.warning(
            "LocalIssuer rebuild after complete-staged failed: %s", exc,
        )

    await log_audit(
        agent_id="admin",
        action="mastio_key.complete_staged",
        status="success",
        detail=(
            f"decision={result['decision']}, kid={result.get('kid', '')}, "
            f"old_kid={result.get('old_kid', '')}"
        ),
    )
    return RedirectResponse(
        url=(
            f"/proxy/mastio-key?completed={result['decision']}"
            f"&kid={result.get('kid', '')}"
        ),
        status_code=303,
    )
