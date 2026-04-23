"""Dashboard endpoints for the federation update framework.

Three handlers under ``/proxy/updates``:

- ``GET  /proxy/updates``                     — merged list of every
  registered :class:`Migration` with its row in ``pending_updates``.
  JSON response so the dashboard UI (PR 5) can fetch it via ``fetch()``
  and ``curl`` / test harnesses can consume it without following
  redirects.
- ``POST /proxy/updates/{migration_id}/apply``    — run ``up()``
  wrapped in try/except, mutate ``pending_updates.status`` to
  ``applied`` / ``failed``, log audit, then clear sign-halt and
  re-run the boot detector so another still-pending critical
  migration re-engages the halt on its own.
- ``POST /proxy/updates/{migration_id}/rollback`` — same shape as apply
  but against ``rollback()`` and gated on ``status in {'applied',
  'failed'}``.

Every state-changing endpoint requires CSRF + an authenticated
dashboard session and ``confirm_text``: ``APPLY`` for apply,
``ROLLBACK`` for rollback — mirrors the ``ACTIVATE`` / ``DROP`` gate
on ``/proxy/mastio-key/complete-staged`` (PR #288).

Design notes captured from planning:

- Route prefix is ``/proxy/`` rather than ``/admin/`` to match the
  existing dashboard admin surface; a separate ``/v1/admin/updates/*``
  JSON API layer may be added later.
- No per-route rate limit. The dashboard admin bucket covers the
  whole ``/proxy/*`` tree; apply/rollback are deliberate authenticated
  actions, not abuse vectors.
- On DB UPDATE failure after a successful ``up()`` / ``rollback()``,
  the handler retries 3 times with exponential backoff and then
  surfaces 500. The next boot's ``detect_pending_migrations`` is the
  self-healing safety net — ``check()`` is the source of truth.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Iterable

import pathlib

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from starlette.responses import RedirectResponse

from mcp_proxy.dashboard.session import (
    ProxyDashboardSession,
    require_login,
    verify_csrf,
)
from mcp_proxy.db import (
    get_pending_updates,
    insert_pending_update,
    log_audit,
    update_pending_update_status,
)
from mcp_proxy.updates import Migration, discover, get_by_id
from mcp_proxy.updates.boot import detect_pending_migrations

_TEMPLATE_DIR = pathlib.Path(__file__).parent / "templates"
_templates = Jinja2Templates(directory=str(_TEMPLATE_DIR))


_log = logging.getLogger("mcp_proxy.dashboard.updates")


router = APIRouter(prefix="/proxy/updates", tags=["dashboard", "updates"])


_APPLY_CONFIRM = "APPLY"
_ROLLBACK_CONFIRM = "ROLLBACK"

# DB UPDATE retry policy after a successful migration up/rollback call
# but a transient DB write failure. Three tries with exponential backoff
# — 0.1, 0.2, 0.4 seconds, total ~700ms worst case.
_DB_RETRY_DELAYS_S: tuple[float, ...] = (0.1, 0.2, 0.4)


def _migration_to_dict(
    m: Migration,
    row: dict | None,
) -> dict:
    """Flatten a Migration + its ``pending_updates`` row to a JSON-safe dict."""
    return {
        "migration_id": m.migration_id,
        "migration_type": m.migration_type,
        "criticality": m.criticality,
        "description": m.description,
        "preserves_enrollments": m.preserves_enrollments,
        "affects_enrollments": list(m.affects_enrollments),
        "db_status": (row or {}).get("status"),
        "detected_at": (row or {}).get("detected_at"),
        "applied_at": (row or {}).get("applied_at"),
        "error": (row or {}).get("error"),
    }


async def _update_status_with_retry(
    *,
    migration_id: str,
    status: str,
    applied_at: str | None = None,
    error: str | None = None,
) -> None:
    """Retry the pending_updates UPDATE a few times before giving up.

    Transient DB lock / timeout during the UPDATE after a successful
    ``up()`` / ``rollback()`` is the drift case we care about. After
    three attempts we surface 500; the next boot's detector reconverges
    against the real state via ``check()``.
    """
    last_exc: Exception | None = None
    for idx, delay in enumerate((0.0,) + _DB_RETRY_DELAYS_S):
        if delay:
            await asyncio.sleep(delay)
        try:
            await update_pending_update_status(
                migration_id=migration_id,
                status=status,
                applied_at=applied_at,
                error=error,
            )
            if idx > 0:
                _log.warning(
                    "updates: status UPDATE succeeded after %d retries "
                    "(migration_id=%s, status=%s)",
                    idx, migration_id, status,
                )
            return
        except Exception as exc:
            last_exc = exc
            _log.warning(
                "updates: status UPDATE attempt %d failed (migration_id=%s, "
                "status=%s): %s",
                idx + 1, migration_id, status, exc,
            )
    _log.error(
        "updates: status UPDATE drift — %d attempts all failed for "
        "migration_id=%s. The next boot's detect_pending_migrations "
        "will reconverge from check(). Last error: %s",
        len(_DB_RETRY_DELAYS_S) + 1, migration_id, last_exc,
    )
    raise HTTPException(
        status_code=500,
        detail=(
            f"status write failed for {migration_id!r} after retries; "
            f"the physical state change succeeded but the DB row is "
            f"stale. The next boot will reconverge. Last error: {last_exc}"
        ),
    )


def _extract_form_field(form: Iterable, key: str) -> str:
    """``form.get(key)`` with a ``.strip()``; returns '' on missing."""
    try:
        value = form.get(key) or ""  # type: ignore[attr-defined]
    except AttributeError:
        value = ""
    return str(value).strip()


async def _require_session_and_csrf(request: Request):
    """Shared guard. Returns the session on success, RedirectResponse on
    unauthenticated access, or raises ``HTTPException(403)`` on CSRF.

    Matches the pattern from ``/proxy/mastio-key/complete-staged`` (#288).
    """
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if not await verify_csrf(request, session):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")
    return session


async def _refresh_halt_state(request: Request) -> None:
    """Clear the sign-halt and re-run the boot detector.

    Invoked after a successful apply / rollback. If another critical
    migration is still pending against current state, the detector
    re-engages the halt with a fresh reason; otherwise the proxy
    returns to normal signing.
    """
    agent_mgr = getattr(request.app.state, "agent_manager", None)
    if agent_mgr is None:
        # The manager isn't attached (test harness that bypasses
        # lifespan, or a proxy that booted without ca_loaded).
        # Nothing to halt/clear; the detector call is still useful to
        # refresh the Prometheus gauge but requires an agent_mgr shape;
        # skip quietly.
        return
    agent_mgr.clear_sign_halt()
    try:
        await detect_pending_migrations(agent_mgr)
    except Exception as exc:
        # Defensive — the apply/rollback succeeded, we don't want to
        # mask that success because the re-detect tripped.
        _log.warning(
            "updates: detect_pending_migrations after action failed: %s "
            "— halt state may be stale until next restart", exc,
        )


# ─────────────────────────────────────────────────────────────────────
# Handlers
# ─────────────────────────────────────────────────────────────────────


async def _build_updates_view() -> list[dict]:
    """Shared assembler used by the HTML page and the JSON endpoint."""
    migrations = discover()
    rows_by_id = {
        row["migration_id"]: row for row in await get_pending_updates()
    }
    return [
        _migration_to_dict(m, rows_by_id.get(m.migration_id))
        for m in migrations
    ]


def _has_critical_pending(updates_view: list[dict]) -> bool:
    return any(
        u["criticality"] == "critical" and u["db_status"] == "pending"
        for u in updates_view
    )


@router.get("", response_class=HTMLResponse)
async def updates_page(request: Request):
    """Render the dashboard UI for federation updates.

    HTML response. Login-gated; GET so no CSRF. The UI consumes the
    same ``updates`` view the JSON endpoint exposes — matching the
    dashboard convention of one URL, one content type. The JSON
    view lives at ``/proxy/updates/api`` for scripts and tests.
    """
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session

    updates_view = await _build_updates_view()
    return _templates.TemplateResponse(
        "proxy_updates.html",
        {
            "request": request,
            "session": session,
            "csrf_token": session.csrf_token,
            "active": "updates",
            "updates": updates_view,
            "has_critical_pending": _has_critical_pending(updates_view),
        },
    )


@router.get("/api")
async def updates_list_json(request: Request):
    """JSON view of every registered migration + its ``pending_updates`` row.

    Companion to :func:`updates_page` for curl / scripts / tests.
    """
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    return JSONResponse({"updates": await _build_updates_view()})


@router.post("/{migration_id}/apply")
async def updates_apply(migration_id: str, request: Request):
    """Run ``migration.up()``, mutate status, clear+re-detect halt.

    409 if the DB row is not in ``pending``. 404 if the migration is
    not registered. 400 on missing/wrong ``confirm_text``. 500 with a
    drift explanation if the DB UPDATE fails after ``up()`` succeeded.
    """
    session = await _require_session_and_csrf(request)
    if isinstance(session, RedirectResponse):
        return session

    form = await request.form()
    confirm = _extract_form_field(form, "confirm_text")
    if confirm != _APPLY_CONFIRM:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Confirmation text mismatch — type {_APPLY_CONFIRM} "
                f"to apply this migration"
            ),
        )

    migration = get_by_id(migration_id)
    if migration is None:
        raise HTTPException(
            status_code=404,
            detail=f"migration {migration_id!r} not registered",
        )

    rows_by_id = {
        row["migration_id"]: row for row in await get_pending_updates()
    }
    row = rows_by_id.get(migration_id)
    if row is not None and row["status"] not in ("pending", "failed"):
        # ``applied`` and ``rolled_back`` terminal states require an
        # explicit rollback before a new apply; retry-from-failed is
        # the intended path for recovering a prior failed attempt,
        # safe because Migration.up() is documented idempotent (PR 1).
        raise HTTPException(
            status_code=409,
            detail=(
                f"migration {migration_id!r} is currently in status "
                f"{row['status']!r} — only pending or failed migrations "
                f"can be applied. Roll back first if a reset is intended."
            ),
        )

    # Operator override — ``check()`` False here is acceptable (C. of
    # the PR plan): the admin has decided. Log WARNING so the decision
    # is in the ops record.
    try:
        if not await migration.check():
            _log.warning(
                "updates.apply: %s — check() returned False but admin "
                "is applying anyway",
                migration_id,
            )
    except Exception as exc:
        _log.warning(
            "updates.apply: %s — check() raised during pre-apply probe "
            "(%s); proceeding with apply attempt",
            migration_id, exc,
        )

    # Ensure a ``pending_updates`` row exists (the admin can trigger
    # apply before the boot detector has populated it — e.g. a
    # fresh-out-of-the-box migration). Idempotent insert.
    now_iso = _now_iso()
    if row is None:
        await insert_pending_update(
            migration_id=migration_id,
            detected_at=now_iso,
        )

    try:
        await migration.up()
    except Exception as exc:
        error_msg = f"{type(exc).__name__}: {exc}"
        _log.error(
            "updates.apply: %s up() failed: %s", migration_id, error_msg,
        )
        try:
            await _update_status_with_retry(
                migration_id=migration_id,
                status="failed",
                error=error_msg,
            )
        except HTTPException:
            # Drift already surfaced as 500 to the client.
            raise
        await log_audit(
            agent_id="admin",
            action="updates.apply",
            status="failure",
            detail=f"migration_id={migration_id}, error={error_msg}",
        )
        raise HTTPException(
            status_code=500,
            detail=f"apply failed: {error_msg}",
        )

    await _update_status_with_retry(
        migration_id=migration_id,
        status="applied",
        applied_at=now_iso,
    )
    await log_audit(
        agent_id="admin",
        action="updates.apply",
        status="success",
        detail=f"migration_id={migration_id}",
    )
    await _refresh_halt_state(request)

    return JSONResponse({"status": "applied", "migration_id": migration_id})


@router.post("/{migration_id}/rollback")
async def updates_rollback(migration_id: str, request: Request):
    """Run ``migration.rollback()``, mutate status, clear+re-detect halt.

    409 when the row is not in ``applied`` / ``failed`` (pending or
    already rolled_back can't be rolled back). Otherwise the same shape
    as :func:`updates_apply`.
    """
    session = await _require_session_and_csrf(request)
    if isinstance(session, RedirectResponse):
        return session

    form = await request.form()
    confirm = _extract_form_field(form, "confirm_text")
    if confirm != _ROLLBACK_CONFIRM:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Confirmation text mismatch — type {_ROLLBACK_CONFIRM} "
                f"to roll back this migration"
            ),
        )

    migration = get_by_id(migration_id)
    if migration is None:
        raise HTTPException(
            status_code=404,
            detail=f"migration {migration_id!r} not registered",
        )

    rows_by_id = {
        row["migration_id"]: row for row in await get_pending_updates()
    }
    row = rows_by_id.get(migration_id)
    if row is None or row["status"] not in ("applied", "failed"):
        raise HTTPException(
            status_code=409,
            detail=(
                f"migration {migration_id!r} is currently in status "
                f"{(row or {}).get('status', 'none')!r} — only applied or "
                f"failed migrations can be rolled back"
            ),
        )

    try:
        await migration.rollback()
    except Exception as exc:
        error_msg = f"{type(exc).__name__}: {exc}"
        _log.error(
            "updates.rollback: %s rollback() failed: %s",
            migration_id, error_msg,
        )
        try:
            await _update_status_with_retry(
                migration_id=migration_id,
                status="failed",
                error=error_msg,
            )
        except HTTPException:
            raise
        await log_audit(
            agent_id="admin",
            action="updates.rollback",
            status="failure",
            detail=f"migration_id={migration_id}, error={error_msg}",
        )
        raise HTTPException(
            status_code=500,
            detail=f"rollback failed: {error_msg}",
        )

    await _update_status_with_retry(
        migration_id=migration_id,
        status="rolled_back",
        applied_at=_now_iso(),
    )
    await log_audit(
        agent_id="admin",
        action="updates.rollback",
        status="success",
        detail=f"migration_id={migration_id}",
    )
    await _refresh_halt_state(request)

    return JSONResponse(
        {"status": "rolled_back", "migration_id": migration_id},
    )


# ─────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()
