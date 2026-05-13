"""Helper for endpoint handlers that may be intercepted by an approval plugin.

Endpoints that fall under 4-eyes / separation-of-duty workflows call
:func:`maybe_intercept_for_approval` after authentication and CSRF check
but before executing the mutation. If a plugin (e.g. the enterprise
``rbac_multi_admin`` quorum extension) declares the action gated, the
helper submits the pending approval and returns a redirect to the
approval detail page. The endpoint then returns that redirect to the
caller and skips its normal execution path.

Community deploys without any opt-in plugin observe unchanged behavior:
the helper returns ``None`` and the endpoint proceeds.
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import Request
from starlette.responses import RedirectResponse

_log = logging.getLogger("mcp_proxy.admin.approval_hook")


# Stable identifiers used to address actions across the core/plugin boundary.
# Plugins keyed by these strings in their config. Do not rename without a
# coordinated plugin release.
ACTION_POLICIES_SAVE = "policies.save"
ACTION_PKI_ROTATE_CA = "pki.rotate_ca"
ACTION_MASTIO_KEY_ROTATE = "mastio_key.rotate"
ACTION_VAULT_MIGRATE_KEYS = "vault.migrate_keys"
ACTION_USERS_DELETE = "users.delete"
ACTION_AGENTS_DELETE = "agents.delete"


async def maybe_intercept_for_approval(
    *,
    session: Any,
    action_type: str,
    payload: dict[str, Any],
) -> RedirectResponse | None:
    """If a plugin gates ``action_type``, submit a pending approval.

    Returns a :class:`RedirectResponse` to the plugin-managed approval
    detail page (the endpoint should return this verbatim). Returns
    ``None`` when no plugin opts in; the caller proceeds with normal
    execution.

    Parameters
    ----------
    session
        Authenticated dashboard session. ``session.role`` is forwarded as
        the submitter identifier for plugin storage and audit. Plugins
        observe richer principal identity via their own session table.
    action_type
        One of the ``ACTION_*`` constants above. Stable identifier across
        the core/plugin boundary.
    payload
        Opaque dict captured from the request body (form or JSON). The
        plugin persists this verbatim and re-plays it when quorum is
        reached.
    """
    # Local import: avoid bootstrapping the plugin registry at module load
    # in tests that monkey-patch it.
    from mcp_proxy.plugins import get_registry

    plugin = get_registry().approval_required_for(action_type)
    if plugin is None:
        return None

    submitter_id = getattr(session, "role", None) or "admin"
    try:
        approval_id = await plugin.submit_approval(
            action_type=action_type,
            payload=payload,
            submitter_id=submitter_id,
        )
    except NotImplementedError:
        _log.error(
            "plugin %s gated %s but did not implement submit_approval; "
            "falling through to direct execution",
            plugin.name, action_type,
        )
        return None
    except Exception as exc:
        _log.exception(
            "plugin %s submit_approval(%s) failed: %s — falling through",
            plugin.name, action_type, exc,
        )
        return None

    _log.info(
        "action %s submitted for approval: id=%s by=%s plugin=%s",
        action_type, approval_id, submitter_id, plugin.name,
    )
    return RedirectResponse(
        url=f"/proxy/admin/approvals/{approval_id}",
        status_code=303,
    )
