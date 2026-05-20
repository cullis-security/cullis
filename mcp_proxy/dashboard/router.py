"""
MCP Proxy Dashboard - admin control plane for managing agents, tools, and policies.

The dashboard surface is decomposed into per-feature sub-routers under
``mcp_proxy/dashboard/*_routes.py``. This module is now a thin aggregator
that declares the ``/proxy`` prefix and wires the sub-routers via
``include_router`` (sprint F-B-201).

Sub-routers (mounted via ``include_router``):

  auth_routes          /proxy/login, /proxy/logout, /proxy/register   (PR-2)
  setup_routes         /proxy/setup wizard                            (PR-3)
  agents_routes        /proxy/agents + per-agent management           (PR-4)
  tools_network_routes /proxy/tools + /proxy/network                  (PR-5)
  policies_routes      /proxy/policies + PDP probe                    (PR-6)
  audit_routes         /proxy/audit unified log viewer                (PR-7)
  pki_routes           /proxy/pki overview + export + rotate          (PR-8)
  vault_routes         /proxy/vault connection management             (PR-9)
  oidc_routes          /proxy/oidc/start + /proxy/oidc/callback       (PR-9)
  core_routes          /proxy/, /proxy/org-status, /proxy/overview,
                       /proxy/settings/org/display-name x3            (PR-13)
  settings_routes      /proxy/settings + password rotate + license    (PR-13)
  api_status_routes    /proxy/api/update-status x2 + version-status   (PR-13)

Routes still inline in this module are the mastio-key rotation surface,
the enrollment review surface, the HTMX badge fragments, and the users
control plane. Those are scheduled to migrate into their own sub-routers
in follow-up PRs of this sprint.
"""
import logging
import pathlib

import httpx

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from starlette.responses import RedirectResponse

from mcp_proxy.dashboard.session import (
    get_session,
    require_login,
    verify_csrf,
)
from mcp_proxy.admin.approval_hook import (
    maybe_intercept_for_approval,
)

_log = logging.getLogger("mcp_proxy.dashboard")

_TEMPLATE_DIR = pathlib.Path(__file__).parent / "templates"

# Re-exports for backward compat with existing test imports + the e2e
# bootstrap script: ``_parse_device_info`` (tests/test_proxy_device_info.py),
# ``_enforce_safe_outbound_url`` (tests/test_wave_b_pr1_dashboard_security.py),
# and ``generate_org_ca`` (tests/e2e/scripts/setup_proxy_org.py) used to
# live in this module; keep them re-exportable until those callers move.
from mcp_proxy.dashboard._template_env import (  # noqa: E402, F401
    _parse_device_info,
    build_templates,
)
# F-B-201 PR-1: pure helpers extracted to a sibling module so upcoming
# per-feature sub-routers can import them without dragging the
# 5000-LOC router.py. Mirrors the Court sibling _helpers.py (F-B-202).
from mcp_proxy.dashboard._helpers import (  # noqa: E402, F401
    _ctx,
    _enforce_safe_outbound_url,
    _login_client_ip,
    _post_login_redirect,
    generate_org_ca,
)
templates = build_templates(_TEMPLATE_DIR)

router = APIRouter(prefix="/proxy", tags=["dashboard"])

# F-B-201 PR-2: include the auth sub-router (login / logout / register).
# Routes inside auth_routes.py declare paths relative to /proxy so the
# outer router's prefix is inherited via include_router. Mirrors the
# Court PR-2 pattern (#841).
from mcp_proxy.dashboard import auth_routes as _auth_routes  # noqa: E402
router.include_router(_auth_routes.router)

# F-B-201 PR-3: include the setup sub-router (broker uplink wizard).
from mcp_proxy.dashboard import setup_routes as _setup_routes  # noqa: E402
router.include_router(_setup_routes.router)

# F-B-201 PR-4: include the agents sub-router (list + per-agent management).
from mcp_proxy.dashboard import agents_routes as _agents_routes  # noqa: E402
router.include_router(_agents_routes.router)

# F-B-201 PR-5: include the tools + network sub-router.
from mcp_proxy.dashboard import tools_network_routes as _tools_network_routes  # noqa: E402
router.include_router(_tools_network_routes.router)

# F-B-201 PR-6: include the policies sub-router (rules + PDP + webhook probe).
from mcp_proxy.dashboard import policies_routes as _policies_routes  # noqa: E402
router.include_router(_policies_routes.router)

# F-B-201 PR-7: include the audit sub-router (admin + traffic stream viewer).
from mcp_proxy.dashboard import audit_routes as _audit_routes  # noqa: E402
router.include_router(_audit_routes.router)

# F-B-201 PR-8: include the pki sub-router (CA overview + export + rotate).
from mcp_proxy.dashboard import pki_routes as _pki_routes  # noqa: E402
router.include_router(_pki_routes.router)

# F-B-201 PR-9: include the vault + oidc sub-routers.
from mcp_proxy.dashboard import vault_routes as _vault_routes  # noqa: E402
router.include_router(_vault_routes.router)
from mcp_proxy.dashboard import oidc_routes as _oidc_routes  # noqa: E402
router.include_router(_oidc_routes.router)

# F-B-201 PR-10: include the mastio-key sub-router (rotation lifecycle).
from mcp_proxy.dashboard import mastio_key_routes as _mastio_key_routes  # noqa: E402
router.include_router(_mastio_key_routes.router)

# F-B-201 PR-11: include the users sub-router (multi-user admin lifecycle).
from mcp_proxy.dashboard import users_routes as _users_routes  # noqa: E402
router.include_router(_users_routes.router)

# F-B-201 PR-12: include the enrollments sub-router (admin review queue
# for pending Connector enrollment requests).
from mcp_proxy.dashboard import enrollments_routes as _enrollments_routes  # noqa: E402
router.include_router(_enrollments_routes.router)

# F-B-201 PR-12: include the badges sub-router (sidebar HTMX status
# indicators for agents / enrollments / users / approvals / audit /
# updates / version).
from mcp_proxy.dashboard import badges_routes as _badges_routes  # noqa: E402
router.include_router(_badges_routes.router)

# F-B-201 PR-13 (sprint closer): include the core + settings + api-status
# sub-routers. These cover the smart entry point, org-status banner,
# display-name partials, overview landing, OIDC settings + password +
# license rotation, and the update-advisory HTMX/JSON endpoints. The
# parent router.py is now a thin aggregator: prefix declaration plus
# include_router calls (PR-2..PR-13).
from mcp_proxy.dashboard import core_routes as _core_routes  # noqa: E402
router.include_router(_core_routes.router)
from mcp_proxy.dashboard import settings_routes as _settings_routes  # noqa: E402
router.include_router(_settings_routes.router)
from mcp_proxy.dashboard import api_status_routes as _api_status_routes  # noqa: E402
router.include_router(_api_status_routes.router)


# Helpers (_ctx, _enforce_safe_outbound_url, _login_client_ip,
# _post_login_redirect, _load_display_name, generate_org_ca,
# _test_vault_connectivity, _store_ca_key_in_vault) live in
# ``mcp_proxy/dashboard/_helpers.py`` since F-B-201 PR-1 / PR-2 / PR-3.


# Routes already extracted into per-feature sub-routers:
#   PR-2 auth (login / logout / register)        -> auth_routes.py
#   PR-3 setup wizard                            -> setup_routes.py
#   PR-4 agents surface                          -> agents_routes.py
#   PR-5 tools + network                         -> tools_network_routes.py
#   PR-6 policies                                -> policies_routes.py
#   PR-7 audit                                   -> audit_routes.py
#   PR-8 pki                                     -> pki_routes.py
#   PR-9 vault + oidc                            -> vault_routes.py + oidc_routes.py
#   PR-13 core (/, /org-status, /overview,
#         /settings/org/display-name x3)         -> core_routes.py
#   PR-13 settings (OIDC + password + license)   -> settings_routes.py
#   PR-13 api status (/api/update-status x2,
#         /api/version-status)                   -> api_status_routes.py


# Mastio Key rotation (/proxy/mastio-key + /mastio-key/grace-days + /mastio-key/rotate +
# /mastio-key/complete-staged) moved to ``mcp_proxy/dashboard/mastio_key_routes.py``
# since F-B-201 PR-10.


# Vault (/proxy/vault + /proxy/vault/save + /proxy/vault/test +
# /proxy/vault/migrate-keys) moved to
# ``mcp_proxy/dashboard/vault_routes.py`` since F-B-201 PR-9.


# Connector enrollments (/proxy/enrollments + approve + reject) moved to
# ``mcp_proxy/dashboard/enrollments_routes.py`` since F-B-201 PR-12.


# HTMX badge fragments for agents / enrollments / users / approvals /
# audit / updates / version moved to
# ``mcp_proxy/dashboard/badges_routes.py`` since F-B-201 PR-13.


# Users management (/proxy/users + lifecycle endpoints) moved to ``mcp_proxy/dashboard/users_routes.py`` since F-B-201 PR-11.


# API update-status (/api/update-status GET + dismiss POST) moved to
# ``mcp_proxy/dashboard/api_status_routes.py`` since F-B-201 PR-13.


# /badge/audit, /badge/updates and /badge/version moved to
# ``mcp_proxy/dashboard/badges_routes.py`` since F-B-201 PR-13.


# ─────────────────────────────────────────────────────────────────────────────
# Update advisory — banner + JSON polled by the dashboard frame.
# The container can't auto-replace itself (no docker.sock), so we
# advise + show the operator the exact ``./deploy.sh --upgrade <ver>``
# they should run on the host.
# ─────────────────────────────────────────────────────────────────────────────

# API version-status (/api/version-status) moved to
# ``mcp_proxy/dashboard/api_status_routes.py`` since F-B-201 PR-13.


# Overview (/proxy/overview) moved to
# ``mcp_proxy/dashboard/core_routes.py`` since F-B-201 PR-13.
#
# /badge/version moved to
# ``mcp_proxy/dashboard/badges_routes.py`` since F-B-201 PR-12.


# Settings (OIDC config GET + POST, /settings/local-password,
# /settings/admin-password/change, /settings/license) moved to
# ``mcp_proxy/dashboard/settings_routes.py`` since F-B-201 PR-13.


# OIDC handshake (/proxy/oidc/start + /proxy/oidc/callback) moved to
# ``mcp_proxy/dashboard/oidc_routes.py`` since F-B-201 PR-9.
# OIDC primitives (state, JWKS, token exchange) still live in the
# sibling ``mcp_proxy/dashboard/oidc.py`` module.


# _load_display_name moved to ``mcp_proxy/dashboard/_helpers.py``
# since F-B-201 PR-2.


# ─────────────────────────────────────────────────────────────────────────────
# Federated-agents partial (accordion expansion) — REMOVED.
# The ``/proxy/agents`` accordion that consumed this partial was
# deleted in the reach-UX refactor (PR #224). Peer-org discovery
# now lives on ``/proxy/network``. The helper ``_federated_agents_rows``
# template was removed alongside.
# ─────────────────────────────────────────────────────────────────────────────
