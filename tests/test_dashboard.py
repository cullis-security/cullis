"""
Test dashboard — verifies all dashboard pages render and operations work.
Tests cover both admin and org login flows, CSRF protection, security headers,
auth enforcement on all endpoints, and input validation.
"""
import json
import pytest
from httpx import AsyncClient

from app.config import get_settings

pytestmark = pytest.mark.asyncio


def _extract_csrf(cookies: dict) -> str:
    """Extract CSRF token from the signed session cookie.

    httpx stores the Set-Cookie value with Starlette's encoding
    (backslash-escaped special chars, surrounding quotes). We undo
    that encoding before parsing JSON.
    """
    cookie = cookies.get("atn_session", "")
    if not cookie:
        return ""
    # Strip surrounding quotes added by Starlette cookie encoding
    if cookie.startswith('"') and cookie.endswith('"'):
        cookie = cookie[1:-1]
    # Undo backslash/octal escapes (e.g. \\054 -> comma, \\" -> ")
    import codecs
    try:
        cookie = codecs.decode(cookie, "unicode_escape")
    except Exception:
        pass
    if "." not in cookie:
        return ""
    payload_str = cookie.rsplit(".", 1)[0]
    try:
        data = json.loads(payload_str)
        return data.get("csrf_token", "")
    except (json.JSONDecodeError, TypeError):
        return ""


async def _admin_cookies(client: AsyncClient) -> dict:
    """Login as admin and return cookies dict."""
    resp = await client.post("/dashboard/login", data={
        "login_type": "admin", "admin_secret": get_settings().admin_secret,
    }, follow_redirects=False)
    assert resp.status_code == 303
    return dict(resp.cookies)


async def _admin_ctx(client: AsyncClient) -> tuple[dict, str]:
    """Login as admin, return (cookies, csrf_token)."""
    cookies = await _admin_cookies(client)
    return cookies, _extract_csrf(cookies)


async def _org_cookies(client: AsyncClient, org_id: str, org_secret: str) -> dict:
    """Login as org and return cookies dict."""
    resp = await client.post("/dashboard/login", data={
        "login_type": "org", "org_id": org_id, "org_secret": org_secret,
    }, follow_redirects=False)
    assert resp.status_code == 303
    return dict(resp.cookies)


async def _org_ctx(client: AsyncClient, org_id: str, org_secret: str) -> tuple[dict, str]:
    """Login as org, return (cookies, csrf_token)."""
    cookies = await _org_cookies(client, org_id, org_secret)
    return cookies, _extract_csrf(cookies)


# ─────────────────────────────────────────────────────────────────────────────
# Login / Logout
# ─────────────────────────────────────────────────────────────────────────────

async def test_login_page_renders(client: AsyncClient):
    resp = await client.get("/dashboard/login")
    assert resp.status_code == 200
    assert "Admin" in resp.text
    assert "SSO" in resp.text


async def test_unauthenticated_redirects_to_login(client: AsyncClient):
    resp = await client.get("/dashboard", follow_redirects=False)
    assert resp.status_code == 303


async def test_admin_login_success(client: AsyncClient):
    cookies = await _admin_cookies(client)
    assert "atn_session" in cookies


async def test_admin_login_wrong_secret(client: AsyncClient):
    resp = await client.post("/dashboard/login", data={
        "login_type": "admin", "admin_secret": "wrong",
    })
    assert resp.status_code == 200
    assert "Invalid" in resp.text


async def test_logout(client: AsyncClient):
    cookies = await _admin_cookies(client)
    # Logout changed to POST with CSRF (#43)
    csrf = _extract_csrf(cookies)
    resp = await client.post("/dashboard/logout", cookies=cookies, follow_redirects=False,
                             data={"csrf_token": csrf})
    assert resp.status_code == 303


# ─────────────────────────────────────────────────────────────────────────────
# Admin — pages render
# ─────────────────────────────────────────────────────────────────────────────

async def test_overview_renders(client: AsyncClient):
    c = await _admin_cookies(client)
    resp = await client.get("/dashboard", cookies=c)
    assert resp.status_code == 200
    assert "Network Overview" in resp.text


async def test_orgs_page_renders(client: AsyncClient):
    c = await _admin_cookies(client)
    resp = await client.get("/dashboard/orgs", cookies=c)
    assert resp.status_code == 200
    assert "Organizations" in resp.text


async def test_agents_page_renders(client: AsyncClient):
    c = await _admin_cookies(client)
    resp = await client.get("/dashboard/agents", cookies=c)
    assert resp.status_code == 200
    assert "Agents" in resp.text


async def test_sessions_page_renders(client: AsyncClient):
    c = await _admin_cookies(client)
    resp = await client.get("/dashboard/sessions", cookies=c)
    assert resp.status_code == 200


async def test_sessions_filter(client: AsyncClient):
    c = await _admin_cookies(client)
    resp = await client.get("/dashboard/sessions?status=active", cookies=c)
    assert resp.status_code == 200


async def test_audit_page_renders(client: AsyncClient):
    c = await _admin_cookies(client)
    resp = await client.get("/dashboard/audit", cookies=c)
    assert resp.status_code == 200
    assert "Audit Log" in resp.text


async def test_audit_filter(client: AsyncClient):
    c = await _admin_cookies(client)
    resp = await client.get("/dashboard/audit?q=auth", cookies=c)
    assert resp.status_code == 200


# ─────────────────────────────────────────────────────────────────────────────
# Admin — onboard org
# ─────────────────────────────────────────────────────────────────────────────

async def test_onboard_form_renders(client: AsyncClient):
    c = await _admin_cookies(client)
    resp = await client.get("/dashboard/orgs/onboard", cookies=c)
    assert resp.status_code == 200
    assert "Onboard New Organization" in resp.text


async def test_onboard_org_and_approve(client: AsyncClient):
    from tests.cert_factory import get_org_ca_pem
    c, csrf = await _admin_ctx(client)
    ca_pem = get_org_ca_pem("dash-onboard-org")
    resp = await client.post("/dashboard/orgs/onboard", data={
        "csrf_token": csrf,
        "org_id": "dash-onboard-org", "display_name": "Dashboard Onboard Test",
        "secret": "test-secret", "contact_email": "test@example.com",
        "webhook_url": "", "ca_certificate": ca_pem, "action": "approve",
    }, cookies=c)
    assert resp.status_code == 200
    assert "registered and approved" in resp.text


async def test_onboard_then_approve_button(client: AsyncClient):
    from tests.cert_factory import get_org_ca_pem
    c, csrf = await _admin_ctx(client)
    ca_pem = get_org_ca_pem("dash-pending-org")
    await client.post("/dashboard/orgs/onboard", data={
        "csrf_token": csrf,
        "org_id": "dash-pending-org", "display_name": "Pending Org",
        "secret": "test-secret", "contact_email": "", "webhook_url": "",
        "ca_certificate": ca_pem, "action": "pending",
    }, cookies=c)
    resp = await client.post("/dashboard/orgs/dash-pending-org/approve",
                             data={"csrf_token": csrf},
                             cookies=c, follow_redirects=False)
    assert resp.status_code == 303


async def test_onboard_duplicate_rejected(client: AsyncClient):
    from tests.cert_factory import get_org_ca_pem
    c, csrf = await _admin_ctx(client)
    ca_pem = get_org_ca_pem("dash-dup-org")
    await client.post("/dashboard/orgs/onboard", data={
        "csrf_token": csrf,
        "org_id": "dash-dup-org", "display_name": "Dup", "secret": "s",
        "contact_email": "", "webhook_url": "", "ca_certificate": ca_pem, "action": "approve",
    }, cookies=c)
    resp = await client.post("/dashboard/orgs/onboard", data={
        "csrf_token": csrf,
        "org_id": "dash-dup-org", "display_name": "Dup2", "secret": "s",
        "contact_email": "", "webhook_url": "", "ca_certificate": ca_pem, "action": "approve",
    }, cookies=c)
    assert resp.status_code == 200
    assert "already exists" in resp.text


# ─────────────────────────────────────────────────────────────────────────────
# Admin — register agent
# ─────────────────────────────────────────────────────────────────────────────

async def test_register_agent_form_renders(client: AsyncClient):
    c = await _admin_cookies(client)
    resp = await client.get("/dashboard/agents/register", cookies=c)
    assert resp.status_code == 200
    assert "Register New Agent" in resp.text


async def test_register_agent_via_dashboard(client: AsyncClient):
    from tests.cert_factory import get_org_ca_pem
    c, csrf = await _admin_ctx(client)
    # Create org first
    ca_pem = get_org_ca_pem("dash-agent-org")
    await client.post("/dashboard/orgs/onboard", data={
        "csrf_token": csrf,
        "org_id": "dash-agent-org", "display_name": "Agent Org", "secret": "secret",
        "contact_email": "", "webhook_url": "", "ca_certificate": ca_pem, "action": "approve",
    }, cookies=c)
    # Register agent
    resp = await client.post("/dashboard/agents/register", data={
        "csrf_token": csrf,
        "org_id": "dash-agent-org", "agent_name": "test-agent",
        "display_name": "Test Agent", "capabilities": "order.read, order.write",
    }, cookies=c)
    assert resp.status_code == 200
    assert "registered" in resp.text.lower()


# ─────────────────────────────────────────────────────────────────────────────
# Org login — scoped view
# ─────────────────────────────────────────────────────────────────────────────

async def test_org_login_and_scoped_view(client: AsyncClient):
    """Org user sees only their own agents, not other orgs."""
    from tests.cert_factory import get_org_ca_pem
    admin_c, admin_csrf = await _admin_ctx(client)

    # Create two orgs via admin
    for org_id in ("scope-org-a", "scope-org-b"):
        ca_pem = get_org_ca_pem(org_id)
        await client.post("/dashboard/orgs/onboard", data={
            "csrf_token": admin_csrf,
            "org_id": org_id, "display_name": org_id, "secret": f"{org_id}-secret",
            "contact_email": "", "webhook_url": "", "ca_certificate": ca_pem, "action": "approve",
        }, cookies=admin_c)
        await client.post("/dashboard/agents/register", data={
            "csrf_token": admin_csrf,
            "org_id": org_id, "agent_name": "agent",
            "display_name": f"Agent of {org_id}", "capabilities": "test.read",
        }, cookies=admin_c)

    # Login as org A
    org_c = await _org_cookies(client, "scope-org-a", "scope-org-a-secret")

    # Overview works
    resp = await client.get("/dashboard", cookies=org_c)
    assert resp.status_code == 200

    # Agents page — should see only org-a's agent
    resp = await client.get("/dashboard/agents", cookies=org_c)
    assert resp.status_code == 200
    assert "scope-org-a::agent" in resp.text
    assert "scope-org-b::agent" not in resp.text

    # Orgs page — admin only, org user gets redirected
    resp = await client.get("/dashboard/orgs", cookies=org_c, follow_redirects=False)
    assert resp.status_code == 303


async def test_org_cannot_onboard(client: AsyncClient):
    """Org user cannot access the onboard form — admin only."""
    from tests.cert_factory import get_org_ca_pem
    admin_c, admin_csrf = await _admin_ctx(client)
    ca_pem = get_org_ca_pem("cant-onboard-org")
    await client.post("/dashboard/orgs/onboard", data={
        "csrf_token": admin_csrf,
        "org_id": "cant-onboard-org", "display_name": "X", "secret": "secret",
        "contact_email": "", "webhook_url": "", "ca_certificate": ca_pem, "action": "approve",
    }, cookies=admin_c)

    org_c = await _org_cookies(client, "cant-onboard-org", "secret")
    resp = await client.get("/dashboard/orgs/onboard", cookies=org_c, follow_redirects=False)
    assert resp.status_code == 303  # redirected — not admin


# ─────────────────────────────────────────────────────────────────────────────
# Security — CSRF protection
# ─────────────────────────────────────────────────────────────────────────────

async def test_csrf_missing_token_rejected(client: AsyncClient):
    """POST without CSRF token is rejected."""
    from tests.cert_factory import get_org_ca_pem
    c = await _admin_cookies(client)
    ca_pem = get_org_ca_pem("csrf-test-org")
    resp = await client.post("/dashboard/orgs/onboard", data={
        "org_id": "csrf-test-org", "display_name": "CSRF Test",
        "secret": "s", "contact_email": "", "webhook_url": "",
        "ca_certificate": ca_pem, "action": "approve",
    }, cookies=c)
    assert resp.status_code == 403
    assert "CSRF" in resp.text


async def test_csrf_wrong_token_rejected(client: AsyncClient):
    """POST with wrong CSRF token is rejected."""
    from tests.cert_factory import get_org_ca_pem
    c = await _admin_cookies(client)
    ca_pem = get_org_ca_pem("csrf-wrong-org")
    resp = await client.post("/dashboard/orgs/onboard", data={
        "csrf_token": "totally-wrong-token",
        "org_id": "csrf-wrong-org", "display_name": "CSRF Wrong",
        "secret": "s", "contact_email": "", "webhook_url": "",
        "ca_certificate": ca_pem, "action": "approve",
    }, cookies=c)
    assert resp.status_code == 403
    assert "CSRF" in resp.text


async def test_csrf_valid_token_accepted(client: AsyncClient):
    """POST with correct CSRF token is accepted."""
    from tests.cert_factory import get_org_ca_pem
    c, csrf = await _admin_ctx(client)
    ca_pem = get_org_ca_pem("csrf-valid-org")
    resp = await client.post("/dashboard/orgs/onboard", data={
        "csrf_token": csrf,
        "org_id": "csrf-valid-org", "display_name": "CSRF Valid",
        "secret": "s", "contact_email": "", "webhook_url": "",
        "ca_certificate": ca_pem, "action": "approve",
    }, cookies=c)
    assert resp.status_code == 200
    assert "registered and approved" in resp.text


async def test_csrf_agent_register_rejected_without_token(client: AsyncClient):
    """Agent register POST without CSRF token is rejected."""
    c = await _admin_cookies(client)
    resp = await client.post("/dashboard/agents/register", data={
        "org_id": "some-org", "agent_name": "a",
        "display_name": "A", "capabilities": "",
    }, cookies=c)
    assert resp.status_code == 403
    assert "CSRF" in resp.text


# ─────────────────────────────────────────────────────────────────────────────
# Security — auth enforcement on approve/reject/badge
# ─────────────────────────────────────────────────────────────────────────────

async def test_approve_requires_auth(client: AsyncClient):
    """Unauthenticated approve redirects to login."""
    resp = await client.post("/dashboard/orgs/some-org/approve",
                             data={}, follow_redirects=False)
    assert resp.status_code == 303
    assert "/login" in resp.headers.get("location", "")


async def test_reject_requires_auth(client: AsyncClient):
    """Unauthenticated reject redirects to login."""
    resp = await client.post("/dashboard/orgs/some-org/reject",
                             data={}, follow_redirects=False)
    assert resp.status_code == 303
    assert "/login" in resp.headers.get("location", "")


async def test_approve_requires_admin(client: AsyncClient):
    """Org user cannot approve an org."""
    from tests.cert_factory import get_org_ca_pem
    admin_c, csrf = await _admin_ctx(client)
    ca_pem = get_org_ca_pem("approve-auth-org")
    await client.post("/dashboard/orgs/onboard", data={
        "csrf_token": csrf,
        "org_id": "approve-auth-org", "display_name": "X", "secret": "sec",
        "contact_email": "", "webhook_url": "", "ca_certificate": ca_pem, "action": "approve",
    }, cookies=admin_c)
    org_c = await _org_cookies(client, "approve-auth-org", "sec")
    resp = await client.post("/dashboard/orgs/approve-auth-org/approve",
                             data={}, cookies=org_c, follow_redirects=False)
    assert resp.status_code == 303
    assert "/dashboard" in resp.headers.get("location", "")


async def test_badge_pending_orgs_requires_admin(client: AsyncClient):
    """Badge endpoint returns empty for unauthenticated users."""
    resp = await client.get("/dashboard/badge/pending-orgs")
    assert resp.status_code == 200
    assert resp.text == ""


async def test_badge_pending_sessions_requires_auth(client: AsyncClient):
    """Badge endpoint returns empty for unauthenticated users."""
    resp = await client.get("/dashboard/badge/pending-sessions")
    assert resp.status_code == 200
    assert resp.text == ""


# ─────────────────────────────────────────────────────────────────────────────
# Security — security headers
# ─────────────────────────────────────────────────────────────────────────────

async def test_security_headers_on_dashboard(client: AsyncClient):
    """Dashboard pages include security headers."""
    c = await _admin_cookies(client)
    resp = await client.get("/dashboard", cookies=c)
    assert resp.headers.get("x-content-type-options") == "nosniff"
    assert resp.headers.get("x-frame-options") == "DENY"
    assert resp.headers.get("referrer-policy") == "strict-origin-when-cross-origin"
    assert "frame-ancestors 'none'" in resp.headers.get("content-security-policy", "")


async def test_security_headers_on_api(client: AsyncClient):
    """API endpoints get base security headers but not CSP."""
    resp = await client.get("/health")
    assert resp.headers.get("x-content-type-options") == "nosniff"
    assert resp.headers.get("x-frame-options") == "DENY"
    # CSP is only on /dashboard routes
    assert "content-security-policy" not in resp.headers


# ─────────────────────────────────────────────────────────────────────────────
# Security — input validation
# ─────────────────────────────────────────────────────────────────────────────

async def test_invalid_org_id_rejected(client: AsyncClient):
    """Org IDs with special characters are rejected."""
    from tests.cert_factory import get_org_ca_pem
    c, csrf = await _admin_ctx(client)
    ca_pem = get_org_ca_pem("x")
    resp = await client.post("/dashboard/orgs/onboard", data={
        "csrf_token": csrf,
        "org_id": "bad org id!!", "display_name": "X", "secret": "s",
        "contact_email": "", "webhook_url": "", "ca_certificate": ca_pem, "action": "approve",
    }, cookies=c)
    assert resp.status_code == 200
    assert "alphanumeric" in resp.text


async def test_invalid_webhook_url_rejected(client: AsyncClient):
    """Webhook URLs with invalid scheme are rejected."""
    from tests.cert_factory import get_org_ca_pem
    c, csrf = await _admin_ctx(client)
    ca_pem = get_org_ca_pem("x")
    resp = await client.post("/dashboard/orgs/onboard", data={
        "csrf_token": csrf,
        "org_id": "webhook-test-org", "display_name": "X", "secret": "s",
        "contact_email": "", "webhook_url": "ftp://evil.com/pwn",
        "ca_certificate": ca_pem, "action": "approve",
    }, cookies=c)
    assert resp.status_code == 200
    assert "https://" in resp.text or "http://" in resp.text


async def test_invalid_agent_id_rejected(client: AsyncClient):
    """Agent IDs with special characters are rejected."""
    from tests.cert_factory import get_org_ca_pem
    c, csrf = await _admin_ctx(client)
    ca_pem = get_org_ca_pem("valid-id-org")
    await client.post("/dashboard/orgs/onboard", data={
        "csrf_token": csrf,
        "org_id": "valid-id-org", "display_name": "X", "secret": "s",
        "contact_email": "", "webhook_url": "", "ca_certificate": ca_pem, "action": "approve",
    }, cookies=c)
    resp = await client.post("/dashboard/agents/register", data={
        "csrf_token": csrf,
        "org_id": "valid-id-org", "agent_name": "../../../etc/passwd",
        "display_name": "Evil Agent", "capabilities": "",
    }, cookies=c)
    assert resp.status_code == 200
    assert "alphanumeric" in resp.text


async def test_invalid_capability_rejected(client: AsyncClient):
    """Capabilities with special characters are rejected."""
    from tests.cert_factory import get_org_ca_pem
    c, csrf = await _admin_ctx(client)
    ca_pem = get_org_ca_pem("cap-test-org")
    await client.post("/dashboard/orgs/onboard", data={
        "csrf_token": csrf,
        "org_id": "cap-test-org", "display_name": "X", "secret": "s",
        "contact_email": "", "webhook_url": "", "ca_certificate": ca_pem, "action": "approve",
    }, cookies=c)
    resp = await client.post("/dashboard/agents/register", data={
        "csrf_token": csrf,
        "org_id": "cap-test-org", "agent_name": "agent",
        "display_name": "Agent", "capabilities": "<script>alert(1)</script>",
    }, cookies=c)
    assert resp.status_code == 200
    assert "Invalid capability" in resp.text
