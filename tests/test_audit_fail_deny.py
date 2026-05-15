"""H3 P0.3 — audit-fail-deny configurable mode.

When ``log_audit`` exhausts its IntegrityError retry budget (or any
other persistence path fails), the proxy must either:

- raise so the calling request surfaces 5xx (default,
  ``MCP_PROXY_AUDIT_FAIL_DENY=true``), or
- log critical and swallow (opt-out,
  ``MCP_PROXY_AUDIT_FAIL_DENY=false``) for operators who run an
  external audit sink and prefer availability over local-audit
  completeness.

Closes the gap surfaced by the 2026-05-15 threat-model verification
pass: the MCP-proxy Repudiation row claimed the behaviour is
configurable; this was aspirational until this commit.
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient


@pytest_asyncio.fixture
async def proxy_app(tmp_path, monkeypatch):
    db_file = tmp_path / "audit_fail_deny.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "cullis.local")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    from mcp_proxy.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as _:
        async with app.router.lifespan_context(app):
            yield app
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_log_audit_raises_when_retry_budget_exhausted_default(
    proxy_app, monkeypatch,
):
    """Default behaviour: chain-seq exhaustion → RuntimeError."""
    from mcp_proxy import db as proxy_db

    # Force every INSERT to look like a chain_seq collision; the retry
    # loop will exhaust its budget on the first call. The default
    # MCP_PROXY_AUDIT_FAIL_DENY value (true) must surface the failure
    # as RuntimeError.
    monkeypatch.setattr(proxy_db, "_AUDIT_CHAIN_MAX_RETRIES", 1)

    from sqlalchemy.exc import IntegrityError

    class _AlwaysCollideConn:
        async def execute(self, *_args, **_kwargs):
            raise IntegrityError("stmt", {}, Exception("UNIQUE"))

    class _AlwaysCollideCtx:
        async def __aenter__(self):
            return _AlwaysCollideConn()
        async def __aexit__(self, *exc):
            return False

    async def _head(_conn):
        return 0, ""

    monkeypatch.setattr(proxy_db, "get_db", lambda: _AlwaysCollideCtx())
    monkeypatch.setattr(proxy_db, "_audit_chain_head", _head)

    with pytest.raises(RuntimeError, match="chain_seq UNIQUE"):
        await proxy_db.log_audit(
            agent_id="alice", action="t.invoke", status="ok",
            tool_name="echo", detail="d",
        )


@pytest.mark.asyncio
async def test_log_audit_swallows_when_fail_deny_disabled(
    proxy_app, monkeypatch,
):
    """Opt-out: chain-seq exhaustion → log + swallow, no exception."""
    from mcp_proxy import db as proxy_db
    from mcp_proxy.config import get_settings

    # Flip the gate via the cached Settings instance (same as setting
    # MCP_PROXY_AUDIT_FAIL_DENY=false would do at boot).
    settings = get_settings()
    monkeypatch.setattr(settings, "audit_fail_deny", False)

    monkeypatch.setattr(proxy_db, "_AUDIT_CHAIN_MAX_RETRIES", 1)

    from sqlalchemy.exc import IntegrityError

    class _AlwaysCollideConn:
        async def execute(self, *_args, **_kwargs):
            raise IntegrityError("stmt", {}, Exception("UNIQUE"))

    class _AlwaysCollideCtx:
        async def __aenter__(self):
            return _AlwaysCollideConn()
        async def __aexit__(self, *exc):
            return False

    async def _head(_conn):
        return 0, ""

    monkeypatch.setattr(proxy_db, "get_db", lambda: _AlwaysCollideCtx())
    monkeypatch.setattr(proxy_db, "_audit_chain_head", _head)

    # The mcp_proxy logger has propagate=False so caplog won't capture
    # its records (project-wide pattern). Monkeypatch _log.critical
    # instead to record the calls.
    critical_calls: list[tuple] = []
    monkeypatch.setattr(
        proxy_db._log,
        "critical",
        lambda *a, **kw: critical_calls.append((a, kw)),
    )

    # Must NOT raise.
    await proxy_db.log_audit(
        agent_id="alice", action="t.invoke", status="ok",
        tool_name="echo", detail="d",
    )

    # And the critical log line must carry the gate label so an
    # operator scanning for "AUDIT_FAIL_DENY=false" finds it.
    rendered = [a[0] % a[1:] if len(a) > 1 else a[0] for a, _ in critical_calls]
    assert any(
        "AUDIT_FAIL_DENY=false" in line for line in rendered
    ), f"expected a CRITICAL line naming the disabled gate, got: {rendered!r}"


def test_settings_default_audit_fail_deny_is_true():
    """The shipping default must be the production-correct stance."""
    from mcp_proxy.config import ProxySettings

    s = ProxySettings()
    assert s.audit_fail_deny is True
