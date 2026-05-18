"""Tests for the cert_expiry_watcher daemon (Wave 2 fix 5).

Strategy
--------

Each tier (Org Root, Intermediate fallback, Mastio leaf, agent leaves,
nginx server) is driven independently via the ``_check_*`` helpers
exposed on :mod:`mcp_proxy.lifespan.cert_expiry_watcher`. Stub
``AgentManager`` carries the right cached cert object so the watcher
follows the production path without spinning up the full lifespan.

Audit rows are intercepted by monkeypatching ``mcp_proxy.db.log_audit``
to a list-append capture so each test asserts both the log + the
audit side-effect.

Clock skew is simulated by minting certs whose ``not_valid_after`` is
``now + N days`` for a chosen N — no need to mock ``datetime.now``,
the watcher derives ``now`` from the system clock at tick time.
"""
from __future__ import annotations

import asyncio
import datetime
from dataclasses import dataclass
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

import mcp_proxy.lifespan.cert_expiry_watcher as watcher_mod

pytestmark = pytest.mark.xdist_group(name="serial_cert_expiry_watcher")


# ─── helpers ───────────────────────────────────────────────────────────


def _mint_cert(cn: str, *, days_until_expiry: int) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """Mint a self-signed EC P-256 cert whose ``not_valid_after`` is
    ``now + days_until_expiry`` days from the current clock.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=days_until_expiry))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _cert_pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


@dataclass
class _StubMastioKey:
    kid: str
    cert_pem: str | None


class _StubAgentManager:
    """Minimal duck-typed agent manager: cached cert pointers only."""

    def __init__(
        self,
        *,
        org_ca_cert: x509.Certificate | None = None,
        mastio_ca_cert: x509.Certificate | None = None,
        active_key: _StubMastioKey | None = None,
    ) -> None:
        self._org_ca_cert = org_ca_cert
        self._mastio_ca_cert = mastio_ca_cert
        self._active_key = active_key


class _StubSettings:
    def __init__(self, **kwargs) -> None:
        self.nginx_cert_dir = kwargs.pop("nginx_cert_dir", "")
        for k, v in kwargs.items():
            setattr(self, k, v)


@pytest.fixture
def captured_audit(monkeypatch):
    """Capture every ``log_audit`` call as a list of kwargs dicts."""
    rows: list[dict] = []

    async def _capture(**kwargs):
        rows.append(kwargs)

    # Patch the module attribute that the watcher imports lazily.
    import mcp_proxy.db as db_mod
    monkeypatch.setattr(db_mod, "log_audit", _capture)
    return rows


@pytest.fixture
def captured_list_agents(monkeypatch):
    """Make ``list_agents`` return whatever the test assigns to .rows."""
    state = {"rows": []}

    async def _list_agents():
        return list(state["rows"])

    import mcp_proxy.db as db_mod
    monkeypatch.setattr(db_mod, "list_agents", _list_agents)
    return state


# ─── _check_org_root ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_org_root_above_threshold_is_silent(captured_audit, caplog):
    _, cert = _mint_cert("test-org-root", days_until_expiry=3000)
    mgr = _StubAgentManager(org_ca_cert=cert)
    now = datetime.datetime.now(datetime.timezone.utc)

    caplog.set_level("WARNING", logger="mcp_proxy.lifespan.cert_expiry_watcher")
    await watcher_mod._check_org_root(mgr, now, threshold_days=1825)

    assert captured_audit == []
    assert "Org Root" not in caplog.text


@pytest.mark.asyncio
async def test_org_root_below_threshold_warns_and_audits(captured_audit, caplog):
    _, cert = _mint_cert("test-org-root", days_until_expiry=100)
    mgr = _StubAgentManager(org_ca_cert=cert)
    now = datetime.datetime.now(datetime.timezone.utc)

    caplog.set_level("WARNING", logger="mcp_proxy.lifespan.cert_expiry_watcher")
    await watcher_mod._check_org_root(mgr, now, threshold_days=1825)

    assert any(r["action"] == "pki.org_root_expiry_warning" for r in captured_audit)
    assert "Org Root CA expires in" in caplog.text


@pytest.mark.asyncio
async def test_org_root_missing_cert_is_noop(captured_audit):
    mgr = _StubAgentManager(org_ca_cert=None)
    now = datetime.datetime.now(datetime.timezone.utc)

    await watcher_mod._check_org_root(mgr, now, threshold_days=1825)

    assert captured_audit == []


# ─── _check_intermediate (fallback) ────────────────────────────────────


@pytest.mark.asyncio
async def test_intermediate_fallback_below_threshold_emits_info(
    captured_audit, caplog,
):
    _, cert = _mint_cert("test-intermediate", days_until_expiry=400)
    mgr = _StubAgentManager(mastio_ca_cert=cert)
    now = datetime.datetime.now(datetime.timezone.utc)

    caplog.set_level("INFO", logger="mcp_proxy.lifespan.cert_expiry_watcher")
    await watcher_mod._check_intermediate(mgr, now, threshold_days=730)

    assert any(
        r["action"] == "pki.intermediate_ca_expiry_visibility"
        for r in captured_audit
    )
    assert "Intermediate CA expires in" in caplog.text


@pytest.mark.asyncio
async def test_intermediate_fallback_above_threshold_is_silent(
    captured_audit, caplog,
):
    _, cert = _mint_cert("test-intermediate", days_until_expiry=1500)
    mgr = _StubAgentManager(mastio_ca_cert=cert)
    now = datetime.datetime.now(datetime.timezone.utc)

    caplog.set_level("INFO", logger="mcp_proxy.lifespan.cert_expiry_watcher")
    await watcher_mod._check_intermediate(mgr, now, threshold_days=730)

    assert captured_audit == []


# ─── _check_mastio_leaf ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_mastio_leaf_below_threshold_warns(captured_audit, caplog):
    _, cert = _mint_cert("test-mastio-leaf", days_until_expiry=30)
    active = _StubMastioKey(kid="mastio-deadbeef", cert_pem=_cert_pem(cert))
    mgr = _StubAgentManager(active_key=active)
    now = datetime.datetime.now(datetime.timezone.utc)

    caplog.set_level("WARNING", logger="mcp_proxy.lifespan.cert_expiry_watcher")
    await watcher_mod._check_mastio_leaf(mgr, now, threshold_days=90)

    matching = [r for r in captured_audit if r["action"] == "pki.mastio_leaf_expiry_warning"]
    assert len(matching) == 1
    assert "mastio-deadbeef" in matching[0]["detail"]


@pytest.mark.asyncio
async def test_mastio_leaf_above_threshold_is_silent(captured_audit):
    _, cert = _mint_cert("test-mastio-leaf", days_until_expiry=200)
    active = _StubMastioKey(kid="mastio-cafefade", cert_pem=_cert_pem(cert))
    mgr = _StubAgentManager(active_key=active)
    now = datetime.datetime.now(datetime.timezone.utc)

    await watcher_mod._check_mastio_leaf(mgr, now, threshold_days=90)

    assert captured_audit == []


@pytest.mark.asyncio
async def test_mastio_leaf_missing_active_key_is_noop(captured_audit):
    mgr = _StubAgentManager(active_key=None)
    now = datetime.datetime.now(datetime.timezone.utc)

    await watcher_mod._check_mastio_leaf(mgr, now, threshold_days=90)

    assert captured_audit == []


@pytest.mark.asyncio
async def test_mastio_leaf_malformed_pem_is_skipped(captured_audit, caplog):
    active = _StubMastioKey(kid="mastio-malformed", cert_pem="not a cert")
    mgr = _StubAgentManager(active_key=active)
    now = datetime.datetime.now(datetime.timezone.utc)

    caplog.set_level("WARNING", logger="mcp_proxy.lifespan.cert_expiry_watcher")
    await watcher_mod._check_mastio_leaf(mgr, now, threshold_days=90)

    assert captured_audit == []
    assert "mastio leaf cert parse failed" in caplog.text


# ─── _check_agent_leaves ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_agent_leaves_per_agent_audit_uses_agent_id(
    captured_audit, captured_list_agents, caplog,
):
    _, cert_a = _mint_cert("agent-a", days_until_expiry=45)
    _, cert_b = _mint_cert("agent-b", days_until_expiry=200)
    captured_list_agents["rows"] = [
        {"agent_id": "agent-a", "cert_pem": _cert_pem(cert_a)},
        {"agent_id": "agent-b", "cert_pem": _cert_pem(cert_b)},
    ]
    now = datetime.datetime.now(datetime.timezone.utc)

    caplog.set_level("WARNING", logger="mcp_proxy.lifespan.cert_expiry_watcher")
    await watcher_mod._check_agent_leaves(now, threshold_days=90)

    matching = [r for r in captured_audit if r["action"] == "pki.agent_cert_expiry_warning"]
    assert len(matching) == 1
    assert matching[0]["agent_id"] == "agent-a"
    # The other agent is still in the safe window: no row.
    assert all(r["agent_id"] != "agent-b" for r in matching)


@pytest.mark.asyncio
async def test_agent_leaves_missing_cert_pem_is_skipped(
    captured_audit, captured_list_agents,
):
    captured_list_agents["rows"] = [
        {"agent_id": "agent-headless", "cert_pem": None},
        {"agent_id": "agent-empty", "cert_pem": ""},
    ]
    now = datetime.datetime.now(datetime.timezone.utc)

    await watcher_mod._check_agent_leaves(now, threshold_days=90)

    assert captured_audit == []


@pytest.mark.asyncio
async def test_agent_leaves_malformed_cert_is_logged_but_does_not_break_loop(
    captured_audit, captured_list_agents, caplog,
):
    _, cert_ok = _mint_cert("agent-ok", days_until_expiry=10)
    captured_list_agents["rows"] = [
        {"agent_id": "agent-broken", "cert_pem": "not a pem"},
        {"agent_id": "agent-ok", "cert_pem": _cert_pem(cert_ok)},
    ]
    now = datetime.datetime.now(datetime.timezone.utc)

    caplog.set_level("WARNING", logger="mcp_proxy.lifespan.cert_expiry_watcher")
    await watcher_mod._check_agent_leaves(now, threshold_days=90)

    assert "agent-broken cert parse failed" in caplog.text
    matching = [r for r in captured_audit if r["action"] == "pki.agent_cert_expiry_warning"]
    assert len(matching) == 1
    assert matching[0]["agent_id"] == "agent-ok"


# ─── _check_nginx_server ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_nginx_server_below_threshold_warns(captured_audit, tmp_path, caplog):
    _, cert = _mint_cert("mastio.local", days_until_expiry=20)
    crt_path = tmp_path / "mastio-server.crt"
    crt_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    settings = _StubSettings(nginx_cert_dir=str(tmp_path))
    now = datetime.datetime.now(datetime.timezone.utc)

    caplog.set_level("WARNING", logger="mcp_proxy.lifespan.cert_expiry_watcher")
    await watcher_mod._check_nginx_server(settings, now, threshold_days=30)

    matching = [r for r in captured_audit if r["action"] == "pki.nginx_server_cert_expiry_warning"]
    assert len(matching) == 1
    assert str(crt_path) in matching[0]["detail"]


@pytest.mark.asyncio
async def test_nginx_server_above_threshold_is_silent(captured_audit, tmp_path):
    _, cert = _mint_cert("mastio.local", days_until_expiry=60)
    crt_path = tmp_path / "mastio-server.crt"
    crt_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    settings = _StubSettings(nginx_cert_dir=str(tmp_path))
    now = datetime.datetime.now(datetime.timezone.utc)

    await watcher_mod._check_nginx_server(settings, now, threshold_days=30)

    assert captured_audit == []


@pytest.mark.asyncio
async def test_nginx_server_missing_cert_dir_is_noop(captured_audit):
    settings = _StubSettings(nginx_cert_dir="")
    now = datetime.datetime.now(datetime.timezone.utc)

    await watcher_mod._check_nginx_server(settings, now, threshold_days=30)

    assert captured_audit == []


@pytest.mark.asyncio
async def test_nginx_server_missing_file_is_noop(captured_audit, tmp_path):
    settings = _StubSettings(nginx_cert_dir=str(tmp_path))
    now = datetime.datetime.now(datetime.timezone.utc)

    await watcher_mod._check_nginx_server(settings, now, threshold_days=30)

    assert captured_audit == []


# ─── _check_once (integration of all tiers) ────────────────────────────


@pytest.mark.asyncio
async def test_check_once_runs_every_tier_independently(
    captured_audit, captured_list_agents, tmp_path,
):
    """One tick should attempt every tier even if one raises."""
    _, org_root = _mint_cert("test-org-root", days_until_expiry=100)
    _, intermediate = _mint_cert("test-intermediate", days_until_expiry=500)
    _, leaf = _mint_cert("test-mastio-leaf", days_until_expiry=30)
    _, agent_cert = _mint_cert("test-agent", days_until_expiry=10)
    _, nginx_cert = _mint_cert("mastio.local", days_until_expiry=10)
    crt_path = tmp_path / "mastio-server.crt"
    crt_path.write_bytes(nginx_cert.public_bytes(serialization.Encoding.PEM))

    mgr = _StubAgentManager(
        org_ca_cert=org_root,
        mastio_ca_cert=intermediate,
        active_key=_StubMastioKey(kid="kid-x", cert_pem=_cert_pem(leaf)),
    )
    captured_list_agents["rows"] = [
        {"agent_id": "test-agent", "cert_pem": _cert_pem(agent_cert)},
    ]
    settings = _StubSettings(
        nginx_cert_dir=str(tmp_path),
        cert_expiry_warn_days_org_root=1825,
        cert_expiry_warn_days_intermediate=730,
        cert_expiry_warn_days_mastio_leaf=90,
        cert_expiry_warn_days_agent=90,
        cert_expiry_warn_days_nginx=30,
    )

    await watcher_mod._check_once(mgr, settings)

    actions = {r["action"] for r in captured_audit}
    assert "pki.org_root_expiry_warning" in actions
    assert "pki.intermediate_ca_expiry_visibility" in actions
    assert "pki.mastio_leaf_expiry_warning" in actions
    assert "pki.agent_cert_expiry_warning" in actions
    assert "pki.nginx_server_cert_expiry_warning" in actions


@pytest.mark.asyncio
async def test_check_once_uses_default_thresholds_when_setting_absent(
    captured_audit, captured_list_agents,
):
    """Missing settings should NOT crash the tick (fall back to defaults)."""
    _, org_root = _mint_cert("test-org-root", days_until_expiry=100)
    mgr = _StubAgentManager(org_ca_cert=org_root)
    captured_list_agents["rows"] = []

    # settings=None covers the "no settings injected" case (e.g. tests
    # that drive _check_once directly). The defaults kick in.
    await watcher_mod._check_once(mgr, None)

    actions = {r["action"] for r in captured_audit}
    assert "pki.org_root_expiry_warning" in actions


# ─── loop lifecycle ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_loop_stops_on_event(captured_audit):
    """``stop_event.set`` must wake the loop within a single iteration."""
    mgr = _StubAgentManager()
    stop = asyncio.Event()
    settings = _StubSettings()

    task = asyncio.create_task(
        watcher_mod.cert_expiry_watcher_loop(
            mgr, settings=settings, tick_seconds=3600, stop_event=stop,
        ),
    )
    # Let the loop reach the wait_for(stop_event) sleep.
    await asyncio.sleep(0.05)
    stop.set()
    await asyncio.wait_for(task, timeout=2.0)


@pytest.mark.asyncio
async def test_loop_survives_exception_in_tick(captured_audit, monkeypatch):
    """If a tick raises the loop should log + continue, not crash."""
    mgr = _StubAgentManager()
    stop = asyncio.Event()
    settings = _StubSettings()
    calls = {"n": 0}

    async def _boom(agent_manager, settings):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("synthetic tick failure")
        stop.set()

    monkeypatch.setattr(watcher_mod, "_check_once", _boom)

    task = asyncio.create_task(
        watcher_mod.cert_expiry_watcher_loop(
            mgr, settings=settings, tick_seconds=0.01, stop_event=stop,
        ),
    )
    await asyncio.wait_for(task, timeout=2.0)
    assert calls["n"] >= 2
