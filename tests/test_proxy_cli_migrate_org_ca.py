"""``cullis-proxy migrate-org-ca-to-vault`` CLI tests (ADR-031 follow-up).

Drives the subcommand end-to-end with:
- SQLite proxy DB seeded with ``org_ca_key`` + ``org_ca_cert`` in
  ``proxy_config``,
- ``httpx.AsyncClient`` patched with a ``MockTransport`` so the
  ``VaultKMSProvider`` writes go against an in-memory KV v2 fixture.

Covers: happy path with ``--clear-db``, dry-run (no write, no clear),
empty source (nothing to migrate), Vault path already populated
without ``--force`` (refuse), read-back mismatch (abort, DB
preserved), missing Vault settings (clear error).
"""
from __future__ import annotations

import io
import json

import httpx
import pytest
import pytest_asyncio

from mcp_proxy.cli import main as cli_main
from mcp_proxy.db import dispose_db, get_config, init_db, set_config


_VAULT_ADDR = "https://vault.example:8200"
_TOKEN = "hvs.test-token"
_PATH = "secret/data/cullis-mastio/org-ca"


# ── Test fixtures ──────────────────────────────────────────────────


@pytest_asyncio.fixture
async def proxy_db(tmp_path, monkeypatch):
    """Hermetic SQLite proxy DB + flushed settings cache + Vault env."""
    db_file = tmp_path / "proxy.sqlite"
    url = f"sqlite+aiosqlite:///{db_file}"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", url)
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("MCP_PROXY_VAULT_ADDR", _VAULT_ADDR)
    monkeypatch.setenv("MCP_PROXY_VAULT_TOKEN", _TOKEN)
    monkeypatch.setenv("MCP_PROXY_VAULT_ORG_CA_PATH", _PATH)

    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    await init_db(url)
    yield url
    await dispose_db()
    get_settings.cache_clear()


class _FakeVault:
    """In-memory KV v2 fixture for the mocked Vault endpoint."""

    def __init__(self, initial: dict | None = None) -> None:
        # None means "404 on GET" (path not seeded).
        self.data: dict | None = initial
        self.version = 1 if initial else 0
        self.writes: list[dict] = []
        self.write_response: tuple[int, str] = (200, "")

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if not path.startswith(f"/v1/{_PATH}"):
            return httpx.Response(404, json={"errors": ["unknown path"]})
        if request.method == "GET":
            if self.data is None:
                return httpx.Response(404, json={"errors": []})
            return httpx.Response(
                200,
                json={
                    "data": {
                        "data": self.data,
                        "metadata": {"version": self.version},
                    },
                },
            )
        # POST: capture body + update fixture.
        body = json.loads(request.content)
        self.writes.append(body)
        if self.write_response[0] >= 400:
            return httpx.Response(self.write_response[0], text=self.write_response[1])
        self.data = body["data"]
        self.version += 1
        return httpx.Response(200, json={"data": {"version": self.version}})


@pytest.fixture
def patch_vault(monkeypatch):
    """Returns a factory that wires the FakeVault into httpx.AsyncClient."""
    def _apply(fake: _FakeVault) -> None:
        transport = httpx.MockTransport(fake.handler)
        real = httpx.AsyncClient

        def patched(*args, **kwargs):
            kwargs.setdefault("transport", transport)
            return real(*args, **kwargs)

        monkeypatch.setattr(httpx, "AsyncClient", patched)
    return _apply


async def _seed_db_ca(key: str = "KEY_PEM", cert: str = "CERT_PEM") -> None:
    await set_config("org_ca_key", key)
    await set_config("org_ca_cert", cert)


# ── Happy path ─────────────────────────────────────────────────────


def test_cli_migrate_happy_path_with_clear_db(proxy_db, patch_vault, capsys):
    import asyncio
    url = proxy_db
    asyncio.run(_seed_db_ca("MY_KEY", "MY_CERT"))

    fake = _FakeVault(initial=None)
    patch_vault(fake)

    rc = cli_main(["migrate-org-ca-to-vault", "--yes", "--clear-db"])
    assert rc == 0

    # Vault now holds the keypair.
    assert fake.data == {"key_pem": "MY_KEY", "cert_pem": "MY_CERT"}
    # First write must omit CAS (path was unseeded).
    assert "options" not in fake.writes[0]

    # DB rows have been cleared. ``cli_main`` already disposed the
    # engine; re-init for the post-check so we hit the SQLite file
    # again with a fresh loop-bound engine.
    async def _check_cleared():
        await init_db(url)
        try:
            assert await get_config("org_ca_key") == ""
            assert await get_config("org_ca_cert") == ""
        finally:
            await dispose_db()
    asyncio.run(_check_cleared())

    out = capsys.readouterr().out
    assert "migrated to Vault" in out
    assert "cleared" in out


# ── Dry-run ────────────────────────────────────────────────────────


def test_cli_migrate_dry_run_does_not_write_or_clear(proxy_db, patch_vault, capsys):
    import asyncio
    url = proxy_db
    asyncio.run(_seed_db_ca("X", "Y"))

    fake = _FakeVault(initial=None)
    patch_vault(fake)

    rc = cli_main(["migrate-org-ca-to-vault", "--yes", "--clear-db", "--dry-run"])
    assert rc == 0

    # No POST issued.
    assert fake.writes == []
    assert fake.data is None
    # DB untouched.
    async def _check_kept():
        await init_db(url)
        try:
            assert await get_config("org_ca_key") == "X"
            assert await get_config("org_ca_cert") == "Y"
        finally:
            await dispose_db()
    asyncio.run(_check_kept())

    out = capsys.readouterr().out
    assert "DRY RUN" in out


# ── Empty source ───────────────────────────────────────────────────


def test_cli_migrate_refuses_empty_db(proxy_db, patch_vault, capsys):
    fake = _FakeVault(initial=None)
    patch_vault(fake)

    rc = cli_main(["migrate-org-ca-to-vault", "--yes"])
    assert rc == 1

    err = capsys.readouterr().err
    assert "no Org CA to migrate" in err
    assert fake.writes == []


# ── Existing target without --force ───────────────────────────────


def test_cli_migrate_refuses_to_overwrite_without_force(proxy_db, patch_vault, capsys):
    import asyncio
    asyncio.run(_seed_db_ca())

    fake = _FakeVault(initial={"key_pem": "PRIOR_KEY", "cert_pem": "PRIOR_CERT"})
    patch_vault(fake)

    rc = cli_main(["migrate-org-ca-to-vault", "--yes"])
    assert rc == 1

    err = capsys.readouterr().err
    assert "already holds" in err
    assert "--force" in err
    # Vault contents unchanged.
    assert fake.data == {"key_pem": "PRIOR_KEY", "cert_pem": "PRIOR_CERT"}
    assert fake.writes == []


def test_cli_migrate_overwrites_with_force(proxy_db, patch_vault):
    import asyncio
    asyncio.run(_seed_db_ca("NEW_KEY", "NEW_CERT"))

    fake = _FakeVault(initial={"key_pem": "OLD_KEY", "cert_pem": "OLD_CERT"})
    patch_vault(fake)

    rc = cli_main(["migrate-org-ca-to-vault", "--yes", "--force"])
    assert rc == 0
    assert fake.data["key_pem"] == "NEW_KEY"
    assert fake.data["cert_pem"] == "NEW_CERT"
    # CAS write merged with prior version.
    assert fake.writes[0]["options"]["cas"] == 1


# ── Read-back mismatch ─────────────────────────────────────────────


def test_cli_migrate_aborts_on_readback_mismatch_and_preserves_db(
    proxy_db, monkeypatch, capsys,
):
    import asyncio
    asyncio.run(_seed_db_ca("WANT_KEY", "WANT_CERT"))

    # Custom transport that "writes" successfully but returns different
    # content on the post-write read-back, simulating a Vault path that
    # silently rewrites or a misconfigured replication target.
    state = {"phase": "pre-write"}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            if state["phase"] == "pre-write":
                return httpx.Response(404, json={"errors": []})
            # Read-back returns CORRUPTED content.
            return httpx.Response(
                200,
                json={
                    "data": {
                        "data": {"key_pem": "CORRUPTED", "cert_pem": "CORRUPTED"},
                        "metadata": {"version": 1},
                    },
                },
            )
        # POST: accept, then flip state for the next read.
        state["phase"] = "post-write"
        return httpx.Response(200, json={"data": {"version": 1}})

    transport = httpx.MockTransport(handler)
    real = httpx.AsyncClient
    monkeypatch.setattr(
        httpx, "AsyncClient",
        lambda *a, **kw: real(*a, **{**kw, "transport": transport}),
    )

    rc = cli_main(["migrate-org-ca-to-vault", "--yes", "--clear-db"])
    assert rc == 2

    err = capsys.readouterr().err
    assert "read-back" in err

    # Crucially, the DB was NOT cleared — preserves recovery surface.
    url = proxy_db
    async def _check_kept():
        await init_db(url)
        try:
            assert await get_config("org_ca_key") == "WANT_KEY"
            assert await get_config("org_ca_cert") == "WANT_CERT"
        finally:
            await dispose_db()
    asyncio.run(_check_kept())


# ── Missing settings ───────────────────────────────────────────────


def test_cli_migrate_refuses_when_vault_settings_missing(
    proxy_db, monkeypatch, capsys,
):
    monkeypatch.delenv("MCP_PROXY_VAULT_TOKEN", raising=False)
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    rc = cli_main(["migrate-org-ca-to-vault", "--yes"])
    assert rc == 1

    err = capsys.readouterr().err
    assert "MCP_PROXY_VAULT_TOKEN" in err


# ── Help surface ───────────────────────────────────────────────────


def test_cli_migrate_appears_in_help(capsys):
    with pytest.raises(SystemExit):
        cli_main(["--help"])
    out = capsys.readouterr().out
    assert "migrate-org-ca-to-vault" in out


# ── Interactive abort ──────────────────────────────────────────────


def test_cli_migrate_aborts_without_yes(proxy_db, patch_vault, monkeypatch, capsys):
    import asyncio
    asyncio.run(_seed_db_ca())

    fake = _FakeVault(initial=None)
    patch_vault(fake)

    monkeypatch.setattr("sys.stdin", io.StringIO("n\n"))
    rc = cli_main(["migrate-org-ca-to-vault"])
    assert rc == 1

    err = capsys.readouterr().err
    assert "Continue?" in err
    assert "aborted" in err
    assert fake.writes == []
