"""Discovery + sort tests for :mod:`mcp_proxy.updates.registry`.

The registry walks :mod:`mcp_proxy.updates.migrations` at every call,
so the fixtures here inject fresh modules into that package via
``monkeypatch`` and rely on :func:`importlib.reload` semantics provided
by the registry itself (it imports each module every call).

PR 1 leaves ``mcp_proxy.updates.migrations`` empty on disk; these tests
assert that the discover flow still works (returns []) plus the
behaviour when fixture migrations are registered.
"""
from __future__ import annotations

import sys
import types

import pytest

from mcp_proxy.updates import registry as registry_mod
from mcp_proxy.updates.base import Migration


# Unique package name per pytest-xdist worker keeps ``_iter_subclasses``
# traversal isolated — the real ``mcp_proxy.updates.migrations`` is
# empty in PR 1, so any class whose ``__module__`` starts with this
# fake package name is picked up by ``discover`` and nothing else is.
_FAKE_PKG_NAME = "mcp_proxy.updates.migrations._testfixtures"


@pytest.fixture
def fake_pkg(monkeypatch):
    """Per-test throwaway migrations package.

    Each test gets a fresh :class:`types.ModuleType` with a unique id
    embedded in ``__name__``, so fixture migrations registered in
    earlier tests (still alive in ``Migration.__subclasses__``) do not
    leak into the current test's ``discover()`` call — they match a
    stale package prefix the registry does not scan.
    """
    pkg_name = f"{_FAKE_PKG_NAME}_{id(monkeypatch)}"
    pkg = types.ModuleType(pkg_name)
    pkg.__path__ = []  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, pkg_name, pkg)
    monkeypatch.setattr(registry_mod, "_migrations_pkg", pkg)
    return pkg


def _fixture_cls(
    fake_pkg_mod: types.ModuleType,
    name: str,
    migration_id: str,
    migration_type: str = "new-feature",
) -> type[Migration]:
    async def _check(self) -> bool:
        return False

    async def _up(self) -> None:
        return None

    async def _rollback(self) -> None:
        return None

    cls = type(
        name,
        (Migration,),
        {
            "migration_id": migration_id,
            "migration_type": migration_type,
            "criticality": "info",
            "description": f"fixture {name}",
            "preserves_enrollments": True,
            "affects_enrollments": (),
            "check": _check,
            "up": _up,
            "rollback": _rollback,
        },
    )
    # Pin the class to the fake migrations package so ``discover``
    # picks it up via the module-name filter.
    cls.__module__ = fake_pkg_mod.__name__
    # Keep a strong reference on the package so ``Migration.__subclasses__``
    # (which holds weakrefs) doesn't lose the class to GC before the
    # test runs ``discover()``. Caller-side ``_fixture_cls("X", ...)``
    # expressions that ignore the return value would otherwise create
    # orphan classes that the CI runner's more-aggressive GC collects
    # before the assertion — the test passes locally, fails in CI.
    setattr(fake_pkg_mod, name, cls)
    return cls


def test_discover_empty(fake_pkg):
    # No migrations registered — discover returns [].
    assert registry_mod.discover() == []


def test_discover_single_migration(fake_pkg):
    _fixture_cls(fake_pkg, "Single", "2099-01-01-single")
    result = registry_mod.discover()
    assert len(result) == 1
    assert result[0].migration_id == "2099-01-01-single"


def test_discover_sorts_lexically(fake_pkg):
    # Intentionally create out of order.
    _fixture_cls(fake_pkg, "Late", "2099-12-31-late")
    _fixture_cls(fake_pkg, "Mid", "2099-06-15-mid")
    _fixture_cls(fake_pkg, "Early", "2099-01-01-early")
    result = registry_mod.discover()
    ids = [m.migration_id for m in result]
    assert ids == [
        "2099-01-01-early",
        "2099-06-15-mid",
        "2099-12-31-late",
    ]


def test_discover_ignores_abstract_classes(fake_pkg):
    # Abstract subclasses of Migration must be skipped (otherwise the
    # registry would TypeError on instantiation). The helper declares
    # metadata defaults so the contract is satisfied, then stays
    # abstract by leaving ``check`` / ``up`` / ``rollback`` untouched.
    AbstractHelper = type(
        "AbstractHelper",
        (Migration,),
        {
            "migration_id": "2099-00-00-helper",
            "migration_type": "new-feature",
            "criticality": "info",
            "description": "abstract helper — registry must skip",
            "preserves_enrollments": True,
            "affects_enrollments": (),
        },
    )
    AbstractHelper.__module__ = fake_pkg.__name__

    _fixture_cls(fake_pkg, "Concrete", "2099-02-02-concrete")
    result = registry_mod.discover()
    assert [m.migration_id for m in result] == ["2099-02-02-concrete"]


def test_discover_double_call_deterministic(fake_pkg):
    _fixture_cls(fake_pkg, "Alpha", "2099-01-01-alpha")
    _fixture_cls(fake_pkg, "Beta", "2099-02-01-beta")
    first = [m.migration_id for m in registry_mod.discover()]
    second = [m.migration_id for m in registry_mod.discover()]
    assert first == second


def test_get_by_id_hit(fake_pkg):
    _fixture_cls(fake_pkg, "HitTarget", "2099-01-01-hit")
    m = registry_mod.get_by_id("2099-01-01-hit")
    assert m is not None
    assert m.migration_id == "2099-01-01-hit"


def test_get_by_id_miss(fake_pkg):
    _fixture_cls(fake_pkg, "HitTarget", "2099-01-01-hit")
    assert registry_mod.get_by_id("2099-01-01-miss") is None


def test_duplicate_migration_id_raises(fake_pkg):
    # Two different classes declaring the same migration_id → registry
    # must fail loud, not pick one silently.
    _fixture_cls(fake_pkg, "DupA", "2099-01-01-dup")
    _fixture_cls(fake_pkg, "DupB", "2099-01-01-dup")
    with pytest.raises(RuntimeError, match="duplicate migration_id"):
        registry_mod.discover()


def test_imports_modules_from_migrations_package(monkeypatch, tmp_path):
    """Exercise the ``pkgutil.iter_modules`` scan path.

    Builds an ad-hoc single-file package on disk, points the registry
    at it, and asserts the module was imported and its ``Migration``
    subclass picked up.

    Uses a per-test unique ``migration_id`` and a per-test unique
    package name: once a test imports ``fake_migrations_pkg.m1``, the
    ``M1`` class sticks around in ``Migration.__subclasses__`` for
    the lifetime of the process (sys.modules pop doesn't evict it, and
    the weakref can be kept alive by any stray reference). A repeated
    test run with a static id would raise a duplicate-id error on the
    second iteration — not a bug in ``discover``, but a fixture cost.
    """
    unique = tmp_path.name  # pytest injects a fresh dir for every run
    pkg_name = f"fake_migrations_pkg_{unique}".replace("-", "_")
    migration_id = f"2099-03-03-scan-{unique}"

    pkg_dir = tmp_path / "fake_migrations"
    pkg_dir.mkdir()
    (pkg_dir / "__init__.py").write_text("")
    (pkg_dir / "m1.py").write_text(
        "from mcp_proxy.updates.base import Migration\n"
        "class M1(Migration):\n"
        f"    migration_id = '{migration_id}'\n"
        "    migration_type = 'new-feature'\n"
        "    criticality = 'info'\n"
        "    description = 'scanned from disk'\n"
        "    preserves_enrollments = True\n"
        "    affects_enrollments = ()\n"
        "    async def check(self): return False\n"
        "    async def up(self): return None\n"
        "    async def rollback(self): return None\n"
    )

    fake_pkg = types.ModuleType(pkg_name)
    fake_pkg.__path__ = [str(pkg_dir)]  # type: ignore[attr-defined]
    fake_pkg.__name__ = pkg_name
    sys.modules[pkg_name] = fake_pkg
    monkeypatch.setattr(registry_mod, "_migrations_pkg", fake_pkg)
    monkeypatch.syspath_prepend(str(tmp_path / "fake_migrations"))

    try:
        result = registry_mod.discover()
        ids = [m.migration_id for m in result]
        assert migration_id in ids
    finally:
        sys.modules.pop(pkg_name, None)
        sys.modules.pop(f"{pkg_name}.m1", None)
