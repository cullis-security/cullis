"""Tests for ``cullis_connector.tools._identity``.

The helpers take identity as an **explicit parameter** — they no
longer read process-global state. These tests pin the new contract:
silent passthrough when already qualified, prefix when both identity
and bare recipient are present, and a warning (but no exception)
when a bare recipient is paired with ``identity=None``.
"""
from __future__ import annotations

from unittest.mock import MagicMock

from cullis_connector.tools._identity import canonical_recipient, own_org_id


def _fake_identity(org_id: str) -> MagicMock:
    """Minimal duck-typed IdentityBundle stub — only the
    ``.cert.subject.get_attributes_for_oid`` chain matters."""
    fake_attr = MagicMock()
    fake_attr.value = org_id
    fake_cert = MagicMock()
    fake_cert.subject.get_attributes_for_oid.return_value = [fake_attr]
    fake_identity = MagicMock()
    fake_identity.cert = fake_cert
    return fake_identity


# ── own_org_id ───────────────────────────────────────────────────────


def test_own_org_id_reads_subject_O_attr():
    assert own_org_id(_fake_identity("acme")) == "acme"


def test_own_org_id_returns_none_when_identity_none():
    assert own_org_id(None) is None


def test_own_org_id_returns_none_when_cert_missing():
    fake = MagicMock()
    fake.cert = None
    assert own_org_id(fake) is None


def test_own_org_id_returns_none_when_no_O_attr():
    fake_cert = MagicMock()
    fake_cert.subject.get_attributes_for_oid.return_value = []
    fake = MagicMock()
    fake.cert = fake_cert
    assert own_org_id(fake) is None


# ── canonical_recipient ──────────────────────────────────────────────


def test_canonical_recipient_prefixes_bare_handle_with_identity():
    assert canonical_recipient("mario", _fake_identity("acme")) == "acme::mario"


def test_canonical_recipient_passthrough_when_already_qualified():
    # ``::`` present → identity is irrelevant, passthrough silent.
    assert canonical_recipient(
        "other-org::luigi", _fake_identity("acme"),
    ) == "other-org::luigi"


def test_canonical_recipient_qualified_with_none_identity_is_silent(monkeypatch):
    """Already-qualified input + identity=None must NOT log a warning.
    The warning is only for the ambiguous case (bare + no identity).
    Covers diagnostic tools that pass qualified handles before
    enrollment completes."""
    from cullis_connector.tools import _identity as identity_mod

    captured: list = []
    monkeypatch.setattr(
        identity_mod._log, "warning",
        lambda msg, *args, **kw: captured.append((msg, args)),
    )

    assert canonical_recipient("other-org::luigi", None) == "other-org::luigi"
    assert captured == []


def test_canonical_recipient_bare_with_none_identity_warns_and_passes_through(monkeypatch):
    """Bare recipient + identity=None → log warning + return input
    unchanged. The Mastio then rejects with 400; the warning tells
    the dev they forgot to attach identity.

    Monkeypatch the module's ``_log.warning`` directly rather than
    relying on caplog — the memory ``feedback_mcp_proxy_logger_caplog``
    documents that some module loggers don't propagate cleanly under
    xdist and caplog comes back empty. Direct interception is the
    portable pattern."""
    from cullis_connector.tools import _identity as identity_mod

    captured: list[tuple[str, tuple]] = []

    def _capture(msg, *args, **kwargs):
        captured.append((msg, args))

    monkeypatch.setattr(identity_mod._log, "warning", _capture)

    result = canonical_recipient("mario", None)
    assert result == "mario"
    assert len(captured) == 1, captured
    msg, args = captured[0]
    assert "identity=None" in msg
    assert args[0] == "mario"


def test_canonical_recipient_bare_with_identity_missing_org_passes_through():
    """Identity present but cert has no ``O=`` attribute → passthrough
    (no warning). Unusual state but not a programmer error the caller
    should have caught; the server will still produce a clean 400."""
    fake_cert = MagicMock()
    fake_cert.subject.get_attributes_for_oid.return_value = []
    fake = MagicMock()
    fake.cert = fake_cert
    assert canonical_recipient("mario", fake) == "mario"
