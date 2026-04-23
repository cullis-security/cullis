"""Tests for ``cullis_connector.tools._identity``.

Since the ``prime_sender_pubkey_cache`` workaround was replaced by the
SDK-side ``pubkey_fetcher`` injection backed by the Mastio's
``/v1/egress/agents/{id}/public-key`` endpoint, this module now only
owns the small identity helpers ``own_org_id`` and
``canonical_recipient``. Tests mirror that narrower surface.
"""
from __future__ import annotations

from unittest.mock import MagicMock

from cullis_connector.state import get_state, reset_state
from cullis_connector.tools._identity import canonical_recipient, own_org_id


def _seed_identity(org_id: str) -> None:
    reset_state()
    fake_attr = MagicMock()
    fake_attr.value = org_id
    fake_cert = MagicMock()
    fake_cert.subject.get_attributes_for_oid.return_value = [fake_attr]
    fake_identity = MagicMock()
    fake_identity.cert = fake_cert
    get_state().extra["identity"] = fake_identity


def test_own_org_id_reads_subject_O_attr():
    _seed_identity("acme")
    try:
        assert own_org_id() == "acme"
    finally:
        reset_state()


def test_own_org_id_none_when_no_identity_loaded():
    reset_state()
    assert own_org_id() is None


def test_canonical_recipient_prefixes_bare_handle():
    _seed_identity("acme")
    try:
        assert canonical_recipient("mario") == "acme::mario"
    finally:
        reset_state()


def test_canonical_recipient_passthrough_when_already_qualified():
    _seed_identity("acme")
    try:
        assert canonical_recipient("other-org::luigi") == "other-org::luigi"
    finally:
        reset_state()


def test_canonical_recipient_no_identity_returns_input_unchanged():
    """Without an identity loaded there is no org to prefix with —
    returning the bare handle is the safe fallback; the server will
    reject it with a clear 400."""
    reset_state()
    assert canonical_recipient("mario") == "mario"
