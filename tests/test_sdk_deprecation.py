"""Regression test for the v0.4.x deprecation pass (SDK refactor split
closing PR).

The SDK refactor moved every legacy session-based primitive into a
dedicated mixin and tagged 13 methods for removal in v0.5
(~2026-08-15). This test pins the contract:

* every flagged method emits exactly one ``DeprecationWarning`` per
  call, regardless of whether the underlying request succeeds;
* the warning message names the method (so users can grep their
  callsites) and includes the ``v0.5`` sunset marker;
* ``stacklevel=2`` puts the warning on the caller's frame.

When the v0.5 cut removes a method, drop its entry from
``DEPRECATED_METHODS`` and the parametrized test will go with it.
"""
from __future__ import annotations

import warnings
from typing import Callable

import pytest

from cullis_sdk import CullisClient


def _make_offline_client() -> CullisClient:
    """Build a ``CullisClient`` that never touches the network.

    The deprecation warnings fire BEFORE any HTTP call, so we can stub
    the egress + authed-request shims with no-ops and exercise every
    flagged method without booting a broker.
    """
    c = CullisClient.__new__(CullisClient)
    c._use_egress_for_sessions = False
    c._signing_key_pem = None
    c.base = "http://test.invalid"
    c._dpop_privkey = None
    c._dpop_pubkey_jwk = None
    c.token = None
    c.server_role = None
    c._dpop_nonce = None
    c._relogin_callable = None
    c._label = "test-deprecation"
    c._client_seq = {}
    c._pubkey_cache = {}

    class _NoopResp:
        status_code = 204

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return {}

        @property
        def text(self) -> str:
            return ""

    def _noop_authed_request(*_a, **_k) -> _NoopResp:
        return _NoopResp()

    def _noop_egress_http(*_a, **_k) -> _NoopResp:
        return _NoopResp()

    c._authed_request = _noop_authed_request  # type: ignore[method-assign]
    c._egress_http = _noop_egress_http  # type: ignore[method-assign]

    class _NoopHttp:
        def request(self, *_a, **_k) -> _NoopResp:
            return _NoopResp()

        def post(self, *_a, **_k) -> _NoopResp:
            return _NoopResp()

        def get(self, *_a, **_k) -> _NoopResp:
            return _NoopResp()

    c._http = _NoopHttp()  # type: ignore[attr-defined]
    return c


# Each entry maps a stable id → a lambda that invokes the method on a
# CullisClient instance. The id is the canonical method name so the
# parametrize report reads naturally.
DEPRECATED_METHODS: dict[str, Callable[[CullisClient], object]] = {
    # _AuthMixin
    "login": lambda c: c.login("orga::a", "orga", "/dev/null", "/dev/null"),
    # _MessagingLegacyMixin
    "send": lambda c: c.send("s1", "orga::a", {}, recipient_agent_id="orga::b"),
    "send_via_proxy": lambda c: c.send_via_proxy("s1", {}, "orga::b"),
    "receive_via_proxy": lambda c: c.receive_via_proxy("s1"),
    "poll": lambda c: c.poll("s1"),
    "ack_message": lambda c: c.ack_message("s1", "m1"),
    "decrypt_payload": lambda c: c.decrypt_payload({"payload": {}}, session_id="s1"),
    # _SessionsMixin
    "open_session": lambda c: c.open_session("orga::a", "orga", []),
    "accept_session": lambda c: c.accept_session("s1"),
    "reject_session": lambda c: c.reject_session("s1"),
    "close_session": lambda c: c.close_session("s1"),
    "list_sessions": lambda c: c.list_sessions(),
    # _WebSocketMixin
    "connect_websocket": lambda c: c.connect_websocket(),
}


@pytest.mark.parametrize("method_name", sorted(DEPRECATED_METHODS))
def test_deprecated_methods_emit_warning(method_name: str) -> None:
    """Every v0.5-sunset method emits exactly one ``DeprecationWarning``
    naming the method and the cullis-sdk v0.5 sunset target."""
    client = _make_offline_client()
    invoke = DEPRECATED_METHODS[method_name]

    with warnings.catch_warnings(record=True) as recorded:
        warnings.simplefilter("always")
        try:
            invoke(client)
        except Exception:
            # The downstream call may legitimately raise once the
            # warning has been emitted (eg. login() tries to read a
            # file). The warning emission is what we're pinning here,
            # not the method's post-warning behaviour.
            pass

    # Match on ``CullisClient.<name>()`` so we don't conflate
    # ``login()`` with the inner ``login_from_pem`` warning that login()
    # cascades into.
    needle = f"CullisClient.{method_name}()"
    dep = [
        w for w in recorded
        if issubclass(w.category, DeprecationWarning)
        and needle in str(w.message)
    ]
    assert len(dep) == 1, (
        f"{method_name} should emit exactly one DeprecationWarning "
        f"naming {needle!r}, got {len(dep)}: "
        f"{[str(w.message) for w in recorded]}"
    )
    msg = str(dep[0].message)
    assert "v0.5" in msg, f"{method_name} warning missing v0.5 sunset marker: {msg!r}"


def test_login_emits_warning_with_callsite_stacklevel() -> None:
    """``stacklevel=2`` puts the warning on the user's frame, not the
    SDK internal frame — pin this on one representative method so a
    future refactor that bumps stacklevel inadvertently gets caught."""
    client = _make_offline_client()
    with warnings.catch_warnings(record=True) as recorded:
        warnings.simplefilter("always")
        try:
            client.login("orga::a", "orga", "/dev/null", "/dev/null")
        except Exception:
            pass
    dep = [w for w in recorded if issubclass(w.category, DeprecationWarning)
           and "login()" in str(w.message)]
    assert dep, "login() did not emit a DeprecationWarning"
    # The warning's recorded filename should be THIS test file (the
    # caller), not _auth.py — that's what stacklevel=2 buys us.
    assert dep[0].filename.endswith("test_sdk_deprecation.py"), (
        f"stacklevel=2 should point at the caller, got filename={dep[0].filename!r}"
    )
