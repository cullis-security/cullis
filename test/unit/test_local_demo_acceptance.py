"""A blocked DNS query must not hide unrelated failures or accept any reply."""
import errno
from pathlib import Path
import runpy
import socket
import sys
from unittest.mock import Mock

import pytest

ACCEPTANCE = runpy.run_path(str(Path(__file__).resolve().parents[1] / "local-demo/acceptance.py"))


def run_probe(monkeypatch, expected, *, send_error=None, recv_error=None, reply=b"DNS reply"):
    connection = Mock()
    connection.sendto.side_effect = send_error
    connection.recv.side_effect = recv_error
    connection.recv.return_value = reply
    monkeypatch.setattr(socket, "socket", Mock(return_value=connection))
    monkeypatch.setattr(sys, "argv", ["probe", expected])
    try:
        exec(ACCEPTANCE["DNS_PROBE"], {})
    finally:
        connection.close.assert_called_once()


@pytest.mark.parametrize("phase", ["send", "recv"])
@pytest.mark.parametrize("error", [errno.EPERM, errno.EACCES])
def test_explicit_denial_passes_only_negative_control(monkeypatch, phase, error):
    kwargs = {phase + "_error": OSError(error, "blocked")}
    run_probe(monkeypatch, "deny", **kwargs)
    with pytest.raises(AssertionError, match="Unexpected DNS reachability"):
        run_probe(monkeypatch, "allow", **kwargs)


def test_timeout_passes_only_negative_control(monkeypatch):
    run_probe(monkeypatch, "deny", recv_error=socket.timeout())
    with pytest.raises(AssertionError, match="Unexpected DNS reachability"):
        run_probe(monkeypatch, "allow", recv_error=socket.timeout())


@pytest.mark.parametrize("reply", [b"DNS reply", b""])
def test_any_datagram_fails_negative_control(monkeypatch, reply):
    with pytest.raises(AssertionError, match="Unexpected DNS reachability"):
        run_probe(monkeypatch, "deny", reply=reply)


def test_positive_control_requires_response(monkeypatch):
    run_probe(monkeypatch, "allow")


@pytest.mark.parametrize("phase", ["send", "recv"])
def test_unrelated_socket_error_is_not_a_success(monkeypatch, phase):
    with pytest.raises(OSError) as failure:
        run_probe(monkeypatch, "deny", **{phase + "_error": OSError(errno.EBADF, "bad descriptor")})
    assert failure.value.errno == errno.EBADF
