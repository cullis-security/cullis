"""Port availability + already-running-dashboard detection.

Wraps a tight bind/connect probe so the dashboard CLI can fail with
an actionable message *before* uvicorn touches the loop, and so the
systemd autostart unit can use ``RestartPreventExitStatus=`` to keep
a port collision from turning into a crash-loop. The dogfood
incident on 2026-04-29 (~350 fail/h on errno 98) is the motivating
case — see Finding #1 in
``project_dogfood_findings_2026_04_29.md``.

The probe is best-effort. We do not race the eventual ``uvicorn.run``
(``SO_REUSEADDR`` differences across kernels would make us lie either
direction); we just give the operator a fast, clear failure when the
port is obviously held by something else.
"""
from __future__ import annotations

import socket
from typing import Literal

# Exit code reserved for "the configuration says start me, but the
# environment doesn't allow it" (configuration error, not transient).
# systemd ``RestartPreventExitStatus=78`` then refuses to crash-loop
# on this signal; ``sysexits.h`` documents 78 as ``EX_CONFIG``.
EXIT_PORT_UNAVAILABLE = 78


def check_port_available(host: str, port: int) -> bool:
    """Return ``True`` iff ``(host, port)`` is free for binding *now*.

    We open a short-lived AF_INET socket, attempt the bind, and close
    it immediately. ``EADDRINUSE`` and ``EACCES`` (privileged port,
    sandbox) both count as "not available". Any other socket error
    is also treated as unavailable — the operator gets the same
    actionable error and the systemd unit doesn't crash-loop.
    """
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
    except OSError:
        return False
    finally:
        sock.close()
    return True


_DashboardKind = Literal["cullis_connector", "unknown", "no_response"]


def detect_running_dashboard(
    host: str, port: int, *, timeout_s: float = 0.5,
) -> _DashboardKind:
    """Best-effort probe: is *another* Connector dashboard already on this port?

    The Connector dashboard exposes ``GET /api/ping`` returning
    ``{"app": "cullis-connector"}``. We match on the app field, not
    on header strings — uvicorn's ``Server`` header is shared by
    lots of unrelated services.

    Returns ``"cullis_connector"`` on a clear positive, ``"unknown"``
    if something is listening but doesn't smell like our dashboard
    (so the operator at least knows the port is *taken*, not just
    flaky), or ``"no_response"`` if nothing answered in time. We
    never raise — this is purely a diagnostic helper.
    """
    try:
        import httpx  # imported lazily so ``serve``/``enroll`` don't pay the cost
    except ImportError:
        return "no_response"

    url = f"http://{host}:{port}/api/ping"
    try:
        resp = httpx.get(url, timeout=timeout_s)
    except (httpx.HTTPError, OSError):
        return "no_response"

    if resp.status_code != 200:
        return "unknown"
    try:
        body = resp.json()
    except ValueError:
        return "unknown"
    if isinstance(body, dict) and body.get("app") == "cullis-connector":
        return "cullis_connector"
    return "unknown"
