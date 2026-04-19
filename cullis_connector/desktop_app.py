"""Native desktop shell for the Connector (M3.1, Phase 3).

Wraps the FastAPI dashboard in an OS-native webview so non-technical
users never see a terminal. Adds a system-tray icon with a minimal
menu — the dashboard process keeps running in the background when the
user closes the window, and a click on the tray brings it back.

Threading plan (all three matter, pick the wrong one and macOS hangs):
  - Uvicorn runs in a daemon thread, owning its own asyncio loop.
  - pystray.Icon runs detached — it spins its own platform thread
    (AppKit runloop on macOS, GTK main loop on Linux, Win32 message
    pump on Windows).
  - PyWebview owns the main thread. On macOS AppKit strictly requires
    the GUI to sit on the process's initial thread, so webview.start()
    blocks here and everything else is a guest thread.
"""
from __future__ import annotations

import logging
import threading
from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from PIL.Image import Image as PILImage

    from cullis_connector.config import ConnectorConfig


_log = logging.getLogger(__name__)

# Cullis teal — matches the dashboard favicon and brand mark.
_ACCENT = (0, 229, 199, 255)


def _build_tray_image(size: int = 64) -> "PILImage":
    """Draw the portcullis glyph at the requested pixel size.

    We render with Pillow primitives instead of shipping a PNG asset
    so the wheel stays smaller and the icon scales cleanly for high-
    dpi trays. The geometry mirrors `cullis_connector/static/cullis-mark.svg`
    (100x100 viewBox: top bar, three vertical bars, middle crossbar,
    three triangular teeth).
    """
    from PIL import Image, ImageDraw

    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    def _s(value: int) -> int:
        return int(round(value * size / 100))

    draw.rectangle([_s(8), _s(10), _s(92), _s(16)], fill=_ACCENT)
    for x in (20, 46, 72):
        draw.rectangle([_s(x), _s(16), _s(x + 8), _s(78)], fill=_ACCENT)
    draw.rectangle([_s(14), _s(44), _s(86), _s(50)], fill=_ACCENT)
    for x in (14, 40, 66):
        draw.polygon(
            [
                (_s(x), _s(78)),
                (_s(x + 20), _s(78)),
                (_s(x + 10), _s(96)),
            ],
            fill=_ACCENT,
        )
    return img


def _spawn_uvicorn(
    cfg: "ConnectorConfig",
    host: str,
    port: int,
) -> threading.Thread:
    """Launch the dashboard FastAPI app in a daemon thread."""
    import uvicorn

    from cullis_connector.web import build_app

    app = build_app(cfg)
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host=host,
            port=port,
            log_level="info",
            access_log=False,
        )
    )

    thread = threading.Thread(
        target=server.run,
        name="cullis-uvicorn",
        daemon=True,
    )
    thread.start()
    return thread


def _build_menu(
    open_dashboard: Callable[[], None],
    open_inbox: Callable[[], None],
    on_quit: Callable[[], None],
):
    """Minimal tray menu: Open Dashboard / Open Inbox / Quit.

    Pause-notifications and profile switcher are deliberate follow-ups
    (M3.1b and M3.3 in the roadmap) — M3.1 keeps the surface small to
    make the first packaged binary easy to validate.
    """
    import pystray

    return pystray.Menu(
        pystray.MenuItem(
            "Open Dashboard",
            lambda icon, item: open_dashboard(),
            default=True,
        ),
        pystray.MenuItem(
            "Open Inbox",
            lambda icon, item: open_inbox(),
        ),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem(
            "Quit",
            lambda icon, item: on_quit(),
        ),
    )


def run_desktop_app(
    cfg: "ConnectorConfig",
    host: str = "127.0.0.1",
    port: int = 7777,
) -> int:
    """Entry point for `cullis-connector desktop`.

    Returns 2 when the optional `desktop` deps are missing so the CLI
    can surface a friendly install hint.
    """
    try:
        import pystray  # noqa: F401
        import webview
        from PIL import Image  # noqa: F401
    except ImportError as exc:
        _log.error(
            "desktop shell needs extra deps — install with "
            "`pip install 'cullis-connector[dashboard,desktop]'` "
            "(missing: %s)",
            exc.name,
        )
        return 2

    base_url = f"http://{host}:{port}"
    _spawn_uvicorn(cfg, host, port)

    window = webview.create_window(
        "Cullis",
        f"{base_url}/",
        hidden=True,
        width=1120,
        height=760,
    )

    # Intercept the native close button: hide the window so the tray
    # stays live and a later Open reveals the same instance instead of
    # racing uvicorn to spawn a second one.
    def _on_closing() -> bool:
        window.hide()
        return False

    window.events.closing += _on_closing

    def _open_dashboard() -> None:
        window.load_url(f"{base_url}/")
        window.show()

    def _open_inbox() -> None:
        window.load_url(f"{base_url}/inbox")
        window.show()

    import pystray

    icon = pystray.Icon(
        "cullis",
        icon=_build_tray_image(64),
        title="Cullis Connector",
    )

    def _quit_all() -> None:
        icon.stop()
        window.destroy()

    icon.menu = _build_menu(_open_dashboard, _open_inbox, _quit_all)
    icon.run_detached()

    _log.info(
        "desktop shell ready — tray icon active, dashboard at %s",
        base_url,
    )
    webview.start(private_mode=False)
    return 0
