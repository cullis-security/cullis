# PyInstaller spec for a single-binary cullis-connector distribution.
#
# Build locally:
#     pyinstaller cullis-connector.spec
#
# The CI workflow (.github/workflows/release-connector.yml) runs this on
# all three OSes and uploads a zip containing the binary + an installer
# script. See imp/connector_desktop_plan.md for how the whole chain fits.

# Templates and static files must ship as data files — Jinja2Templates
# and StaticFiles read them off disk at runtime relative to
# cullis_connector/__file__.
#
# The ``cullis_connector/static`` entry covers two surfaces:
#   - dashboard CSS + favicon (always present in the source tree)
#   - the Cullis Chat SPA dist at ``cullis_connector/static/cullis-chat/``,
#     which only exists if ``scripts/build-spa.sh`` was run before
#     PyInstaller (ADR-019 Phase 8d). The release CI workflow does this
#     automatically; local builds need to invoke the script first or the
#     resulting binary will log "cullis-chat SPA not mounted" at boot.
datas = [
    ("cullis_connector/templates", "cullis_connector/templates"),
    ("cullis_connector/static", "cullis_connector/static"),
]

# uvicorn picks its loop / protocol implementations dynamically — list
# every automatic import so PyInstaller bundles them. Without these the
# packaged binary fails with "No module named 'uvicorn.loops.asyncio'".
hiddenimports = [
    "uvicorn.loops.auto",
    "uvicorn.loops.asyncio",
    "uvicorn.lifespan.on",
    "uvicorn.lifespan.off",
    "uvicorn.protocols.http.auto",
    "uvicorn.protocols.http.h11_impl",
    "uvicorn.protocols.websockets.auto",
    "uvicorn.protocols.websockets.wsproto_impl",
    "uvicorn.logging",
]

# Desktop shell deps are imported lazily inside function bodies in
# cullis_connector/desktop_app.py and notifier.py, so PyInstaller's
# static analysis misses them. Pull in every submodule — each ships
# platform-specific backends (pystray._xorg / _win32 / _darwin,
# webview.platforms.*, plyer.platforms.*) chosen at runtime.
from PyInstaller.utils.hooks import collect_submodules

for _pkg in ("pystray", "webview", "plyer", "PIL"):
    try:
        hiddenimports += collect_submodules(_pkg)
    except Exception:
        # Package not installed (e.g. building a connector-only binary
        # without the desktop extras) — skip silently.
        pass
# NOTE: gi (pygobject) and cairo (pycairo) are intentionally NOT bundled.
# They ship with the host Python on every supported desktop target:
#   - macOS runners:   `brew install pygobject3` side-installs them
#   - Windows runners: pip wheels resolve them cleanly
#   - Ubuntu runners:  `apt install python3-gi` puts them in site-packages
# Bundling them cross-platform risks ABI mismatches against the OS-provided
# GLib/GObjectIntrospection at runtime (observed on NixOS: "TypeError:
# must be an interface" during gi.overrides.Gtk import).


a = Analysis(
    ["cullis_connector/__main__.py"],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # The MCP server is only spawned by the IDE; the dashboard
        # binary never needs the full mcp stdio stack. Trimming it
        # keeps the bundle a few MB smaller. Uncomment if you want
        # one binary that does both roles.
        # "mcp",
    ],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="cullis-connector",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,  # keep stdout/stderr visible — users debug via terminal
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
