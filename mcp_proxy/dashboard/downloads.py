"""Public download page for the Cullis Connector.

Kept in its own APIRouter on purpose — the main dashboard router is the
admin control plane and is being re-shaped by the ADR-006 work; touching
it would force merge-rebase gymnastics for a page that has nothing to do
with broker state. Mount it from ``mcp_proxy/main.py`` with a single
``include_router`` line.

The page is anonymous (no admin login). Its job is to hand an end user a
zip + a one-line "here's where to send your enrollment" hint — the rest
of onboarding happens inside their local connector dashboard.
"""
from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import urlparse

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from mcp_proxy.dashboard._template_env import build_templates


_TEMPLATE_DIR = Path(__file__).parent / "templates"
templates = build_templates(_TEMPLATE_DIR)

router = APIRouter(prefix="/downloads", tags=["downloads"])


# Admins running an air-gapped deploy can override to point at an
# internal mirror (e.g. S3 bucket that caches GitHub Releases). Default
# is the public repo's ``latest`` redirect — zip filenames are stable
# across versions thanks to the release-connector workflow.
_DEFAULT_BASE = "https://github.com/cullis-security/cullis/releases/latest/download"
DOWNLOAD_BASE = os.environ.get("MCP_PROXY_CONNECTOR_DOWNLOAD_BASE", _DEFAULT_BASE).rstrip("/")

_ASSETS = {
    "macos":   "cullis-connector-macos.zip",
    "linux":   "cullis-connector-linux.zip",
    "windows": "cullis-connector-windows.zip",
}


@router.get("/", response_class=HTMLResponse)
def downloads_index(request: Request) -> Response:
    """Render the download page with per-OS cards and the proxy's
    public URL ready to paste into the local connector dashboard."""
    detected = _detect_os(request.headers.get("user-agent", ""))
    proxy_url = _proxy_public_url(request)

    return templates.TemplateResponse(
        request,
        "downloads.html",
        {
            "proxy_url": proxy_url,
            "detected_os": detected,
            "assets": [
                {
                    "id": "macos",
                    "name": "macOS",
                    "filename": _ASSETS["macos"],
                    "url": f"{DOWNLOAD_BASE}/{_ASSETS['macos']}",
                    "size_hint": "~20 MB",
                    "sub": "Apple Silicon & Intel",
                },
                {
                    "id": "windows",
                    "name": "Windows",
                    "filename": _ASSETS["windows"],
                    "url": f"{DOWNLOAD_BASE}/{_ASSETS['windows']}",
                    "size_hint": "~20 MB",
                    "sub": "Windows 10+",
                },
                {
                    "id": "linux",
                    "name": "Linux",
                    "filename": _ASSETS["linux"],
                    "url": f"{DOWNLOAD_BASE}/{_ASSETS['linux']}",
                    "size_hint": "~20 MB",
                    "sub": "x86_64 · systemd",
                },
            ],
        },
    )


@router.get("/{platform}")
def download_redirect(platform: str) -> Response:
    """Short, shareable link: ``/downloads/mac`` / ``/windows`` / ``/linux``
    redirects to the canonical zip so admins can post a clean URL in
    onboarding emails without copying the full asset name each time."""
    key = _normalize_platform(platform)
    if key is None:
        return RedirectResponse("/downloads/", status_code=303)
    return RedirectResponse(f"{DOWNLOAD_BASE}/{_ASSETS[key]}", status_code=302)


# ── Helpers ───────────────────────────────────────────────────────────


def _detect_os(user_agent: str) -> str:
    """Best-effort OS detection from UA string. Used to visually highlight
    the correct card, never to gate downloads."""
    ua = user_agent.lower()
    if "mac os x" in ua or "macintosh" in ua:
        return "macos"
    if "windows" in ua:
        return "windows"
    if "linux" in ua or "x11" in ua:
        return "linux"
    return ""


def _normalize_platform(raw: str) -> str | None:
    raw = raw.lower()
    if raw in ("mac", "macos", "osx", "darwin"):
        return "macos"
    if raw in ("win", "windows"):
        return "windows"
    if raw in ("linux",):
        return "linux"
    return None


def _proxy_public_url(request: Request) -> str:
    """Return the URL an end user should paste into their local connector
    dashboard to reach this proxy.

    Preference order:
      1. ``MCP_PROXY_PROXY_PUBLIC_URL`` env var (same one DPoP uses —
         explicitly set for deployments behind an ingress / load
         balancer that rewrites the Host header).
      2. The scheme + host from the incoming request, which is correct
         for the common "user opens the page directly on the proxy".
    """
    configured = os.environ.get("MCP_PROXY_PROXY_PUBLIC_URL", "").strip().rstrip("/")
    if configured:
        return configured
    parsed = urlparse(str(request.url))
    host = request.headers.get("x-forwarded-host") or parsed.netloc
    scheme = request.headers.get("x-forwarded-proto") or parsed.scheme or "https"
    return f"{scheme}://{host}"
