"""Background watcher for the nginx sidecar server TLS cert expiry.

Wave 2 fix 6 (post audit 2026-05-18). Boot-time
:meth:`AgentManager.ensure_nginx_server_cert` already mints / renews the
nginx leaf when the Mastio container starts, but the renewal only runs
once at boot. A container that stays up beyond the cert validity
(``NGINX_SERVER_CERT_VALIDITY_DAYS`` = 90d post-A) would serve an
expired cert until the operator restarted manually.

This loop closes the gap. Once per ``tick_seconds`` (default 24h) the
leader-elected worker invokes ``ensure_nginx_server_cert`` again with
the configured ``renew_within_days`` threshold. The method is
idempotent: if the on-disk leaf is fresh, SAN-correct, and issued by
the current Intermediate, nothing is written; otherwise a new leaf is
emitted and the trust bundle rewritten. A change in the cert file's
mtime is the signal the sidecar ``nginx-reload-watcher`` script picks
up to send ``nginx -s reload`` — no docker socket, no SIGHUP from the
Mastio container needed.

Audit chain entries:

* ``pki.nginx_server_cert_rotated`` (status=success) on every actual
  rewrite, with the new expiry + SAN list in ``detail``.
* ``pki.nginx_server_cert_rotation_failed`` (status=error) on
  exception. The loop continues so the next tick retries.

Leader-elected via :func:`mcp_proxy.lifespan.get_leader` so only one
worker runs the loop in a multi-worker deployment (pattern from
PR #784, replicated by ``intermediate_ca_watcher.py``).
"""
from __future__ import annotations

import asyncio
import logging
from datetime import timezone

logger = logging.getLogger("mcp_proxy.lifespan.nginx_cert_watcher")

_DEFAULT_TICK_SECONDS = 24 * 60 * 60


async def nginx_cert_watcher_loop(
    agent_manager,
    *,
    out_dir: str,
    sans: list[str],
    tick_seconds: int = _DEFAULT_TICK_SECONDS,
    renew_within_days: int = 30,
    stop_event: asyncio.Event | None = None,
) -> None:
    """Loop tail: check expiry, rotate if needed, audit on rotation."""
    stop_event = stop_event or asyncio.Event()
    logger.info(
        "nginx_cert_watcher loop starting (tick=%ds, renew_within=%dd, sans=%s)",
        tick_seconds, renew_within_days, ",".join(sans),
    )
    while not stop_event.is_set():
        try:
            await _check_once(
                agent_manager,
                out_dir=out_dir,
                sans=sans,
                renew_within_days=renew_within_days,
            )
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "nginx_cert_watcher tick raised %s — continuing", exc,
            )
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=tick_seconds)
        except asyncio.TimeoutError:
            pass
    logger.info("nginx_cert_watcher loop stopped")


async def _check_once(
    agent_manager,
    *,
    out_dir: str,
    sans: list[str],
    renew_within_days: int,
) -> None:
    """One tick: call ensure_nginx_server_cert, audit on rotation."""
    from mcp_proxy.db import log_audit

    if getattr(agent_manager, "_mastio_ca_cert", None) is None:
        logger.debug(
            "nginx_cert_watcher: Mastio Intermediate not loaded — skipping tick",
        )
        return

    try:
        rotated = await agent_manager.ensure_nginx_server_cert(
            out_dir=out_dir,
            sans=sans,
            renew_within_days=renew_within_days,
        )
    except Exception as exc:
        logger.error(
            "nginx_cert_watcher: ensure_nginx_server_cert failed: %s — "
            "audit + continue (next tick retries)", exc,
        )
        try:
            await log_audit(
                agent_id="system",
                action="pki.nginx_server_cert_rotation_failed",
                status="error",
                detail=f"error={type(exc).__name__}",
            )
        except Exception:
            pass
        return

    if not rotated:
        return

    not_after_iso = ""
    try:
        from pathlib import Path
        from cryptography import x509
        crt_path = Path(out_dir) / "mastio-server.crt"
        leaf = x509.load_pem_x509_certificate(crt_path.read_bytes())
        not_after = leaf.not_valid_after
        if not_after.tzinfo is None:
            not_after = not_after.replace(tzinfo=timezone.utc)
        not_after_iso = not_after.isoformat(timespec="seconds")
    except Exception as exc:  # noqa: BLE001
        logger.debug(
            "nginx_cert_watcher: failed to read new cert for audit detail: %s",
            exc,
        )

    logger.info(
        "nginx_cert_watcher: nginx server cert rotated (new_expiry=%s)",
        not_after_iso or "unknown",
    )
    try:
        await log_audit(
            agent_id="system",
            action="pki.nginx_server_cert_rotated",
            status="success",
            detail=(
                f"new_expiry={not_after_iso!r} "
                f"sans={','.join(sans)!r} "
                f"renew_within_days={renew_within_days}"
            ),
        )
    except Exception:
        pass


__all__ = ["nginx_cert_watcher_loop"]
