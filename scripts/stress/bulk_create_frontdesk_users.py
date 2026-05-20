#!/usr/bin/env python3
"""Bulk-seed N Frontdesk test users for k6 stress runs.

Mirrors ``bulk_enroll_agents.py`` for the Mastio side. Two-step flow:

  1. Bulk POST to the Frontdesk ``/admin/users`` endpoint (gated by
     ``X-Admin-Secret``). Each call creates one row in ``local_users``
     with ``must_change_password=False`` so subsequent logins go
     straight to the provisioning path. Parallelised through aiohttp
     with bounded concurrency to keep bcrypt cost 12 from saturating
     the Connector CPU.

  2. Optional pre-warmup: parallel ``POST /api/auth/login`` per user.
     Each successful login triggers ``LocalUserProvisioner`` which
     mints a user cert via Mastio's ``/v1/principals/csr`` and caches
     it in ``UserCredentialCache``. Without warmup, the first k6
     iteration per VU pays the CSR roundtrip; with warmup the cache
     is hot and the k6 measurements reflect steady state.

Output: ``stress_frontdesk_users.json`` next to this script — list of
{user_name, password} + base URL the k6 scenario should target. **Local
only** (carries cleartext shared password). Already gitignored alongside
``stress_agents.json``.

Required env (or CLI flag):
  - ``CULLIS_CONNECTOR_ADMIN_SECRET`` (or ``--admin-secret``) — the
    Connector admin secret. Read from ``packaging/frontdesk-bundle/
    frontdesk.env`` after ``deploy.sh`` or from the sandbox proxy.env
    after ``dogfood-frontdesk.sh``.

Usage::

    nix-shell -p 'python311.withPackages(ps: with ps; [ aiohttp ])' --run \\
        "python scripts/stress/bulk_create_frontdesk_users.py \\
            --n 100 --wipe --warmup"

    # Local sandbox (dogfood-frontdesk.sh):
    CULLIS_CONNECTOR_ADMIN_SECRET=$(docker exec \\
        dogfood-frontdesk-frontdesk-connector-1 \\
        sh -c 'echo $CULLIS_CONNECTOR_ADMIN_SECRET') \\
        python scripts/stress/bulk_create_frontdesk_users.py \\
            --n 50 --wipe --warmup --base-url http://localhost:18080
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import secrets
import ssl
import sys
import time
from pathlib import Path
from typing import Optional


HERE = Path(__file__).resolve().parent

DEFAULT_BASE_URL = os.environ.get(
    "FRONTDESK_BASE_URL", "http://localhost:18080",
)
DEFAULT_ADMIN_SECRET = os.environ.get("CULLIS_CONNECTOR_ADMIN_SECRET", "")


async def _create_one(
    session, base_url: str, admin_secret: str,
    user_name: str, password: str, timeout_s: float,
) -> tuple[str, str, Optional[str]]:
    """One create-user call. Returns (user_name, status, error_detail)."""
    try:
        async with session.post(
            f"{base_url}/admin/users",
            json={
                "user_name": user_name,
                "password": password,
                "must_change_password": False,
                "display_name": f"Stress {user_name}",
            },
            headers={"X-Admin-Secret": admin_secret},
            timeout=timeout_s,
        ) as resp:
            text = await resp.text()
            if resp.status == 201:
                return user_name, "created", None
            if resp.status == 409:
                # Already exists — re-runs are idempotent only if --wipe
                # was used. Treat as "skipped" so the operator can spot
                # the situation without it counting as failure.
                return user_name, "exists", text[:200]
            return user_name, "http_error", f"{resp.status}: {text[:200]}"
    except Exception as exc:  # noqa: BLE001
        return user_name, "exception", str(exc)


async def _delete_prefix(
    base_url: str, admin_secret: str, prefix: str,
    *, concurrency: int, timeout_s: float, insecure_tls: bool,
) -> int:
    """Best-effort DELETE for every existing <prefix>-* user. Returns count."""
    import aiohttp

    ssl_ctx = None
    if base_url.startswith("https://") and insecure_tls:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

    connector = aiohttp.TCPConnector(limit=concurrency, ssl=ssl_ctx)
    async with aiohttp.ClientSession(connector=connector) as session:
        # List first, then delete each matching user. We paginate by
        # asking for a large batch; /admin/users returns everything in
        # one go for the sizes we work with here.
        try:
            async with session.get(
                f"{base_url}/admin/users",
                headers={"X-Admin-Secret": admin_secret},
                timeout=timeout_s,
            ) as resp:
                if resp.status != 200:
                    sys.stderr.write(
                        f"  wipe: GET /admin/users returned {resp.status}, "
                        "skipping wipe\n",
                    )
                    return 0
                body = await resp.json()
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write(f"  wipe: list call failed: {exc}\n")
            return 0

        targets = [
            u["user_name"] for u in body.get("users", [])
            if u["user_name"].startswith(f"{prefix}-")
        ]
        if not targets:
            return 0

        sem = asyncio.Semaphore(concurrency)

        async def _del_one(name: str) -> bool:
            async with sem:
                try:
                    async with session.delete(
                        f"{base_url}/admin/users/{name}",
                        headers={"X-Admin-Secret": admin_secret},
                        timeout=timeout_s,
                    ) as resp:
                        return resp.status in (200, 204, 404)
                except Exception:  # noqa: BLE001
                    return False

        ok = await asyncio.gather(*[_del_one(n) for n in targets])
        return sum(1 for x in ok if x)


async def bulk_create_http(
    base_url: str, admin_secret: str, users: list[dict],
    *, concurrency: int, timeout_s: float, insecure_tls: bool,
) -> dict:
    """Parallel POST /admin/users for all users."""
    import aiohttp

    ssl_ctx = None
    if base_url.startswith("https://") and insecure_tls:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

    connector = aiohttp.TCPConnector(limit=concurrency, ssl=ssl_ctx)
    sem = asyncio.Semaphore(concurrency)
    counts = {"created": 0, "exists": 0, "http_error": 0, "exception": 0}
    errors_sample: list[dict] = []

    async with aiohttp.ClientSession(connector=connector) as session:
        async def bounded(u):
            async with sem:
                return await _create_one(
                    session, base_url, admin_secret,
                    u["user_name"], u["password"], timeout_s,
                )

        t0 = time.time()
        coros = [bounded(u) for u in users]
        for fut in asyncio.as_completed(coros):
            user_name, status, detail = await fut
            counts[status] = counts.get(status, 0) + 1
            if status not in {"created", "exists"} and len(errors_sample) < 5:
                errors_sample.append(
                    {"user": user_name, "status": status, "detail": detail},
                )

    return {
        **counts,
        "errors_sample": errors_sample,
        "elapsed_s": round(time.time() - t0, 2),
        "rps": round(len(users) / max(time.time() - t0, 0.001), 1),
    }


async def _login_one(
    session,
    base_url: str,
    user_name: str,
    password: str,
    timeout_s: float,
) -> tuple[str, str, Optional[str]]:
    """One login call. Returns (user_name, status, error_detail)."""
    import aiohttp  # noqa: F401  imported for type
    try:
        async with session.post(
            f"{base_url}/api/auth/login",
            json={"user_name": user_name, "password": password},
            timeout=timeout_s,
        ) as resp:
            text = await resp.text()
            if resp.status != 200:
                return user_name, "http_error", f"{resp.status}: {text[:200]}"
            try:
                body = json.loads(text)
            except json.JSONDecodeError:
                return user_name, "bad_json", text[:200]
            prov = body.get("provisioning", "?")
            if prov == "ok":
                return user_name, "ok", None
            return user_name, f"prov_{prov}", body.get("provisioning_detail")
    except Exception as exc:  # noqa: BLE001
        return user_name, "exception", str(exc)


async def warmup_logins(
    base_url: str,
    users: list[dict],
    *,
    concurrency: int,
    timeout_s: float,
    insecure_tls: bool,
) -> dict:
    """Parallel login pre-warm. Populates the per-user cred cache."""
    import aiohttp

    ssl_ctx = None
    if base_url.startswith("https://") and insecure_tls:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

    connector = aiohttp.TCPConnector(limit=concurrency, ssl=ssl_ctx)
    sem = asyncio.Semaphore(concurrency)
    results = {"ok": 0, "prov_deferred": 0, "prov_skipped": 0,
               "http_error": 0, "exception": 0, "bad_json": 0,
               "errors_sample": []}

    async with aiohttp.ClientSession(connector=connector) as session:
        async def bounded(u):
            async with sem:
                return await _login_one(
                    session, base_url, u["user_name"], u["password"], timeout_s,
                )

        t0 = time.time()
        coros = [bounded(u) for u in users]
        for fut in asyncio.as_completed(coros):
            user_name, status, detail = await fut
            key = status if status in results else "exception"
            results[key] = results.get(key, 0) + 1
            if status != "ok" and len(results["errors_sample"]) < 5:
                results["errors_sample"].append(
                    {"user": user_name, "status": status, "detail": detail},
                )

    results["elapsed_s"] = round(time.time() - t0, 2)
    results["rps"] = round(len(users) / max(results["elapsed_s"], 0.001), 1)
    return results


def main() -> None:
    p = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--n", type=int, required=True, help="number of users to seed")
    p.add_argument("--prefix", default="stress",
                   help="user_name prefix (default 'stress' → stress-00001..)")
    p.add_argument("--wipe", action="store_true",
                   help="DELETE any prior <prefix>-* users via /admin/users first")
    p.add_argument("--password", default=None,
                   help="shared password (default: random 24-char)")
    p.add_argument("--base-url", default=DEFAULT_BASE_URL,
                   help=f"Frontdesk base URL (default {DEFAULT_BASE_URL})")
    p.add_argument("--admin-secret", default=DEFAULT_ADMIN_SECRET,
                   help="X-Admin-Secret value (default from "
                        "CULLIS_CONNECTOR_ADMIN_SECRET env)")
    p.add_argument("--create-concurrency", type=int, default=10,
                   help="max concurrent /admin/users POSTs (default 10; bcrypt "
                        "cost 12 saturates CPU above this)")
    p.add_argument("--create-timeout-s", type=float, default=30.0,
                   help="per-create timeout in seconds (default 30)")
    p.add_argument("--warmup", action="store_true",
                   help="run parallel pre-login to warm provisioner cache")
    p.add_argument("--warmup-concurrency", type=int, default=20,
                   help="max concurrent logins during warmup (default 20)")
    p.add_argument("--warmup-timeout-s", type=float, default=30.0,
                   help="per-login timeout in seconds (default 30)")
    p.add_argument("--insecure-tls", action="store_true",
                   help="skip TLS verify (for self-signed Frontdesk certs)")
    p.add_argument("--output", default=str(HERE / "stress_frontdesk_users.json"),
                   help="where to write the user manifest")
    args = p.parse_args()

    if args.n < 1:
        sys.exit("--n must be >= 1")
    if not args.admin_secret:
        sys.exit(
            "missing admin secret. Pass --admin-secret or set "
            "CULLIS_CONNECTOR_ADMIN_SECRET. For the sandbox dogfood run:\n"
            "  CULLIS_CONNECTOR_ADMIN_SECRET=$(docker exec "
            "dogfood-frontdesk-frontdesk-connector-1 "
            "sh -c 'echo $CULLIS_CONNECTOR_ADMIN_SECRET')",
        )

    password = args.password or secrets.token_urlsafe(18) + "Aa1!"
    if len(password) < 8:
        sys.exit("password too short (need >=8 chars)")

    users = [
        {"user_name": f"{args.prefix}-{i:05d}", "password": password}
        for i in range(1, args.n + 1)
    ]

    if args.wipe:
        sys.stderr.write(
            f"  wipe: deleting any prior '{args.prefix}-*' users...\n",
        )
        deleted = asyncio.run(_delete_prefix(
            args.base_url, args.admin_secret, args.prefix,
            concurrency=args.warmup_concurrency,
            timeout_s=args.create_timeout_s,
            insecure_tls=args.insecure_tls,
        ))
        sys.stderr.write(f"  wipe: deleted {deleted} prior rows\n")

    sys.stderr.write(
        f"  creating {len(users)} users via POST /admin/users "
        f"(concurrency={args.create_concurrency})...\n",
    )
    create_report = asyncio.run(bulk_create_http(
        args.base_url, args.admin_secret, users,
        concurrency=args.create_concurrency,
        timeout_s=args.create_timeout_s,
        insecure_tls=args.insecure_tls,
    ))
    sys.stderr.write(
        f"  create done in {create_report['elapsed_s']}s "
        f"({create_report['rps']}/s) created={create_report['created']} "
        f"exists={create_report['exists']} "
        f"errors={create_report['http_error'] + create_report['exception']}\n",
    )
    if create_report["created"] + create_report["exists"] < len(users) * 0.95:
        sys.exit(
            f"FAIL: fewer than 95% of users were created. "
            f"errors={create_report['errors_sample']}",
        )

    manifest = {
        "base_url": args.base_url,
        "prefix": args.prefix,
        "shared_password": password,
        "n_users": args.n,
        "users": users,
        "create_report": create_report,
    }

    if args.warmup:
        sys.stderr.write(
            f"  warmup: parallel login on {len(users)} users "
            f"(concurrency={args.warmup_concurrency})...\n",
        )
        warm = asyncio.run(warmup_logins(
            args.base_url, users,
            concurrency=args.warmup_concurrency,
            timeout_s=args.warmup_timeout_s,
            insecure_tls=args.insecure_tls,
        ))
        manifest["warmup"] = warm
        sys.stderr.write(
            f"  warmup done in {warm['elapsed_s']}s "
            f"({warm['rps']}/s) ok={warm['ok']} "
            f"deferred={warm.get('prov_deferred', 0)} "
            f"errors={warm.get('http_error', 0) + warm.get('exception', 0)}\n",
        )
        if warm["ok"] < len(users) * 0.95:
            sys.stderr.write(
                f"  WARN: fewer than 95% of warmup logins succeeded. "
                f"Inspect errors_sample in {args.output}.\n",
            )

    Path(args.output).write_text(json.dumps(manifest, indent=2))
    sys.stderr.write(f"  manifest -> {args.output} ({len(users)} users)\n")


if __name__ == "__main__":
    main()
