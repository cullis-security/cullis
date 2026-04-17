"""
E2E helper — provision a Cullis org and/or its first agent inside a
running mcp_proxy container.

Two phases (driven by --phase) because in the real flow the broker
side enforces "org must be approved before any agent registration":

  --phase=org    Register the org with the broker (status=pending),
                 generate Org CA, save broker_url + invite token in
                 proxy_config. Idempotent: re-running on the same DB
                 is a no-op as long as the org_secret is preserved.

  --phase=agent  Create the local internal agent (x509 cert + API key)
                 and call the broker registry endpoints to register
                 the agent + create+approve a binding. Requires the
                 org to already be `active` on the broker side, i.e.
                 the network admin has called approve_org between the
                 two phases.

The two phases share state via the proxy_config table — phase=agent
reads `org_id`, `org_secret`, `org_ca_cert`, `org_ca_key`, `broker_url`
that phase=org persisted.

Output (phase=agent only): single JSON line on stdout with the
credentials the test runner needs to drive the egress API:
    {"org_id": "...", "agent_id": "...", "api_key": "..."}

Usage:
    python /e2e_scripts/setup_proxy_org.py \
        --phase        org \
        --broker-url   http://broker:8000 \
        --invite-token <token> \
        --org-id       acme \
        --display-name "Acme Corp"

    python /e2e_scripts/setup_proxy_org.py \
        --phase        agent \
        --org-id       acme \
        --agent-name   buyer \
        --capabilities procurement.read,procurement.write
"""
import argparse
import asyncio
import json
import os
import secrets
import sys
from typing import Any

# The proxy image installs the codebase under /app
sys.path.insert(0, "/app")

import httpx  # noqa: E402

from mcp_proxy.config import get_settings as _proxy_settings  # noqa: E402
from mcp_proxy.db import init_db, set_config, get_config  # noqa: E402, F401
from mcp_proxy.dashboard.router import generate_org_ca  # noqa: E402
from mcp_proxy.egress.agent_manager import AgentManager  # noqa: E402


# ─────────────────────────────────────────────────────────────────────────────
# Phase: register org with broker
# ─────────────────────────────────────────────────────────────────────────────

async def _register_org_with_broker(
    broker_url: str,
    invite_token: str,
    org_id: str,
    display_name: str,
    secret: str,
    ca_pem: str,
    webhook_url: str,
) -> dict[str, Any]:
    """POST /v1/onboarding/join — same call the dashboard register endpoint makes."""
    async with httpx.AsyncClient(verify=False, timeout=15.0) as http:
        resp = await http.post(
            f"{broker_url}/v1/onboarding/join",
            json={
                "org_id": org_id,
                "display_name": display_name,
                "secret": secret,
                "ca_certificate": ca_pem,
                "contact_email": f"e2e+{org_id}@example.test",
                "webhook_url": webhook_url,
                "invite_token": invite_token,
            },
        )
    return {"status_code": resp.status_code, "body": resp.text[:500]}


async def _do_phase_org(args: argparse.Namespace) -> None:
    if not args.broker_url:
        print("--phase=org requires --broker-url", file=sys.stderr)
        sys.exit(2)
    if not args.invite_token:
        print("--phase=org requires --invite-token", file=sys.stderr)
        sys.exit(2)
    if not args.display_name:
        print("--phase=org requires --display-name", file=sys.stderr)
        sys.exit(2)

    # Save broker URL + invite token in proxy_config (login equivalent)
    await set_config("broker_url", args.broker_url)
    await set_config("invite_token", args.invite_token)

    # Generate Org CA and persist
    org_secret = secrets.token_urlsafe(32)
    ca_cert_pem, ca_key_pem = generate_org_ca(args.org_id)
    await set_config("org_id", args.org_id)
    await set_config("org_secret", org_secret)
    await set_config("org_ca_cert", ca_cert_pem)
    await set_config("org_ca_key", ca_key_pem)

    # Call broker /onboarding/join
    webhook_url = args.pdp_url or os.environ.get("MCP_PROXY_PDP_URL", "")
    join_result = await _register_org_with_broker(
        broker_url=args.broker_url,
        invite_token=args.invite_token,
        org_id=args.org_id,
        display_name=args.display_name,
        secret=org_secret,
        ca_pem=ca_cert_pem,
        webhook_url=webhook_url,
    )
    if join_result["status_code"] not in (201, 202):
        print(json.dumps({
            "error": "broker /onboarding/join failed",
            "details": join_result,
        }), file=sys.stderr)
        sys.exit(2)
    await set_config("org_status", "pending")

    # Returning org_secret here is intentional: the demo orchestrator uses it
    # to print broker dashboard credentials so an audience can log in as the
    # org and explore the architecture. Tests ignore this field.
    print(json.dumps({
        "phase":      "org",
        "org_id":     args.org_id,
        "status":     "registered",
        "org_secret": org_secret,
    }))


# ─────────────────────────────────────────────────────────────────────────────
# Phase: create local agent + register with broker
# ─────────────────────────────────────────────────────────────────────────────

async def _mark_federated(agent_id: str) -> None:
    """Flip ``internal_agents.federated=True`` + bump revision.

    ADR-010 Phase 6a-4 — ``POST /v1/registry/agents`` is gone. The
    publisher loop (Phase 3) picks the flag up on its next tick and
    pushes the agent to the Court via ``POST /v1/federation/publish-
    agent``. We're inside the proxy container, so we have DB access
    directly.
    """
    from mcp_proxy.db import get_db
    from sqlalchemy import text

    async with get_db() as conn:
        await conn.execute(
            text(
                """
                UPDATE internal_agents
                   SET federated = :fed,
                       federation_revision = federation_revision + 1
                 WHERE agent_id = :aid
                """
            ),
            {"fed": True, "aid": agent_id},
        )


async def _bind_agent_to_broker(
    broker_url: str,
    org_id: str,
    org_secret: str,
    agent_id: str,
    display_name: str,
    capabilities: list[str],
    timeout_s: float = 60.0,
    retry_s: float = 2.0,
) -> None:
    """Mark local row as federated, retry binding-create until the
    publisher has propagated the agent, then approve.

    ADR-010 Phase 6a-4 rewrite: the legacy
    ``POST /v1/registry/agents`` path is gone; the Mastio is the sole
    authoritative writer for agent records and the publisher carries
    federated rows to the Court. Bindings still flow through
    ``POST /v1/registry/bindings`` (endpoint unchanged).
    """
    import time

    await _mark_federated(agent_id)

    headers = {"X-Org-Id": org_id, "X-Org-Secret": org_secret}
    body = {"org_id": org_id, "agent_id": agent_id, "scope": capabilities}

    deadline = time.monotonic() + timeout_s
    last = "(no attempt)"
    binding_id: str | None = None
    async with httpx.AsyncClient(verify=False, timeout=15.0) as http:
        # Retry binding create until the publisher has pushed the agent
        # to the Court. 404 = not yet visible, retry. 201 = created,
        # proceed to approve. 409 = already exists (re-run), fetch id
        # from the bindings list and skip straight to approve.
        while time.monotonic() < deadline:
            resp = await http.post(
                f"{broker_url}/v1/registry/bindings",
                json=body, headers=headers,
            )
            if resp.status_code == 201:
                binding_id = resp.json().get("id")
                break
            if resp.status_code == 409:
                list_resp = await http.get(
                    f"{broker_url}/v1/registry/bindings",
                    params={"org_id": org_id},
                    headers=headers,
                )
                list_resp.raise_for_status()
                binding_id = next(
                    (b["id"] for b in list_resp.json()
                     if b.get("agent_id") == agent_id),
                    None,
                )
                break
            last = f"HTTP {resp.status_code} {resp.text[:200]}"
            await asyncio.sleep(retry_s)

        if binding_id is None:
            raise RuntimeError(
                f"create_binding never succeeded within {timeout_s:.0f}s "
                f"(publisher stuck? last={last})"
            )

        approve_resp = await http.post(
            f"{broker_url}/v1/registry/bindings/{binding_id}/approve",
            headers=headers,
        )
        if approve_resp.status_code not in (200, 204):
            raise RuntimeError(
                f"approve_binding failed: HTTP {approve_resp.status_code} "
                f"{approve_resp.text[:300]}"
            )


async def _do_phase_agent(args: argparse.Namespace) -> None:
    if not args.agent_name:
        print("--phase=agent requires --agent-name", file=sys.stderr)
        sys.exit(2)
    if not args.capabilities:
        print("--phase=agent requires --capabilities", file=sys.stderr)
        sys.exit(2)

    capabilities = [c.strip() for c in args.capabilities.split(",") if c.strip()]

    # Pull state stashed by phase=org
    broker_url = await get_config("broker_url") or args.broker_url
    org_secret = await get_config("org_secret") or ""
    if not broker_url or not org_secret:
        print(json.dumps({
            "error": "phase=agent requires phase=org to have run first "
                     "(broker_url and org_secret missing from proxy_config)",
        }), file=sys.stderr)
        sys.exit(3)

    # Create local agent (x509 + API key)
    mgr = AgentManager(org_id=args.org_id)
    if not await mgr.load_org_ca_from_config():
        print(json.dumps({"error": "Org CA load from config failed"}), file=sys.stderr)
        sys.exit(3)

    agent_info, raw_key = await mgr.create_agent(
        args.agent_name,
        f"E2E {args.agent_name}",
        capabilities,
    )
    agent_id = agent_info["agent_id"]

    # ADR-010 Phase 6a-4 — ``AgentManager.create_agent`` no longer pushes
    # the agent to the Court (the legacy broker-register call was removed
    # with ``POST /v1/registry/agents``). Flip the ``federated`` flag and
    # wait for the publisher to carry the row to the Court so the
    # cross-org binding can be approved here.
    await _bind_agent_to_broker(
        broker_url=broker_url,
        org_id=args.org_id,
        org_secret=org_secret,
        agent_id=agent_id,
        display_name=f"E2E {args.agent_name}",
        capabilities=capabilities,
    )

    print(json.dumps({
        "phase":    "agent",
        "org_id":   args.org_id,
        "agent_id": agent_id,
        "api_key":  raw_key,
    }))


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", required=True, choices=["org", "agent"])
    parser.add_argument("--org-id", required=True)
    # phase=org args
    parser.add_argument("--broker-url",   default="")
    parser.add_argument("--invite-token", default="")
    parser.add_argument("--display-name", default="")
    parser.add_argument("--pdp-url",      default="",
                        help="PDP webhook URL — defaults to MCP_PROXY_PDP_URL env")
    # phase=agent args
    parser.add_argument("--agent-name",   default="")
    parser.add_argument("--capabilities", default="",
                        help="comma-separated list (phase=agent)")
    args = parser.parse_args()

    # Init DB schema — read DB path from the same env var the proxy
    # main process uses (MCP_PROXY_DATABASE_URL).
    await init_db(_proxy_settings().database_url)

    if args.phase == "org":
        await _do_phase_org(args)
    elif args.phase == "agent":
        await _do_phase_agent(args)


if __name__ == "__main__":
    asyncio.run(main())
