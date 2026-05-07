"""
Hardcoded demo cast for Phase 1 of the SPA rework (insurance demo).

The Mastio admin dashboard renders four principal-type sections (Users,
Agents, Workloads, Resources). The corresponding admin REST routes
(/v1/admin/users, /v1/admin/workloads) are still being designed by the
backend session — see ``imp/insurance-demo-spec.md``. Until those land,
this module returns the principal cast hardcoded from the spec so the
dashboard can be screenshot-recorded for the demo.

Swap path: when the admin endpoints ship, replace each ``*_cast`` call
in ``app/dashboard/router.py`` with an httpx call to the real route.
This module then deletes cleanly.
"""
from __future__ import annotations


def users_cast() -> list[dict]:
    """Return the user principals from the insurance demo spec."""
    return [
        {
            "principal_id": "mediterranean::user::claim-officer",
            "display_name": "Claim Officer",
            "reach": "cross",
            "surface": "Cullis Chat (desktop)",
            "last_active": "active",
            "last_active_iso": None,
        },
        {
            "principal_id": "mediterranean::user::claim-manager",
            "display_name": "Claim Manager",
            "reach": "cross",
            "surface": "Cullis Chat /chat (web)",
            "last_active": "active",
            "last_active_iso": None,
        },
        {
            "principal_id": "asia-pacific::user::counterparty-liaison",
            "display_name": "Counterparty Liaison",
            "reach": "both",
            "surface": "Frontdesk (web)",
            "last_active": "active",
            "last_active_iso": None,
        },
    ]


def workloads_cast() -> list[dict]:
    """Return the workload principals from the insurance demo spec."""
    return [
        {
            "principal_id": "asia-pacific::workload::frontdesk-container",
            "display_name": "Asia-Pacific Frontdesk",
            "reach": "both",
            "hosted_principals_count": 1,
            "image_digest": "sha256:c1ed4e8f7a02b9d4f6e3c2a1b8d7e6f5",
            "runtime_status": "running",
        },
    ]


def resources_cast() -> list[dict]:
    """Return MCP/HTTP/DB resources from the insurance demo spec."""
    return [
        {
            "resource_id": "mediterranean::resource::mcp::claims-db",
            "display_name": "Claims Database",
            "type": "mcp",
            "endpoint": "mcp://claims-db.mediterranean.local",
            "bindings_count": 2,
            "last_accessed": "active",
            "last_accessed_iso": None,
        },
    ]


def peers_cast() -> list[dict]:
    """Return federated peer organizations for the demo (two orgs)."""
    return [
        {
            "org_id": "mediterranean",
            "trust_domain": "mediterranean.cullis.test",
            "status": "active",
            "ca_fingerprint": "sha256:a1b2c3d4e5f6a7b8c9d0e1f2",
            "joined_at": "active",
            "joined_at_iso": None,
        },
        {
            "org_id": "asia-pacific",
            "trust_domain": "asia-pacific.cullis.test",
            "status": "active",
            "ca_fingerprint": "sha256:9f8e7d6c5b4a3928170615f4",
            "joined_at": "active",
            "joined_at_iso": None,
        },
    ]


def agent_extras(agent_id: str) -> dict:
    """Return enrollment_method + automation_type for known cast agents.

    Returns empty dict for agents that are not in the demo cast — the
    template renders an em-dash for missing fields. This is intentional:
    real agents from the registry may not yet have these fields tagged.
    """
    table = {
        "mediterranean::agent::night-reporter": {
            "enrollment_method": "Connector",
            "automation_type": "cron",
        },
        "mediterranean::agent::ticket-bot": {
            "enrollment_method": "BYOCA",
            "automation_type": "request-response",
        },
    }
    return table.get(agent_id, {})


def cast_counts() -> dict:
    """Counts for the left-nav badges (HTMX-polled)."""
    return {
        "users": len(users_cast()),
        "agents": len([a for a in agent_extras_keys()]),
        "workloads": len(workloads_cast()),
        "resources": len(resources_cast()),
    }


def agent_extras_keys() -> list[str]:
    """Return the agent_ids known to the demo cast."""
    return [
        "mediterranean::agent::night-reporter",
        "mediterranean::agent::ticket-bot",
    ]
