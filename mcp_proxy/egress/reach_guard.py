"""Enforce ``internal_agents.reach`` at the egress boundary.

Migration 0017 classifies every internal agent with one of three reach
values:

    ``intra`` — can only talk to other agents *in this org*
    ``cross`` — can only talk to agents in *other* orgs
    ``both``  — either is allowed (default, legacy behaviour)

The dashboard lets operators flip the value from the Reach pill on
``/proxy/agents``. Without a runtime gate, the classification is mere
metadata — an agent flagged ``intra`` could still fire cross-org
requests if a misconfigured client, compromised credential, or buggy
SDK asked for them. This module is the gate: called from every egress
handler before any forwarding happens, after the agent has been
authenticated.

The deny is always a plain HTTP 403 so the client sees the same error
shape it would on any other policy failure. The caller is responsible
for writing the matching audit trail — we don't do it here so the
handler keeps ownership of its request_id / session_id / correlation_id
context (which vary too much to abstract cleanly).
"""
from __future__ import annotations

import logging

from fastapi import HTTPException, status

from mcp_proxy.models import InternalAgent

_log = logging.getLogger("mcp_proxy.egress.reach_guard")


_VALID_REACH = frozenset({"intra", "cross", "both"})


def resolve_target_org(
    recipient_id: str,
    explicit_org: str | None = None,
) -> str | None:
    """Extract the recipient's ``org_id`` from an agent handle.

    Accepts any of the three forms the egress surface sees:

    * ``org::agent`` — the broker's canonical form.
    * ``spiffe://<trust_domain>/<org>/<agent>`` — SPIFFE URIs as
      written by the sandbox's SPIRE stacks and ADR-011 enrollment.
    * ``spiffe://<org>.<suffix>/...`` — trust-domain-per-org naming
      (``orga.test``), where the org is encoded in the TD itself.

    Returns ``None`` when no org can be extracted. Callers treat that
    as "cannot decide" and fall through — the downstream resolver
    will either succeed (and route) or 404 with a clearer message.
    The gate is a defence-in-depth layer, not the only policy check.

    ``explicit_org``, when non-empty, wins over parsing. The session
    open path passes ``body.target_org_id`` here so a client that
    spelled ``agent`` without an ``org::`` prefix still pins the org
    it meant.
    """
    if explicit_org:
        return explicit_org.strip() or None

    if not recipient_id:
        return None

    if recipient_id.startswith("spiffe://"):
        rest = recipient_id[len("spiffe://"):]
        parts = rest.split("/", 2)
        if not parts:
            return None
        trust_domain = parts[0]
        # Two SPIFFE conventions co-exist and both show up in the
        # sandbox and ADR-011 registrations:
        #
        #   (a) spiffe://<td>/<org>/<agent>     — org as first path segment
        #   (b) spiffe://<org>.<suffix>/<agent> — org baked into TD
        #
        # Precedence is by evidence: if the path carries ≥2 segments,
        # the first one is authoritative (matches both the ADR-011
        # SPIRE entries like ``spiffe://orgb.test/orgb/agent-b`` and
        # pure (a) forms like ``spiffe://cullis.local/orgb/agent-b``).
        # Only when the path is a single segment do we fall back to
        # splitting the TD on the first dot — that handles minimalist
        # (b) forms like ``spiffe://orga.test/byoca-bot``.
        path_segments = [p for p in parts[1:] if p] if len(parts) >= 2 else []
        if len(path_segments) >= 2:
            return path_segments[0]
        if "." in trust_domain:
            return trust_domain.split(".", 1)[0]
        if path_segments:
            return path_segments[0]
        return trust_domain

    if "::" in recipient_id:
        return recipient_id.split("::", 1)[0]

    return None


def check_reach(
    agent: InternalAgent,
    target_org_id: str | None,
    local_org_id: str,
) -> None:
    """Raise 403 when the agent's ``reach`` forbids this direction.

    ``target_org_id=None`` is a soft-pass: we couldn't tell whether
    the traffic is intra or cross, so we don't second-guess the
    downstream resolver — see the module docstring for why.

    ``local_org_id`` empty is also a soft-pass: proxy in an
    unconfigured state (Setup wizard not complete) has no notion of
    "its own org", so reach enforcement can't be framed correctly.
    The rest of the egress surface already refuses requests in that
    state with clearer errors.
    """
    reach = (getattr(agent, "reach", None) or "both").lower()
    if reach not in _VALID_REACH:
        _log.warning(
            "agent %s has unknown reach=%r — defaulting to 'both'",
            agent.agent_id, reach,
        )
        reach = "both"

    if reach == "both":
        return
    if not target_org_id or not local_org_id:
        return

    is_intra = (target_org_id == local_org_id)

    if reach == "intra" and not is_intra:
        _log.warning(
            "reach deny: agent=%s reach=intra target_org=%s (cross-org)",
            agent.agent_id, target_org_id,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"agent reach='intra' — cross-org traffic denied "
                f"(target_org={target_org_id}). Change reach from the "
                "Mastio dashboard to allow."
            ),
        )

    if reach == "cross" and is_intra:
        _log.warning(
            "reach deny: agent=%s reach=cross target_org=%s (intra-org)",
            agent.agent_id, target_org_id,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"agent reach='cross' — intra-org traffic denied "
                f"(target_org={target_org_id}). Change reach from the "
                "Mastio dashboard to allow."
            ),
        )
