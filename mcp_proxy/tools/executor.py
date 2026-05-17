"""
Tool executor — orchestrates lookup, capability check, secret injection,
context assembly, handler invocation, and audit logging.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import httpx

from mcp_proxy.db import log_audit
from mcp_proxy.models import TokenPayload, ToolExecuteRequest, ToolExecuteResponse
from mcp_proxy.policy.denied_reason_codes import (
    CAPABILITY_DENIED,
    INSUFFICIENT_TIER,
    INTERNAL_ERROR,
    MISSING_BINDING,
    TOOL_NOT_FOUND,
)
from mcp_proxy.policy.tier_eval import resolve_effective_tier
from mcp_proxy.policy.tier_matrix import tier_meets_requirement
from mcp_proxy.tools.context import ToolContext
from mcp_proxy.tools.http_whitelist import ToolExecutionError, WhitelistedTransport
from mcp_proxy.tools.registry import tool_registry
from mcp_proxy.tools.secrets import SecretProvider

_log = logging.getLogger("mcp_proxy.tools.executor")

# Default timeout for tool handler execution (seconds)
DEFAULT_TOOL_TIMEOUT = 30.0


async def _load_principal_capabilities(
    agent: TokenPayload,
    app_state: Any | None,
) -> set[str]:
    """Return the capability set the principal carries into the
    capability gate.

    Today the source is the JWT ``scope`` claim — same data the
    pre-#730 ``has_capability`` call used for agents. The helper
    exists as the single extension point for richer authz stores
    that are out of scope for this hotfix:

    * ADR-021 — per-user capability grants from the Mastio user
      store. The schema exists (``local_user_principals``) but the
      capability column does not yet; once added, fetch the row by
      ``agent.agent_id`` and union the result here.
    * ADR-020 — workload SPIRE binding richer claims. Today a
      workload's capabilities ride through the JWT ``scope`` itself
      (SPIRE entry → broker JWT issuance → here); the helper
      already covers that path. A direct-bind table that the
      Mastio honours independently of the JWT could plug in here.

    The function is async by design so future stores (DB / Vault /
    HTTP service) can plug in without refactoring every callsite.
    Any exception propagates to the executor, which fails closed —
    deny + audit "capability lookup failed". Never assume "if I
    can't load the row, let it pass".

    ``app_state`` is the FastAPI ``request.app.state`` proxy; today
    it is unused, kept in the signature so the helper can resolve
    DB sessions / cache references from there without changing
    callers.
    """
    del app_state  # reserved for the future per-principal-store path
    return set(agent.scope or [])


async def run(
    request: ToolExecuteRequest,
    agent: TokenPayload,
    db: Any,
    secret_provider: SecretProvider,
    *,
    timeout: float = DEFAULT_TOOL_TIMEOUT,
    app_state: Any | None = None,
) -> ToolExecuteResponse:
    """Execute a tool on behalf of an authenticated agent.

    The ``db`` parameter is retained for API compatibility but no longer
    used — ``log_audit`` opens its own connection via ``get_db()`` since
    the SQLAlchemy async refactor (#36).

    ``app_state`` is the FastAPI ``request.app.state`` object (or
    equivalent) so handlers that need cross-subsystem dependencies
    (broker bridge, WS manager, audit chain) can fetch them from a
    single well-known location. Callers that don't have one (CLI
    paths, unit tests) pass ``None``.
    """
    del db  # kept in signature for backwards compatibility
    t0 = time.monotonic()
    tool_name = request.tool
    request_id = request.request_id

    # 1. Lookup
    tool_def = tool_registry.get(tool_name)
    if tool_def is None:
        duration_ms = _elapsed_ms(t0)
        await log_audit(
            agent_id=agent.agent_id,
            action="tool_execute",
            tool_name=tool_name,
            status="error",
            detail="Tool not found",
            request_id=request_id,
            duration_ms=duration_ms,
        )
        return ToolExecuteResponse(
            request_id=request_id,
            tool=tool_name,
            status="error",
            error=f"Tool '{tool_name}' not found",
            denied_reason_code=TOOL_NOT_FOUND,
            execution_time_ms=duration_ms,
        )

    # 2. Capability gate.
    #
    # Pre-#730 this block was guarded by ``principal_type == "agent"``,
    # so user- and workload-typed principals silently bypassed the
    # capability check on every builtin. The reasoning at the time
    # (see ADR-020 + the CRIT-2 comment at step 2b below) was that
    # typed principals authorise via ``local_agent_resource_bindings``
    # instead of JWT scope. That's correct for **MCP resources** (the
    # binding table is authoritative there) but it doesn't apply to
    # builtins — builtins have no binding row, so "no binding check"
    # meant "no check at all" for typed callers.
    #
    # PR #729 weaponised the gap by adding the first privileged
    # builtin (``cullis_send_to_agent``). Subagent security review
    # surfaced it post-merge. The hotfix:
    #
    # * Agent-typed callers: capability gate runs unchanged — same
    #   coverage as before, for both builtins and MCP resources. The
    #   existing CRIT-2 regression (``test_agent_principal_with_
    #   binding_but_no_capability_denied``) pins this.
    # * Typed callers (user / workload) on **builtins**: capability
    #   gate now runs, sourced from
    #   :func:`_load_principal_capabilities`. Today the helper just
    #   wraps ``agent.scope``; future ADR-021 per-user grants + ADR-020
    #   workload-binding richer claims plug in there, single point of
    #   extension.
    # * Typed callers on **MCP resources**: behaviour unchanged. The
    #   binding gate at step 2b is the authoritative authz path
    #   (ADR-007); capability stays optional metadata for discovery
    #   filtering.
    #
    # Fail-closed: if ``_load_principal_capabilities`` raises (e.g.
    # an ADR-021 user-store outage in a future iteration), the
    # executor denies and audits "capability lookup failed". No
    # silent grant.
    principal_type = getattr(agent, "principal_type", "agent")
    capability_gate_applies = (
        principal_type == "agent"
        or (
            principal_type in ("user", "workload")
            and not tool_def.is_mcp_resource
        )
    )

    if capability_gate_applies and tool_def.required_capability:
        try:
            principal_caps = await _load_principal_capabilities(
                agent, app_state,
            )
        except Exception as exc:
            duration_ms = _elapsed_ms(t0)
            _log.warning(
                "Capability lookup failed for principal '%s' (type=%s, "
                "tool='%s'): %s",
                agent.agent_id, principal_type, tool_name, exc,
            )
            await log_audit(
                agent_id=agent.agent_id,
                action="tool_execute",
                tool_name=tool_name,
                status="denied",
                detail=f"capability lookup failed ({type(exc).__name__})",
                request_id=request_id,
                duration_ms=duration_ms,
            )
            return ToolExecuteResponse(
                request_id=request_id,
                tool=tool_name,
                status="error",
                error="Forbidden: capability lookup failed",
                execution_time_ms=duration_ms,
                denied_reason_code=CAPABILITY_DENIED,
            )

        if tool_def.required_capability not in principal_caps:
            duration_ms = _elapsed_ms(t0)
            _log.warning(
                "Principal '%s' (type=%s) lacks capability '%s' for "
                "tool '%s'",
                agent.agent_id,
                principal_type,
                tool_def.required_capability,
                tool_name,
            )
            await log_audit(
                agent_id=agent.agent_id,
                action="tool_execute",
                tool_name=tool_name,
                status="denied",
                detail=(
                    f"Missing capability: {tool_def.required_capability} "
                    f"(principal_type={principal_type})"
                ),
                request_id=request_id,
                duration_ms=duration_ms,
            )
            return ToolExecuteResponse(
                request_id=request_id,
                tool=tool_name,
                status="error",
                error=(
                    f"Forbidden: missing capability "
                    f"'{tool_def.required_capability}'"
                ),
                execution_time_ms=duration_ms,
                denied_reason_code=CAPABILITY_DENIED,
            )

    # 2a. Tier gate (ADR-032 Decision E / F5).
    #
    # The capability check above answers "does the principal have
    # permission to call this tool, in principle?". The tier gate
    # answers "is the principal's device in good enough shape RIGHT
    # NOW to be trusted with that permission?". The two checks are
    # orthogonal — a principal with the ``mcp.transfer_money``
    # scope can still get refused if their device's last
    # attestation shows ``soft_only`` strength.
    #
    # **Agent-only by design (F5 follow-up #6).** The gate reads
    # ``internal_agents.last_attestation`` via
    # :func:`resolve_effective_tier`; that column exists by
    # construction (migration 0035) because the Connector device IS
    # the agent under ADR-014. Typed principals (``user`` /
    # ``workload`` per ADR-020) do NOT have an ``internal_agents``
    # row — a ``user::alice`` ``agent_id`` resolves to ``None`` in
    # ``get_agent``, which collapses the tier to ``untrusted`` and
    # would deny every tier-gated capability for every typed caller.
    # That's a wrong default: user attestation is a separate path
    # (ADR-021 multi-user KMS, Frontdesk SSO/IdP, Connector
    # local-credentials), not a device claim on the agent row.
    # Migration 0035's commit message documents this explicitly:
    # "the attestation is a per-device claim ... a similar column
    # on ``user_sessions``" is the planned home for shared-mode F4
    # R2. Until that wire-up lands, typed principals are exempt.
    #
    # The gate runs whenever the capability gate ran above AND the
    # principal is agent-typed. Builtins called by typed principals
    # still get their capability check at step 2 — they just skip
    # the device tier check that has no data source for them.
    # MCP-resource calls by typed principals get the binding gate at
    # step 2b, which the F5 follow-up will tier-gate separately when
    # we wire the same check into ``has_active_binding``.
    #
    # Fail-closed on the resolver: if ``resolve_effective_tier``
    # crashes (DB outage, malformed JSON), the helper already
    # collapses to ``("untrusted", None)``, so a tier requirement
    # higher than ``untrusted`` naturally denies — no separate
    # error branch needed.
    tier_matrix = _resolve_tier_matrix(app_state)
    if (
        tier_matrix is not None
        and capability_gate_applies
        and tool_def.required_capability
        and principal_type == "agent"
    ):
        try:
            effective_tier, attestation_claim = await resolve_effective_tier(
                agent.agent_id,
            )
        except Exception as exc:  # noqa: BLE001 — defensive belt
            _log.warning(
                "Tier resolution failed for agent '%s' (tool '%s'): %s",
                agent.agent_id, tool_name, exc,
            )
            effective_tier = "untrusted"
            attestation_claim = None

        required_tier = tier_matrix.lookup(tool_def.required_capability)

        # Emit the canonical audit row for every evaluation — allow OR
        # deny — so a CISO query can correlate "denied at tier X" with
        # "previous successful calls at tier Y" on the same principal.
        # The audit subtype lives in the ``action`` column (schema-doc
        # sez. 4.3 uses ``policy.tier_evaluated``); the executor's
        # tool-call audit subtype stays ``tool_execute``.
        await _audit_tier_evaluated(
            agent_id=agent.agent_id,
            capability=tool_def.required_capability,
            effective_tier=effective_tier,
            required_tier=required_tier,
            decision="allow" if tier_meets_requirement(
                effective_tier, required_tier,
            ) else "deny",
            reason_code=(
                None if tier_meets_requirement(
                    effective_tier, required_tier,
                ) else "insufficient_tier"
            ),
            attestation_claim=attestation_claim,
            request_id=request_id,
        )

        if not tier_meets_requirement(effective_tier, required_tier):
            duration_ms = _elapsed_ms(t0)
            _log.warning(
                "Principal '%s' tier=%s below required=%s for capability '%s' "
                "(tool '%s')",
                agent.agent_id, effective_tier, required_tier,
                tool_def.required_capability, tool_name,
            )
            await log_audit(
                agent_id=agent.agent_id,
                action="tool_execute",
                tool_name=tool_name,
                status="denied",
                detail=(
                    f"insufficient_tier: device {effective_tier} below "
                    f"required {required_tier} for "
                    f"{tool_def.required_capability}"
                ),
                request_id=request_id,
                duration_ms=duration_ms,
            )
            return ToolExecuteResponse(
                request_id=request_id,
                tool=tool_name,
                status="error",
                error=(
                    f"Forbidden: device tier '{effective_tier}' below "
                    f"required '{required_tier}' for capability "
                    f"'{tool_def.required_capability}'"
                ),
                execution_time_ms=duration_ms,
                denied_reason_code=INSUFFICIENT_TIER,
            )

    # 2b. Binding check for MCP-resource tools (CRIT-2 fix, audit T3-F1).
    # The JSON-RPC ``tools/call`` aggregator (``mcp_aggregator._handle_tools_call``)
    # gates ``is_mcp_resource`` tools behind ``has_active_binding(...)``
    # before it ever calls ``executor.run``. The REST surface
    # ``POST /v1/ingress/execute`` calls ``executor.run`` directly; pre-fix
    # the binding check was skipped entirely for any ``principal_type !=
    # "agent"``, so a user / workload token could call any registered
    # MCP-resource tool by name with no per-resource grant. Mirror the
    # aggregator's gate here so both ingress paths enforce the same
    # contract.
    if tool_def.is_mcp_resource:
        from mcp_proxy.local.bindings import has_active_binding
        if not await has_active_binding(
            agent.agent_id, principal_type, tool_def.resource_id,
        ):
            duration_ms = _elapsed_ms(t0)
            _log.warning(
                "Principal '%s' (type=%s) has no active binding for "
                "MCP resource '%s' (tool '%s')",
                agent.agent_id, principal_type,
                tool_def.resource_id, tool_name,
            )
            await log_audit(
                agent_id=agent.agent_id,
                action="tool_execute",
                tool_name=tool_name,
                status="denied",
                detail=(
                    f"No active binding for resource "
                    f"'{tool_def.resource_id}' (principal_type={principal_type})"
                ),
                request_id=request_id,
                duration_ms=duration_ms,
            )
            return ToolExecuteResponse(
                request_id=request_id,
                tool=tool_name,
                status="error",
                denied_reason_code=MISSING_BINDING,
                error=(
                    f"Forbidden: no active binding for resource "
                    f"'{tool_def.resource_id}'"
                ),
                execution_time_ms=duration_ms,
            )

    # 3. Fetch secrets
    try:
        secrets = await secret_provider.get_tool_secrets(tool_name)
    except Exception:
        _log.exception("Failed to fetch secrets for tool '%s'", tool_name)
        secrets = {}

    # 4. Build context
    transport = WhitelistedTransport(allowed_domains=tool_def.allowed_domains)
    async with httpx.AsyncClient(transport=transport) as http_client:
        ctx = ToolContext(
            parameters=request.parameters,
            agent_id=agent.agent_id,
            org_id=agent.org,
            capabilities=agent.scope,
            secrets=secrets,
            http_client=http_client,
            request_id=request_id,
            secret_provider=secret_provider,
            app_state=app_state,
        )

        # 5. Execute handler with timeout
        try:
            result = await asyncio.wait_for(
                tool_def.handler(ctx),
                timeout=timeout,
            )
            duration_ms = _elapsed_ms(t0)

            _log.info(
                "Tool '%s' executed successfully for agent '%s' in %.1fms (request=%s)",
                tool_name,
                agent.agent_id,
                duration_ms,
                request_id,
            )
            await log_audit(
                agent_id=agent.agent_id,
                action="tool_execute",
                tool_name=tool_name,
                status="success",
                request_id=request_id,
                duration_ms=duration_ms,
            )
            return ToolExecuteResponse(
                request_id=request_id,
                tool=tool_name,
                status="success",
                result=result,
                execution_time_ms=duration_ms,
            )

        except asyncio.TimeoutError:
            duration_ms = _elapsed_ms(t0)
            _log.error(
                "Tool '%s' timed out after %.0fs (request=%s)",
                tool_name,
                timeout,
                request_id,
            )
            await log_audit(
                agent_id=agent.agent_id,
                action="tool_execute",
                tool_name=tool_name,
                status="error",
                detail=f"Timeout after {timeout}s",
                request_id=request_id,
                duration_ms=duration_ms,
            )
            return ToolExecuteResponse(
                request_id=request_id,
                tool=tool_name,
                status="error",
                error=f"Tool execution timed out after {timeout}s",
                execution_time_ms=duration_ms,
                denied_reason_code=INTERNAL_ERROR,
            )

        except ToolExecutionError as exc:
            duration_ms = _elapsed_ms(t0)
            _log.warning(
                "Tool '%s' execution error: %s (request=%s)",
                tool_name,
                exc,
                request_id,
            )
            await log_audit(
                agent_id=agent.agent_id,
                action="tool_execute",
                tool_name=tool_name,
                status="error",
                detail=str(exc),
                request_id=request_id,
                duration_ms=duration_ms,
            )
            return ToolExecuteResponse(
                request_id=request_id,
                tool=tool_name,
                status="error",
                error=str(exc),
                execution_time_ms=duration_ms,
                denied_reason_code=INTERNAL_ERROR,
            )

        except Exception as exc:
            duration_ms = _elapsed_ms(t0)
            _log.exception(
                "Unexpected error in tool '%s' (request=%s)",
                tool_name,
                request_id,
            )
            await log_audit(
                agent_id=agent.agent_id,
                action="tool_execute",
                tool_name=tool_name,
                status="error",
                detail=f"Internal error: {type(exc).__name__}",
                request_id=request_id,
                duration_ms=duration_ms,
            )
            return ToolExecuteResponse(
                request_id=request_id,
                tool=tool_name,
                status="error",
                error="Internal tool execution error",
                execution_time_ms=duration_ms,
                denied_reason_code=INTERNAL_ERROR,
            )


def _elapsed_ms(t0: float) -> float:
    return (time.monotonic() - t0) * 1000.0


def _resolve_tier_matrix(app_state: Any | None) -> Any | None:
    """Return the cached :class:`TierMatrix` from ``app.state`` or a
    fresh load when no matrix has been stashed yet.

    The executor is called both from the FastAPI handler chain (where
    ``app_state`` is the live Starlette state object) and from unit
    tests that pass ``app_state=None``. In test paths the env var
    ``MCP_PROXY_TIER_MATRIX_PATH`` lets a test point at a fixture
    YAML, so a per-call ``load_default_tier_matrix()`` is cheap +
    deterministic.

    Returns ``None`` when the matrix cannot be located at all — the
    caller treats that as "tier gate disabled" rather than denying
    every call, matching the permissive-fallback semantics in
    :func:`mcp_proxy.policy.tier_matrix.load_default_tier_matrix`.
    """
    cached = getattr(app_state, "tier_matrix", None) if app_state is not None else None
    if cached is not None:
        return cached
    try:
        from mcp_proxy.policy.tier_matrix import load_default_tier_matrix
        return load_default_tier_matrix()
    except Exception as exc:  # noqa: BLE001 — defensive
        _log.warning("tier matrix load failed at gate-time: %s", exc)
        return None


async def _audit_tier_evaluated(
    *,
    agent_id: str,
    capability: str,
    effective_tier: str,
    required_tier: str,
    decision: str,
    reason_code: str | None,
    attestation_claim: dict | None,
    request_id: str | None,
) -> None:
    """Emit one ``policy.tier_evaluated`` audit row.

    Payload shape mirrors ``imp/attestation-claim-schema.md`` sez. 4.3
    — the JSON detail carries ``principal_id``, ``capability_requested``,
    ``effective_tier``, ``required_tier``, ``decision``,
    ``denied_reason_code`` (when present), and a snapshot of the
    attestation claim under ``device_attestation_ref``. The claim
    snapshot lets a forensic query see the exact inputs the gate
    evaluated against, even if the principal's ``last_attestation``
    rolls over between the call and the audit query.

    Best-effort: an audit-write failure logs a warning and continues
    so a transient SQLite write contention can't take down the gate.
    """
    import json as _json

    detail_payload: dict[str, Any] = {
        "capability_requested": capability,
        "effective_tier": effective_tier,
        "required_tier": required_tier,
        "decision": decision,
    }
    if reason_code:
        detail_payload["denied_reason_code"] = reason_code
    if attestation_claim is not None:
        detail_payload["device_attestation_ref"] = attestation_claim

    try:
        await log_audit(
            agent_id=agent_id,
            action="policy.tier_evaluated",
            tool_name=capability,
            status=decision,
            detail=_json.dumps(detail_payload, sort_keys=True, separators=(",", ":")),
            request_id=request_id,
        )
    except Exception as exc:  # noqa: BLE001 — audit best-effort
        _log.warning(
            "policy.tier_evaluated audit write failed for agent=%s "
            "capability=%s: %s",
            agent_id, capability, exc,
        )
