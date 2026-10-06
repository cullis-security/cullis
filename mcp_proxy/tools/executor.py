"""
Tool executor — orchestrates lookup, capability check, secret injection,
context assembly, handler invocation, and audit logging.
"""
from __future__ import annotations

import asyncio
import json as _json
import logging
import time
from typing import Any

import httpx

from mcp_proxy.db import get_config, log_audit
from mcp_proxy.models import TokenPayload, ToolExecuteRequest, ToolExecuteResponse
from mcp_proxy.policy.denied_reason_codes import (
    CAPABILITY_DENIED,
    INSUFFICIENT_TIER,
    INTERNAL_ERROR,
    MISSING_BINDING,
    POLICY_DENIED,
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


async def _resource_requires_delegation(resource_id: str) -> bool:
    """Read the requirement per call so another worker cannot use a stale grant."""
    from sqlalchemy import text
    from mcp_proxy.db import get_db
    async with get_db() as conn:
        row = (await conn.execute(text(
            "SELECT requires_delegation FROM local_mcp_resources "
            "WHERE resource_id = :rid AND enabled = 1"
        ), {"rid": resource_id})).first()
    if row is None:
        raise ValueError("Resource unavailable")
    return bool(row[0])


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
    # ``request.request_id`` carries the caller-supplied MCP JSON-RPC
    # ``id`` field. The Python SDK pins it to ``"1"`` for every POST
    # (each tools/call is a fresh JSON-RPC envelope), which makes it
    # useless as a trace key for the dashboard — the dashboard needs
    # to group the policy decision + tool_execute + resource_call
    # rows that fan out from a single invocation. We therefore mint
    # a server-side invocation id at ``run()`` entry and propagate it
    # as ``request_id`` everywhere: into the audit_log column, into
    # ``ToolContext.request_id`` (which the MCP resource forwarder
    # records under ``local_audit.details.mcp_request_id``), and into
    # the ``ToolExecuteResponse.request_id`` returned to the caller.
    # The original MCP id is discarded; nothing downstream relies on
    # the literal ``"1"``. See dashboard ``_group_audit_events`` for
    # how the join key flows through.
    import uuid as _uuid_run
    request_id = f"inv-{_uuid_run.uuid4().hex[:12]}"

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

    # Every tool and principal must carry an explicit action capability.
    # Resource binding is an additional permission, never a substitute.
    principal_type = getattr(agent, "principal_type", "agent")
    capability_gate_applies = True
    if not isinstance(tool_def.required_capability, str) or not tool_def.required_capability.strip():
        await log_audit(
            agent_id=agent.agent_id, action="tool_execute", tool_name=tool_name,
            status="denied", detail="Tool missing capability declaration",
            request_id=request_id, duration_ms=_elapsed_ms(t0),
        )
        return ToolExecuteResponse(
            request_id=request_id, tool=tool_name, status="error",
            error="Forbidden: tool has no capability declaration",
            denied_reason_code=CAPABILITY_DENIED, execution_time_ms=_elapsed_ms(t0),
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

    # 2c. Operator conditions run only after capability, tier and binding.
    # Rego may constrain an authorized action, never grant a missing permission.
    # Static tool rules and required delegations precede Rego on every surface.
    from mcp_proxy.policy import (
        parse_policy_rules, policy_error_decision,
    )

    from mcp_proxy.policy.composition import tool_decision

    rego_input = {
        "agent_id": agent.agent_id,
        "principal_type": principal_type,
        "tool_name": tool_name,
        "arguments": request.parameters,
        "mcp_server_id": tool_def.resource_id,
    }
    try:
        requires_delegation = tool_def.requires_delegation
        if tool_def.is_mcp_resource:
            requires_delegation = (await _resource_requires_delegation(tool_def.resource_id)) or requires_delegation
        _rego_rules = parse_policy_rules(await get_config("policy_rules"))
    except Exception:
        # Unreadable config is not evidence that no operator policy exists.
        rego_decision = policy_error_decision("policy_configuration_error")
    else:
        rego_decision = tool_decision(
            _rego_rules, rego_input, requires_delegation=requires_delegation,
        )
    if rego_decision is not None and rego_decision.get("decision") == "deny":
        duration_ms = _elapsed_ms(t0)
        reason = rego_decision.get("reason") or "operator policy denied this tool call"
        _log.warning(
            "Operator policy denied tool '%s' for principal '%s': %s",
            tool_name, agent.agent_id, reason,
        )
        await log_audit(
            agent_id=agent.agent_id,
            action="tool_execute",
            tool_name=tool_name,
            status="denied",
            detail=f"Operator policy deny: {reason}",
            request_id=request_id,
            duration_ms=duration_ms,
        )
        return ToolExecuteResponse(
            request_id=request_id,
            tool=tool_name,
            status="error",
            error=f"Forbidden by operator policy: {reason}",
            execution_time_ms=duration_ms,
            denied_reason_code=POLICY_DENIED,
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
            # Resolve the per-call cap + redaction settings lazily — keeps
            # the executor importable when ``ProxySettings`` cannot be
            # constructed (test fixtures that monkeypatch only the bits
            # they care about), at the cost of one settings fetch per
            # success path.
            try:
                from mcp_proxy.config import get_settings as _get_settings
                _settings = _get_settings()
                _max_bytes = _settings.audit_detail_max_bytes
                _redaction_settings = {
                    "capture_parameters": _settings.audit_capture_tool_parameters,
                    "capture_result": _settings.audit_capture_tool_result,
                    "parameters_denylist": list(
                        _settings.audit_capture_tool_parameters_denylist,
                    ),
                    "result_denylist": list(
                        _settings.audit_capture_tool_result_denylist,
                    ),
                }
            except Exception:  # noqa: BLE001 — never let config crash audit
                _max_bytes = 4096
                _redaction_settings = None
            success_detail = _build_success_detail(
                parameters=request.parameters,
                result=result,
                max_bytes=_max_bytes,
                tool_name=tool_name,
                redaction_settings=_redaction_settings,
            )
            await log_audit(
                agent_id=agent.agent_id,
                action="tool_execute",
                tool_name=tool_name,
                status="success",
                detail=success_detail,
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


def _safe_json_value(value: Any, _seen: set[int] | None = None) -> Any:
    """Return a JSON-serialisable surrogate for ``value`` or a repr fallback.

    The audit chain row hash is computed over a canonical JSON encoding of
    ``detail``, so any non-serialisable input (custom objects, binary
    blobs, ``datetime``, exceptions) must collapse to a string here before
    ``json.dumps`` runs in :func:`_build_success_detail`. We never raise:
    audit on the success path is best-effort metadata, not a gate, and a
    ``ValueError`` from ``json.dumps`` would otherwise propagate up through
    ``log_audit`` and turn a successful tool call into a 500. Returning a
    truncated ``repr(...)`` + ``_non_serializable`` flag preserves
    business-readable signal without poisoning the chain.

    Containers are walked one level so a single bad leaf doesn't nuke
    the whole ``parameters`` / ``result_summary`` business signal:
    ``{"recipient": "acme", "when": datetime}`` becomes
    ``{"recipient": "acme", "when": {"_non_serializable": True, ...}}``
    rather than the whole dict collapsing.

    Cycle detection (P0 #2 fix). A handler that returns a SQLAlchemy ORM
    object with ``relationship(backref=...)`` or any user code that
    constructs ``d = {}; d['self'] = d`` would otherwise drive the
    recursive walk into a ``RecursionError`` that propagates through
    ``log_audit`` and 500s a successful tool call. The ``_seen`` set
    tracks ``id(value)`` across the walk; a repeated visit returns a
    typed circular-reference marker.
    """
    if _seen is None:
        _seen = set()

    # Fast happy path: value is JSON-clean as-is. ``json.dumps`` itself
    # detects circular references (raises ``ValueError``) so the cheap
    # check before recursing is still correct for non-container leaves.
    try:
        _json.dumps(value)
        # ``json.dumps`` accepted it, but for containers we still want to
        # recurse so a nested non-serialisable leaf gets the marker
        # treatment rather than relying on dumps to find it again at the
        # outer call site. Plain values short-circuit here.
        if not isinstance(value, (dict, list, tuple)):
            return value
    except (TypeError, ValueError):
        pass

    if isinstance(value, (dict, list, tuple)):
        value_id = id(value)
        if value_id in _seen:
            return {
                "_omitted": True,
                "type": type(value).__name__,
                "reason": "circular_reference",
            }
        _seen.add(value_id)
        try:
            if isinstance(value, dict):
                return {str(k): _safe_json_value(v, _seen) for k, v in value.items()}
            return [_safe_json_value(v, _seen) for v in value]
        finally:
            # Pop on the way back up so siblings sharing the same id (rare
            # but legitimate, e.g. a shared sub-dict) aren't false-positive
            # flagged as circular.
            _seen.discard(value_id)
    # Leaf-level fallback: keep enough of the repr to identify the
    # object (class, key fields) without letting a giant binary blob
    # inflate the audit row.
    return {
        "_non_serializable": True,
        "repr": repr(value)[:512],
        "type": type(value).__name__,
    }


def _safe_json_value_top(value: Any) -> Any:
    """Top-level entry point with belt-and-suspenders ``RecursionError``
    guard. The ``_safe_json_value`` walker carries cycle detection, but a
    pathological non-cyclic depth (>1000 nested dicts) would still trip
    Python's recursion limit. Turn any such crash into the same omit
    marker so a successful tool call never 500s on audit-side
    serialisation."""
    try:
        return _safe_json_value(value)
    except RecursionError:
        return {
            "_omitted": True,
            "type": type(value).__name__,
            "reason": "circular_reference",
        }


def _omit_marker(value: Any) -> dict[str, Any]:
    """Sentinel payload used when ``result_summary`` must be dropped to
    fit under ``max_bytes``. Keeps the type hint for forensic readers
    so the operator knows what was elided."""
    return {"_omitted": True, "type": type(value).__name__}


def _parameters_omit_marker(value: Any, encoded_size: int) -> dict[str, Any]:
    """Sentinel payload used when ``parameters`` themselves must be
    dropped because they alone exceed ``max_bytes`` after the result
    has already been omitted (P0 #1 oversize-parameters fix).

    Forensic readers need at least the top-level shape of the original
    parameters so the audit row stays actionable — without it the only
    surviving signal would be the tool name, which loses the "what did
    the agent ask for" trail. ``size_bytes`` carries the original
    encoded length so a CISO can flag "agent shipped 100 KiB of input
    to ``payments.transfer``" without recovering the secret values.
    """
    marker: dict[str, Any] = {
        "_omitted": True,
        "type": type(value).__name__,
        "size_bytes": encoded_size,
    }
    if isinstance(value, dict):
        # Top-level keys are usually structural (recipient, amount,
        # memo) and not secret in themselves; preserve them as a
        # forensic anchor. If a deployment treats the parameter keys
        # themselves as PII it should redact via the denylist instead
        # (see ``audit_redaction``).
        try:
            marker["top_level_keys"] = sorted(str(k) for k in value.keys())
        except Exception:  # noqa: BLE001 — never let the marker raise
            marker["top_level_keys"] = []
    return marker


def _build_success_detail(
    *,
    parameters: Any,
    result: Any,
    max_bytes: int,
    tool_name: str | None = None,
    redaction_settings: dict[str, Any] | None = None,
) -> str:
    """Build the canonical JSON ``detail`` payload for a successful
    ``tool_execute`` audit row.

    Shape: ``{"parameters": <input>, "result_summary": <result>}``.
    The encoding is ``json.dumps(..., sort_keys=True, separators=(",",":"))``
    so the size check is deterministic and the result is a stable input
    to the per-row hash chain.

    Default behaviour captures both ``parameters`` and ``result_summary``
    on every successful tool call. For regulated environments handling
    PII / MNPI / deal-sensitive data, pass ``redaction_settings`` with
    ``capture_parameters`` / ``capture_result`` toggles and matching
    denylists (fnmatch glob patterns, e.g. ``payments.*``); see
    :mod:`mcp_proxy.tools.audit_redaction`. The matching side is
    replaced with a ``{"_redacted": True, "reason": ...}`` marker
    before the size + truncation pipeline runs.

    Truncation policy (in order, P0 #1 fix):

      1. Replace non-JSON-serialisable values with the repr fallback
         from :func:`_safe_json_value`; circular references collapse to
         the typed marker.
      2. Apply redaction (when configured) — redacted markers are tiny
         and consume budget proportionally.
      3. If the payload still exceeds ``max_bytes``, drop
         ``result_summary`` to ``{"_omitted": True, "type": ...}`` and
         re-encode with a ``"detail_truncated": True`` flag.
      4. If still over budget (oversize ``parameters`` alone — possible
         because ``MAX_TOOL_PARAMETERS_BYTES`` is 128 KiB, well above
         the 4 KiB / 16 KiB audit caps), drop ``parameters`` to a
         structural marker that keeps the top-level keys + encoded
         size for forensic anchoring. This guards against the failure
         mode "tool handler committed side effects, audit row refused
         by ``_enforce_audit_detail_size``, request becomes a 500
         under ``audit_fail_deny=True``, agent retries, double-spend".
      5. If even that is over budget (patological case — top-level keys
         alone overflow 4 KiB), collapse both sides to bare markers
         and trust the outer ``AUDIT_DETAILS_MAX_BYTES`` (16 KiB) cap
         in :func:`mcp_proxy.db._enforce_audit_detail_size` to refuse;
         the helper deliberately leaves that final cliff to the
         boundary so the operator sees a structured error rather than
         a row that lies about its content.
    """
    from mcp_proxy.tools.audit_redaction import (
        REASON_CAPTURE_DISABLED,
        REASON_TOOL_DENYLIST,
        redacted_marker,
        should_redact_parameters,
        should_redact_result,
    )

    safe_params: Any = _safe_json_value_top(parameters)
    safe_result: Any = _safe_json_value_top(result)

    if redaction_settings is not None:
        capture_params_enabled = bool(
            redaction_settings.get("capture_parameters", True),
        )
        capture_result_enabled = bool(
            redaction_settings.get("capture_result", True),
        )
        params_denylist = list(
            redaction_settings.get("parameters_denylist", []) or [],
        )
        result_denylist = list(
            redaction_settings.get("result_denylist", []) or [],
        )
        if should_redact_parameters(
            tool_name=tool_name,
            capture_enabled=capture_params_enabled,
            denylist=params_denylist,
        ):
            reason = (
                REASON_CAPTURE_DISABLED
                if not capture_params_enabled
                else REASON_TOOL_DENYLIST
            )
            safe_params = redacted_marker(reason=reason)
        if should_redact_result(
            tool_name=tool_name,
            capture_enabled=capture_result_enabled,
            denylist=result_denylist,
        ):
            reason = (
                REASON_CAPTURE_DISABLED
                if not capture_result_enabled
                else REASON_TOOL_DENYLIST
            )
            safe_result = redacted_marker(reason=reason)

    payload: dict[str, Any] = {
        "parameters": safe_params,
        "result_summary": safe_result,
    }
    encoded = _json.dumps(payload, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode("utf-8")) <= max_bytes:
        return encoded

    # Step 3 — drop result first. Parameters are usually the load-bearing
    # signal for "what did the agent ask for", result is the noisier
    # surface (logs, file dumps, embedding vectors).
    truncated_payload: dict[str, Any] = {
        "parameters": safe_params,
        "result_summary": _omit_marker(result),
        "detail_truncated": True,
    }
    encoded = _json.dumps(truncated_payload, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode("utf-8")) <= max_bytes:
        return encoded

    # Step 4 — parameters alone overflow. Measure the original encoded
    # size so the forensic marker carries that signal. ``json.dumps`` on
    # the safe-walked structure cannot raise here (already serialisable).
    params_encoded_size = len(
        _json.dumps(safe_params, sort_keys=True, separators=(",", ":")).encode(
            "utf-8",
        ),
    )
    truncated_payload = {
        "parameters": _parameters_omit_marker(parameters, params_encoded_size),
        "result_summary": _omit_marker(result),
        "detail_truncated": True,
    }
    encoded = _json.dumps(truncated_payload, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode("utf-8")) <= max_bytes:
        return encoded

    # Step 5 — pathological: even the structural markers + top_level_keys
    # overflow. Strip the keys hint and ship bare markers. The outer
    # ``AUDIT_DETAILS_MAX_BYTES`` boundary still bounds this at 16 KiB,
    # so the worst case here is "two markers without key lists", which
    # is always tiny.
    bare_payload: dict[str, Any] = {
        "parameters": {
            "_omitted": True,
            "type": type(parameters).__name__,
            "size_bytes": params_encoded_size,
        },
        "result_summary": _omit_marker(result),
        "detail_truncated": True,
    }
    return _json.dumps(bare_payload, sort_keys=True, separators=(",", ":"))


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
