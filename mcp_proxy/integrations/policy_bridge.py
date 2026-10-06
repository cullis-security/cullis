"""Policy + audit bridge for any external OPA-compatible /
CloudEvents-emitting agent infrastructure component.

Two endpoints:

  * ``POST /v1/data/cullis/policy/{path}`` — OPA Data API binding.
    Any policy-fetching gateway that already speaks the OPA Data API
    contract (request body ``{"input": {...}}`` → response
    ``{"result": ...}``) can point its OPA endpoint at
    ``https://mastio.example.com/v1/data/cullis/policy`` and let Cullis
    drive the allow/deny decision from its ``policy_rules`` config.
    Two paths are wired today:

      - ``/v1/data/cullis/policy/session`` — session-open authorization,
        mirrors the existing ``/pdp/policy`` semantics (allow / deny +
        optional reason) but in OPA-shaped JSON.

      - ``/v1/data/cullis/policy/tool_call`` — tool-execution
        authorization, mirrors ``/v1/policy/tool-call``.

    Any other path returns ``{"result": null}`` — OPA's convention for
    "document undefined", which makes the caller fall back to its own
    default posture (typically default-deny).

  * ``POST /v1/integrations/cloudevents`` — CloudEvents HTTP-binding
    sink. Accepts both binary mode (CloudEvent metadata in HTTP
    headers, payload in body) and structured mode (entire CloudEvent
    in a JSON body). Each event becomes one append-only row on
    ``audit_log`` via :func:`mcp_proxy.db.log_audit`, so a customer
    that emits decisions / per-call events from any adjacent
    component gets one cryptographically verifiable audit trail
    covering both planes without writing aggregation code.

Both endpoints optionally verify ``X-Cullis-Integration-Signature``
(HMAC-SHA256 over the raw body, hex-encoded) when
``MCP_PROXY_INTEGRATIONS_HMAC_SECRET`` is set. Without the secret the
endpoints accept unsigned calls and the Mastio logs a warning at boot
— eases the mid-rollout window while the operator configures the
shared secret on both sides. Default-deny once the secret is
configured: a missing or mismatching signature returns 401 with no
body so an unauthenticated caller cannot use differential timing /
responses to probe ``policy_rules`` content (same threat the existing
PDP HMAC guards against, audit 2026-04-30 lane 3 H3).
"""
from __future__ import annotations

import hashlib
import hmac
import json as _json
import logging

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import JSONResponse

from mcp_proxy.config import get_settings
from mcp_proxy.db import get_config, log_audit
from mcp_proxy.policy import parse_policy_rules, policy_error_decision

_log = logging.getLogger("mcp_proxy.integrations.policy_bridge")

router = APIRouter(tags=["integrations"])


_SIGNATURE_HEADER = "x-cullis-integration-signature"


async def _verify_signature(request: Request, raw_body: bytes) -> None:
    """Enforce the HMAC-SHA256 signature on the integrations bridge.

    Refuses with HTTP 401 (no body) when the secret is set but the header
    is missing or mismatching.

    H10 (audit 2026-06-02): when no secret is configured the posture is
    environment-dependent. The bridge router is mounted unconditionally,
    so an unsigned request could inject rows into the append-only
    ``audit_log`` (CloudEvents ingest) or probe the policy decision
    surface. We therefore **fail closed in production** — unsigned
    requests are rejected even without a secret — and accept unsigned only
    outside production (sandbox / local dev ergonomics). This is a runtime
    default-deny rather than a boot gate so it never breaks a prod deploy
    that hasn't wired the (optional) integrations secret.
    """
    settings = get_settings()
    secret = settings.integrations_hmac_secret
    if not secret:
        if settings.environment == "production":
            _log.warning(
                "policy_bridge: rejected unsigned request to %s — "
                "integrations_hmac_secret is empty in production "
                "(audit 2026-06-02 H10, fail-closed)",
                request.url.path,
            )
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
        return
    provided = request.headers.get(_SIGNATURE_HEADER, "")
    expected = hmac.new(
        secret.encode(), raw_body, hashlib.sha256,
    ).hexdigest()
    if not provided or not hmac.compare_digest(provided, expected):
        _log.warning(
            "policy_bridge: rejected unsigned/mismatched request to %s",
            request.url.path,
        )
        # No body — don't leak whether the path / payload would have
        # been accepted on a valid signature.
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)


# ─────────────────────────────────────────────────────────────────────────────
# OPA Data API
# ─────────────────────────────────────────────────────────────────────────────


async def _evaluate_session_policy(opa_input: dict) -> dict:
    """Mirror of /pdp/policy logic against the OPA-shaped input.

    Expected ``opa_input`` keys (the calling gateway populates these
    from its identity + request context):

      - initiator_agent_id (str)
      - target_agent_id (str)
      - initiator_org_id (str, optional)
      - target_org_id (str, optional)
      - session_context (str: 'initiator' | 'target')
      - capabilities (list[str], optional)

    Returns an OPA-shaped result with a ``decision`` field (``allow`` /
    ``deny``) and optional ``reason``. The caller maps allow → pass,
    deny → block.
    """
    try:
        rules = parse_policy_rules(await get_config("policy_rules"))
    except Exception:
        return policy_error_decision("policy_configuration_error")

    from mcp_proxy.policy.composition import session_decision
    return session_decision(rules, opa_input)


async def _evaluate_tool_call_policy(opa_input: dict) -> dict:
    """Tool-execution policy mirror of /v1/policy/tool-call.

    Expected ``opa_input`` keys:

      - agent_id (str)
      - tool_name (str)
      - arguments (dict, optional — passed through but not inspected
        today; available for the operator's Rego when they want to
        write a richer rule on the caller side)

    Returns ``{"decision": "allow" | "deny", "reason": ...}``. Pulls
    the ``tool_rules`` subtree of ``policy_rules`` — same surface the
    existing /v1/policy/tool-call endpoint reads.
    """
    try:
        rules = parse_policy_rules(await get_config("policy_rules"))
    except Exception:
        return policy_error_decision("policy_configuration_error")

    from mcp_proxy.policy.composition import tool_decision
    return tool_decision(rules, opa_input)


@router.post("/v1/data/cullis/policy/{path:path}")
async def opa_data_api(path: str, request: Request) -> JSONResponse:
    """OPA Data API binding.

    Body shape (per OPA Data API spec): ``{"input": {...}}``.
    Response shape: ``{"result": {...}}`` (or ``{"result": null}`` for
    unknown paths so the caller's ``default`` posture wins).

    Supported ``path`` segments:

      * ``session`` — session-open authorization. Reuses
        ``policy_rules`` from the dashboard's Policies page exactly
        like ``/pdp/policy`` does. Returns
        ``{"result": {"decision": "allow" | "deny", "reason": ...}}``.

      * ``tool_call`` — tool-execution authorization. Same shape,
        reads ``tool_rules`` subtree of ``policy_rules``.
    """
    raw_body = await request.body()
    await _verify_signature(request, raw_body)

    try:
        body = _json.loads(raw_body) if raw_body else {}
    except _json.JSONDecodeError:
        raise HTTPException(
            status_code=400, detail="body must be valid JSON",
        )
    if not isinstance(body, dict):
        raise HTTPException(
            status_code=400, detail="body must be a JSON object",
        )
    opa_input = body.get("input")
    if not isinstance(opa_input, dict):
        # OPA convention: missing ``input`` is a client bug, not a deny.
        raise HTTPException(
            status_code=400, detail="missing 'input' object in body",
        )

    if path == "session":
        result = await _evaluate_session_policy(opa_input)
    elif path == "tool_call":
        result = await _evaluate_tool_call_policy(opa_input)
    else:
        # Unknown path — OPA's contract is to return ``result: null``
        # so the caller's ``default`` posture wins. Callers typically
        # default-deny on the operator side; this just signals "Cullis
        # has no opinion on this query".
        _log.info(
            "policy_bridge OPA query for unknown path %s — returning "
            "result=null", path,
        )
        return JSONResponse({"result": None})

    return JSONResponse({"result": result})


# ─────────────────────────────────────────────────────────────────────────────
# CloudEvents sink
# ─────────────────────────────────────────────────────────────────────────────


_CE_REQUIRED_ATTRIBUTES = ("id", "source", "type", "specversion")


def _parse_cloudevent(
    request: Request, raw_body: bytes,
) -> dict:
    """Return the CloudEvent in canonical dict form regardless of mode.

    The CloudEvents HTTP binding has two modes:

      * **Binary mode** — CloudEvent attributes (``id``, ``source``,
        ``type``, ``specversion``, ``time``, ...) live in HTTP headers
        prefixed with ``ce-``. The body is the event's ``data`` (raw).

      * **Structured mode** — the entire CloudEvent is one JSON object
        in the body. ``Content-Type`` is
        ``application/cloudevents+json``.

    We accept both, normalise into the structured shape, and validate
    the four required attributes are present. The agent / data field
    is preserved verbatim — it lands on ``audit_log.detail`` as the
    canonical JSON-encoded payload (the same encoding ``log_audit``
    applies to the legacy ``details`` kwarg).
    """
    content_type = request.headers.get("content-type", "").lower()

    if content_type.startswith("application/cloudevents+json"):
        # Structured mode — entire envelope in the body.
        try:
            event = _json.loads(raw_body) if raw_body else {}
        except _json.JSONDecodeError as exc:
            raise HTTPException(
                status_code=400,
                detail=f"cloudevents structured body not valid JSON: {exc}",
            )
        if not isinstance(event, dict):
            raise HTTPException(
                status_code=400,
                detail="cloudevents structured body must be a JSON object",
            )
    else:
        # Binary mode — attributes in headers prefixed ``ce-``.
        event = {}
        for header_name, header_value in request.headers.items():
            lname = header_name.lower()
            if lname.startswith("ce-"):
                event[lname[len("ce-"):]] = header_value
        if raw_body:
            # ``data`` is the body itself; try to JSON-decode for
            # structured payloads and fall back to a base64-style
            # preservation for opaque bodies.
            try:
                event["data"] = _json.loads(raw_body)
            except _json.JSONDecodeError:
                event["data_base64"] = raw_body.decode(
                    "utf-8", errors="replace",
                )

    missing = [a for a in _CE_REQUIRED_ATTRIBUTES if not event.get(a)]
    if missing:
        raise HTTPException(
            status_code=400,
            detail=(
                f"cloudevents missing required attribute(s): {missing}. "
                f"Binary mode expects ce-{{id,source,type,specversion}} "
                f"headers; structured mode expects the same keys at the "
                f"top level of the JSON body."
            ),
        )
    return event


@router.post("/v1/integrations/cloudevents")
async def cloudevents_sink(request: Request) -> JSONResponse:
    """Accept a CloudEvent and write one audit_log row.

    Mapping from CloudEvent attributes to ``audit_log`` columns:

      | CloudEvent      | audit_log              |
      | --------------- | ---------------------- |
      | ``source``      | ``agent_id`` (prefix)  |
      | ``type``        | ``action``             |
      | ``subject``     | ``tool_name`` (if any) |
      | ``data``        | ``detail`` (JSON)      |
      | ``id``          | ``request_id``         |
      | ``time``        | ignored — Cullis stamps its own (audit chain integrity) |

    The mapping is intentionally lossy on ``time``: Cullis' hash chain
    requires deterministic per-row timestamps stamped by
    :func:`mcp_proxy.db.log_audit`. The originating ``time`` is
    preserved inside ``detail`` (under the ``cloudevent`` key) so the
    auditor can reconcile the two when needed.
    """
    raw_body = await request.body()
    await _verify_signature(request, raw_body)

    event = _parse_cloudevent(request, raw_body)

    source = str(event.get("source") or "external")
    type_ = str(event.get("type") or "external.event")
    subject = event.get("subject")
    tool_name = str(subject) if subject else None
    event_id = str(event.get("id") or "")
    data = event.get("data")

    # Preserve the CloudEvent envelope inside detail so the auditor can
    # reconstruct ``time`` / ``datacontenttype`` / extensions later
    # without re-fetching from the source.
    detail_payload = {
        "cloudevent": {
            "id": event_id,
            "source": source,
            "type": type_,
            "specversion": event.get("specversion"),
            "time": event.get("time"),
        },
        "data": data,
    }
    if "data_base64" in event:
        detail_payload["data_base64"] = event["data_base64"]

    # Stamp the audit row. ``agent_id`` is namespaced ``external:`` to
    # make the cross-plane origin obvious in dashboard queries; Cullis'
    # own internal_agents table never holds an ``external:...`` row,
    # so a regex ``^external:`` in audit_log selects the
    # external-emitter history cleanly.
    agent_id = f"external:{source}"

    await log_audit(
        agent_id=agent_id,
        action=type_,
        tool_name=tool_name,
        status="recorded",
        details=detail_payload,
        request_id=event_id or None,
    )

    _log.info(
        "policy_bridge CloudEvent recorded: id=%s source=%s type=%s "
        "tool=%s", event_id, source, type_, tool_name,
    )
    return JSONResponse(
        {"status": "recorded", "id": event_id},
        status_code=202,
    )
