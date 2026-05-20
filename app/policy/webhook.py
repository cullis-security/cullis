"""
PDP Webhook caller, federated policy decision for session requests.

Each organization registers a webhook URL at onboarding time.
When Agent A (org A) requests a session with Agent B (org B), the broker
calls BOTH webhooks and proceeds only if both return {"decision": "allow"}.

Default-deny: if an org has no webhook configured, the decision is DENY.
Timeout: 5 seconds per webhook call (synchronous, sequential).

Webhook contract (ADR-029 extended, backward compatible):
  Request:  POST {webhook_url}
            Content-Type: application/json
            X-ATN-Signature: HMAC-SHA256 of the body
            Body: {
              # Legacy session-open payload (always present)
              "initiator_agent_id": str,
              "initiator_org_id":   str,
              "target_agent_id":    str,
              "target_org_id":      str,
              "capabilities":       list[str],
              "session_context":    str,   # "initiator" | "target"

              # ADR-029 extended payload (present when the broker has the data)
              "model":      dict | None,   # {id, provider, via_gateway}
              "invocation": dict | None,   # {kind, tool_name?, mcp_server_id?, capabilities_requested}
              "context":    dict | None    # {trace_id?, parent_session_id?, request_idempotency_key?}
            }

  Response: 200 OK  { "decision": "allow" }
            200 OK  { "decision": "deny", "reason": "..." }
            200 OK  ADR-029 extended:
              {
                "decision": "allow",
                "reason": "...",
                "scope": {
                  "tools_allowed": [...],
                  "tools_denied":  [...],
                  "max_session_duration_s": int
                },
                "rate_limit": {
                  "per_minute": int,
                  "per_day":    int
                },
                "obligations": {
                  "require_user_confirmation": bool,
                  "trace_visibility":          "full" | "redacted" | "off"
                }
              }
            any non-200 or timeout means DENY.

A PDP that returns the legacy shape continues to work: scope, rate_limit,
and obligations stay None on the decision and the broker treats that as
no extra constraints (Phase B backward compatibility).
"""
import hashlib
import hmac
import ipaddress
import json
import logging
import socket
import time
import typing
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx
import httpcore

from app.telemetry import tracer
from app.telemetry_metrics import PDP_WEBHOOK_LATENCY_HISTOGRAM

_log = logging.getLogger("agent_trust")

_WEBHOOK_TIMEOUT = 5.0  # seconds
_MAX_RESPONSE_BODY = 4096  # bytes — limit PDP response parsing


def _allow_private_webhooks() -> bool:
    """Demo/e2e escape hatch — controlled by POLICY_WEBHOOK_ALLOW_PRIVATE_IPS."""
    from app.config import get_settings
    return get_settings().policy_webhook_allow_private_ips


def _validate_response_ip(resp: httpx.Response) -> None:
    """
    Post-request SSRF check: verify that the server IP in the response
    is not private/loopback. Defends against DNS rebinding attacks where
    the hostname resolves to an internal IP between validation and request.

    httpx does not expose the remote IP in all transports; when unavailable,
    we rely on the pre-request DNS validation as a best-effort defense.

    F-A-204 (audit 2026-05-20) fix: distinguish "cannot determine the
    server address" (accept, defer to pre-request validation) from
    "address determined and unsafe" (raise). The previous broad
    ``except (TypeError, ValueError, IndexError)`` clause was swallowing
    the very ``ValueError`` this function raises on a private-IP hit,
    turning the post-request belt-and-braces into a no-op.
    """
    if _allow_private_webhooks():
        return
    network_stream = resp.extensions.get("network_stream")
    if network_stream is None:
        return
    # Stage 1: extract the peer address. Broad except: any failure here
    # means "cannot determine", which is the documented accept path.
    try:
        server_addr = network_stream.get_extra_info("server_addr")
    except (TypeError, AttributeError):
        return
    if not server_addr:
        return
    # Stage 2: parse the address. Malformed → cannot determine → accept.
    try:
        ip = ipaddress.ip_address(server_addr[0])
    except (ValueError, IndexError, TypeError):
        return
    # Stage 3: refuse private/reserved. ValueError raised here is the
    # safety signal the caller must surface — do NOT catch it locally.
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
        raise ValueError(f"Response came from private/reserved IP: {ip}")


def _validate_and_resolve_webhook_url(url: str) -> str:
    """
    Validate that a webhook URL does not point to internal/private networks (SSRF protection).
    Returns the first safe resolved IP address to pin the connection to, preventing DNS rebinding.
    Raises ValueError if the URL is unsafe.

    When POLICY_WEBHOOK_ALLOW_PRIVATE_IPS=true (demo/e2e mode) the private-IP
    bans are skipped — the resolved IP is still pinned, so DNS rebinding
    protection still applies, but webhooks pointing at docker compose service
    names or RFC1918 addresses are accepted.
    """
    allow_private = _allow_private_webhooks()
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Webhook URL has no hostname")

    # Block common internal hostnames (production only)
    if not allow_private and hostname in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
        raise ValueError(f"Webhook URL points to loopback address: {hostname}")

    # Resolve hostname and check all resulting IPs
    try:
        addr_infos = socket.getaddrinfo(hostname, parsed.port or 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise ValueError(f"Cannot resolve webhook hostname: {hostname}")

    safe_ip: str | None = None
    for _family, _type, _proto, _canonname, sockaddr in addr_infos:
        ip = ipaddress.ip_address(sockaddr[0])
        if not allow_private and (
            ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
        ):
            raise ValueError(f"Webhook URL resolves to private/reserved IP: {ip}")
        if safe_ip is None:
            safe_ip = str(ip)

    if safe_ip is None:
        raise ValueError(f"Cannot resolve webhook hostname: {hostname}")

    return safe_ip


class _PinnedDNSBackend(httpcore.AsyncNetworkBackend):
    """Network backend that pins DNS resolution to a pre-resolved IP.

    This prevents DNS rebinding attacks: the hostname resolves to the pinned IP
    at the socket level, while httpx/httpcore still use the original hostname
    for TLS SNI and certificate validation.
    """

    def __init__(self, pinned_ip: str, default_port: int = 443):
        self._pinned_ip = pinned_ip
        self._default_port = default_port
        self._backend = httpcore.AnyIOBackend()

    async def connect_tcp(
        self, host: str, port: int, timeout: float | None = None, local_address: str | None = None, socket_options: typing.Iterable | None = None,
    ) -> httpcore.AsyncNetworkStream:
        # Connect to the pinned IP instead of resolving the hostname again.
        return await self._backend.connect_tcp(
            self._pinned_ip, port, timeout=timeout, local_address=local_address, socket_options=socket_options,
        )

    async def connect_unix_socket(
        self, path: str, timeout: float | None = None, socket_options: typing.Iterable | None = None,
    ) -> httpcore.AsyncNetworkStream:
        return await self._backend.connect_unix_socket(path, timeout=timeout, socket_options=socket_options)

    async def sleep(self, seconds: float) -> None:
        await self._backend.sleep(seconds)


@dataclass
class DecisionScope:
    """ADR-029 extended scope returned by a tool-aware PDP.

    A PDP can constrain which tools the session is allowed to invoke and
    how long the session may stay open. None values mean unset / inherit.
    """
    tools_allowed: list[str] | None = None
    tools_denied: list[str] | None = None
    max_session_duration_s: int | None = None


@dataclass
class DecisionRateLimit:
    """ADR-029 extended rate-limit hints returned by the PDP. Enforced at
    the gate, not by the PDP itself. None values mean no limit."""
    per_minute: int | None = None
    per_day: int | None = None


@dataclass
class DecisionObligations:
    """ADR-029 obligations the PDP attaches to the allow. Defaults are
    safe-permissive (no confirmation required, redacted trace visibility).
    """
    require_user_confirmation: bool = False
    trace_visibility: str = "redacted"  # full | redacted | off


@dataclass
class WebhookDecision:
    allowed: bool
    reason: str
    org_id: str
    # ADR-029 extended fields. All optional, all None on legacy responses.
    # The broker treats None as "no constraint" so existing PDP webhooks
    # continue to work unchanged.
    scope: DecisionScope | None = None
    rate_limit: DecisionRateLimit | None = None
    obligations: DecisionObligations | None = None


def _parse_scope(raw: object) -> DecisionScope | None:
    """Lift a PDP response 'scope' dict into a DecisionScope dataclass.

    Returns None when the field is absent or malformed; callers treat
    that as 'no scope restriction'.
    """
    if not isinstance(raw, dict):
        return None
    return DecisionScope(
        tools_allowed=_string_list(raw.get("tools_allowed")),
        tools_denied=_string_list(raw.get("tools_denied")),
        max_session_duration_s=_int_or_none(raw.get("max_session_duration_s")),
    )


def _parse_rate_limit(raw: object) -> DecisionRateLimit | None:
    if not isinstance(raw, dict):
        return None
    return DecisionRateLimit(
        per_minute=_int_or_none(raw.get("per_minute")),
        per_day=_int_or_none(raw.get("per_day")),
    )


def _parse_obligations(raw: object) -> DecisionObligations | None:
    if not isinstance(raw, dict):
        return None
    visibility = raw.get("trace_visibility", "redacted")
    if visibility not in ("full", "redacted", "off"):
        visibility = "redacted"
    return DecisionObligations(
        require_user_confirmation=bool(raw.get("require_user_confirmation", False)),
        trace_visibility=visibility,
    )


def _string_list(raw: object) -> list[str] | None:
    if raw is None:
        return None
    if not isinstance(raw, list):
        return None
    return [str(x) for x in raw if isinstance(x, (str, int))]


def _int_or_none(raw: object) -> int | None:
    if raw is None:
        return None
    try:
        v = int(raw)
        return v if v > 0 else None
    except (TypeError, ValueError):
        return None


async def call_pdp_webhook(
    org_id: str,
    webhook_url: str | None,
    initiator_agent_id: str,
    initiator_org_id: str,
    target_agent_id: str,
    target_org_id: str,
    capabilities: list[str],
    session_context: str,  # "initiator" | "target"
    *,
    # ADR-029 extended payload. Each kwarg is optional and only added to
    # the wire payload when non-None, so existing PDP webhooks that
    # ignore unknown fields keep working.
    model: dict | None = None,
    invocation: dict | None = None,
    context: dict | None = None,
) -> WebhookDecision:
    """
    Call the PDP webhook for one organization and return its decision.

    If webhook_url is None or the call fails, returns DENY (default-deny).
    """
    if not webhook_url:
        from app.config import get_settings as _get_settings
        default_decision = _get_settings().policy_default_decision
        if default_decision == "allow":
            # Sandbox/demo escape hatch (issue #461). Distinct from
            # ``policy_enforcement=false``: the dispatcher still ran,
            # this audit row marks the decision as a default-allow so
            # operators can grep their chain for unconfigured orgs and
            # wire webhooks before going to production.
            _log.warning(
                "PDP webhook not configured for org '%s' — POLICY_DEFAULT_DECISION='allow' fall-through",
                org_id,
            )
            return WebhookDecision(
                allowed=True,
                reason=(
                    f"policy_default_allow: org '{org_id}' has no PDP webhook "
                    f"configured (POLICY_DEFAULT_DECISION=allow)"
                ),
                org_id=org_id,
            )
        _log.warning(
            "PDP webhook not configured for org '%s' — default-deny", org_id
        )
        return WebhookDecision(
            allowed=False,
            reason=(
                f"policy_default_deny: organization '{org_id}' has no PDP webhook "
                f"configured. Set 'webhook_url' on the org via "
                f"PATCH /v1/registry/orgs/{org_id}, OR set "
                f"POLICY_DEFAULT_DECISION=allow on the broker for sandbox/demo "
                f"deploys (issue #461)."
            ),
            org_id=org_id,
        )

    # SSRF protection: validate webhook URL and pin the resolved IP to
    # prevent DNS rebinding attacks between validation and request.
    try:
        pinned_ip = _validate_and_resolve_webhook_url(webhook_url)
    except ValueError as exc:
        _log.warning("PDP webhook URL rejected (SSRF): org=%s url=%s reason=%s", org_id, webhook_url, exc)
        return WebhookDecision(
            allowed=False,
            reason=f"PDP webhook URL rejected: {exc}",
            org_id=org_id,
        )

    payload: dict = {
        "initiator_agent_id": initiator_agent_id,
        "initiator_org_id":   initiator_org_id,
        "target_agent_id":    target_agent_id,
        "target_org_id":      target_org_id,
        "capabilities":       capabilities,
        "session_context":    session_context,
    }
    # ADR-029 extended fields. Only present when the caller provides them
    # so legacy PDP webhooks see the exact same payload they always saw.
    if model is not None:
        payload["model"] = model
    if invocation is not None:
        payload["invocation"] = invocation
    if context is not None:
        payload["context"] = context

    # Audit 2026-04-30 lane 3 H3 — sign the body with the shared
    # secret so the receiving PDP can verify the call originated
    # from the broker. We hash the exact bytes we send on the wire,
    # not ``payload`` re-serialised, to avoid sender/receiver
    # canonicalisation drift. ``json.dumps`` defaults match httpx's
    # ``json=`` serialisation closely enough that we serialise once
    # and reuse the bytes for both the body and the signature.
    body_bytes = json.dumps(payload).encode()
    headers: dict[str, str] = {"Content-Type": "application/json"}
    from app.config import get_settings as _get_settings
    secret = _get_settings().policy_webhook_hmac_secret
    if secret:
        sig = hmac.new(
            secret.encode(), body_bytes, hashlib.sha256,
        ).hexdigest()
        headers["X-ATN-Signature"] = sig

    t0 = time.monotonic()
    try:
        with tracer.start_as_current_span("pdp.webhook_call") as span:
            span.set_attribute("pdp.org_id", org_id)
            span.set_attribute("pdp.context", session_context)

            # Pin the connection to the resolved IP to prevent DNS rebinding.
            # We use a custom httpcore network backend that returns the pinned IP
            # for any lookup, while httpx keeps the original hostname for TLS SNI.
            parsed_url = urlparse(webhook_url)
            port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)
            pinned_backend = _PinnedDNSBackend(pinned_ip, port)
            pool = httpcore.AsyncConnectionPool(network_backend=pinned_backend)
            transport = httpx.AsyncHTTPTransport()
            # Replace the internal pool with our pinned one
            transport._pool = pool

            async with httpx.AsyncClient(
                timeout=_WEBHOOK_TIMEOUT,
                follow_redirects=False,
                transport=transport,
            ) as client:
                resp = await client.post(
                    webhook_url, content=body_bytes, headers=headers,
                )

            # Post-request safety check (belt and suspenders)
            _validate_response_ip(resp)
            PDP_WEBHOOK_LATENCY_HISTOGRAM.record((time.monotonic() - t0) * 1000, {"org_id": org_id})

        if resp.status_code != 200:
            _log.warning(
                "PDP webhook for org '%s' returned HTTP %d — default-deny",
                org_id, resp.status_code,
            )
            return WebhookDecision(
                allowed=False,
                reason=f"PDP webhook for '{org_id}' returned HTTP {resp.status_code}",
                org_id=org_id,
            )

        # Limit response body size to prevent memory exhaustion from malicious webhooks
        if len(resp.content) > _MAX_RESPONSE_BODY:
            _log.warning(
                "PDP webhook response too large for org '%s' (%d bytes) — default-deny",
                org_id, len(resp.content),
            )
            return WebhookDecision(
                allowed=False,
                reason=f"PDP webhook response too large ({len(resp.content)} bytes)",
                org_id=org_id,
            )

        data = resp.json()
        decision = data.get("decision", "deny").lower()
        if decision not in ("allow", "deny"):
            _log.warning(
                "PDP webhook for org '%s' returned invalid decision '%s' — default-deny",
                org_id, decision,
            )
            decision = "deny"
        reason = str(data.get("reason", ""))[:512]  # limit reason length

        # ADR-029 extended response: scope / rate_limit / obligations are
        # all optional. _parse_* returns None on missing or malformed
        # fields, which the broker treats as "no constraint".
        scope = _parse_scope(data.get("scope"))
        rate_limit = _parse_rate_limit(data.get("rate_limit"))
        obligations = _parse_obligations(data.get("obligations"))

        if decision == "allow":
            _log.info("PDP webhook allow: org=%s context=%s", org_id, session_context)
            return WebhookDecision(
                allowed=True,
                reason=reason,
                org_id=org_id,
                scope=scope,
                rate_limit=rate_limit,
                obligations=obligations,
            )

        _log.info(
            "PDP webhook deny: org=%s context=%s reason=%s",
            org_id, session_context, reason,
        )
        return WebhookDecision(
            allowed=False,
            reason=reason or f"Denied by org '{org_id}' PDP",
            org_id=org_id,
            scope=scope,
            rate_limit=rate_limit,
            obligations=obligations,
        )

    except httpx.TimeoutException:
        _log.warning("PDP webhook timeout for org '%s' — default-deny", org_id)
        return WebhookDecision(
            allowed=False,
            reason=f"PDP webhook for '{org_id}' timed out after {_WEBHOOK_TIMEOUT}s",
            org_id=org_id,
        )
    except Exception as exc:
        _log.warning("PDP webhook error for org '%s': %s — default-deny", org_id, exc)
        return WebhookDecision(
            allowed=False,
            reason=f"PDP webhook for '{org_id}' error: {exc}",
            org_id=org_id,
        )


def _intersect_scopes(
    initiator: DecisionScope | None,
    target: DecisionScope | None,
) -> DecisionScope | None:
    """ADR-029 §Decision: source ∩ target. Never union, never expand.

    A None on either side means "no restriction from that side", so the
    intersection is the other side's restriction. Both None means no
    scope constraint at all (legacy behaviour).
    """
    if initiator is None and target is None:
        return None
    if initiator is None:
        return target
    if target is None:
        return initiator

    # Intersection rules:
    #   tools_allowed: intersection (only what both allow)
    #   tools_denied:  union        (anyone says deny → deny)
    #   max_session_duration_s: min (tighter wins)
    a_allowed = set(initiator.tools_allowed) if initiator.tools_allowed is not None else None
    b_allowed = set(target.tools_allowed) if target.tools_allowed is not None else None
    if a_allowed is None and b_allowed is None:
        allowed: list[str] | None = None
    elif a_allowed is None:
        allowed = sorted(b_allowed) if b_allowed is not None else None
    elif b_allowed is None:
        allowed = sorted(a_allowed)
    else:
        allowed = sorted(a_allowed & b_allowed)

    denied_set: set[str] = set()
    if initiator.tools_denied:
        denied_set.update(initiator.tools_denied)
    if target.tools_denied:
        denied_set.update(target.tools_denied)
    denied = sorted(denied_set) if denied_set else None

    durations = [
        d for d in (initiator.max_session_duration_s, target.max_session_duration_s)
        if d is not None
    ]
    duration = min(durations) if durations else None

    return DecisionScope(
        tools_allowed=allowed,
        tools_denied=denied,
        max_session_duration_s=duration,
    )


def _intersect_rate_limits(
    initiator: DecisionRateLimit | None,
    target: DecisionRateLimit | None,
) -> DecisionRateLimit | None:
    """Tighter rate limit wins (min of per_minute, min of per_day)."""
    if initiator is None and target is None:
        return None
    if initiator is None:
        return target
    if target is None:
        return initiator

    def _min_or_none(a: int | None, b: int | None) -> int | None:
        vals = [v for v in (a, b) if v is not None]
        return min(vals) if vals else None

    return DecisionRateLimit(
        per_minute=_min_or_none(initiator.per_minute, target.per_minute),
        per_day=_min_or_none(initiator.per_day, target.per_day),
    )


def _intersect_obligations(
    initiator: DecisionObligations | None,
    target: DecisionObligations | None,
) -> DecisionObligations | None:
    """Conservative merge: any side that demands user confirmation wins;
    visibility downgrades to the more restrictive of the two."""
    if initiator is None and target is None:
        return None
    if initiator is None:
        return target
    if target is None:
        return initiator
    rank = {"full": 2, "redacted": 1, "off": 0}
    visibility = (
        initiator.trace_visibility
        if rank[initiator.trace_visibility] <= rank[target.trace_visibility]
        else target.trace_visibility
    )
    return DecisionObligations(
        require_user_confirmation=(
            initiator.require_user_confirmation or target.require_user_confirmation
        ),
        trace_visibility=visibility,
    )


async def evaluate_session_via_webhooks(
    initiator_org_id: str,
    initiator_webhook_url: str | None,
    target_org_id: str,
    target_webhook_url: str | None,
    initiator_agent_id: str,
    target_agent_id: str,
    capabilities: list[str],
    *,
    # ADR-029 extended kwargs. Passed through to both webhooks so each
    # side has the same context to decide on.
    model: dict | None = None,
    invocation: dict | None = None,
    context: dict | None = None,
) -> WebhookDecision:
    """
    Call both orgs' PDP webhooks. Returns DENY if either denies.
    Both calls are made even if the first denies (for audit completeness).

    On dual allow, the returned WebhookDecision carries the intersection
    of scope, rate_limit, and obligations (ADR-029 §Decision).
    """
    initiator_decision = await call_pdp_webhook(
        org_id=initiator_org_id,
        webhook_url=initiator_webhook_url,
        initiator_agent_id=initiator_agent_id,
        initiator_org_id=initiator_org_id,
        target_agent_id=target_agent_id,
        target_org_id=target_org_id,
        capabilities=capabilities,
        session_context="initiator",
        model=model,
        invocation=invocation,
        context=context,
    )

    target_decision = await call_pdp_webhook(
        org_id=target_org_id,
        webhook_url=target_webhook_url,
        initiator_agent_id=initiator_agent_id,
        initiator_org_id=initiator_org_id,
        target_agent_id=target_agent_id,
        target_org_id=target_org_id,
        capabilities=capabilities,
        session_context="target",
        model=model,
        invocation=invocation,
        context=context,
    )

    # Track dual-org policy mismatch (one allowed, other denied)
    if initiator_decision.allowed != target_decision.allowed:
        from app.telemetry_metrics import POLICY_DUAL_ORG_MISMATCH_COUNTER
        POLICY_DUAL_ORG_MISMATCH_COUNTER.add(1, {
            "denied_by": target_org_id if initiator_decision.allowed else initiator_org_id,
        })

    if not initiator_decision.allowed:
        return initiator_decision
    if not target_decision.allowed:
        return target_decision

    # Both allow: intersect the constraints (ADR-029).
    return WebhookDecision(
        allowed=True,
        reason="both PDPs allowed",
        org_id="broker",
        scope=_intersect_scopes(initiator_decision.scope, target_decision.scope),
        rate_limit=_intersect_rate_limits(
            initiator_decision.rate_limit, target_decision.rate_limit,
        ),
        obligations=_intersect_obligations(
            initiator_decision.obligations, target_decision.obligations,
        ),
    )
