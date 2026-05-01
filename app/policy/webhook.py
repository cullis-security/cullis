"""
PDP Webhook caller — federated policy decision for session requests.

Each organization registers a webhook URL at onboarding time.
When Agent A (org A) requests a session with Agent B (org B), the broker
calls BOTH webhooks and proceeds only if both return {"decision": "allow"}.

Default-deny: if an org has no webhook configured, the decision is DENY.
Timeout: 5 seconds per webhook call (synchronous, sequential).

Webhook contract:
  Request:  POST {webhook_url}
            Content-Type: application/json
            X-ATN-Signature: HMAC-SHA256 of the body (future — not yet enforced)
            Body: {
              "initiator_agent_id": str,
              "initiator_org_id":   str,
              "target_agent_id":    str,
              "target_org_id":      str,
              "capabilities":       list[str],
              "session_context":    str   # "initiator" | "target"
            }

  Response: 200 OK  { "decision": "allow" }
            200 OK  { "decision": "deny", "reason": "..." }
            any non-200 or timeout → treated as DENY
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
    """
    if _allow_private_webhooks():
        return
    # httpx stores network info in response.extensions when using httpcore
    network_stream = resp.extensions.get("network_stream")
    if network_stream is not None:
        try:
            server_addr = network_stream.get_extra_info("server_addr")
            if server_addr:
                ip = ipaddress.ip_address(server_addr[0])
                if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                    raise ValueError(f"Response came from private/reserved IP: {ip}")
        except (TypeError, ValueError, IndexError):
            pass  # cannot determine — fall through to pre-request validation


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
class WebhookDecision:
    allowed: bool
    reason: str
    org_id: str


async def call_pdp_webhook(
    org_id: str,
    webhook_url: str | None,
    initiator_agent_id: str,
    initiator_org_id: str,
    target_agent_id: str,
    target_org_id: str,
    capabilities: list[str],
    session_context: str,  # "initiator" | "target"
) -> WebhookDecision:
    """
    Call the PDP webhook for one organization and return its decision.

    If webhook_url is None or the call fails, returns DENY (default-deny).
    """
    if not webhook_url:
        _log.warning(
            "PDP webhook not configured for org '%s' — default-deny", org_id
        )
        return WebhookDecision(
            allowed=False,
            reason=f"Organization '{org_id}' has no PDP webhook configured — denied by default",
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

    payload = {
        "initiator_agent_id": initiator_agent_id,
        "initiator_org_id":   initiator_org_id,
        "target_agent_id":    target_agent_id,
        "target_org_id":      target_org_id,
        "capabilities":       capabilities,
        "session_context":    session_context,
    }

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

        if decision == "allow":
            _log.info("PDP webhook allow: org=%s context=%s", org_id, session_context)
            return WebhookDecision(allowed=True, reason=reason, org_id=org_id)

        _log.info(
            "PDP webhook deny: org=%s context=%s reason=%s",
            org_id, session_context, reason,
        )
        return WebhookDecision(
            allowed=False,
            reason=reason or f"Denied by org '{org_id}' PDP",
            org_id=org_id,
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


async def evaluate_session_via_webhooks(
    initiator_org_id: str,
    initiator_webhook_url: str | None,
    target_org_id: str,
    target_webhook_url: str | None,
    initiator_agent_id: str,
    target_agent_id: str,
    capabilities: list[str],
) -> WebhookDecision:
    """
    Call both orgs' PDP webhooks. Returns DENY if either denies.
    Both calls are made even if the first denies (for audit completeness).
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
    return WebhookDecision(allowed=True, reason="both PDPs allowed", org_id="broker")
