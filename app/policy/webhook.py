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
import logging
import time
from dataclasses import dataclass

import httpx

from app.telemetry import tracer
from app.telemetry_metrics import PDP_WEBHOOK_LATENCY_HISTOGRAM

_log = logging.getLogger("agent_trust")

_WEBHOOK_TIMEOUT = 5.0  # seconds


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
        _log.info(
            "PDP webhook not configured for org '%s' — skipping (allow)", org_id
        )
        return WebhookDecision(
            allowed=True,
            reason=f"Organization '{org_id}' has no PDP webhook — skipped",
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

    t0 = time.monotonic()
    try:
        with tracer.start_as_current_span("pdp.webhook_call") as span:
            span.set_attribute("pdp.org_id", org_id)
            span.set_attribute("pdp.context", session_context)
            async with httpx.AsyncClient(timeout=_WEBHOOK_TIMEOUT) as client:
                resp = await client.post(webhook_url, json=payload)
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

        data = resp.json()
        decision = data.get("decision", "deny").lower()
        reason = data.get("reason", "")

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

    if not initiator_decision.allowed:
        return initiator_decision
    if not target_decision.allowed:
        return target_decision
    return WebhookDecision(allowed=True, reason="both PDPs allowed", org_id="broker")
