"""
Policy backend dispatcher — routes session policy decisions to the
configured backend (webhook or OPA).

This is the single entry point called from the broker router.
The backend is selected via the POLICY_BACKEND env var.

Supported backends:
  webhook  — per-org PDP webhooks (default, existing behavior)
  opa      — Open Policy Agent REST API
"""
import logging

from app.policy.webhook import WebhookDecision

_log = logging.getLogger("agent_trust")


async def evaluate_session_policy(
    initiator_org_id: str,
    initiator_webhook_url: str | None,
    target_org_id: str,
    target_webhook_url: str | None,
    initiator_agent_id: str,
    target_agent_id: str,
    capabilities: list[str],
) -> WebhookDecision:
    """
    Evaluate a session request using the configured policy backend.

    For webhook backend: calls both orgs' PDP webhooks (dual allow).
    For OPA backend: calls the OPA REST API once with full context.
    """
    from app.config import get_settings, is_policy_enforced
    settings = get_settings()

    if not is_policy_enforced():
        return WebhookDecision(
            allowed=True,
            reason="Policy enforcement disabled (demo mode)",
            org_id="broker",
        )

    backend = settings.policy_backend.lower()

    if backend == "opa":
        if not settings.opa_url:
            _log.error("POLICY_BACKEND=opa but OPA_URL is not configured — default-deny")
            return WebhookDecision(
                allowed=False,
                reason="OPA URL not configured",
                org_id="broker",
            )
        from app.policy.opa import evaluate_session_via_opa
        return await evaluate_session_via_opa(
            opa_url=settings.opa_url,
            initiator_org_id=initiator_org_id,
            target_org_id=target_org_id,
            initiator_agent_id=initiator_agent_id,
            target_agent_id=target_agent_id,
            capabilities=capabilities,
        )

    # Default: webhook backend
    if backend != "webhook":
        _log.warning("Unknown POLICY_BACKEND '%s' — falling back to webhook", backend)

    from app.policy.webhook import evaluate_session_via_webhooks
    return await evaluate_session_via_webhooks(
        initiator_org_id=initiator_org_id,
        initiator_webhook_url=initiator_webhook_url,
        target_org_id=target_org_id,
        target_webhook_url=target_webhook_url,
        initiator_agent_id=initiator_agent_id,
        target_agent_id=target_agent_id,
        capabilities=capabilities,
    )
