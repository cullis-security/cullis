"""
Policy engine — evaluates whether a session or message is allowed.

Defaults:
  - sessions: default deny  (without a policy, nothing passes)
  - messages: default allow (if the session is open, messages pass
                              unless an explicit policy blocks them)
"""
import json
from dataclasses import dataclass, field

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.audit import log_event
from app.policy.store import list_policies
from app.telemetry import tracer
from app.telemetry_metrics import POLICY_ALLOW_COUNTER, POLICY_DENY_COUNTER


@dataclass
class PolicyDecision:
    allowed: bool
    reason: str
    policy_id: str | None = None


class PolicyEngine:

    # ------------------------------------------------------------------
    # Sessions — default deny
    # ------------------------------------------------------------------

    async def evaluate_session(
        self,
        db: AsyncSession,
        initiator_org_id: str,
        target_org_id: str,
        capabilities: list[str],
        active_session_count: int = 0,
        agent_id: str | None = None,
        session_id: str | None = None,
    ) -> PolicyDecision:
        """
        Evaluate whether the initiator can open a session with the target.

        Logic:
          1. Evaluate org-specific policies for initiator_org_id.
             - A matching deny  → immediate deny.
             - A matching allow → allow.
          2. No policy found → deny (strict default deny).
        """
        policies = await list_policies(db, initiator_org_id, policy_type="session")

        if not policies:
            decision = PolicyDecision(
                allowed=False,
                reason="Nessuna policy definita — default deny",
            )
            await self._audit(db, "session", decision, initiator_org_id, agent_id, session_id)
            return decision

        last_deny_reason = "No matching org policy found"
        last_deny_policy_id: str | None = None

        for record in policies:
            rules = record.rules
            conditions = rules.get("conditions", {})
            effect = rules.get("effect", "allow")

            is_match = True

            # Condition 1: target_org_id
            allowed_orgs: list[str] = conditions.get("target_org_id", [])
            if allowed_orgs and target_org_id not in allowed_orgs:
                is_match = False
                last_deny_reason = f"Target organisation '{target_org_id}' not permitted by policy"
                last_deny_policy_id = record.policy_id

            # Condition 2: capabilities
            if is_match:
                allowed_caps: list[str] = conditions.get("capabilities", [])
                if allowed_caps:
                    blocked = [c for c in capabilities if c not in allowed_caps]
                    if blocked:
                        is_match = False
                        last_deny_reason = f"Capabilities {blocked} not permitted by policy"
                        last_deny_policy_id = record.policy_id

            # Condition 3: max_active_sessions
            if is_match:
                max_sessions: int | None = conditions.get("max_active_sessions")
                if max_sessions is not None and active_session_count >= max_sessions:
                    is_match = False
                    last_deny_reason = f"Active session limit reached ({active_session_count}/{max_sessions})"
                    last_deny_policy_id = record.policy_id

            if not is_match:
                continue  # conditions not met — try next policy

            # Policy conditions matched — apply effect
            if effect == "deny":
                decision = PolicyDecision(
                    allowed=False,
                    reason="Explicitly denied by org policy",
                    policy_id=record.policy_id,
                )
                await self._audit(db, "session", decision, initiator_org_id, agent_id, session_id)
                return decision

            decision = PolicyDecision(
                allowed=True,
                reason="Allowed by org policy",
                policy_id=record.policy_id,
            )
            await self._audit(db, "session", decision, initiator_org_id, agent_id, session_id)
            return decision

        decision = PolicyDecision(
            allowed=False,
            reason=last_deny_reason,
            policy_id=last_deny_policy_id,
        )
        await self._audit(db, "session", decision, initiator_org_id, agent_id, session_id)
        return decision

    # ------------------------------------------------------------------
    # Messages — default allow
    # ------------------------------------------------------------------

    async def evaluate_message(
        self,
        db: AsyncSession,
        sender_org_id: str,
        payload: dict,
        agent_id: str | None = None,
        session_id: str | None = None,
    ) -> PolicyDecision:
        """
        Evaluate whether a message payload can transit.

        Logic:
          1. Load active "message" policies for sender_org_id.
          2. If none exist → allow (default allow for messages).
          3. For each active policy, evaluate conditions.
             If a condition fails → immediate deny.
          4. If all policies are satisfied → allow.
        """
        policies = await list_policies(db, sender_org_id, policy_type="message")

        if not policies:
            decision = PolicyDecision(
                allowed=True,
                reason="No message policy — default allow",
            )
            await self._audit(db, "message", decision, sender_org_id, agent_id, session_id)
            return decision

        payload_str = json.dumps(payload)

        for record in policies:
            rules = record.rules
            conditions = rules.get("conditions", {})
            effect = rules.get("effect", "allow")

            # Condition 1: payload size
            max_size: int | None = conditions.get("max_payload_size_bytes")
            if max_size is not None and len(payload_str.encode()) > max_size:
                decision = PolicyDecision(
                    allowed=False,
                    reason=(
                        f"Payload too large: {len(payload_str.encode())} bytes "
                        f"(max {max_size})"
                    ),
                    policy_id=record.policy_id,
                )
                await self._audit(db, "message", decision, sender_org_id, agent_id, session_id)
                return decision

            # Condition 2: required fields
            required: list[str] = conditions.get("required_fields", [])
            missing = [f for f in required if f not in payload]
            if missing:
                decision = PolicyDecision(
                    allowed=False,
                    reason=f"Required fields missing from payload: {missing}",
                    policy_id=record.policy_id,
                )
                await self._audit(db, "message", decision, sender_org_id, agent_id, session_id)
                return decision

            # Condition 3: blocked fields
            blocked_fields: list[str] = conditions.get("blocked_fields", [])
            present_blocked = [f for f in blocked_fields if f in payload]
            if present_blocked:
                decision = PolicyDecision(
                    allowed=False,
                    reason=f"Blocked fields present in payload: {present_blocked}",
                    policy_id=record.policy_id,
                )
                await self._audit(db, "message", decision, sender_org_id, agent_id, session_id)
                return decision

            # Condition 4: explicit deny (catch-all — e.g. emergency block with no field conditions)
            if effect == "deny":
                decision = PolicyDecision(
                    allowed=False,
                    reason="Message explicitly denied by policy",
                    policy_id=record.policy_id,
                )
                await self._audit(db, "message", decision, sender_org_id, agent_id, session_id)
                return decision

        decision = PolicyDecision(
            allowed=True,
            reason="Payload compliant with policies",
            policy_id=None,
        )
        await self._audit(db, "message", decision, sender_org_id, agent_id, session_id)
        return decision

    # ------------------------------------------------------------------
    # Audit helper
    # ------------------------------------------------------------------

    async def _audit(
        self,
        db: AsyncSession,
        policy_type: str,
        decision: PolicyDecision,
        org_id: str,
        agent_id: str | None,
        session_id: str | None,
    ) -> None:
        if decision.allowed:
            POLICY_ALLOW_COUNTER.add(1, {"policy_type": policy_type})
        else:
            POLICY_DENY_COUNTER.add(1, {"policy_type": policy_type})
        await log_event(
            db,
            event_type="policy.evaluated",
            result="ok" if decision.allowed else "denied",
            agent_id=agent_id,
            session_id=session_id,
            org_id=org_id,
            details={
                "policy_type": policy_type,
                "policy_id": decision.policy_id,
                "reason": decision.reason,
            },
        )
