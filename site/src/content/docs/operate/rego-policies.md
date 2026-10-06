---
title: "Rego policies — beyond allowlists"
description: "Constrain authorized actions with Rego rules compiled to WASM. Configured policies deny requests when evaluation fails."
category: "Operate"
order: 9
updated: "2026-10-06"
---

# Rego policies

Tool execution follows cumulative checks:

1. **Action permission:** every tool must declare a capability and every caller must hold it. Agent device tier requirements also apply.
2. **Tool permission:** MCP resources require an active binding. Operator Tool Rules can further restrict tools, principals, models and servers.
3. **Conditions:** the gateway selects the authenticated agent's delegation and evaluates Rego. An allow at this stage cannot override any earlier denial.

REST `/v1/ingress/execute` and MCP `/v1/mcp` share the executor. Their discovery endpoints filter capabilities and resource bindings. Session PDP endpoints evaluate Built-in Rules before Rego; tool PDP endpoints use the same Tool Rules and Rego composition as the executor. External PDP callers remain responsible for authenticating their users and enforcing their own capability and binding checks: a PDP response does not execute a tool or grant access to a resource.

Cullis ships OPA, so there is **no extra component to install**. Writing Rego adds expressiveness without changing the deployment topology.

## Why Rego over allowlists

Allowlists answer "is this agent / org / tool on the list". Rego answers anything you can describe in a rule:

- "Treasury wire transfers are allowed only when the agent's enrollment is less than 24 hours old"
- "The KYC screener can call sanctions_lookup but never PII export"
- "Cross-org session-open is allowed only when the target org is in the operator's approved partner list AND the initiator has the `kyc.partner-disclose` capability"

The expressiveness comes from the same Rego the OPA community uses, with all of `data` / `input` / `package` / function composition. Operators familiar with OPA write what they already know; operators new to Rego work from the examples below.

## Surfaces

Cullis evaluates two Rego entrypoints:

- `data.cullis.policy.session` — invoked for `/pdp/policy` (legacy broker webhook) and `/v1/data/cullis/policy/session` (external policy bridge). The `input` document mirrors the OPA Data API session shape:

  ```json
  {
    "initiator_agent_id": "orga::a",
    "target_agent_id": "orgb::b",
    "initiator_org_id": "orga",
    "target_org_id": "orgb",
    "session_context": "initiator",
    "capabilities": ["kyc.read", "kyc.submit"]
  }
  ```

- `data.cullis.policy.tool_call` — invoked for `/v1/data/cullis/policy/tool_call` and authorized REST/MCP tool executions. The executor supplies the authenticated `agent_id` and `principal_type`; caller arguments cannot replace them. The `input` mirrors the OPA Data API tool-call shape:

  ```json
  {
    "agent_id": "orga::kyc-screener",
    "tool_name": "sanctions_lookup",
    "arguments": { "...": "..." }
  }
  ```

Both rules must return one of these shapes:

- A boolean — `true` ⇒ allow, `false` ⇒ deny
- An object — `{"decision": "allow"|"deny", "reason"?: "<string>"}` — recommended, because the dashboard surfaces the `reason` to the operator on every deny.

Anything else fails closed (the call is denied, and the failure is logged so the operator catches it on next dashboard load).

## Example 1 — session policy with org allowlist + capability gate

```rego
package cullis.policy

# Session-open default: allow inside the org, otherwise consult the
# operator's approved partners list and the initiator's capabilities.
session := {"decision": "allow"} if {
    same_org
}

session := {"decision": "allow"} if {
    cross_org_allowed
}

session := {"decision": "deny", "reason": msg} if {
    not same_org
    not cross_org_allowed
    msg := sprintf(
        "cross-org session %s -> %s requires partner approval AND kyc.partner-disclose capability",
        [input.initiator_org_id, input.target_org_id],
    )
}

same_org if {
    input.initiator_org_id == input.target_org_id
    input.initiator_org_id != ""
}

approved_partners := {"orga", "orgb", "treasury-partner-eu"}

cross_org_allowed if {
    input.target_org_id == approved_partners[_]
    "kyc.partner-disclose" == input.capabilities[_]
}
```

What this expresses in plain English: same-org sessions always pass; cross-org sessions pass only when the target org is in the operator's approved list AND the initiator brought the `kyc.partner-disclose` capability. Anything else returns deny with a specific reason the operator sees on every blocked attempt.

## Example 2 — tool-call policy with per-agent allowlist

```rego
package cullis.policy

# Default deny — only the explicit allow rules below let calls through.
tool_call := {"decision": "deny", "reason": msg} if {
    not allow_tool_call
    msg := sprintf(
        "agent %s is not authorised to call tool %s",
        [input.agent_id, input.tool_name],
    )
}

tool_call := {"decision": "allow"} if {
    allow_tool_call
}

# KYC screener: read-only KYC tools.
allow_tool_call if {
    input.agent_id == "orga::kyc-screener"
    input.tool_name == "sanctions_lookup"
}

allow_tool_call if {
    input.agent_id == "orga::kyc-screener"
    input.tool_name == "kyc_status_check"
}

# Treasury bot: explicit list of money-moving tools.
allow_tool_call if {
    input.agent_id == "orga::treasury"
    input.tool_name == {"treasury_wire", "sepa_credit_transfer"}[_]
}

# Open KB lookups for any internal agent.
allow_tool_call if {
    startswith(input.agent_id, "orga::")
    input.tool_name == "knowledge_base_query"
}
```

Both examples use the OPA v1 syntax (`if` keyword required on rule bodies). The bundled OPA binary is v1.16.2; the engine surfaces the `opa build` diagnostic verbatim when the operator pastes pre-v1 Rego, so the error message names the exact line + column to fix.

Default-deny is the safer default — but you can flip the polarity by setting `tool_call := {"decision": "allow"}` as the bare default and explicitly denying the dangerous tools. Make the choice that matches your operator's mental model.

## Authoring workflow

1. Open the dashboard at `https://mastio.example.com:9443/proxy/policies`.
2. Paste Rego into the Policies editor. Save.
3. Cullis runs `opa build -t wasm -e cullis/policy/session -e cullis/policy/tool_call` on the source. On success: green checkmark, WASM bundle persisted, next decision evaluates Rego. On failure: red banner with the `opa build` diagnostic (line + column + error reason). The previously saved policy stays active; legacy rules apply only if no Rego policy was previously saved.
4. Watch the audit log. Every Rego-decided call carries the WASM SHA-256 prefix in the log line (`PDP[rego] DENY: ... sha256=ab12cd34...`) so the operator can correlate a runtime decision back to the policy version that produced it.

## Constraints

A few OPA built-ins do not work in the WASM target — primarily anything that requires a host binding (HTTP, time, crypto outside `crypto.hmac.*`). For deployments that need those, run Cullis with an external OPA server fronting the policy-bridge endpoint and keep the in-process Rego limited to pure rules over `input`. Most policy rules describing access control over `agent_id` / `org_id` / `tool_name` / `capabilities` do not hit these constraints.

The compile step bounds Rego at **10 seconds**. Honest policies compile in well under a second; a 10-second compile usually means a runaway loop and the operator hears about it explicitly on Save.

## Performance

The OPA binary bundled in the image is **v1.16.2**, SHA-256-pinned at build time (`scripts/opa-sha256.txt`, verified with `sha256sum -c`). Policies compile to WebAssembly on Save (~25 ms) and evaluate in-process via `opa-wasmtime` — no sidecar, no network hop. After the first evaluate warms the instance cache, a representative 60-line policy runs at **p50 ~0.2 ms / ~4 600 evals/s** single-thread. The benchmark is reproducible: `python scripts/bench-rego-eval.py`.

## Required delegations

Enable **Require an agent delegation and Rego policy** on a sensitive MCP resource (`requires_delegation: true` in the admin API). This requirement is stored on the resource independently of `policy_rules` and read on every execution, including across workers. Removing the rule or the entire policy therefore denies access. Builtin definitions can declare the same requirement.

In Tool Rules, set delegations by exact principal ID:

```json
{
  "tool_rules": {
    "issue_refund": {
      "delegations": {
        "acme::refund100": {"max_amount_cents": 10000},
        "acme::refund1000": {"max_amount_cents": 100000}
      }
    }
  }
}
```

A nonempty named Tool Rules collection denies unlisted tools. `allowed_principals: []` explicitly denies every principal; omitting the field imposes no additional principal restriction. Legacy `allowed_tools` and `blocked_tools` lists are also enforced. Malformed restrictions deny rather than disappear.

Rego receives the selected conditions as `input.delegation`; arguments cannot replace this value or `input.agent_id`:

```rego
package cullis.policy

default session := {"decision": "deny"}
default tool_call := {"decision": "deny"}

tool_call := {"decision": "allow"} if {
    input.tool_name == "issue_refund"
    input.arguments.currency == "EUR"
    is_number(input.arguments.amount_cents)
    input.arguments.amount_cents > 0
    input.arguments.amount_cents == floor(input.arguments.amount_cents)
    input.arguments.amount_cents <= input.delegation.max_amount_cents
}
```

These limits are per invocation. Cumulative spending limits require a transactional ledger; this example does not implement one. A ticket agent without `refunds.issue` never reaches refund Rego, even if accidentally bound to the financial resource.

A missing delegation denies with `delegation_missing`; a delegation without Rego denies with `delegation_policy_missing`. Configured but corrupt artifacts, runtime exceptions, undefined rules and malformed decisions deny. Other policy errors use `policy_configuration_error`, `rego_artifact_error` or `rego_evaluation_error`. Executor failures retain `policy_denied` and are audited before secrets or handler execution.

## Upgrade behavior

Tools with no declared capability can no longer execute, including MCP resources. User and workload principals also need the declared capability. Add explicit capabilities and grants to existing resources before upgrading. Binding remains required in addition to capability. Device tier applies to agent identities; users and workloads have no agent device attestation source.

Static denials now win over Rego on every PDP surface. Model restrictions cannot be satisfied by placing a model ID in tool arguments; the native executor has no authoritative model context, so such restricted calls deny. The `scope`, `rate_limit` and `obligations` fields are advisory PDP output; enforce runtime conditions in Rego rather than assuming these fields alone constrain execution.

Resources with optional delegation preserve execution without Rego after all other checks pass. Mark sensitive resources as requiring delegation before relying on amount limits.

## What stays the same

- The dashboard Policies page is still the authoring surface.
- `policy_rules` is still the source of truth (the Rego source and compiled WASM live in two new fields inside that same JSON document).
- The OPA Data API + CloudEvents bridge introduced in PR #907 keeps working unchanged — external gateways already pointing at `/v1/data/cullis/policy/*` get the new Rego-shaped decision automatically.
- The audit log still records every decision with the originating agent / org / tool. Rego adds a `sha256=<prefix>` in the log line so the operator can trace decisions back to the policy version, but the audit row itself stays the same shape — no schema migration.
