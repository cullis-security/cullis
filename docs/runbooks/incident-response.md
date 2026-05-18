# Incident response runbook (Cullis)

**Audience:** customer security operators running Cullis Mastio or
Cullis Court in production, plus the Cullis security team handling
vulnerability reports under coordinated disclosure.

**Status:** Version 1.0, 2026-05-18. Quarterly review.
Next review: 2026-08-18.

**Contact for active incidents:** security@cullis.io (mailbox
monitored continuously, expect acknowledgment within 48 hours).

---

## 1. Overview

This runbook covers detection, containment, recovery, and
communication for security incidents that affect Cullis components
(Court, Mastio, Connector) or that are reported against the Cullis
codebase. The threat surface itself is documented in
[`docs/security/threat-model.md`](../security/threat-model.md); this
file is the response side of the same picture.

The flow for any incident is:

1. **Detect.** Trigger from operator alerting, customer report, or
   inbound vulnerability disclosure.
2. **Classify.** Apply the severity matrix in section 2.
3. **Contain.** Apply the per-severity procedure in section 3. The
   first-line goal is to stop the bleeding, not to find root cause.
4. **Investigate.** Once contained, gather evidence (audit chain
   slice, log bundle, registry snapshot).
5. **Recover.** Restore service per the procedure for the relevant
   key or component.
6. **Communicate.** Customer notification, status page, public
   disclosure on the timeline in section 4.
7. **Retrospective.** Within 14 days of resolution, write a
   post-incident review (template in section 7) and feed lessons
   back into the threat model.

Cullis ships pre-1.0; in practice the founder is the on-call. A
24x7 PagerDuty partner will be contracted ahead of the first paid
pilot. Section 6 describes the interim arrangement.

---

## 2. Severity classification

The matrix below mirrors the CVSS-derived SLA tiers in
[`SECURITY.md`](../../SECURITY.md) but adds operational triggers
keyed to Cullis-specific assets.

### Sev 1 (Critical)

CVSS 9.0 to 10.0, or any of the following operational triggers:

- Org Root CA private key compromise (any organisation, any
  deployment).
- Cullis-side license JWT signing key compromise.
- Active CVE exploitation against any Mastio or Court in production
  (in-the-wild, not theoretical).
- Customer data breach: agent identity material, audit chain
  contents, or upstream LLM session material has been confirmed
  exfiltrated.
- Audit chain forgery confirmed against a federated peer's anchor.

Acknowledgment SLA: 4 hours.
Containment SLA: 24 hours.
Fix SLA: 7 days.

### Sev 2 (High)

CVSS 7.0 to 8.9, or any of the following:

- Mastio Intermediate CA private key compromise.
- Mastio leaf (federation) cert compromise.
- Agent cert leak affecting more than 10 agents in one org.
- Connector compromise in Frontdesk shared mode (multi-user blast
  radius).
- Authentication bypass (anyone can authenticate as anyone, scoped
  but not org-wide).
- Privileged builtin capability bypass affecting more than one tool.

Acknowledgment SLA: 24 hours.
Containment SLA: 72 hours.
Fix SLA: 14 days.

### Sev 3 (Medium)

CVSS 4.0 to 6.9, or any of the following:

- Single agent cert leak (one agent, one org).
- DPoP token theft (single token, contained by 5-minute JTI cache
  TTL).
- Audit replication delay between Mastio and Court exceeding 1
  hour.
- Non-privileged tool capability misconfiguration.
- Information disclosure of non-secret metadata (agent enrolment
  timestamps, federation org names) outside the authorised
  audience.

Acknowledgment SLA: 48 hours.
Containment SLA: 7 days.
Fix SLA: 30 days.

### Sev 4 (Low)

CVSS 0.1 to 3.9, or any of the following:

- Config drift on a single agent (logged, not user-visible).
- Telemetry gap under 15 minutes.
- Minor non-security UX issues with security implications (e.g. an
  admin form that warns less clearly than it should).

Acknowledgment SLA: 5 business days.
Fix SLA: best effort, next minor release.

---

## 3. Response procedures

Each procedure follows the same five-step shape: **detect, contain,
investigate, recover, communicate**. Times below are wall-clock
elapsed from the start of containment.

### 3.1 Sev 1: Org Root CA compromise

**Detect.** Trigger: unexplained `pki.org_root_unsealed` audit row
(Wave 1-A introduced this), unexplained re-issuance of a Mastio
Intermediate CA, evidence the operator-side `MCP_PROXY_DB_ENCRYPTION_KEY`
or the at-rest envelope was exfiltrated.

**Contain (0 to 4 h).**

1. Take the Mastio offline:
   `docker compose -p cullis-mastio down` (no `-v`, preserve
   volumes for forensics).
2. If federated, notify Court operators to mark the org as
   suspended via `POST /v1/admin/federation/orgs/<id>/suspend`.
   Court will refuse cross-org calls signed by the compromised
   Mastio leaf and emit a federation event to peer Mastios.
3. Disable any operator workflow that requires Org Root unseal
   (Intermediate rotation, CA bundle re-generation) until recovery
   begins.

**Investigate (4 to 24 h).**

1. Capture the audit chain slice for the period from the last clean
   reference point (last known-good anchor at Court) to the moment
   of containment.
2. Capture host telemetry: process tree, file system state of the
   `pki_key_store` table, last 30 days of `MCP_PROXY_DB_ENCRYPTION_KEY`
   access events from the secrets manager.
3. Identify the unsealing path: legitimate operator activity,
   unauthorised dashboard access, or container compromise.

**Recover (24 to 168 h).**

1. Generate a new Org Root CA on a clean host using the recovery
   procedure in `operate/rotate-keys.md`. This is a cold-storage
   ceremony: airgapped laptop, freshly generated passphrase, key
   sealed back to the at-rest envelope on the recovered host.
2. Re-issue Mastio Intermediate CA from the new Root.
3. Re-issue every agent leaf cert (bulk re-enrolment). The runbook
   for bulk re-enrolment is in `operate/rotate-keys.md`; allow up
   to 48 h for fleet rollout depending on agent count.
4. Push the new CA bundle to federated peers via Court
   `ContinuityProof` flow.

**Communicate.**

- Customer notification email within 4 hours of confirmation.
  Template in section 4.1.
- Status page update at cullis.io/status (placeholder; the page
  goes live ahead of the first paid pilot).
- Public CVE issued simultaneously with the fix release.
- Post-incident review published within 14 days, redacted where
  customer information requires it.

### 3.2 Sev 1: Mastio Intermediate CA compromise

**Detect.** Trigger: unexpected new Intermediate observed in the
auto-rotation watcher log without a matching legitimate trigger,
evidence the Vault path holding the Intermediate key was accessed
out-of-band.

**Contain (0 to 4 h).**

1. Same offline step as 3.1 if the compromise vector is unclear.
   If the auto-rotation watcher already replaced the Intermediate
   and the compromise is to the *prior* Intermediate, recovery is
   faster (skip to step 2).
2. Confirm the watcher has signed a new Intermediate (the new chain
   is already published via the CA bundle as of Wave 1-A, PR #788).

**Investigate (4 to 24 h).**

1. Audit chain slice for `pki.intermediate_*` rows.
2. Vault audit log for the Intermediate KV path (if Vault backend).
3. Identify whether any leaves were issued by the compromised
   Intermediate to non-legitimate agents.

**Recover.**

The Wave 1-A rotation hook makes this fast: the new Intermediate is
signed by the still-cold Org Root, the published CA bundle now
contains both Intermediates for the grace window, all valid leaves
continue to authenticate. Schedule the old Intermediate for
removal from the bundle once the grace window expires (default 30
days, configurable).

**Communicate.** Sev 1 customer notification, but the absence of
re-enrolment is itself the headline: customers should not need to
take action.

### 3.3 Sev 2: Agent cert leak

**Detect.** Trigger: customer report, anomalous DPoP `jti` activity
from a known agent, agent cert thumbprint observed in unauthorised
logs.

**Contain (0 to 4 h).**

1. Revoke the agent cert via the dashboard form `rotate_agent_cert`
   (operator-side action). Public REST endpoint for this is on the
   P2 roadmap; until it lands, the dashboard is the only path.
2. Pinning rejects the old thumbprint on the next request. Existing
   DPoP proofs signed with the leaked key are useless without the
   matching cert.

**Investigate.**

1. Audit chain slice for the agent's recent calls (per-agent
   filter on `audit_log.agent_id`).
2. Cross-reference with upstream MCP server logs to identify any
   calls that should not have happened.

**Recover.**

1. Re-enrol the agent via the dashboard. New keypair, new cert,
   new thumbprint pinned.
2. **Grace-period transition (Wave 2 fix 7, in progress).** Once
   landed, the operator can keep the old cert valid for a
   configurable window (24 to 48 hours) so the agent process can
   migrate without an enrolment outage. Until Wave 2 lands, the
   agent must be re-enrolled with a brief downtime.

**Communicate.** Customer notification within 24 hours of
confirmation. No public disclosure required unless the leak vector
is a Cullis defect (then escalate to Sev 1 / Sev 2 fix path).

### 3.4 Sev 2: Frontdesk Connector compromise

**Detect.** Trigger: spike in
`frontdesk_shared_unauthenticated_user_session_warning` audit
events (the Phase 1 baseline metric), evidence the Frontdesk
container has been root-shell-accessed, observation of impersonated
user activity.

The detection guidance and Grafana alert pseudo-query are in
[`docs/runbooks/frontdesk-shared-hardening.md`](./frontdesk-shared-hardening.md)
section 3. Re-read it before responding.

**Contain (0 to 2 h).**

1. Revoke the Connector cert at the Mastio:
   `POST /v1/admin/agents/<connector-agent-id>/revoke`. After
   revocation the Mastio rejects all DPoP-authenticated requests
   from the Connector; existing user sessions are invalidated
   because they depend on the Connector's cert thumbprint for
   pinning.
2. Revoke all user sessions:
   `POST /v1/admin/agents/<connector-agent-id>/revoke-all-sessions`.
3. Take the container offline:
   `docker compose -p cullis-frontdesk down`.

**Investigate.**

1. Audit chain filter on `connector_agent_id` for the window from
   the suspected start of compromise to the revocation.
2. Focus on rows with `on_behalf_of_user_id` populated: these show
   which users may have been impersonated.
3. If WebAuthn is enabled (Phase 2, PR #789), the
   `user_signed_assertion` field is the second source of truth: a
   row without a valid assertion in a Phase-2 deployment is a hard
   anomaly.

**Recover.**

1. Verify the container image is clean (cosign verify, SBOM
   review).
2. Bring the bundle back up: `./deploy.sh`.
3. Re-approve the Connector enrolment in the Mastio dashboard.
4. All users log in again; users without an enrolled WebAuthn
   credential are prompted to enrol one (Phase 2).

**Communicate.** Customer notification within 24 hours, including
the list of potentially impersonated users (the
`on_behalf_of_user_id` set from the audit slice). Phase 2 WebAuthn
materially shrinks this list: a row with a valid
`user_signed_assertion` cannot have been impersonated by the
container alone.

### 3.5 Sev 3: Single agent cert leak / DPoP token theft

For a single-agent leak, follow 3.3 with these adjustments:

- No customer-wide notification; the affected customer is
  notified directly.
- Replication of the audit chain slice is optional unless the
  customer requests forensic support.

For a single DPoP token theft, the 5-minute JTI cache TTL is the
primary containment: the stolen token is useless after the window
elapses, and the JTI is registered as used. Operators still rotate
the agent cert as a defence-in-depth step.

### 3.6 Sev 4: Configuration drift / minor issues

Operator workflow handles Sev 4 via the standard PR / release path.
The CHANGELOG entry under "Security" notes the fix; no separate
customer notification is required unless the operator opts in via
their internal change management policy.

---

## 4. Communication templates

### 4.1 Customer notification email (Sev 1)

```
Subject: [Cullis] Sev 1 security incident — action may be required

To: <customer security contact>
From: security@cullis.io

We are notifying you of a Sev 1 security incident affecting Cullis
that may require action on your side.

Summary
-------
- Date of detection: <UTC timestamp>
- Component affected: <Court / Mastio / Connector>
- Nature: <one-line description, no premature attribution>
- Customer action required: <yes / no, and what>
- Cullis action in progress: <containment / recovery / fix>
- Time to expected resolution: <hours or days>

What you should do now
----------------------
<bullet list, customer-specific>

What Cullis is doing
--------------------
<bullet list, transparency-first>

Next update
-----------
You will receive a follow-up within <X hours>. For urgent questions
in the meantime, reply to this email or call <on-call number>.

Coordinated disclosure
----------------------
We are operating under our coordinated disclosure policy
(SECURITY.md). Please do not share this notification outside your
security team until the public disclosure window opens; the
expected public disclosure date is <date>.

— The Cullis security team
  security@cullis.io
```

### 4.2 Status page update (Sev 1 or Sev 2)

```
Title: <one-line incident summary>
Status: investigating | identified | monitoring | resolved
Severity: critical | major | minor
Affected: <component list>
Posted: <UTC>
Last update: <UTC>

<short update body, ~2 sentences, no internal jargon>

Next update in <X hours>.
```

The status page lives at cullis.io/status (placeholder until the
first paid pilot; until then, the customer email is the
authoritative channel).

### 4.3 Public disclosure post

Published on cullis.io/blog when the public disclosure window opens
(default 90 days after the report, or upon coordinated release,
whichever comes first). Template:

- Headline: factual, no marketing.
- Summary: what the vulnerability was, who was affected, what the
  fix is.
- Timeline: report received, acknowledged, fix released, public
  disclosure.
- Credit: reporter named unless they asked to remain anonymous.
- CVE: linked.
- Mitigation guidance for customers still on a vulnerable version.
- Lessons: what we changed in the codebase or process to prevent a
  similar issue.

---

## 5. SLA summary

| Severity | Acknowledgment | Containment | Fix       | Customer notification | Public disclosure                    |
|----------|----------------|-------------|-----------|-----------------------|--------------------------------------|
| Sev 1    | 4 hours        | 24 hours    | 7 days    | within 4 hours        | 90 days, or upon coordinated release |
| Sev 2    | 24 hours       | 72 hours    | 14 days   | within 24 hours       | 90 days, or upon coordinated release |
| Sev 3    | 48 hours       | 7 days      | 30 days   | affected customer only| 90 days, or upon coordinated release |
| Sev 4    | 5 business days| n/a         | next minor| not required          | CHANGELOG entry on release           |

These targets mirror the SLA matrix in
[`SECURITY.md`](../../SECURITY.md). A target that cannot be met
because of a coordinated upstream release will be renegotiated with
the reporter on first contact.

---

## 6. Contacts and on-call

- **Cullis security team:** security@cullis.io. Mailbox monitored
  continuously by the founder; acknowledgment within 48 hours
  (faster for Sev 1 and Sev 2, see section 5).
- **PGP key:** to be published before the first paid pilot. Until
  then, use GitHub's private vulnerability reporting if the
  contents are sensitive enough that an unencrypted email is
  unacceptable (see SECURITY.md).
- **On-call rotation:** founder direct, currently solo. A 24x7
  PagerDuty partner will be contracted ahead of the first paid
  engagement; the contact details for that partner will land in
  this file when the contract is in place.
- **Legal / breach notification (GDPR 72-hour):** an external IT
  lawyer will be retained ahead of the first regulated-industry
  pilot. Until that lawyer is named here, escalate any potential
  GDPR-relevant incident to security@cullis.io within the first
  hour of containment so we can engage outside counsel.
- **Cybersecurity insurance:** policy procurement is in progress.
  Until a policy is bound, customer indemnification is per the
  signed customer agreement; default contract is the Apache 2.0
  / FSL-1.1-Apache-2.0 license terms (no warranty), modified per
  customer engagement.

---

## 7. Post-incident review template

Within 14 days of resolution, the on-call writes a post-incident
review. Template:

```
# Post-incident review: <short title>

- Severity: <Sev 1 / 2 / 3 / 4>
- Affected component: <Court / Mastio / Connector / SDK / Connector container>
- Affected customers: <count, or "single internal" if pre-pilot>
- Date detected: <UTC>
- Date contained: <UTC>
- Date fixed: <UTC>
- Date public disclosure: <UTC, or "n/a">
- Author: <name>

## Timeline

<bulleted UTC log of events, from first signal to resolution>

## Root cause

<technical explanation, no blame>

## Why our defences did not catch it earlier

<honest assessment: missing test, missing alert, threat-model gap>

## What we changed

- Code: <commits, PRs>
- Tests: <new tests, coverage targets>
- Threat model: <new row in docs/security/threat-model.md, ADR if needed>
- Runbook: <new section here>

## What we did not change, and why

<things that came up during the post-mortem but were deferred,
with the reason and the tracking issue>

## Lessons

<one or two paragraphs, written for the next on-call>
```

Reviews are filed in `imp/post-incident-reviews/` (internal,
gitignored). A redacted summary is published on cullis.io/blog
when the public disclosure window opens.

---

## 8. References

- [`SECURITY.md`](../../SECURITY.md): responsible disclosure policy
  and SLA matrix.
- [`docs/security/threat-model.md`](../security/threat-model.md):
  threat catalog and trust boundaries.
- [`docs/runbooks/frontdesk-shared-hardening.md`](./frontdesk-shared-hardening.md):
  Frontdesk shared-mode operational controls and Sev 2 compromise
  response.
- [`docs/runbooks/postgres-pilot.md`](./postgres-pilot.md):
  Postgres pilot operational runbook (capacity, backup, restore).
- [`operate/rotate-keys.md`](../operate/rotate-keys.md): manual
  rotation procedures for Org Root and bulk agent re-enrolment.
- ADR-013 (layered defence), ADR-033 (PKI three-tier hardening),
  ADR-033 (Frontdesk shared-mode threat model).
