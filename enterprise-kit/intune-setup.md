# Microsoft Intune integration — admin runbook

> Status: Phase 1 (ADR-032 Layer 1, F2 spike)
> Audience: customer tenant admin (Azure AD + Intune licensed)
> Effort: 30-60 minutes once you have admin consent from the Azure AD tenant admin
> Outcome: Mastio polls Microsoft Graph for managed device compliance and stamps a `device_attestation` claim on each Connector enrollment

## What this gets you

Mastio queries `https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/delta` on a polling interval and caches the compliance state of every Intune-enrolled laptop in the tenant. When a Connector enrolls (or its certificate is re-issued), Mastio joins on the device's `azureADDeviceId` and writes a `device_attestation` JSON claim into the agent row. F5 policy consumption and F6 revocation hooks are out of scope here — this PR ships the scaffolding only.

No AppSource Marketplace listing is involved (Cullis is pre-revenue, see ADR-032 Q7). The customer tenant admin registers a multi-tenant app manually and grants admin consent. Plan for 2-4 weeks of bank IT review on a regulated customer.

## Prerequisites

- Microsoft Entra ID tenant with admin role `Cloud Application Administrator` or `Global Administrator`
- At least one device enrolled in Intune (Windows, macOS, iOS, Android, or Linux supported by the Intune connector)
- Network egress from the Mastio host to `https://login.microsoftonline.com` and `https://graph.microsoft.com` (port 443)

## Step 1 — Register the application

1. Open the Azure portal as a tenant admin.
2. Navigate to **Microsoft Entra ID** → **App registrations** → **New registration**.
3. Fill in:
   - **Name**: `Cullis Mastio Intune Reader` (you can customise; this name appears in the consent dialog and in audit logs).
   - **Supported account types**: **Accounts in any organizational directory (Any Microsoft Entra ID tenant - Multitenant)**. This lets the same app definition be re-used across multiple Mastio deployments without a per-tenant publisher account.
   - **Redirect URI**: leave blank. This is a daemon flow (client credentials), not an interactive user flow.
4. Click **Register**. Note the **Application (client) ID** and **Directory (tenant) ID** shown on the overview page.

## Step 2 — Grant API permissions

1. In the app you just registered, click **API permissions** → **Add a permission** → **Microsoft Graph** → **Application permissions** (NOT delegated).
2. Add:
   - `DeviceManagementManagedDevices.Read.All` — required. Lets the app read the inventory of Intune-managed devices and their compliance state.
   - `Directory.Read.All` — optional. Useful if you later want to enrich the audit log with user metadata (display name, department). Not used in Phase 1.
3. Click **Grant admin consent for `<your tenant>`**. A tenant admin (you, if you have the role) must click through the consent dialog. This is the gate that turns the app from "registered but inert" into "able to call Graph".

If a different person holds the Global Administrator role, send them the consent URL:
```
https://login.microsoftonline.com/<tenant-id>/adminconsent?client_id=<application-id>
```

## Step 3 — Create a client secret

1. In the app, click **Certificates & secrets** → **Client secrets** → **New client secret**.
2. Set:
   - **Description**: `cullis-mastio-prod` (or similar — the description shows up when you list secrets later).
   - **Expires**: pick a window agreed with sales. Default Microsoft options are 6 months, 12 months, 24 months, or custom. For regulated customers we recommend 12 months with a calendar reminder to rotate.
3. Click **Add**. Copy the secret **Value** immediately — it is shown once and unrecoverable. Paste it into your secrets manager (Vault, 1Password, Azure Key Vault, etc.).

NOTE: client secrets are bearer credentials with the granted permissions on your whole tenant. Treat them with the same care as the Mastio Org CA private key. Do not commit them to git and do not log them. Rotate at expiry or sooner if compromised.

## Step 4 — Configure Mastio

Add the following to your `proxy.env` (or equivalent secrets store) and restart the Mastio process:

```
MCP_PROXY_MDM_INTUNE_ENABLED=true
MCP_PROXY_MDM_INTUNE_TENANT_ID=00000000-0000-0000-0000-000000000000
MCP_PROXY_MDM_INTUNE_CLIENT_ID=00000000-0000-0000-0000-000000000000
MCP_PROXY_MDM_INTUNE_CLIENT_SECRET=<paste-the-secret-value-from-step-3>
MCP_PROXY_MDM_INTUNE_POLL_INTERVAL_SECONDS=600
MCP_PROXY_ATTESTATION_STALE_THRESHOLD_SECONDS=900
```

`MCP_PROXY_MDM_INTUNE_POLL_INTERVAL_SECONDS` controls how often Mastio fetches the delta endpoint. Default 600 seconds (10 minutes). Microsoft documents Intune compliance state freshness on the order of 5-15 minutes, so polling much faster will not yield fresher data and will increase Graph throttling risk.

`MCP_PROXY_ATTESTATION_STALE_THRESHOLD_SECONDS` controls the age at which a cached device entry is considered stale. Default 900 seconds. Stale entries are reported as `compliance=unknown` in the claim, which downgrades the `effective_tier` (typically from `managed` to `byod_*` or `untrusted`).

## Step 5 — Verify

After restart, tail the Mastio logs for the polling task announcement:

```
docker compose logs mcp-proxy | grep -i intune
```

You should see lines such as:
```
{"timestamp": "...", "level": "INFO", "logger": "mcp_proxy.mdm.poller", "message": "Intune polling loop started (interval=600s)"}
{"timestamp": "...", "level": "INFO", "logger": "mcp_proxy.mdm.poller", "message": "Intune delta fetch: 142 devices upserted (lag_s=4)"}
```

Then run the dashboard's **MDM cache** page (or query the DB directly):

```sql
SELECT mdm, device_id, compliance, device_name, user_principal_name, last_seen_at
FROM mdm_device_state
ORDER BY last_seen_at DESC
LIMIT 10;
```

If you see rows, the integration is live. Enrol a fresh Connector against this Mastio and the audit log should contain a `device_attestation_verified` row with the device claim attached.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Logs say `Intune polling disabled (MCP_PROXY_MDM_INTUNE_ENABLED=false)` | Flag not set or set to `false` | Set `MCP_PROXY_MDM_INTUNE_ENABLED=true` and restart |
| `Intune polling error: 401 invalid_client` | Wrong `MCP_PROXY_MDM_INTUNE_CLIENT_ID` or expired client secret | Re-check the values; if the secret expired, create a new one (Step 3) |
| `Intune polling error: 403 Insufficient privileges` | Admin consent not granted, or permission `DeviceManagementManagedDevices.Read.All` not added | Repeat Step 2 |
| `Intune polling error: 429 Throttled` | Polling interval too aggressive, or shared tenant burst | Increase `MCP_PROXY_MDM_INTUNE_POLL_INTERVAL_SECONDS`; Mastio backs off automatically |
| Cache populated but Connector enrollments still report `mdm=null` in audit | Connector did not pass `azure_ad_device_id` hint in `device_info` | Connector ≥ v0.4.4 required; older Connectors enrol without the hint |

## What this does NOT do (yet)

- F5 — policy tier consumption (capability matrix wired to `effective_tier`)
- F6 — live revocation (push events from Graph webhook so a non-compliant transition is reflected sub-poll)
- Jamf and Workspace ONE support (deferred — Intune ships first, multi-MDM after pilot signal)
- Hardware attestation (`tpm_2.0`, `secure_enclave`) — F3 ships TPM EK validation for Linux Connector

If a customer asks for any of the above before they appear in the public CHANGELOG, escalate to product — there is no quick workaround.

## Security notes

- The client secret you create in Step 3 grants read access to the entire managed-device inventory of your tenant. Anyone who exfiltrates it can list every Intune-enrolled device and its compliance state, but not modify policy, push commands, or read user data beyond `userPrincipalName`.
- Mastio never logs the access token (`access_token` in the OAuth2 response) or the client secret. If you see either in the logs, file a security issue.
- The polling token is cached in memory for 50 minutes (Microsoft mints it at 60 minutes; we refresh 10 minutes early). Token cache lives only in the Mastio process; restart wipes it.

## References

- ADR-032 (internal-only): device attestation across multiple MDM providers + BYOD
- `imp/attestation-claim-schema.md` v1.0: the claim shape and `effective_tier` algorithm both ends compute against
- Microsoft Graph `managedDevices`: https://learn.microsoft.com/en-us/graph/api/intune-devices-manageddevice-list
- Microsoft Graph delta queries: https://learn.microsoft.com/en-us/graph/delta-query-overview
