# Mastio and your first autonomous agent

Install one Mastio, connect a Python agent and give it a task. The agent calls
the model through Mastio and can use the MCP tools you explicitly select.
Mastio holds the provider credentials and checks access to tools.

For the packaged single-computer path with a local model already connected,
start with [Local model demo](LOCAL_DEMO.md). The guide below covers an existing
Mastio and separately operated model providers or MCP services.

This is the single-host evaluation path. You need Docker with Compose v2 on
the Mastio host, Python 3.10+ on the agent host, and a model provider configured
in Mastio. They can be the same computer. Corporate deployment, existing PKI
and high availability are separate steps after this first connection works.

## 1. Start Mastio and configure a model

From the extracted bundle:

```bash
./deploy.sh
```

Use an address the agent's computer can reach when the installer asks for the
public URL. Keep the printed URL: it is the address used throughout this guide.
`localhost` only works when Mastio and the agent run on the same computer.

Open the dashboard at that URL and create the administrator account. In
**Settings → AI Providers**, configure and save your provider, then run its
connection test. Note a model ID supported by that provider. Provider credentials
stay in Mastio; do not put them on the agent computer.

Standalone Mastio does not need a broker connection. The separate **Setup**
screen for broker/organisation/Vault configuration is not part of this path.

The default bundle uses its own certificate authority. On the Mastio host,
`certs/org-ca.pem` is the public CA certificate exported by the installer.
Copy that file to the agent computer through a channel you trust, together
with `first-agent.py` from this bundle. Do not copy `proxy.env`, the Mastio
data directory or CA private keys. The browser may require you to trust this
local CA; the agent will verify it explicitly.

## 2. Install the SDK on the agent computer

In a directory containing `first-agent.py` and `org-ca.pem`:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install 'cullis-sdk==0.2.2'
```

On Windows, activate with `.venv\Scripts\Activate.ps1` in PowerShell.
The commands below use `python` from this environment. This starter uses the
existing SDK API; it does not require a framework or an admin token.

## 3. Request the agent identity and approve it

Replace the address, name and email with your values:

```bash
python first-agent.py connect \
  --url https://mastio.example.internal:9443 \
  --ca-cert ./org-ca.pem \
  --name "My first agent" \
  --email operator@example.com
```

The command prints the approval page and waits up to ten minutes. In Mastio,
open **Enrollments**, find the request you just started and click **Approve**:

- Choose a short agent ID, for example `first_agent`.
- Assign `llm.chat, mcp.tools.list` in **Capabilities**.
- Leave groups empty for this example, then issue the certificate.

Only approve requests whose origin you recognize. The requester name and
email are descriptive, not proof of identity.

The command saves the identity under `~/.cullis/first-agent`. Certificate and
request-signing keys are generated on the agent host. Reuse this directory
for later runs; do not enroll again at every startup. Use `--identity PATH`
on every command if you want a different directory. `connect` refuses to
overwrite a nonempty directory.

If the Mastio URL already has a certificate trusted by the agent's operating
system, omit `--ca-cert`. There is no switch to disable TLS verification.

## 4. Check the connection and run a first task

```bash
python first-agent.py check
```

Expect `Agent authentication succeeded` and a list of visible tools. `none`
is normal before connecting a tool server. This check does not call a model
or execute tools, so it does not prove those services work yet.

Replace `YOUR_CONFIGURED_MODEL` with the model ID from step 1:

```bash
python first-agent.py run \
  --model YOUR_CONFIGURED_MODEL \
  --task "Write a three-item checklist for reviewing a weekly project update."
```

The answer and the model request's audit trace appear in the terminal. In
Mastio, open **Audit** to inspect the request. This is a first model connection
check; no external tools are offered unless you select them explicitly.

## 5. Give the agent a tool

Use an existing MCP server with a harmless read-only tool for the first run.
You need its address and any credentials from the person operating it.

In Mastio **Backends → New backend**, register the selected tool:

- **Name:** the exact tool name exposed by the MCP server, for example
  `get_project_status`. The current interface uses one entry per tool;
  a friendly server name here will not select its tools automatically.
- **Endpoint URL:** the server's MCP endpoint, supplied by its operator.
- **Allowed domains:** a JSON list containing the endpoint hostname, for
  example `["mcp.example.internal"]`. Do not leave the default `[]`.
- **Auth type / Auth secret ref:** use the values supplied by the server's
  operator. `none` is suitable only for a sample server that needs no credentials.
- **Required capability:** declare the permission for this tool, for example
  `projects.read`, and grant that capability to the agent. Tools without a
  required capability cannot execute.
- Keep **Enabled** selected.

After saving, expand **Bindings** for that entry, select the enrolled agent
and click **Grant**. Provider and backend credentials belong in Mastio, not
in the task or the agent script.

For a server on a private network, the Mastio operator must also include its
hostname in `MCP_PROXY_INTERNAL_HOST_ALLOWLIST` in the deployment configuration.
This is an explicit permission for that internal destination, not a reason
to disable outbound address checks. That infrastructure step is still required
in the current bundle.

Run `check` again. Copy a tool name from the visible list, then give the agent
a task that uses it. For example, if your server provides `get_project_status`:

```bash
python first-agent.py run \
  --model YOUR_CONFIGURED_MODEL \
  --tool get_project_status \
  --task "Use get_project_status to read the demo project's status and summarise the outstanding work."
```

The example tool name is a placeholder, not a tool shipped by Mastio. Repeat
`--tool` to select more tools. The model must support tool calling. The starter
lets it choose when to call the selected tools, sends their results back to
the model and stops at its final answer. It makes at most five model calls
and ten tool calls per run by default. It reports failure if the task reaches
these limits, receives malformed calls, or a tool fails; it does not silently
claim completion or automatically retry an action.

Selecting a tool locally never grants server permissions. Mastio still makes
the authorization decision on each call. Tool results are sent to the model
provider, so use sample data for this first exercise.

## 6. Verify that removing access actually stops the agent

Remove this agent's binding to the sample MCP resource in Mastio. Run `check`
again: the tool should no longer be listed. Repeating the task with that
`--tool` should stop with `Requested tools are not visible`, before a model
call. This demonstrates discovery and the starter's local selection check.

To verify the **server-side** deny as well, keep the binding removed and call
the tool directly with the same SDK identity (run from this directory):

```python
import runpy
from pathlib import Path

starter = runpy.run_path("first-agent.py")
client = starter["load_client"](Path.home() / ".cullis" / "first-agent")
try:
    client.call_mcp_tool("get_project_status", {})  # use your real tool and arguments
finally:
    client.close()
```

Expect an access error, no execution on the upstream MCP server, and a denial
in Mastio's audit. If the call succeeds, stop and investigate the effective
permissions. Restore the binding only when you intend to grant access again.
This exercise tests resource authorization, not every Rego policy or failure
mode. Independent audit export verification is described in the audit guide.

## When a step fails

| What you see | What to check |
|---|---|
| Cannot establish a trusted connection | Exact Mastio URL, DNS/network access and the CA file supplied by the operator. Do not disable certificate verification. |
| Approval timed out or denied | Pending request in **Enrollments**, administrator decision and enrollment rate limits. Do not repeatedly create requests. |
| Identity directory is not empty | Use `check` for an existing identity. For a new agent, choose another `--identity` directory. Review partial enrollments before discarding files. |
| HTTP 401 | Revocation, certificate expiry, request-signing identity and the configured public URL. |
| HTTP 403 | `llm.chat`/`mcp.tools.list`, tool capabilities, resource bindings and policy. |
| HTTP 429 | Request rate or token budget; inspect the configured limit before retrying. |
| HTTP 502/503/504 | Mastio readiness and the provider/backend connection test. |
| Tool is not visible | MCP registration, resource binding and permissions for this particular agent. |
| Task limit reached | Inspect work already done before retrying; a tool may have completed an action in an earlier step. |

## What this first path establishes

You have an agent identity, a model request through Mastio, and optionally an
autonomous loop over explicitly selected MCP tools. Authentication, model
access, tool access and audit visibility are checked separately. This starter
is not a background service or a full agent framework, and successful setup
is not a production-readiness or security certification.

Before using real company data, complete the production profile, persistence,
backup and restore checks for your deployment. The bundle's [README](README.md)
links to those operational guides.
