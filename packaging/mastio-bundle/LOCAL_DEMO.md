# Local model demo

Run Mastio and a small local model, approve an agent, and ask it to summarise a
fictional reimbursement case. Model requests go through Mastio. The example
makes no business decision and connects to no company system.

You need Docker with Compose v2 and Python 3.11+ on Linux or macOS (WSL2 on
Windows). Python needs no additional packages: the agent uses the SDK in the
Mastio image. The initial model is about 400 MB; allow several GB for images,
weights and runtime memory. This small CPU model is for checking the connection,
not measuring business accuracy or autonomous tool use.

## 1. Prepare and start

From an extracted bundle containing these files:

```bash
python3 local-demo.py prepare
python3 local-demo.py up
```

`prepare` downloads missing images and the model before isolation, creates
random credentials and records the resolved image IDs and model hashes.
It also builds a small nginx image with a container-local outbound filter;
the first build downloads Alpine packages before any private state is mounted.
`up` starts the internal networks without pulling images, configures Ollama
through Mastio's admin API and verifies the HTTPS dashboard connection.

Open **https://localhost:9443/proxy/** on the same computer. Trust the public
CA at `local-demo-state/public/org-ca.pem` in your browser and sign in with the
initial password in `local-demo-state/admin-password.txt`. Open that file locally;
do not paste it into support messages. The provider is already configured.

The demo creates separate state and a unique Docker project; it does not use
the existing bundle's `proxy.env` or database. If port 9443 is occupied, choose
`prepare --port 9444` for a fresh installation and use the printed address.
Use `--state /path/to/demo` **before** the command to choose another state
directory; repeat it for every command. `prepare` refuses existing state.

## 2. Approve the agent

```bash
python3 local-demo.py connect --name "My demo agent" --email you@example.com
```

Keep the command running. In **Enrollments**, find the matching request and
approve it with agent ID `local_demo` and capabilities `llm.chat, mcp.tools.list`.
Only approve the request you just started. The command finishes once approved.
The printed internal approval URL uses `mastio-nginx`; use your already-open
localhost dashboard to approve it. The agent's internal address is intentional.

This is the one deliberate approval step. The installer never auto-approves
an identity or passes administrator credentials to the agent.

## 3. Run the example

```bash
python3 local-demo.py check
python3 local-demo.py run
```

The default task describes a fictional trip reimbursement case with a missing
cancellation receipt. Expect a short summary and the missing document in the
terminal. Open **Audit** to inspect the model request. Wording may vary; review
the answer yourself. The sample has no tools and cannot modify business records.
For another synthetic prompt, use `run --task "Your fictional example"`.

## Stop and resume

```bash
python3 local-demo.py status
python3 local-demo.py down
python3 local-demo.py up
python3 local-demo.py run
```

The model, password, database and enrolled identity survive `down`. Do not run
`prepare` or `connect` again to resume. If you changed the local provider in
the dashboard, startup refuses incompatible settings instead of overwriting
them. Inspect the reported failure before retrying.

## Cached or disconnected preparation

In a source checkout, provide a built Mastio image explicitly. With every image
already available locally (including the filtered nginx image built by an earlier
online preparation of this bundle), use:

```bash
python3 local-demo.py --state /path/to/fresh-demo prepare \
  --offline --mastio-image cullis-security/cullis-mastio:smoke-local \
  --model-cache /path/to/ollama/models
```

Only the selected model's manifest and verified blobs are copied, not Ollama
account keys or history. `--model name:tag` chooses another cached/downloaded
library model. Model licensing, suitability and resource needs require review.

## Boundary and next step

Mastio, Redis and Ollama have no published ports. Only nginx publishes HTTPS
on host loopback. The agent joins the client network and cannot directly reach
Mastio's internal port or Ollama. Agent and backend networks are Docker `internal`.
Only nginx joins an additional ingress bridge so Docker can publish the local
port. Before nginx starts, its entrypoint blocks new outbound connections except
TCP to Mastio's resolved internal IP on port 9100 and its own healthcheck on
127.0.0.1:9443. Replies to established TCP connections are permitted. IPv6 new
outbound connections and DNS queries are blocked; the upstream address is resolved
once during startup and pinned in the container's hosts file. Restart the demo if
you recreate Mastio independently and its address changes.

The filter is inside nginx's network namespace, with no host firewall changes.
Startup requires `NET_ADMIN`, which is removed from nginx's capability bounding
set before it starts, together with raw-socket capability. If filter installation
fails, nginx does not start. This profile requires Docker's normal Linux network
namespace and netfilter support; hardened/rootless environments need separate
validation. Ollama cloud features are disabled. The host and Docker administrator are trusted;
this is not a sandbox against them. The host browser has its own network access.

This is a single-host evaluation using SQLite and local KMS. Private state and
agent keys are protected by filesystem permissions, not encrypted by this
installer. Some internal traffic is HTTP. External audit timestamping is disabled;
tool-content audit capture is disabled. These choices do not establish production
readiness, universal absence of data leakage, or regulatory compliance.

Keep all data synthetic. Before a real-data pilot, address production key custody,
backup/restore, retention, the remaining policy failure cases and privacy coverage
of errors, streaming and other integrations. Connecting an actual internal MCP
service needs an explicit network and authorization design: follow
[FIRST_AGENT.md](FIRST_AGENT.md) for the general agent/tool workflow. This demo
does not open arbitrary outbound access to make an integration succeed.
