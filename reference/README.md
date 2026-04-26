# Cullis Reference Deployment

**Infrastructure stress test with six real LLM-driven agents.** Each agent is a separate container running its own LLM-powered decision loop (Ollama on the host). They are enrolled via three different methods (BYOCA, SPIFFE/SPIRE, Connector device-code), authenticated end-to-end with API-key + DPoP, and message each other through the Cullis broker — intra-org and cross-org.

The point of this deployment is **not** "agents make smart decisions" — it's "six LLM processes use Cullis the way a real customer would, and the infrastructure carries the traffic correctly". The widget-hunt scenario kicks off real LLM inference on every hop; whether the model produces a coherent multi-hop story depends on how big the model is. With the default `gemma3:1b` you'll see real traffic, real signing, real cross-org envelopes — and the LLM may or may not chain the decisions sensibly. The hop counter caps loose chains. Either way, the **infrastructure** demonstrates correctly: identities, mTLS, DPoP, ECDH E2E, hash-chain audit. That's the demo.

This is the bigger sibling of `sandbox/`. The sandbox is a didactic playground (hard-coded nonce ping-pong, BYOCA-only enrollment); this directory replaces those scripted agents with real LLM containers and exercises all three enrollment paths in parallel.

> **Mutually exclusive with `sandbox/`** — both bind the same host ports (9100, 9200, 8000, …). Bring the sandbox down before this stack up: `bash sandbox/down.sh && bash reference/up.sh`.

## Prerequisites

- Docker Engine + Compose v2
- ~6 GB RAM available (14 containers + Ollama on host)
- ~6 GB free disk
- **Ollama running on the host** with a small chat model loaded (e.g. `gemma3:1b` or `qwen3.5:2b`). The agent containers reach Ollama via `host.docker.internal:11434`.
- Ollama tuned for concurrency: `OLLAMA_HOST=0.0.0.0:11434` + `OLLAMA_NUM_PARALLEL=6`. See the host setup section below.

## Demo runbook — copy/paste in order

Five steps, ~2 minutes from cold start to live dashboard. Run from the repo root.

### 1. Pre-flight (only first time, or if you changed Ollama config)

```bash
# Verify Ollama is up on the host with gemma3:1b
curl -s http://172.17.0.1:11434/api/tags | python3 -c "import sys,json; print([m['name'] for m in json.load(sys.stdin)['models']])"
# Expected: ['gemma3:1b', ...]   (the model name list must include gemma3:1b)

# If the sandbox is running, bring it down first (mutually exclusive — same ports)
bash sandbox/down.sh 2>/dev/null || true
```

### 2. Bring up the stack with the kick-off prompt baked in

```bash
bash reference/scenarios/widget-hunt.sh
```

This script is the canonical demo entry point — it tears down any previous reference run, builds + starts all 19 containers with `BOOTSTRAP_SCOPE=full` and `ALICE_BYOCA_INITIAL_PROMPT=...`, then tails the multi-hop conversation in the terminal. Wait until the script prints "stack ready".

### 3. Open Grafana — the single demo URL

```
http://localhost:3000
```

Anonymous Viewer access is enabled (no login click). Navigate: **Dashboards → Cullis Reference → "Cullis Reference — Widget-hunt Live"**.

What to point at, panel by panel:

| Panel | Pitch line |
|---|---|
| **🤖 Live LLM agent decisions** | "Each row is a real LLM decision from gemma3:1b. Same `msg_id` appears twice — once at the sender as `tool.cullis_send`, once at the receiver as `inbox.recv`. The hop counter caps loose chains at 8." |
| **🔐 Enrollment events (3 paths)** | "Six rows, one per agent. Two via BYOCA, two via SPIFFE (with real `spiffe_id=spiffe://...`), two via Connector device-code (simulated). All three paths land on the same API-key + DPoP runtime auth — ADR-011 unified enrollment." |
| **🏛️ Mastio + Court infrastructure** | "Underneath the LLM noise, this is the Cullis wire: federation publish, mTLS authentication, token issuance, policy decisions. JSON-structured, parsed live by Promtail." |
| **📈 Per-agent message rate** | "Stacked bars showing how many `cullis_send` + `inbox.recv` events each agent generated per minute. Spikes correspond to scenario kicks; flat tails between are the agents idle on their inbox poll." |

### 4. Add traffic during the demo (optional)

If the dashboard goes flat and you need a fresh burst:

```bash
docker compose -f reference/docker-compose.yml --profile full exec -T alice-byoca python <<'PY'
import pathlib
from cullis_sdk import CullisClient
ID = pathlib.Path("/state/orga/agents/alice-byoca")
c = CullisClient.from_api_key_file(
    "http://proxy-a:9100",
    api_key_path=ID/"api-key", dpop_key_path=ID/"dpop.jwk",
    agent_id="orga::alice-byoca", org_id="orga",
)
c.login_via_proxy()
c._signing_key_pem = (ID/"agent-key.pem").read_text()

for sku in ["gear-Y", "bolt-Z", "widget-X"]:
    r = c.send_oneshot("orga::alice-spiffe",
        {"content": f"do you have {sku}?", "from": "orga::alice-byoca", "hops": 1})
    print(f"injected {sku}: {r.get('msg_id', '?')[:12]}")
PY
```

For a cross-org burst (exercises ADR-009 counter-sig + ECDH E2E):

```bash
docker compose -f reference/docker-compose.yml --profile full exec -T alice-connector python <<'PY'
import pathlib
from cullis_sdk import CullisClient
ID = pathlib.Path("/state/orga/agents/alice-connector")
c = CullisClient.from_api_key_file(
    "http://proxy-a:9100",
    api_key_path=ID/"api-key", dpop_key_path=ID/"dpop.jwk",
    agent_id="orga::alice-connector", org_id="orga",
)
c.login_via_proxy()
c._signing_key_pem = (ID/"agent-key.pem").read_text()
r = c.send_oneshot("orgb::bob-connector",
    {"content": "request from orga: source 50 widget-X cross-org",
     "from": "orga::alice-connector", "hops": 1})
print(f"cross-org: {r.get('msg_id', '?')[:12]}")
PY
```

### 5. Tear down when done

```bash
bash reference/down.sh
```

This removes containers + volumes (clean state for next run).

---

## Other URLs (for deep dives, not for the live demo)

| URL | Service | Login |
|---|---|---|
| <http://localhost:3000> | **Grafana — single-pane live view** | anonymous viewer (admin/admin to edit) |
| <http://localhost:9100/proxy/dashboard> | Mastio A admin (orga) | first-boot wizard |
| <http://localhost:9200/proxy/dashboard> | Mastio B admin (orgb) | first-boot wizard |
| <http://localhost:9090> | Prometheus raw + alert rules | none |
| <http://localhost:9090/alerts> | `cullis_security_critical` + `cullis_operational` + `cullis_liveness` rules | none |
| <http://localhost:8180> | Keycloak orga | admin / admin-sandbox |
| <http://localhost:8280> | Keycloak orgb | admin / admin-sandbox |

## What's running

| Service | Port (host) | Role |
|---|---|---|
| Court (broker) | `:8000` | Cross-org federation broker |
| Mastio A (proxy-a) | `:9100` | orga data plane + admin dashboard |
| Mastio B (proxy-b) | `:9200` | orgb data plane + admin dashboard |
| Keycloak A | `:8180` | OIDC IdP for orga admin SSO |
| Keycloak B | `:8280` | OIDC IdP for orgb admin SSO |
| SPIRE server A / B | (internal) | Workload identity for SPIFFE-enrolled agents |
| Postgres / Redis | (internal) | Shared state for Court + both Mastios |
| MCP catalog / inventory | (internal) | Downstream tool servers reverse-proxied by Mastios |
| 6 LLM agents | (internal) | The point of this deployment |

## The six agents

| Agent | Org | Enrollment method | Role | Capability advertised |
|---|---|---|---|---|
| `alice-byoca` | orga | BYOCA (cert from Org CA) | BUYER | `order.create` |
| `alice-spiffe` | orga | SPIFFE/SPIRE workload SVID | INVENTORY | `inventory.read` |
| `alice-connector` | orga | Device-code (auto-approved) | BROKER | `discovery.federate` |
| `bob-byoca` | orgb | BYOCA | INVENTORY | `inventory.read` |
| `bob-spiffe` | orgb | SPIFFE/SPIRE | SUPPLIER | `order.fulfill` |
| `bob-connector` | orgb | Device-code (auto-approved) | BROKER | `discovery.federate` |

The role determines the system prompt and tool set; the enrollment method is orthogonal — every agent ends up with the same API-key + DPoP runtime auth (ADR-011 unified enrollment), regardless of how it got there.

## The widget-hunt scenario

```
[orga, intra-org, ADR-001 short-circuit]
  alice-byoca → alice-inventory: "Do we have widget-X?"
  alice-inventory → alice-byoca: "qty=0"
  alice-byoca → alice-broker: "Find widget-X cross-org"

[discovery via Court registry]
  alice-broker → discover(capability="order.fulfill") → bob-broker

[cross-org, ADR-009 counter-signature, ECDH end-to-end]
  alice-broker → bob-broker: "Looking for 100 widget-X for orga"

[orgb, intra-org]
  bob-broker → bob-inventory: "Check widget-X"
  bob-inventory → bob-broker: "qty=500"
  bob-broker → bob-byoca: "Source 100 widget-X for orga"
  bob-byoca → bob-broker → (cross-org) → alice-broker → alice-byoca: "OK, will fulfill"
```

What this exercises:
- All three enrollment paths active simultaneously
- Intra-org short-circuit (Court never sees these hops)
- Cross-org counter-signed encrypted envelope
- Capability-based discovery via Court registry
- Multi-hop LLM-driven conversation (each agent really thinks via Ollama, not scripted)

## Host setup — Ollama on NixOS

Add to `configuration.nix`:

```nix
services.ollama = {
  enable = true;
  acceleration = "vulkan";   # or "rocm" / "cuda" depending on GPU
  host = "0.0.0.0";          # so Docker containers can reach it
  environmentVariables = {
    OLLAMA_NUM_PARALLEL = "6";    # 6 concurrent inference slots for 6 agents
    OLLAMA_FLASH_ATTENTION = "0"; # Vulkan compatibility
  };
};

# Firewall: 11434 is NOT in allowedTCPPorts, so external interfaces are blocked.
# Docker bridge interfaces bypass the firewall by default → containers reach Ollama.
networking.firewall.enable = true;
```

Pull the model:

```bash
ollama pull gemma3:1b      # or qwen3.5:2b
```

## How this differs from `sandbox/`

| | `sandbox/` | `reference/` |
|---|---|---|
| Agent runtime | Hard-coded nonce ping-pong | Real LLM containers (Ollama) |
| Enrollment | All BYOCA | BYOCA + SPIFFE + Connector device-code |
| Scenario | `oneshot-a-to-b` (single message) | `widget-hunt` (LLM-generated traffic, multi-hop) |
| Setup time | ~30s | ~30s + Ollama warm-up |
| Audience | Learning Cullis primitives | Infrastructure stress test with real LLMs, integration reference |

If you're trying to understand Cullis for the first time, start with `sandbox/`. If you want to verify the infrastructure carries real LLM-generated traffic — including the messy parts like agents looping or going off-script — you're in the right place.

## On model size and "smart" agents

The default model (`gemma3:1b`) is great at single-turn structured output (the personal-agent stress test measured 100% valid JSON across 6 concurrent calls × 3 roles), but small enough that multi-hop conversational state — *"I already asked X, got reply Y, now I should escalate to Z"* — is unreliable. You will see chains where the BUYER pings the INVENTORY a few times before the hop counter caps it, or where the BROKER `done`s without routing.

That's by design for this deployment. The whole point is to show the **infrastructure** carrying real LLM traffic correctly: enrollment via three paths, mTLS, DPoP-bound tokens, ECDH end-to-end encryption on cross-org envelopes, hash-chain audit. Whether the LLM produces a coherent narrative is a function of the model you point Ollama at — swap in `gemma3:4b` or `qwen3.5:2b` for better reasoning, accepting the VRAM and concurrency cost. The Cullis side does not care.

If you want a coherent narrative regardless of model, the right architecture is to make the BROKER + INVENTORY + SUPPLIER roles deterministic (rule-based) and only LLM the BUYER — that's how a production deployment would actually look (you don't want an AI making routing decisions). This deployment intentionally LLMs all six to stress-test the infrastructure with real model-driven traffic.
