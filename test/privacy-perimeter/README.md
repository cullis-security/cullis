# Private perimeter evaluation

This evaluation runs Mastio, a real local Ollama model, and a synthetic read-only
MCP service in an isolated Docker project. It checks network boundaries, tool
revocation, audit minimization and offline audit integrity. It is a test profile,
not a production deployment or a statement of GDPR compliance.

The only business records are synthetic markers. Do not supply customer records,
production credentials or an existing Mastio data directory.

## Boundary

```text
operator / SDK -- verified HTTPS --> nginx -- HTTP --> Mastio
                                                    |-- HTTP --> local Ollama
                                                    |-- verified HTTPS --> synthetic MCP
                                                    |-- Redis / local database
```

Each tier has a separate Docker internal network. The operator can reach nginx,
but cannot directly connect to Mastio, Ollama or MCP. No service publishes a host
port. The Docker administrator and host are trusted and can inspect all containers
and volumes. This is not isolation against a compromised host or administrator.
Internal HTTP remains inside the single test host; a multi-host deployment needs
its own transport and network design.

Ollama cloud features are disabled. Images and cached model weights are prepared
before the test; the test stack has no runtime Internet access by design. A separate
controlled TCP destination provides a positive connectivity control, followed by
negative checks from each protected network namespace. Direct public-IP TCP access
is checked separately. These are sampled connectivity checks, not a packet capture
or proof against every possible covert channel or Docker daemon configuration.

Mastio requires DPoP on egress and verifies TLS to the MCP fixture. Tool parameters
and results are excluded from both audit chains using existing capture settings.
Audit durability and audit-failure denial are enabled. The test does not add a
content classifier, anonymizer, row-level database authorization or new policy
semantics.

There is no external timestamp authority in this profile. External TSA requests
are explicitly disabled; the offline check demonstrates chain consistency and
rejection of an altered export, not independent proof of the entire history.

## Prepare

Requirements: Docker Compose, Python 3.11+ with `cryptography`, a locally built
Mastio image, and a fully cached Ollama library model. Run commands from the
repository root. Model preparation copies only the selected manifest and blobs,
checks their SHA-256 digests and does not copy Ollama account keys or history.

```bash
# Build the current Mastio source using the existing smoke build definition.
docker compose -f test/smoke/compose.yml --env-file test/smoke/env.smoke build mcp-proxy

# Provision images before entering the isolated runtime.
docker pull ollama/ollama:latest
docker pull busybox:stable
docker pull redis:7-alpine
docker pull nginx:1.27-alpine
docker image inspect ollama/ollama:latest --format '{{index .RepoDigests 0}}'

# Choose a NEW state directory for every run.
python test/privacy-perimeter/prepare.py \
  --state imp/private-perimeter-evaluation \
  --models /path/to/ollama/models \
  --model qwen2.5:0.5b
```

Use the Ollama digest printed above, rather than `latest`, for the run. For strict
artifact reproducibility, pass a Mastio image digest or local image ID as well.
The report records the resolved IDs of all running images. Dependencies and the
model's suitability for a business task require separate review.

`prepare.py` creates fresh random test credentials and a short-lived fixture CA.
Keep the resulting directory private. The fixture certificates expire after two
days, so prepare new state when repeating the evaluation later.

## Run

```bash
python test/privacy-perimeter/run.py \
  --state imp/private-perimeter-evaluation \
  --mastio-image cullis-security/cullis-mastio:smoke-local \
  --ollama-image ollama/ollama@sha256:REPLACE_WITH_DOWNLOADED_DIGEST
```

The runner uses the dedicated project `cullis-private-check` and refuses to reuse
an existing run. It stops on the first failed assertion and preserves the stack
for diagnosis. Do not change expected outcomes or privacy settings to obtain a
passing result.

The application journey uses dashboard forms with CSRF, client-side enrollment,
the SDK and the actual native Ollama adapter. It reads a synthetic case through
MCP, passes the result to the local model, then revokes tool access and demands a
server-side denial. This is a script-orchestrated workflow, not a benchmark of
autonomous planning or model accuracy.

The audit export must contain execution and denial evidence, explicit redaction
markers, and none of the synthetic input, output or prompt canaries. Its original
form must pass the standalone verifier; a locally altered copy must fail. Service
logs are scanned for the same canaries. Model output saved by the test harness is
expected to contain synthetic content and is kept separately from service logs.

## Evidence and cleanup

Results live in `STATE/evidence/`: `run.json`, `topology.json`, `journey.json`,
`model.json`, audit exports, verifier output and service logs. Inspect failures in
the named log file. Never publish `runtime.env`, identity private keys, database
volumes or fixture private keys.

After diagnosis or a completed run, use the SAME state and image values:

```bash
export CULLIS_PERIMETER_STATE=/absolute/path/to/imp/private-perimeter-evaluation
export MASTIO_IMAGE=cullis-security/cullis-mastio:smoke-local
export OLLAMA_IMAGE=ollama/ollama@sha256:REPLACE_WITH_DOWNLOADED_DIGEST
docker compose -p cullis-private-check -f test/privacy-perimeter/compose.yml down
```

Cleanup removes only this project's containers and networks. State and evidence
remain on disk. The test does not touch an existing demo or change host firewall
rules.

## Still required for a regulated pilot

The application runs in development mode with SQLite, one worker and local KMS.
The required production Vault setup, database operations, key rotation, backups,
retention, restore, incident response and DPoP replay tests are outside this run.
This journey grants `cases.read` and a resource binding explicitly. Delegation
limits and Rego failure denial are exercised separately by the authorization
smoke in `test/smoke/`; this perimeter run does not cover every operator rule.

The operator harness holds test administrator credentials; it is not an example
of how to distribute credentials to an untrusted agent. Production agents need
separate identities and no administrator secrets or backend network access.

Audit minimization must also cover errors, streaming, alternate endpoints and
every enabled integration. These successful-call canaries do not establish that
all possible personal data is removed. Updates, browser-loaded resources, DNS,
support access, backups and external timestamping need an explicit data-flow
review for the customer's environment.

Sources for the underlying deployment options:
[Docker internal networks](https://docs.docker.com/reference/compose-file/networks/#internal),
[Ollama local-only mode](https://docs.ollama.com/faq#how-do-i-disable-ollama-cloud-features).
