#!/usr/bin/env python3
"""Pre-enroll N agent identities into a running Cullis Mastio for k6 stress.

Reads org_ca_key/org_ca_cert/org_id from the target Mastio's proxy_config
(via ``docker exec ... python -`` over SSH), then generates N agents
in-process and bulk-INSERTs them into ``internal_agents`` so the
subsequent k6 scenario can mint LOCAL_TOKENs without paying the
device-code flow per VU.

Each agent gets:
  - EC P-256 keypair signed by the Org CA (matches mcp_proxy
    ``AgentManager.sign_agent_cert`` format: CN=org::name, O=org,
    SAN URI = spiffe://<trust_domain>/<org>/<name>)
  - EC P-256 DPoP keypair (ephemeral but pinned via
    ``internal_agents.dpop_jkt`` so both /v1/auth/token and
    /v1/ingress/* binding paths accept it)

Output (``stress_agents.json``) carries enough material for k6 to:
  1. sign a client_assertion JWT with the agent private key (x5c=cert)
  2. sign a DPoP proof with the agent's DPoP private key
  3. derive cnf.jkt matching ``internal_agents.dpop_jkt``

NEVER commit ``stress_agents.json`` — it carries private keys.

Usage::

    nix-shell -p python311Packages.cryptography --run \\
        "python scripts/stress/bulk_enroll_agents.py --n 50"

    BULK_VM_HOST=cullis@192.168.122.170 \\
    BULK_CONTAINER=cullis-mastio-mcp-proxy-1 \\
        python scripts/stress/bulk_enroll_agents.py --n 5000 --wipe
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path


HERE = Path(__file__).resolve().parent
DEFAULT_HOST = os.environ.get("BULK_VM_HOST", "cullis@192.168.122.170")
DEFAULT_CONTAINER = os.environ.get("BULK_CONTAINER", "cullis-mastio-mcp-proxy-1")
DEFAULT_DB_PATH = os.environ.get("BULK_DB_PATH", "/data/mcp_proxy.db")


# In-container payload kept in a sibling file so the orchestrator can stay
# free of escape headaches around the embedded SQL.
PAYLOAD_PATH = HERE / "_bulk_inject.py"
CONTAINER_PAYLOAD = PAYLOAD_PATH.read_text()


def run_in_container(*, n: int, prefix: str, wipe: bool, capabilities: str,
                     trust_domain: str, host: str, container: str,
                     db_path: str) -> dict:
    env_bits = [
        f"DB_PATH={db_path}",
        f"N_AGENTS={n}",
        f"PREFIX={prefix}",
        f"TRUST_DOMAIN={trust_domain}",
        f"WIPE_PREFIX={'1' if wipe else '0'}",
        f"AGENT_CAPABILITIES={capabilities}",
    ]
    remote = (
        f"docker exec -i -e {' -e '.join(env_bits)} {container} python -"
    )
    t0 = time.time()
    proc = subprocess.run(
        ["ssh", host, remote],
        input=CONTAINER_PAYLOAD,
        capture_output=True,
        text=True,
        check=False,
    )
    elapsed = time.time() - t0
    if proc.returncode != 0:
        sys.stderr.write(
            f"docker-exec failed (rc={proc.returncode}) in {elapsed:.1f}s\n"
            f"--- stderr ---\n{proc.stderr}\n"
            f"--- stdout ---\n{proc.stdout[:2000]}\n"
        )
        sys.exit(proc.returncode)
    sys.stderr.write(
        f"[bulk_enroll] container payload: {elapsed:.1f}s for "
        f"{n} agents (≈{n / max(elapsed, 0.001):.0f}/s)\n{proc.stderr}"
    )
    # Reuse the env hint as a sanity probe — fail clearly if stdout
    # carries logs instead of JSON.
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        sys.exit(f"non-JSON stdout from container: {exc}\n{proc.stdout[:2000]}")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--n", type=int, default=50,
                   help="Number of agents to enroll (default 50)")
    p.add_argument("--prefix", default="stress",
                   help="Agent name prefix (default 'stress')")
    p.add_argument("--wipe", action="store_true",
                   help="Delete prior <prefix>-* agents before insert")
    p.add_argument("--capabilities", default="",
                   help="Comma-separated capability list to seed on each agent")
    p.add_argument("--trust-domain", default="cullis.local")
    p.add_argument("--vm-host", default=DEFAULT_HOST,
                   help="SSH target (user@host) — defaults to BULK_VM_HOST")
    p.add_argument("--container", default=DEFAULT_CONTAINER,
                   help="Mastio container name (default %(default)s)")
    p.add_argument("--db-path", default=DEFAULT_DB_PATH,
                   help="SQLite path inside the container (default %(default)s)")
    p.add_argument("--output", default=str(HERE / "stress_agents.json"),
                   help="Local JSON output path for k6 SharedArray")
    args = p.parse_args()

    result = run_in_container(
        n=args.n, prefix=args.prefix, wipe=args.wipe,
        capabilities=args.capabilities, trust_domain=args.trust_domain,
        host=args.vm_host, container=args.container, db_path=args.db_path,
    )

    out_path = Path(args.output)
    out_path.write_text(json.dumps(result, indent=2))
    sys.stderr.write(
        f"[bulk_enroll] wrote {out_path} "
        f"({len(result['agents'])} agents, requested {result['requested']}, "
        f"after_count {result['after_count']})\n"
    )


if __name__ == "__main__":
    main()
