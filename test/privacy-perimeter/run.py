"""Run a fresh, isolated perimeter evaluation. Stops on the first failed check.

Run prepare.py first. This script leaves its dedicated stack for diagnosis;
use the documented compose down command after collecting evidence.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

CHECKS = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--mastio-image", required=True)
    parser.add_argument("--ollama-image", required=True)
    args = parser.parse_args()
    state = args.state.resolve()
    evidence = state / "evidence"
    if (evidence / "run.json").exists():
        parser.error("Previous run exists; prepare fresh state to preserve evidence")
    env = dict(os.environ, CULLIS_PERIMETER_STATE=str(state), MASTIO_IMAGE=args.mastio_image,
               OLLAMA_IMAGE=args.ollama_image)
    project = "cullis-private-check"
    compose = ["docker", "compose", "-p", project, "-f", str(CHECKS / "compose.yml")]
    results = []

    def record(step, **details):
        results.append({"step": step, **details})
        (evidence / "run.json").write_text(json.dumps(results, indent=2) + "\n")
        print(step, json.dumps(details), flush=True)

    def command(label, argv, timeout=180):
        result = subprocess.run(argv, env=env, text=True, capture_output=True, timeout=timeout)
        (evidence / f"{label}.log").write_text(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError(f"{label} failed with exit {result.returncode}; see {label}.log")
        return result.stdout

    # Never overwrite another run or reuse an old database.
    existing = subprocess.run([*compose, "ps", "-aq"], env=env, text=True, capture_output=True, check=True)
    if existing.stdout.strip():
        parser.error("Dedicated project already has containers; inspect it before continuing")
    try:
        # Avoid exporting effective compose config or container environments: they contain secrets.
        command("compose-config", [*compose, "config", "--quiet"])
        command("boot", [*compose, "up", "-d", "--wait", "--wait-timeout", "120", "--pull", "never"])
        record("stack_started", project=project)
        ids = {name: command("id-" + name, [*compose, "ps", "-q", name]).strip()
               for name in ("operator", "mcp-proxy", "mastio-nginx", "redis", "ollama", "fixture", "outside")}
        # Save topology without Docker Config.Env, credentials or private key material.
        topology = {}
        for name, identifier in ids.items():
            data = json.loads(subprocess.check_output(["docker", "inspect", identifier], env=env))[0]
            networks = data["NetworkSettings"]["Networks"]
            if data["HostConfig"].get("PortBindings"):
                raise AssertionError(f"Unexpected published port on {name}")
            topology[name] = {"image": data["Image"], "networks": {
                key: item["IPAddress"] for key, item in networks.items()}}
            for network in networks:
                net = json.loads(subprocess.check_output(["docker", "network", "inspect", network], env=env))[0]
                if not net["Internal"]:
                    raise AssertionError(f"Non-internal network on {name}")
        (evidence / "topology.json").write_text(json.dumps(topology, indent=2) + "\n")
        outside_ip = next(iter(topology["outside"]["networks"].values()))

        def probe(label, service, host, port, expect):
            output = command(label, ["docker", "run", "--rm", "--network", "container:" + ids[service],
                "--cap-drop=ALL", "--security-opt=no-new-privileges", "--entrypoint", "python",
                "-v", str(CHECKS) + ":/checks:ro", args.mastio_image,
                "/checks/network_probe.py", host, str(port), "--expect", expect], timeout=25)
            record(label, **json.loads(output))

        probe("external_destination_positive_control", "outside", outside_ip, 8080, "allow")
        for name in ids:
            if name == "outside":
                continue
            probe("external_block_" + name, name, outside_ip, 8080, "deny")
            probe("internet_block_" + name, name, "1.1.1.1", 443, "deny")
        for name, port in (("ollama", 11434), ("fixture", 8443), ("mcp-proxy", 9100)):
            for address in topology[name]["networks"].values():
                probe("agent_direct_block_" + name + "_" + address, "operator", address, port, "deny")
        probe("agent_gateway_allowed", "operator", "mastio-nginx", 9443, "allow")
        probe("gateway_model_allowed", "mcp-proxy", "ollama", 11434, "allow")
        probe("gateway_tool_allowed", "mcp-proxy", "fixture", 8443, "allow")
        command("copy-public-ca", [*compose, "cp", "mcp-proxy:/var/lib/mastio/nginx-certs/org-ca.crt",
                                  str(evidence / "server-ca.pem")])
        command("journey", [*compose, "exec", "-T", "operator", "python", "/checks/journey.py"], timeout=300)
        command("service-logs", [*compose, "logs", "--no-color"])
        from fixture import INPUT_MARKER, OUTPUT_MARKER
        for marker in (INPUT_MARKER, OUTPUT_MARKER, "SYNTHETIC-PROMPT-PRIVATE-9216"):
            if marker in (evidence / "service-logs.log").read_text():
                raise AssertionError("Synthetic sensitive value present in service logs")
        record("service_logs_canaries_absent")
        record("PASS", scope="synthetic-data perimeter evaluation, not production or privacy certification")
    except Exception as exc:
        # Collect logs for diagnosis, but never alter configuration or retry a failed test.
        logs = subprocess.run([*compose, "logs", "--no-color"], env=env, text=True, capture_output=True)
        (evidence / "service-logs.log").write_text(logs.stdout + logs.stderr)
        record("FAIL", error_type=type(exc).__name__, reason=str(exc))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
