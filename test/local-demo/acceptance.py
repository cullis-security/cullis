"""Exercise an already started, fresh local demo from an extracted bundle.

Uses synthetic data only. The test administrator approves the one request
created by this runner. The shipped installer never auto-approves agents.
Stops on failure; leaves the demo state intact for diagnosis.
"""
import argparse
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import runpy
import signal
import ssl
import subprocess
import sys
import time

import httpx

LOG = logging.getLogger("local-demo-acceptance")
CHECKS = Path(__file__).resolve().parents[1] / "privacy-perimeter"
DNS_PROBE = """import errno, socket, struct, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)
packet = struct.pack('!6H', 1234, 256, 1, 0, 0, 0) + b'\\x09mcp-proxy\\x00' + struct.pack('!2H', 1, 1)
received = False
try:
    s.sendto(packet, ('127.0.0.11', 53))
    s.recv(4096)
    received = True
except socket.timeout:
    pass
except OSError as exc:
    if exc.errno not in (errno.EPERM, errno.EACCES):
        raise
finally:
    s.close()
assert received == (sys.argv[1] == 'allow'), 'Unexpected DNS reachability'
"""


def cancel(signum, frame):
    """Turn SIGTERM into normal cleanup, just like an interactive interrupt."""
    raise KeyboardInterrupt


def cleanup_containers(project, evidence):
    """Remove only this test project's agent jobs and labelled probe fixtures."""
    filters = [
        ["label=cullis.local-demo.acceptance=" + project],
        ["label=com.docker.compose.project=" + project,
         "label=com.docker.compose.service=agent", "label=com.docker.compose.oneoff=True"],
    ]
    logs = []
    for selection in filters:
        argv = ["docker", "ps", "-aq"]
        for value in selection:
            argv += ["--filter", value]
        found = subprocess.run(argv, capture_output=True, text=True, check=True, timeout=20)
        identifiers = found.stdout.split()
        if identifiers:
            removed = subprocess.run(["docker", "rm", "-f", *identifiers],
                                     capture_output=True, text=True, check=True, timeout=30)
            logs.append(removed.stdout + removed.stderr)
        remaining = subprocess.run(argv, capture_output=True, text=True, check=True, timeout=20)
        need(not remaining.stdout.strip(), "Test containers remain after cleanup")
    (evidence / "runner-cleanup.log").write_text("".join(logs) + "No test containers remain.\n")


def need(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    bundle, state, evidence = args.bundle.resolve(), args.state.resolve(), args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    need(not (evidence / "acceptance.json").exists(), "Preserve prior results; use a fresh run")
    need(not any((state / "agent").iterdir()), "Use a fresh agent identity")
    config = json.loads((state / "install.json").read_text())
    demo = runpy.run_path(str(bundle / "local-demo.py"))
    cli = [sys.executable, str(bundle / "local-demo.py"), "--state", str(state)]
    results = []
    outside = config["project"] + "-outside-test"
    connect = None
    fixture_label = "cullis.local-demo.acceptance=" + config["project"]
    previous_sigterm = signal.signal(signal.SIGTERM, cancel)

    def record(step, **details):
        results.append({"step": step, **details})
        (evidence / "acceptance.json").write_text(json.dumps(results, indent=2) + "\n")
        LOG.info("%s %s", step, json.dumps(details))

    def command(label, argv, timeout=180):
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        (evidence / (label + ".log")).write_text(result.stdout + result.stderr)
        need(result.returncode == 0, f"{label} exited {result.returncode}; inspect its log")
        return result.stdout

    def inspect(identifier):
        # Do not write the full inspect: Config.Env contains test credentials.
        return json.loads(subprocess.check_output(["docker", "inspect", identifier]))[0]

    try:
        trust = ssl.create_default_context(cafile=str(state / "public/org-ca.pem"))
        base = f"https://localhost:{config['port']}"
        with httpx.Client(base_url=base, verify=trust, trust_env=False, timeout=30) as admin:
            response = admin.post("/proxy/login", data={"password": (state / "admin-password.txt").read_text().strip()})
            need(response.status_code == 303, "Dashboard login over verified host HTTPS failed")
            record("host_dashboard_tls_login")
            with (evidence / "connect.log").open("w") as output:
                connect = subprocess.Popen([*cli, "connect", "--name", "Synthetic local demo",
                    "--email", "operator@example.test"], stdout=output, stderr=subprocess.STDOUT,
                    start_new_session=True)
                deadline = time.monotonic() + 45
                session = None
                while time.monotonic() < deadline and connect.poll() is None:
                    match = re.search(r"Request: ([a-zA-Z0-9_-]+)\.", (evidence / "connect.log").read_text())
                    if match:
                        session = match[1]
                        break
                    time.sleep(0.2)
                need(session, "Agent did not request approval; inspect connect.log")

                ids, topology = {}, {}
                for service in ("agent", "mastio-nginx", "mcp-proxy", "redis", "ollama"):
                    identifiers = subprocess.check_output(["docker", "ps", "-q", "--filter",
                        "label=com.docker.compose.project=" + config["project"], "--filter",
                        "label=com.docker.compose.service=" + service], text=True).split()
                    need(len(identifiers) == 1, f"Expected one running {service}")
                    ids[service] = identifiers[0]
                    data = inspect(identifiers[0])
                    ports = {key: value for key, value in data["NetworkSettings"]["Ports"].items() if value}
                    if service == "mastio-nginx":
                        need(ports == {"9443/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(config["port"])}]},
                             "Unexpected or missing dashboard publication")
                    else:
                        need(not ports, f"Unexpected published port on {service}")
                    networks = data["NetworkSettings"]["Networks"]
                    for name in networks:
                        net = json.loads(subprocess.check_output(["docker", "network", "inspect", name]))[0]
                        need(net["Internal"] or (service == "mastio-nginx" and name == config["project"] + "_ingress"),
                             "Unexpected external network")
                    if service == "agent":
                        env_names = {value.split("=", 1)[0] for value in data["Config"]["Env"]}
                        need(not any("SECRET" in key or "PASSWORD" in key for key in env_names), "Agent received secrets")
                        mounts = {item["Destination"] for item in data["Mounts"]}
                        required = {"/identity", "/trust", "/opt/first-agent.py"}
                        need(required <= mounts <= required | {"/tmp"}, "Unexpected agent mount")
                    topology[service] = {"image": data["Image"], "ports": ports,
                        "networks": {name: value["IPAddress"] for name, value in networks.items()}}
                (evidence / "topology.json").write_text(json.dumps(topology, indent=2) + "\n")
                status = command("nginx-process", ["docker", "exec", ids["mastio-nginx"], "cat", "/proc/1/status"])
                fields = dict(line.split(":", 1) for line in status.splitlines() if ":" in line)
                for field in ("CapEff", "CapBnd"):
                    need(int(fields[field].strip(), 16) & ((1 << 12) | (1 << 13)) == 0,
                         "nginx retained NET_ADMIN or NET_RAW")
                need(fields["NoNewPrivs"].strip() == "1", "nginx can gain privileges")
                for binary in ("iptables", "ip6tables"):
                    rules = command(binary, ["docker", "exec", ids["mastio-nginx"], binary, "-S"])
                    need("-P OUTPUT DROP" in rules and "-P FORWARD DROP" in rules, "Missing deny policy")
                record("topology_and_nginx_privileges")

                listener = ("import socket,time; s=socket.socket(); s.bind(('0.0.0.0',8080)); "
                            "s.listen(); print('READY',flush=True); time.sleep(600)")
                command("outside-start", ["docker", "run", "-d", "--name", outside, "--pull=never",
                    "--label", fixture_label,
                    "--network", config["project"] + "_ingress", "--cap-drop=ALL", "--entrypoint", "python",
                    config["images"]["MASTIO"], "-c", listener])
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    if "READY" in subprocess.check_output(["docker", "logs", outside], text=True):
                        break
                    time.sleep(0.2)
                else:
                    raise AssertionError("Controlled outside listener did not start")
                outside_ip = next(iter(inspect(outside)["NetworkSettings"]["Networks"].values()))["IPAddress"]

                def probe(label, namespace, host, port, expected):
                    result = command(label, ["docker", "run", "--rm", "--pull=never",
                        "--label", fixture_label,
                        "--network", "container:" + namespace, "--cap-drop=ALL", "--security-opt=no-new-privileges",
                        "--entrypoint", "python", "-v", str(CHECKS) + ":/checks:ro", config["images"]["MASTIO"],
                        "/checks/network_probe.py", host, str(port), "--expect", expected], timeout=20)
                    record(label, **json.loads(result))

                probe("outside-positive-control", outside, outside_ip, 8080, "allow")
                for service, identifier in ids.items():
                    probe("outside-block-" + service, identifier, outside_ip, 8080, "deny")
                    probe("internet-block-" + service, identifier, "1.1.1.1", 443, "deny")
                for service, port in (("ollama", 11434), ("mcp-proxy", 9100)):
                    for index, address in enumerate(topology[service]["networks"].values()):
                        probe(f"agent-direct-block-{service}-{index}", ids["agent"], address, port, "deny")
                proxy_ip = topology["mcp-proxy"]["networks"][config["project"] + "_gateway"]
                model_ip = next(iter(topology["ollama"]["networks"].values()))
                probe("agent-nginx-allowed", ids["agent"], "mastio-nginx", 9443, "allow")
                probe("nginx-mastio-allowed", ids["mastio-nginx"], proxy_ip, 9100, "allow")
                probe("mastio-model-allowed", ids["mcp-proxy"], model_ip, 11434, "allow")

                # Query Docker's embedded resolver for a LOCAL name, not an
                # external domain. A positive control validates the DNS packet.
                for service, expected in (("mcp-proxy", "allow"), ("mastio-nginx", "deny")):
                    command("dns-" + service, ["docker", "run", "--rm", "--pull=never",
                        "--label", fixture_label, "--network",
                        "container:" + ids[service], "--cap-drop=ALL", "--entrypoint", "python",
                        config["images"]["MASTIO"], "-c", DNS_PROBE, expected], timeout=15)
                record("nginx_dns_block_with_positive_control")
                command("outside-cleanup", ["docker", "rm", "-f", outside])

                page = admin.get("/proxy/enrollments")
                need(page.status_code == 200, "Enrollments page unavailable")
                token = re.search(r'name="csrf_token"\s+value="([^"]+)"', page.text)
                need(token, "Missing approval CSRF token")
                response = admin.post(f"/proxy/enrollments/{session}/approve", data={
                    "csrf_token": token[1], "agent_id": "local_demo", "capabilities": "llm.chat, mcp.tools.list", "groups": ""})
                need(response.status_code == 303, "Agent approval failed")
                need(connect.wait(timeout=45) == 0, "Agent enrollment did not complete")
            record("agent_approved_and_enrolled")
        command("check", [*cli, "check"])
        command("run", [*cli, "run"])
        # CLI logging is on stderr; completion is enforced by first-agent.py.
        need("Agent answer:" in (evidence / "run.log").read_text(), "No model answer")
        record("real_local_inference", model=config["model"], quality_scored=False)
        identity = {path.name: hashlib.sha256(path.read_bytes()).digest() for path in (state / "agent").iterdir() if path.is_file()}
        ca_before = (state / "public/org-ca.pem").read_bytes()
        command("restart-down", [*cli, "down"])
        command("restart-up", [*cli, "up"], timeout=200)
        need(ca_before == (state / "public/org-ca.pem").read_bytes(), "Server CA changed on restart")
        need(identity == {path.name: hashlib.sha256(path.read_bytes()).digest() for path in (state / "agent").iterdir() if path.is_file()},
             "Agent identity changed on restart")
        command("restart-check", [*cli, "check"])
        command("restart-run", [*cli, "run"])
        record("restart_preserves_identity_and_model_access")
    except KeyboardInterrupt:
        record("CANCELLED")
        return 130
    except Exception as exc:
        record("FAIL", reason=str(exc), error_type=type(exc).__name__)
        return 1
    finally:
        try:
            if connect is not None:
                # Terminating the wrapper alone leaves its Compose child alive.
                try:
                    os.killpg(connect.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    connect.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(connect.pid, signal.SIGKILL)
                    connect.wait(timeout=10)
        finally:
            try:
                cleanup_containers(config["project"], evidence)
                logs = demo["compose"](state, config, "logs", "--no-color", capture=True)
                (evidence / "service-logs.log").write_text(logs.stdout + logs.stderr)
            except Exception as exc:
                record("FAIL", phase="cleanup", reason=str(exc), error_type=type(exc).__name__)
                raise
            finally:
                signal.signal(signal.SIGTERM, previous_sigterm)
    record("PASS", scope="synthetic local demo, not a production qualification")
    return 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    sys.exit(main())
