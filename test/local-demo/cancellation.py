"""Interrupt a live acceptance run and verify that its containers are removed.

Requires an already started local demo with no enrolled agent. Uses only the
project in that demo's install.json; preserves all state and diagnostic logs.
"""
import argparse
import json
import logging
import os
from pathlib import Path
import runpy
import signal
import subprocess
import sys
import time


def need(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--signal", choices=["SIGTERM", "SIGINT"], default="SIGTERM")
    args = parser.parse_args()
    os.umask(0o077)
    bundle, state, evidence = args.bundle.resolve(), args.state.resolve(), args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    config = json.loads((state / "install.json").read_text())
    project = config["project"]
    demo = runpy.run_path(str(bundle / "local-demo.py"))
    fixture = ["label=cullis.local-demo.acceptance=" + project]
    agent = ["label=com.docker.compose.project=" + project,
             "label=com.docker.compose.service=agent", "label=com.docker.compose.oneoff=True"]

    def containers(filters):
        command = ["docker", "ps", "-aq"]
        for selection in filters:
            command += ["--filter", selection]
        return subprocess.check_output(command, text=True, timeout=10).split()

    need(not containers(fixture) and not containers(agent), "Existing test jobs; use an idle demo")
    with (evidence / "runner.log").open("w") as output:
        child = subprocess.Popen([sys.executable, str(Path(__file__).with_name("acceptance.py")),
            "--bundle", str(bundle), "--state", str(state), "--evidence", str(evidence / "runner")],
            stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            deadline = time.monotonic() + 90
            while time.monotonic() < deadline:
                need(child.poll() is None, "Acceptance exited before the cancellation checkpoint")
                # Outside listener plus a live probe: cancellation must clean up
                # both docker run fixtures and the pending Compose agent job.
                if len(containers(fixture)) >= 2 and containers(agent):
                    break
                time.sleep(0.2)
            else:
                raise AssertionError("No active probe and pending agent within 90 seconds")
            child.send_signal(getattr(signal, args.signal))
            need(child.wait(timeout=45) == 130, "Cancelled acceptance must exit 130")
            results = json.loads((evidence / "runner/acceptance.json").read_text())
            need(results[-1]["step"] == "CANCELLED", "Cancellation was not recorded")
            need(not containers(fixture), "Probe or outside fixture survived cancellation")
            need(not containers(agent), "One-off agent survived cancellation")
            stopped = demo["compose"](state, config, "down", capture=True)
            (evidence / "down.log").write_text(stopped.stdout + stopped.stderr)
            need(not containers(["label=com.docker.compose.project=" + project]),
                 "Project containers remain after down")
            networks = subprocess.check_output(["docker", "network", "ls", "-q", "--filter",
                "label=com.docker.compose.project=" + project], text=True, timeout=10)
            need(not networks.strip(), "Project networks remain after down")
            (evidence / "result.json").write_text(json.dumps({
                "result": "PASS", "signal": args.signal, "runner_exit": 130,
                "test_containers_remaining": 0, "project_containers_after_down": 0,
                "project_networks_after_down": 0,
            }, indent=2) + "\n")
            logging.info("Cancellation and full teardown passed for %s", args.signal)
        finally:
            if child.poll() is None:
                child.terminate()
                child.wait(timeout=45)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    main()
