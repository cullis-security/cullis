#!/usr/bin/env python3
"""Prepare and run a local Mastio evaluation with Docker and Python's standard library."""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import secrets
import shutil
import ssl
import subprocess
import sys
import urllib.request

LOG = logging.getLogger("local-demo")
BUNDLE = Path(__file__).resolve().parent
OLLAMA_IMAGE = "ollama/ollama@sha256:292ee7945dfc3d5840a181f3ab86fedb1e66703e02c8af98b50f4da56b7e278c"
TASK = ("Summarise this fictional case in two sentences and list the missing document. "
        "Demo case DEMO-001: a customer requested reimbursement for a cancelled trip. "
        "The booking confirmation is present; the cancellation receipt is missing. "
        "No decision has been made. Do not invent facts or make an eligibility decision.")


class SetupError(Exception):
    """A failed prerequisite or a configuration that needs operator review."""


def run(args: list[str], *, capture: bool = False, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(args, check=True, text=True, capture_output=capture, **kwargs)


def model_path(model: str) -> Path:
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]*:[a-zA-Z0-9][a-zA-Z0-9_.-]*", model):
        raise SetupError("Use a local library model in name:tag format, without paths.")
    name, tag = model.split(":")
    return Path("manifests/registry.ollama.ai/library") / name / tag


def verify_model(cache: Path, model: str, destination: Path | None = None) -> dict:
    """Copy only selected model artifacts and verify each blob, never account files."""
    relative = model_path(model)
    manifest_bytes = (cache / relative).read_bytes()
    manifest = json.loads(manifest_bytes)
    entries = [manifest["config"], *manifest["layers"]]
    for entry in entries:
        digest = entry["digest"]
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise SetupError("Invalid cached model digest.")
        source = cache / "blobs" / digest.replace(":", "-")
        if destination is not None:
            target = destination / "blobs" / source.name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            source = target
        with source.open("rb") as stream:
            actual = hashlib.file_digest(stream, "sha256").hexdigest()
        if actual != digest[7:]:
            raise SetupError("Model digest mismatch; do not start this state directory.")
    if destination is not None:
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(manifest_bytes)
    return {"model": model, "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(), "blobs": entries}


def settings() -> dict[str, str]:
    values = {
        "MCP_PROXY_ENVIRONMENT": "development",
        "MCP_PROXY_STANDALONE": "true",
        "MCP_PROXY_LOCAL_AUTH_ENABLED": "true",
        "MCP_PROXY_DATABASE_URL": "sqlite+aiosqlite:////data/mcp_proxy.db",
        "MCP_PROXY_PROXY_PUBLIC_URL": "https://mastio-nginx:9443",
        "MCP_PROXY_NGINX_SAN": "mastio-nginx,localhost,127.0.0.1",
        "MCP_PROXY_NGINX_CERT_DIR": "/var/lib/mastio/nginx-certs",
        "MCP_PROXY_REDIS_URL": "redis://redis:6379/0",
        "MCP_PROXY_EGRESS_DPOP_MODE": "required",
        "MCP_PROXY_INTERNAL_HOST_ALLOWLIST": "ollama,mcp-proxy",
        "MCP_PROXY_POLICY_WEBHOOK_ALLOW_PRIVATE_IPS": "false",
        "MCP_PROXY_PDP_URL": "http://mcp-proxy:9100/pdp/policy",
        "MCP_PROXY_AI_GATEWAY_BACKEND": "cullis_native",
        "MCP_PROXY_AI_GATEWAY_REQUEST_TIMEOUT_S": "120",
        "MCP_PROXY_AUDIT_CAPTURE_TOOL_PARAMETERS": "false",
        "MCP_PROXY_AUDIT_CAPTURE_TOOL_RESULT": "false",
        "MCP_PROXY_AUDIT_CHAIN_DURABLE": "true",
        "MCP_PROXY_AUDIT_FAIL_DENY": "true",
        "MCP_PROXY_AUDIT_ANCHOR_ENABLED": "false",
        "MCP_PROXY_AUDIT_MERKLE_TSA_ENABLED": "false",
        "OTEL_SDK_DISABLED": "true",
    }
    for name in ("ADMIN_SECRET", "DASHBOARD_SIGNING_KEY", "DPOP_NONCE_SECRET",
                 "INITIAL_ADMIN_PASSWORD", "INTEGRATIONS_HMAC_SECRET"):
        values["MCP_PROXY_" + name] = secrets.token_hex(32)
    return values


def image_id(reference: str, offline: bool) -> str:
    result = subprocess.run(["docker", "image", "inspect", reference, "--format", "{{.Id}}"],
                            capture_output=True, text=True)
    if result.returncode:
        if offline:
            raise SetupError(f"Required image not cached: {reference}")
        run(["docker", "pull", reference])
        result = run(["docker", "image", "inspect", reference, "--format", "{{.Id}}"], capture=True)
    value = result.stdout.strip()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
        raise SetupError("Docker did not return a valid image ID.")
    return value


def guarded_nginx(offline: bool) -> str:
    """Cache a small nginx derivative keyed by its base image and guard sources."""
    base = "nginx:1.27-alpine"
    base_id = image_id(base, offline)
    context = BUNDLE / "local-demo-nginx"
    fingerprint = hashlib.sha256(base_id.encode())
    for name in ("Dockerfile", "entrypoint.sh"):
        fingerprint.update((context / name).read_bytes())
    tag = "cullis-local-nginx:" + fingerprint.hexdigest()[:24]
    cached = subprocess.run(["docker", "image", "inspect", tag, "--format", "{{.Id}}"],
                            capture_output=True, text=True)
    if cached.returncode:
        if offline:
            raise SetupError("Filtered nginx image is not cached. Prepare once with network access before using --offline.")
        LOG.info("Building nginx with its egress filter before starting the private environment.")
        run(["docker", "build", "--pull=false", "--build-arg", "NGINX_BASE=" + base,
             "--tag", tag, str(context)])
    return image_id(tag, True)


def prepare(args: argparse.Namespace) -> None:
    state = args.state
    if state.exists():
        raise SetupError("State already exists. Use up to resume, or a NEW --state directory.")
    model_path(args.model)
    if args.offline and args.model_cache is None:
        raise SetupError("Offline preparation requires --model-cache with complete local weights.")
    if args.mastio_image:
        mastio = args.mastio_image
    elif (BUNDLE / "VERSION").is_file():
        version = (BUNDLE / "VERSION").read_text().strip()
        if not re.fullmatch(r"[A-Za-z0-9.-]+", version):
            raise SetupError("Invalid bundle VERSION.")
        mastio = "ghcr.io/cullis-security/cullis-mastio:" + version
    else:
        raise SetupError("Use a released bundle or provide --mastio-image for a source checkout.")
    run(["docker", "compose", "version"], capture=True)
    images = {name: image_id(ref, args.offline) for name, ref in {
        "MASTIO": mastio, "OLLAMA": args.ollama_image,
        "BUSYBOX": "busybox:stable", "REDIS": "redis:7-alpine",
    }.items()}
    images["NGINX"] = guarded_nginx(args.offline)
    state.mkdir(parents=True, mode=0o700)
    for name in ("data", "certs", "agent", "public", "models"):
        (state / name).mkdir(mode=0o700)
    project = "cullis-local-" + secrets.token_hex(4)
    if args.model_cache is not None:
        manifest = verify_model(args.model_cache.expanduser().resolve(), args.model, state / "models")
    else:
        LOG.info("Downloading model weights before isolation. No company data is involved.")
        # This transient download container has no Mastio state or credentials.
        script = ('ollama serve >/tmp/ollama-download.log 2>&1 & pid=$!; '
                  'trap \'kill "$pid" 2>/dev/null || true\' EXIT; '
                  'i=0; until ollama list >/dev/null 2>&1; do '
                  'i=$((i+1)); [ "$i" -lt 30 ] || exit 1; sleep 1; done; '
                  'ollama pull "$1"')
        run(["docker", "run", "--rm", "--name", project + "-download", "--pull=never",
             "--user", f"{os.getuid()}:{os.getgid()}", "-e", "HOME=/tmp", "-e", "OLLAMA_NO_CLOUD=1",
             "-e", "OLLAMA_MODELS=/models", "--mount", f"type=bind,src={state / 'models'},dst=/models",
             "--entrypoint", "/bin/sh", images["OLLAMA"], "-ec", script, "download", args.model])
        manifest = verify_model(state / "models", args.model)
    (state / "model.json").write_text(json.dumps(manifest, indent=2) + "\n")
    values = settings()
    (state / "runtime.env").write_text("".join(f"{key}={value}\n" for key, value in values.items()))
    (state / "admin-password.txt").write_text(values["MCP_PROXY_INITIAL_ADMIN_PASSWORD"] + "\n")
    config = {"project": project, "port": args.port, "model": args.model, "images": images,
              "uid": os.getuid(), "gid": os.getgid()}
    # Written last: interrupted preparation is never treated as a complete install.
    (state / "install.json").write_text(json.dumps(config, indent=2) + "\n")
    LOG.info("Prepared %s. Next: run up with the same --state.", state)


def compose(state: Path, config: dict, *args: str, capture: bool = False) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env.update({"DEMO_STATE": str(state), "DEMO_PORT": str(config["port"]),
                "DEMO_MODEL": config["model"], "DEMO_UID": str(config["uid"]),
                "DEMO_GID": str(config["gid"]), "COMPOSE_PROFILES": "",
                "COMPOSE_ENV_FILES": "", "COMPOSE_DISABLE_ENV_FILE": "true"})
    env.update({f"DEMO_{name}_IMAGE": value for name, value in config["images"].items()})
    return run(["docker", "compose", "--project-name", config["project"],
                "--env-file", str(state / "runtime.env"),
                "-f", str(BUNDLE / "docker-compose.local-demo.yml"), *args], env=env, capture=capture)


def up(state: Path, config: dict) -> None:
    compose(state, config, "config", "--quiet")
    compose(state, config, "up", "-d", "--wait", "--wait-timeout", "150", "--pull", "never")
    compose(state, config, "exec", "-T", "mcp-proxy", "python", "/opt/local-demo-bootstrap.py")
    # Export only the public CA. Private keys never enter the agent mount.
    compose(state, config, "cp", "mcp-proxy:/var/lib/mastio/nginx-certs/org-ca.crt",
            str(state / "public/org-ca.pem"))
    (state / "public/org-ca.pem").chmod(0o644)
    trust = ssl.create_default_context(cafile=str(state / "public/org-ca.pem"))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=trust))
    url = f"https://localhost:{config['port']}"
    with opener.open(url + "/health", timeout=10) as response:
        if response.status != 200:
            raise SetupError("Dashboard health check failed.")
    LOG.info("Ready: %s/proxy/ — trust the public CA in %s", url, state / "public/org-ca.pem")
    LOG.info("Initial admin password: read %s locally. It is not printed in setup logs.", state / "admin-password.txt")
    LOG.info("Next: connect, approve the request in Enrollments, then run.")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    root.add_argument("--state", type=Path, default=BUNDLE / "local-demo-state")
    commands = root.add_subparsers(dest="command", required=True)
    cmd = commands.add_parser("prepare", help="Download/cache components and create fresh private state")
    cmd.add_argument("--model", default="qwen2.5:0.5b")
    cmd.add_argument("--model-cache", type=Path, help="Copy verified weights from an existing Ollama models directory")
    cmd.add_argument("--mastio-image")
    cmd.add_argument("--ollama-image", default=OLLAMA_IMAGE)
    cmd.add_argument("--offline", action="store_true", help="Require all images and weights to be already cached")
    cmd.add_argument("--port", type=int, default=9443)
    for name in ("up", "status", "down", "check"):
        commands.add_parser(name)
    cmd = commands.add_parser("connect", help="Request an agent identity; approve it in the dashboard")
    cmd.add_argument("--name", default="Local demo agent")
    cmd.add_argument("--email", default="operator@example.test")
    cmd = commands.add_parser("run", help="Summarise the synthetic example through the local model")
    cmd.add_argument("--task", default=TASK)
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    args.state = args.state.expanduser().resolve()
    os.umask(0o077)
    try:
        if not hasattr(os, "getuid"):
            raise SetupError("Use Linux or macOS; on Windows run this bundle inside WSL2.")
        if args.command == "prepare":
            if not 1024 <= args.port <= 65535:
                raise SetupError("Use a port between 1024 and 65535.")
            prepare(args)
            return 0
        config = json.loads((args.state / "install.json").read_text())
        if args.command == "up":
            up(args.state, config)
        elif args.command == "status":
            compose(args.state, config, "ps", "-a")
        elif args.command == "down":
            compose(args.state, config, "down")
            LOG.info("Stopped. State, credentials, model and identity preserved in %s.", args.state)
        else:
            command = [args.command, "--identity", "/identity"]
            if args.command == "connect":
                command += ["--url", "https://mastio-nginx:9443", "--ca-cert", "/trust/org-ca.pem",
                            "--name", args.name, "--email", args.email]
            elif args.command == "run":
                command += ["--model", "ollama_chat/" + config["model"], "--task", args.task]
            compose(args.state, config, "run", "--rm", "--no-deps", "--pull", "never", "-T", "agent", *command)
        return 0
    except subprocess.CalledProcessError:
        LOG.error("Command failed. State was preserved. Review status and the failed step before retrying.")
    except (OSError, ValueError, KeyError, SetupError) as exc:
        LOG.error("Setup stopped: %s", exc)
    return 1


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    sys.exit(main())
