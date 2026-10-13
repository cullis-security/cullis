"""Run inside the isolated operator container; use real dashboard and SDK APIs."""
import json
import os
from pathlib import Path
import re
import runpy
import ssl
import subprocess
import sys
import time

import httpx

from fixture import INPUT_MARKER, OUTPUT_MARKER

OUT = Path("/evidence")
BASE = "https://mastio-nginx:9443"
PROMPT_MARKER = "SYNTHETIC-PROMPT-PRIVATE-9216"
RESULTS = []


def record(step, **evidence):
    RESULTS.append({"step": step, **evidence})
    (OUT / "journey.json").write_text(json.dumps(RESULTS, indent=2) + "\n")
    print(step, json.dumps(evidence), flush=True)


def need(condition, message):
    if not condition:
        raise AssertionError(message)


def page(admin, path):
    response = admin.get(path)
    need(response.status_code == 200, f"GET {path}: {response.status_code}")
    return response.text


def form(admin, path, fields, source, expected=303):
    token = re.search(r'name="csrf_token"\s+value="([^"]+)"', page(admin, source))
    need(token is not None, "Missing dashboard CSRF token")
    response = admin.post(path, data={**fields, "csrf_token": token[1]})
    need(response.status_code == expected, f"POST {path}: {response.status_code}")
    return response


def enroll(admin):
    log = OUT / "connect.log"
    with log.open("w") as output:
        process = subprocess.Popen([sys.executable, "/first-agent.py", "connect", "--url", BASE,
            "--ca-cert", str(OUT / "server-ca.pem"), "--name", "Synthetic perimeter agent",
            "--email", "operator@example.test", "--identity", str(OUT / "identity")],
            stdout=output, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 40
            session = None
            while time.monotonic() < deadline and process.poll() is None:
                match = re.search(r"Request: ([a-zA-Z0-9_-]+)\.", log.read_text())
                if match:
                    session = match[1]
                    break
                time.sleep(0.2)
            need(session, "Enrollment request not created; inspect connect.log")
            form(admin, f"/proxy/enrollments/{session}/approve", {
                "agent_id": "perimeter_agent", "capabilities": "llm.chat, mcp.tools.list, cases.read", "groups": "",
            }, "/proxy/enrollments")
            need(process.wait(timeout=40) == 0, "Enrollment did not complete")
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
    return runpy.run_path("/first-agent.py")["load_client"](OUT / "identity")


def verify_audit(admin, agent):
    response = admin.get("/v1/admin/audit/export", params={"chain": "both", "include_anchors": "false"},
                         headers={"X-Admin-Secret": os.environ["MCP_PROXY_ADMIN_SECRET"]})
    need(response.status_code == 200, "Audit export failed")
    bundle = OUT / "audit.ndjson"
    bundle.write_bytes(response.content)
    for marker in (INPUT_MARKER, OUTPUT_MARKER, PROMPT_MARKER):
        need(marker not in response.text, "Synthetic sensitive value leaked into audit export")
    rows = [json.loads(line) for line in response.text.splitlines() if line]
    own = [row for row in rows if row.get("agent_id") == agent]
    executed = [row for row in own if row.get("action") == "tool_execute" and row.get("status") == "success"]
    need(executed, "Tool success missing from audit")
    need(any(row.get("event_type") == "resource_call" and row.get("result") == "denied" for row in own),
         "Revoked access denial missing from audit")
    detail = json.loads(executed[0]["detail"])
    need(detail["parameters"].get("_redacted") is True, "Tool input was not explicitly redacted")
    need(detail["result_summary"].get("_redacted") is True, "Tool output was not explicitly redacted")
    for path, expected in ((bundle, 0), (OUT / "audit-tampered.ndjson", 2)):
        if expected:
            executed[0]["detail"] = "deliberate tamper of exported copy"
            path.write_text("".join(json.dumps(row) + "\n" for row in rows))
        check = subprocess.run([sys.executable, "/audit-verify.py", "--bundle", str(path), "--require-genesis"],
                               capture_output=True, text=True, timeout=30)
        path.with_suffix(".verify.log").write_text(check.stdout + check.stderr)
        need(check.returncode == expected, f"Unexpected verifier exit {check.returncode}")
    record("audit_minimization_and_integrity", rows=len(rows), agent_rows=len(own),
           canaries_absent=True, redaction_markers_present=True, original_exit=0, tampered_exit=2,
           independent_timestamp_verified=False)


def main():
    need(not (OUT / "identity").exists(), "Use fresh state; preserve previous evidence")
    trust = ssl.create_default_context(cafile=str(OUT / "server-ca.pem"))
    with httpx.Client(base_url=BASE, verify=trust, trust_env=False, timeout=150) as admin:
        response = admin.post("/proxy/login", data={"password": os.environ["MCP_PROXY_INITIAL_ADMIN_PASSWORD"]})
        need(response.status_code == 303, "Dashboard login failed")
        form(admin, "/proxy/ai-providers/ollama/save", {
            "api_base": "http://ollama:11434", "enabled": "on",
        }, "/proxy/ai-providers")
        result = form(admin, "/proxy/ai-providers/ollama/test", {}, "/proxy/ai-providers", expected=200)
        need("OK" in result.text and "FAIL" not in result.text, "Local provider probe failed")
        record("local_model_configured", model=os.environ["PERIMETER_MODEL"])
        client = enroll(admin)
        client._http.timeout = httpx.Timeout(150)
        agent = json.loads((OUT / "identity/meta.json").read_text())["agent_id"]
        record("enrollment", agent_id=agent, tls_verified=True, dpop_required=True)
        try:
            form(admin, "/proxy/backends/create", {
                "name": "read_case", "description": "Read a synthetic case",
                "endpoint_url": "https://fixture:8443/mcp", "auth_type": "none",
                "required_capability": "cases.read",
                "allowed_domains": '["fixture"]', "enabled": "on", "org_id": "",
            }, "/proxy/backends")
            match = re.search(r'name="resource_id"\s+value="([^"]+)"', page(admin, "/proxy/backends"))
            need(match, "Resource not registered")
            form(admin, "/proxy/backends/bindings/create", {"agent_id": agent, "resource_id": match[1]}, "/proxy/backends")
            revoke = re.search(r'action="(/proxy/backends/bindings/[^/]+/revoke)"', page(admin, "/proxy/backends"))
            need(revoke, "Binding missing")
            tools = client.list_mcp_tools()
            need(any(tool["name"] == "read_case" for tool in tools), "Tool not visible")
            tool_result = client.call_mcp_tool("read_case", {"reference": INPUT_MARKER})
            need(OUTPUT_MARKER in json.dumps(tool_result), "Actual tool result missing")
            record("permitted_tool_executed")
            start = time.monotonic()
            result = client.chat_completion({
                "model": "ollama_chat/" + os.environ["PERIMETER_MODEL"],
                "messages": [{"role": "user", "content": "Summarize this synthetic case in one short sentence. "
                    + PROMPT_MARKER + " " + json.dumps(tool_result)}],
                "max_tokens": 128, "temperature": 0,
            })
            content = result["choices"][0]["message"]["content"]
            need(isinstance(content, str) and content.strip(), "Local model returned no answer")
            need(result.get("usage", {}).get("completion_tokens", 0) > 0, "No inference tokens reported")
            # This is an explicit tool -> real local model workflow, not a test of autonomous planning.
            (OUT / "model-response.json").write_text(json.dumps(result, indent=2) + "\n")
            record("real_local_inference", seconds=round(time.monotonic() - start, 2), usage=result.get("usage"),
                   scope="script-orchestrated tool then model; model quality not scored")
            form(admin, revoke[1], {}, "/proxy/backends")
            need(not any(tool["name"] == "read_case" for tool in client.list_mcp_tools()), "Revoked tool visible")
            try:
                client.call_mcp_tool("read_case", {"reference": INPUT_MARKER})
            except RuntimeError as exc:
                need("No active binding" in str(exc), "Unexpected denial after revocation")
            else:
                raise AssertionError("Revoked tool executed")
            record("direct_sdk_revocation_denied")
            verify_audit(admin, agent)
        finally:
            client.close()
        record("PASS")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        record("FAIL", error_type=type(exc).__name__, reason=str(exc))
        raise
