"""Real enrollment, TLS, JWT/DPoP, bindings, Rego and upstream execution.

Run inside the smoke Mastio image. Only the external business tool is synthetic;
its independent counter proves denied requests never reach it. No auth overrides.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import ssl
import tempfile

import httpx

from cullis_sdk import CullisClient

BASE = "https://mastio-nginx:9443"
CA = "/var/lib/mastio/nginx-certs/org-ca.crt"
CONTEXT = ssl.create_default_context(cafile=CA)
checks = 0


def check(condition, label):
    global checks
    if not condition:
        raise AssertionError(label)
    checks += 1
    print(f"PASS {label}", flush=True)


def main():
    with tempfile.TemporaryDirectory(prefix="policy-smoke-") as tmp, httpx.Client(
        base_url=BASE, verify=CONTEXT, timeout=30,
        headers={"X-Admin-Secret": os.environ["MCP_PROXY_ADMIN_SECRET"]},
    ) as admin, httpx.Client(base_url="http://mock-tsa:2561", timeout=10) as upstream:
        def api(method, path, body=None):
            response = admin.request(method, path, json=body)
            response.raise_for_status()
            return response.json() if response.content else None

        response = admin.post("/proxy/login", data={"password": os.environ["MCP_PROXY_INITIAL_ADMIN_PASSWORD"]})
        check(response.status_code == 303, "operator login")
        page = admin.get("/proxy/policies/rego")
        csrf = re.search(r'name="csrf_token"[^>]*value="([a-f0-9]+)"', page.text).group(1)

        def save_rules(rules):
            response = admin.post("/proxy/policies/save", data={
                "csrf_token": csrf, "tab": "rules", "rules_json": json.dumps(rules),
            })
            check(response.status_code == 303, "operator rules saved")

        clients, ids = {}, {}
        for name, cap in (("tickets", "tickets.open"), ("refund100", "refunds.issue"), ("refund1000", "refunds.issue")):
            row = api("POST", "/v1/admin/agents", {"agent_name": name, "capabilities": [cap, "mcp.tools.list"]})
            ids[name] = row["agent_id"]
            folder = Path(tmp) / name
            folder.mkdir(mode=0o700)
            (folder / "cert.pem").write_text(row.get("cert_chain_pem") or row["cert_pem"])
            (folder / "key.pem").write_text(row["private_key_pem"])
            (folder / "key.pem").chmod(0o600)
            client = CullisClient.from_identity_dir(BASE, cert_path=folder / "cert.pem", key_path=folder / "key.pem", ca_chain_path=CA)
            client.login_via_proxy_with_local_key()
            clients[name] = client
            check(bool(client.token), f"{name}: real certificate login and bound token")

        resources = {}
        for tool, cap, required in (("open_ticket", "tickets.open", False), ("issue_refund", "refunds.issue", True)):
            resources[tool] = api("POST", "/v1/admin/mcp-resources", {
                "name": tool, "endpoint_url": "http://mock-tsa:2561/mcp", "required_capability": cap,
                "requires_delegation": required,
            })["resource_id"]
        bindings = {}
        for name in clients:
            tool = "open_ticket" if name == "tickets" else "issue_refund"
            bindings[name] = api("POST", "/v1/admin/mcp-resources/bindings", {
                "agent_id": ids[name], "resource_id": resources[tool],
            })["binding_id"]
        # Even an accidental financial binding cannot confer the refund action.
        api("POST", "/v1/admin/mcp-resources/bindings", {"agent_id": ids["tickets"], "resource_id": resources["issue_refund"]})

        def invoke(name, tool, amount, allowed, route, extra=None):
            before = upstream.get("/tool-counts").json().get(tool, 0)
            arguments = {"amount_cents": amount, "currency": "EUR", **(extra or {})}
            path = "/v1/ingress/execute" if route == "REST" else "/v1/mcp"
            payload = {"tool": tool, "parameters": arguments} if route == "REST" else {
                "jsonrpc": "2.0", "id": checks, "method": "tools/call", "params": {"name": tool, "arguments": arguments},
            }
            response = clients[name]._authed_request("POST", path, json=payload)
            response.raise_for_status()
            body = response.json()
            success = body.get("status") == "success" if route == "REST" else "result" in body and not body["result"].get("isError", False)
            after = upstream.get("/tool-counts").json().get(tool, 0)
            check(success == allowed and after - before == int(allowed), f"{route} {name} {tool} {amount}: allowed={allowed}, upstream delta={after-before}")

        # Independently persisted resource requirement protects even an empty policy.
        save_rules({})
        for route in ("REST", "MCP"):
            invoke("refund100", "issue_refund", 5000, False, route)
        rules = {"tool_rules": {
            "open_ticket": {"allowed_principals": [ids["tickets"]]},
            "issue_refund": {"delegations": {
                ids["refund100"]: {"max_amount_cents": 10000},
                ids["refund1000"]: {"max_amount_cents": 100000},
            }},
        }}
        save_rules(rules)
        for route in ("REST", "MCP"):
            invoke("refund100", "issue_refund", 5000, False, route)
        rego = '''package cullis.policy
        default session := {"decision": "allow"}
        default tool_call := {"decision": "deny"}
        tool_call := {"decision": "allow"} if { input.tool_name == "open_ticket" }
        tool_call := {"decision": "allow"} if {
            input.tool_name == "issue_refund"
            input.arguments.currency == "EUR"
            is_number(input.arguments.amount_cents)
            input.arguments.amount_cents > 0
            input.arguments.amount_cents == floor(input.arguments.amount_cents)
            input.arguments.amount_cents <= input.delegation.max_amount_cents
        }
        '''
        response = admin.post("/proxy/policies/rego/save", data={"csrf_token": csrf, "rego": rego})
        check(response.status_code == 303, "real OPA compilation")
        check("issue_refund" not in {t["name"] for t in clients["tickets"].list_mcp_tools()}, "ticket discovery excludes refund despite binding")
        for route in ("REST", "MCP"):
            invoke("tickets", "open_ticket", 0, True, route)
            invoke("tickets", "issue_refund", 1, False, route, {"agent_id": ids["refund1000"], "scope": ["refunds.issue"]})
            for name, amounts in (("refund100", ((10000, True), (10001, False), (50000, False))), ("refund1000", ((50000, True), (100000, True), (100001, False)))):
                for amount, allowed in amounts:
                    invoke(name, "issue_refund", amount, allowed, route)
            invoke("refund100", "issue_refund", 50000, False, route, {"delegation": {"max_amount_cents": 999999}, "agent_id": ids["refund1000"]})
        # A stolen token cannot be used with another agent's proof key.
        victim = clients["refund1000"]
        headers = clients["tickets"]._headers("POST", "/v1/ingress/execute")
        headers["Authorization"] = "DPoP " + victim.token
        response = clients["tickets"]._http.post(BASE + "/v1/ingress/execute", headers=headers, json={"tool": "issue_refund", "parameters": {}})
        check(response.status_code == 401, "stolen token with wrong DPoP key rejected")
        # Revocation takes effect on already-issued tokens.
        api("DELETE", "/v1/admin/mcp-resources/bindings/" + bindings["refund1000"])
        for route in ("REST", "MCP"):
            invoke("refund1000", "issue_refund", 5000, False, route)
        # Corrupt artifact and complete policy deletion both remain denied.
        save_rules({**rules, "rego_wasm_base64": "corrupt!"})
        for route in ("REST", "MCP"):
            invoke("refund100", "issue_refund", 5000, False, route)
        save_rules({})
        for route in ("REST", "MCP"):
            invoke("refund100", "issue_refund", 5000, False, route)
        for client in clients.values():
            client.close()
        print(f"AUTHORIZATION_CHAIN_OK checks={checks}", flush=True)


if __name__ == "__main__":
    main()
