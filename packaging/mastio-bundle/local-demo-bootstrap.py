"""Configure the local provider through the admin API, inside Mastio only."""
import json
import logging
import os
import ssl
import sys
import urllib.request


def main() -> None:
    trust = ssl.create_default_context(cafile="/var/lib/mastio/nginx-certs/org-ca.crt")
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=trust),
    )

    def request(method: str, suffix: str = "", body: dict | None = None) -> dict:
        req = urllib.request.Request(
            "https://mastio-nginx:9443/v1/admin/ai-providers/ollama" + suffix,
            data=json.dumps(body).encode() if body is not None else None,
            headers={"X-Admin-Secret": os.environ["MCP_PROXY_ADMIN_SECRET"],
                     "Content-Type": "application/json"}, method=method,
        )
        with opener.open(req, timeout=20) as response:
            return json.load(response)

    # Refuse drift rather than silently overwrite an operator's configuration.
    current = request("GET")
    if current["configured"]:
        if (not current["enabled"] or
                current["creds_masked"].get("api_base") != "http://ollama:11434"):
            raise RuntimeError("The local provider configuration has changed")
    else:
        request("PUT", body={"creds": {"api_base": "http://ollama:11434"},
                             "enabled": True, "updated_by": "local-demo-setup"})
    if request("POST", "/test", {})["status"] != "ok":
        raise RuntimeError("The local model connection test failed")
    logging.info("Local model connected through Mastio.")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    try:
        main()
    except Exception:
        logging.error("Local provider setup failed. Inspect Mastio status and AI Providers; credentials were not printed.")
        sys.exit(1)
