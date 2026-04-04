"""
Mock PDP (Policy Decision Point) — local demo server.

Simulates the webhook that each real organization would expose.
Responds ALLOW to every session request.

In production, each org replaces this with their own internal system
(e.g. an HR system checking agent authorization, a compliance engine, etc.)

Usage:
  python agents/mock_pdp.py                  # port 9000 (manufacturer)
  python agents/mock_pdp.py --port 9001      # port 9001 (buyer)
  python agents/mock_pdp.py --org buyer --port 9001 --deny  # always deny (testing)

Endpoint:
  POST /policy
  Body: {
    "initiator_agent_id": str,
    "initiator_org_id":   str,
    "target_agent_id":    str,
    "target_org_id":      str,
    "capabilities":       list[str],
    "session_context":    "initiator" | "target"
  }
  Response: {"decision": "allow"} | {"decision": "deny", "reason": str}
"""
import argparse
import logging

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")
_log = logging.getLogger("mock_pdp")


def build_app(org_name: str, always_deny: bool) -> FastAPI:
    app = FastAPI(title=f"Mock PDP — {org_name}")

    @app.get("/health")
    async def health():
        return {"status": "ok", "org": org_name}

    @app.post("/policy")
    async def policy_decision(request: Request):
        body = await request.json()
        initiator = body.get("initiator_agent_id", "?")
        target    = body.get("target_agent_id", "?")
        caps      = body.get("capabilities", [])
        context   = body.get("session_context", "?")

        if always_deny:
            _log.info("[%s] DENY  %s → %s  caps=%s  ctx=%s", org_name, initiator, target, caps, context)
            return JSONResponse({"decision": "deny", "reason": "mock PDP configured to deny all"})

        _log.info("[%s] ALLOW %s → %s  caps=%s  ctx=%s", org_name, initiator, target, caps, context)
        return JSONResponse({"decision": "allow"})

    return app


def main() -> None:
    parser = argparse.ArgumentParser(description="Mock PDP webhook server")
    parser.add_argument("--org",   default="demo-org", help="Org name (for logging)")
    parser.add_argument("--port",  type=int, default=9000, help="Port to listen on")
    parser.add_argument("--host",  default="0.0.0.0", help="Host to bind")
    parser.add_argument("--deny",  action="store_true", help="Always return deny (for testing)")
    args = parser.parse_args()

    app = build_app(org_name=args.org, always_deny=args.deny)
    _log.info("Mock PDP starting: org=%s  http://%s:%d/policy  deny=%s",
              args.org, args.host, args.port, args.deny)
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
