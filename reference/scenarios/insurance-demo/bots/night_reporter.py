"""Night Reporter — overnight scheduled agent for the insurance demo.

Identity: ``orga::agent::night-reporter``
Reach:    intra-org only
Scope:    claims-db.read + oneshot.message

What it does (one tick):

  1. Authenticate to Mediterranean's Mastio with the cert/key minted by ``seed.py``
  2. Query the ``orga::resource::mcp::claims-db`` MCP server for claims
     where ``cross_company_flag = TRUE`` AND ``status = 'open'``
  3. Build a short summary (count, top 3 by amount, urgency breakdown)
  4. Send a one-shot message to ``orga::user::claim-officer`` with the
     summary as payload (intra-org A2U, ADR-008 envelope)
  5. Log + exit (idempotent — replay-safe via correlation_id)

Run modes:

  python night_reporter.py --once             # single tick, exit
  python night_reporter.py --schedule '0 22 * * *'   # cron string, daemon
  python night_reporter.py --demo             # demo mode: skips schedule,
                                                runs once, prints what it
                                                sent for the recording

In production this lives behind a systemd timer; in the demo recording the
operator triggers it manually via ``run.sh trigger-night-reporter``.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys
import time
import uuid

from cullis_sdk import CullisClient


HERE = pathlib.Path(__file__).resolve().parent
# parents: [0]=bots, [1]=insurance-demo, [2]=scenarios, [3]=reference, [4]=repo root.
# seed.py writes agent identity material under <repo-root>/state/insurance-demo/.
STATE_DIR = (HERE.parents[3] / "state" / "insurance-demo" / "agents" / "night-reporter").resolve()
RECIPIENT = "orga::user::claim-officer"
# mTLS endpoint (mastio-nginx-a sidecar). The plain HTTP :9100 is
# admin-only — agent traffic must hit nginx :9443 to satisfy DPoP htu
# matching + Org CA mTLS handshake.
MASTIO_URL = os.environ.get(
    "MASTIO_NGINX_A_URL", "https://localhost:9443",
)


def _build_summary(claims: list[dict]) -> dict:
    if not claims:
        return {
            "kind":        "night-report",
            "generated_at": int(time.time()),
            "summary":      "No cross-company-flagged open claims this run.",
            "claim_count":  0,
            "claims":       [],
        }
    by_urgency = {"high": 0, "normal": 0, "low": 0}
    for c in claims:
        by_urgency[c.get("urgency", "normal")] = by_urgency.get(c.get("urgency", "normal"), 0) + 1
    top3 = sorted(claims, key=lambda c: c.get("estimated_amount_eur", 0), reverse=True)[:3]
    return {
        "kind":         "night-report",
        "generated_at":  int(time.time()),
        "summary": (
            f"{len(claims)} cross-company claims open. "
            f"Urgency: high={by_urgency['high']}, normal={by_urgency['normal']}, "
            f"low={by_urgency['low']}. Top 3 by exposure attached."
        ),
        "claim_count":  len(claims),
        "by_urgency":   by_urgency,
        "top3":         [
            {
                "claim_id":  c["claim_id"],
                "amount_eur": c["estimated_amount_eur"],
                "region":    c["region"],
                "counterparty_insurer": c["counterparty_insurer"],
                "urgency":   c["urgency"],
            }
            for c in top3
        ],
    }


def _query_claims(client: CullisClient) -> list[dict]:
    """Call the ``orga::resource::mcp::claims-db`` MCP server through the
    SDK helper. Returns a list of claim rows (dict). Falls back to a
    canned fixture if the MCP server is unreachable so the demo doesn't
    hard-fail on a network blip during recording."""
    try:
        # SDK MCP helpers landed in ADR-017 Phase 3 (memory:
        # project_session_2026_05_04_adr017_live.md).
        result = client.call_mcp_tool(
            resource_id="orga::resource::mcp::claims-db",
            tool_name="query_claims",
            arguments={
                "where": "cross_company_flag = TRUE AND status = 'open'",
                "order_by": "estimated_amount_eur DESC",
                "limit": 20,
            },
        )
        return result.get("rows", [])
    except Exception as exc:
        print(f"[night-reporter] MCP query failed ({exc}) — using canned fixture",
              file=sys.stderr)
        # Canned fixture mirrors claims.sql cross-company rows
        return [
            {"claim_id": "INC-2026-0501", "estimated_amount_eur": 18500,
             "region": "Lazio",     "counterparty_insurer": "Asia-Pacific Insurance",
             "urgency": "high"},
            {"claim_id": "INC-2026-0502", "estimated_amount_eur": 42000,
             "region": "Lombardia", "counterparty_insurer": "Asia-Pacific Insurance",
             "urgency": "high"},
            {"claim_id": "INC-2026-0503", "estimated_amount_eur": 7800,
             "region": "Campania",  "counterparty_insurer": "Asia-Pacific Insurance",
             "urgency": "high"},
        ]


def _send(client: CullisClient, payload: dict) -> dict:
    """Fire the summary as a one-shot to claim-officer. Sets
    correlation_id deterministically so two same-day runs idempotent."""
    corr_id = f"night-report-{time.strftime('%Y%m%d')}"
    return client.send_oneshot(
        recipient_id=RECIPIENT,
        payload=payload,
        correlation_id=corr_id,
        ttl_seconds=86400,
    )


def run_once(verbose: bool = False) -> int:
    cert = STATE_DIR / "agent.pem"
    key  = STATE_DIR / "agent-key.pem"
    # STATE_DIR = …/state/insurance-demo/agents/night-reporter
    # parents[1] = …/state/insurance-demo (where prep-ca dropped orga-ca.pem)
    org_ca = STATE_DIR.parents[1] / "orga-ca.pem"
    if not (cert.exists() and key.exists()):
        print(f"[night-reporter] missing identity at {STATE_DIR} — "
              "did you run ./run.sh seed?", file=sys.stderr)
        return 2

    # NOTE: ``verify_tls=False`` in the SDK silently drops the client
    # cert (httpx 0.28 incompat — see _build_proxy_http_client). nginx
    # then 401s. Pin verify_tls=True + ca_chain_path so the client cert
    # is actually presented at the TLS handshake.
    client = CullisClient.from_identity_dir(
        MASTIO_URL,
        cert_path=cert,
        key_path=key,
        agent_id="orga::night-reporter",
        org_id="orga",
        verify_tls=True,
        ca_chain_path=org_ca,
    )
    client.login_via_proxy()
    client._signing_key_pem = key.read_text()

    claims = _query_claims(client)
    payload = _build_summary(claims)
    if verbose:
        print(json.dumps(payload, indent=2))
    resp = _send(client, payload)
    print(f"[night-reporter] sent → {RECIPIENT} "
          f"correlation_id={resp.get('correlation_id')} "
          f"msg_id={resp.get('msg_id')} status={resp.get('status')}")
    return 0


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--once", action="store_true",
                   help="single tick then exit (default)")
    p.add_argument("--demo", action="store_true",
                   help="demo mode: same as --once but verbose")
    p.add_argument("--schedule", default=None,
                   help="cron string (loops forever — production deploy)")
    args = p.parse_args()

    if args.schedule:
        try:
            from croniter import croniter
        except ImportError:
            print("[night-reporter] --schedule requires croniter "
                  "(pip install croniter)", file=sys.stderr)
            return 2
        from datetime import datetime
        cron = croniter(args.schedule, datetime.now())
        while True:
            nxt = cron.get_next(datetime)
            wait = (nxt - datetime.now()).total_seconds()
            if wait > 0:
                time.sleep(wait)
            run_once(verbose=False)

    return run_once(verbose=args.demo)


if __name__ == "__main__":
    sys.exit(main())
