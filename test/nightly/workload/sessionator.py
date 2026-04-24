"""Sessionator — holds a long-lived intra-org session between two agents
and runs a ping-pong exchange. Two processes form one pair: an initiator
opens the session and drives the ping, a responder accepts and echoes.

Cross-org sessions via the proxy path aren't wired yet (send_via_proxy
raises NotImplementedError for transport=envelope), so this driver runs
intra-org only. Cross-org pressure comes from send_oneshot in chatter +
spammer.

Usage (paired):
    python sessionator.py initiator <self_id> --target <peer_id>
    python sessionator.py responder <self_id> --expect <peer_id>

Log: logs/<run-ts>/sessionator-<self>.jsonl — one record per send/recv.
"""
from __future__ import annotations

import argparse
import sys
import time

from _common import load_client, logger_for, Shutdown

PING_CAPS = ["session.open", "session.message"]
POLL_INTERVAL_S = 0.5
SESSION_RETRY_S = 5.0


# The SDK's open_session / list_sessions / accept_session go through
# _authed_request which hits /v1/broker/sessions — that's the legacy
# reverse-proxy path and requires a broker JWT the from_api_key_file
# client doesn't populate the right way. Use the /v1/egress/sessions
# API-key + DPoP path directly through client._egress_http.
def egress_open_session(client, target_agent_id: str, target_org_id: str,
                        capabilities: list[str]) -> str:
    resp = client._egress_http("post", "/v1/egress/sessions", json={
        "target_agent_id": target_agent_id,
        "target_org_id": target_org_id,
        "capabilities": capabilities,
    })
    resp.raise_for_status()
    return resp.json()["session_id"]


def egress_list_sessions(client, status: str | None = None) -> list[dict]:
    params = [("status", status)] if status else []
    resp = client._egress_http("get", "/v1/egress/sessions", params=params)
    resp.raise_for_status()
    body = resp.json()
    return body if isinstance(body, list) else body.get("sessions", [])


def egress_accept_session(client, session_id: str) -> None:
    resp = client._egress_http("post", f"/v1/egress/sessions/{session_id}/accept")
    resp.raise_for_status()


def run_initiator(self_id: str, target_id: str, log, stop: Shutdown) -> int:
    """Open one session, ping, wait for echo, repeat."""
    client = load_client(self_id)
    target_org, _ = target_id.split("::", 1)

    session_id: str | None = None
    seq = 0
    ok = 0
    fail = 0

    while not stop.stopped:
        if session_id is None:
            try:
                session_id = egress_open_session(client, target_id, target_org, PING_CAPS)
                log.write(event="session_opened", session_id=session_id,
                          target=target_id)
            except Exception as exc:
                log.write(event="open_fail",
                          error=f"{type(exc).__name__}: {exc}")
                stop.wait(SESSION_RETRY_S)
                continue

        seq += 1
        t0 = time.monotonic()
        try:
            client.send_via_proxy(session_id, {"ping_seq": seq}, target_id)
        except Exception as exc:
            log.write(event="send_fail", session_id=session_id, seq=seq,
                      error=f"{type(exc).__name__}: {exc}")
            fail += 1
            session_id = None
            stop.wait(SESSION_RETRY_S)
            continue

        # Wait up to 10s for the echo
        deadline = time.monotonic() + 10.0
        got_reply = False
        while time.monotonic() < deadline and not stop.stopped:
            try:
                msgs = client.receive_via_proxy(session_id)
            except Exception as exc:
                log.write(event="recv_fail", session_id=session_id, seq=seq,
                          error=f"{type(exc).__name__}: {exc}")
                fail += 1
                session_id = None
                break
            if any(m.get("payload", {}).get("pong_seq") == seq for m in msgs):
                got_reply = True
                break
            stop.wait(POLL_INTERVAL_S)

        if got_reply:
            rtt_ms = int((time.monotonic() - t0) * 1000)
            log.write(event="rtt", session_id=session_id, seq=seq,
                      rtt_ms=rtt_ms)
            ok += 1
        else:
            log.write(event="echo_timeout", session_id=session_id, seq=seq)
            fail += 1

        stop.wait(2.0)

    log.write(event="stop", sent=seq, ok=ok, fail=fail)
    return 0


def run_responder(self_id: str, expect_id: str, log, stop: Shutdown) -> int:
    """Accept sessions opened by expect_id, echo every message back."""
    client = load_client(self_id)
    accepted: set[str] = set()
    seen_seqs: dict[str, set[int]] = {}
    echoes = 0

    while not stop.stopped:
        # Accept pending sessions from the expected peer
        try:
            pending = egress_list_sessions(client, status="pending")
        except Exception as exc:
            log.write(event="list_fail",
                      error=f"{type(exc).__name__}: {exc}")
            stop.wait(POLL_INTERVAL_S)
            continue

        for s in pending:
            sid = s.get("session_id") if isinstance(s, dict) else None
            if not sid or sid in accepted:
                continue
            initiator = s.get("initiator_agent_id") if isinstance(s, dict) else None
            if initiator and initiator != expect_id:
                continue
            try:
                egress_accept_session(client, sid)
                accepted.add(sid)
                log.write(event="session_accepted",
                          session_id=sid, from_=expect_id)
            except Exception as exc:
                log.write(event="accept_fail", session_id=sid,
                          error=f"{type(exc).__name__}: {exc}")

        # Drain each accepted session and echo
        for sid in list(accepted):
            try:
                msgs = client.receive_via_proxy(sid)
            except Exception as exc:
                log.write(event="recv_fail", session_id=sid,
                          error=f"{type(exc).__name__}: {exc}")
                continue
            seen = seen_seqs.setdefault(sid, set())
            for m in msgs:
                payload = m.get("payload", {})
                seq = payload.get("ping_seq")
                if seq is None or seq in seen:
                    continue
                seen.add(seq)
                try:
                    client.send_via_proxy(sid, {"pong_seq": seq}, expect_id)
                    echoes += 1
                    log.write(event="echo", session_id=sid, seq=seq)
                except Exception as exc:
                    log.write(event="echo_fail", session_id=sid, seq=seq,
                              error=f"{type(exc).__name__}: {exc}")

        stop.wait(POLL_INTERVAL_S)

    log.write(event="stop", accepted=len(accepted), echoes=echoes)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="role", required=True)
    p_i = sub.add_parser("initiator")
    p_i.add_argument("self_id")
    p_i.add_argument("--target", required=True)
    p_r = sub.add_parser("responder")
    p_r.add_argument("self_id")
    p_r.add_argument("--expect", required=True)
    args = ap.parse_args()

    log = logger_for(f"sessionator-{args.role}", args.self_id)
    stop = Shutdown()

    try:
        if args.role == "initiator":
            rc = run_initiator(args.self_id, args.target, log, stop)
        else:
            rc = run_responder(args.self_id, args.expect, log, stop)
    except Exception as exc:
        log.write(event="fatal", error=f"{type(exc).__name__}: {exc}")
        rc = 1
    finally:
        log.close()
    return rc


if __name__ == "__main__":
    sys.exit(main())
