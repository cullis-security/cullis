"""
checker.py — Cullis demo agent (beta::checker).

Long-running daemon that simulates a real agent waiting for incoming
work. It does NO LLM call, NO Anthropic API call — it is a dumb HTTP
loop whose only job is to prove the broker actually routes messages
end-to-end between two organizations.

Loop, every second, against proxy-beta:
  1. GET  /v1/egress/sessions          list sessions where I'm a peer
  2. POST /v1/egress/sessions/{id}/accept   accept any pending session
                                            in which I am the target
  3. GET  /v1/egress/messages/{id}     poll the inbox for each accepted
                                       session, with `after=<last_seq>`
  4. for every new inbox message, print one line on stdout

Reads its API key + agent_id from scripts/demo/.state.json which
deploy_demo.sh up wrote during bootstrap.

Lifecycle:
  - Started in the background by deploy_demo.sh up (PID file in
    scripts/demo/.checker.pid, log file in scripts/demo/.checker.log).
  - Stopped by deploy_demo.sh down or deploy_demo.sh nuke.
  - Safe to ctrl-C if you run it manually.

Run by hand:
    python scripts/demo/checker.py
"""
from __future__ import annotations

import json
import pathlib
import signal
import sys
import time

import httpx

_HERE = pathlib.Path(__file__).resolve().parent
_STATE_FILE = _HERE / ".state.json"
_PROXY_BETA_URL = "http://localhost:9801"

_POLL_INTERVAL_SECONDS = 1.0
_HTTP_TIMEOUT_SECONDS = 5.0


_running = True


def _stop(_signum: int, _frame) -> None:
    global _running
    _running = False


def _load_state() -> dict:
    if not _STATE_FILE.exists():
        sys.exit(
            f"checker: {_STATE_FILE} not found — run ./deploy_demo.sh up first"
        )
    return json.loads(_STATE_FILE.read_text())


def _log(agent_id: str, msg: str) -> None:
    print(f"[{agent_id}] {msg}", flush=True)


def main() -> None:
    state = _load_state()
    agent_id = state["beta_agent_id"]
    api_key  = state["beta_api_key"]
    headers  = {"X-API-Key": api_key}

    accepted: set[str] = set()           # session_ids we have already accepted
    last_seq: dict[str, int] = {}        # session_id -> highest seq we have read

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT,  _stop)

    _log(agent_id, f"checker daemon started, polling {_PROXY_BETA_URL} every {_POLL_INTERVAL_SECONDS}s")

    client = httpx.Client(timeout=_HTTP_TIMEOUT_SECONDS, headers=headers)
    try:
        while _running:
            try:
                # 1) list sessions and auto-accept any pending ones where
                #    we are the target. The broker /v1/broker/sessions
                #    list_for_agent returns sessions where the agent is
                #    either initiator OR target, so the proxy passes them
                #    through verbatim.
                resp = client.get(f"{_PROXY_BETA_URL}/v1/egress/sessions")
                if resp.status_code == 200:
                    for s in resp.json().get("sessions", []):
                        sid = s.get("session_id")
                        if not sid:
                            continue
                        if sid in accepted:
                            continue
                        if s.get("status") != "pending":
                            continue
                        if s.get("target_agent_id") != agent_id:
                            # we are the initiator side — nothing to accept
                            continue
                        ar = client.post(
                            f"{_PROXY_BETA_URL}/v1/egress/sessions/{sid}/accept",
                        )
                        if ar.is_success:
                            accepted.add(sid)
                            last_seq.setdefault(sid, -1)
                            _log(agent_id, f"accepted pending session {sid}")
                        else:
                            _log(agent_id, f"accept session {sid} failed: HTTP {ar.status_code} {ar.text[:200]}")

                # 2) detect closed/denied sessions from the listing so we
                #    can drain remaining messages and then stop polling.
                closed_sids: set[str] = set()
                if resp.status_code == 200:
                    for s in resp.json().get("sessions", []):
                        sid = s.get("session_id")
                        if sid and sid in accepted and s.get("status") in ("closed", "denied"):
                            closed_sids.add(sid)

                # 3) poll inbox for each accepted session
                for sid in list(accepted):
                    after = last_seq.get(sid, -1)
                    mr = client.get(
                        f"{_PROXY_BETA_URL}/v1/egress/messages/{sid}",
                        params={"after": after},
                    )
                    if mr.status_code == 409:
                        # session is pending/denied — stop polling
                        accepted.discard(sid)
                        last_seq.pop(sid, None)
                        _log(agent_id, f"session {sid} no longer active, stopped polling")
                        continue
                    if mr.status_code != 200:
                        continue
                    messages = mr.json().get("messages", [])
                    for m in messages:
                        seq = m.get("seq", -1)
                        sender = m.get("sender_agent_id", "?")
                        payload = m.get("payload") or {}
                        _log(
                            agent_id,
                            f"received from {sender} (seq {seq}): {json.dumps(payload, ensure_ascii=False)}",
                        )
                        if seq > last_seq.get(sid, -1):
                            last_seq[sid] = seq

                    # If session is closed and we drained all messages, stop
                    if sid in closed_sids:
                        accepted.discard(sid)
                        last_seq.pop(sid, None)
                        _log(agent_id, f"session {sid} closed, drained all messages")

            except httpx.RequestError as exc:
                _log(agent_id, f"poll error: {exc}")
            except Exception as exc:
                _log(agent_id, f"unexpected error: {type(exc).__name__}: {exc}")

            # interruptible sleep
            for _ in range(int(_POLL_INTERVAL_SECONDS * 10)):
                if not _running:
                    break
                time.sleep(0.1)

    finally:
        client.close()
        _log(agent_id, "checker daemon stopping")


if __name__ == "__main__":
    main()
