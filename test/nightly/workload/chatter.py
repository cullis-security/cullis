"""Chatter — one agent sends random one-shots to random peers at a
jittered interval. Simulates the baseline low-rate noise that runs
continuously through the night.

Usage:
    python chatter.py <agent_id> [--interval 3] [--jitter 2]

Log: logs/<run-ts>/chatter-<agent>.jsonl — one record per send attempt.
"""
from __future__ import annotations

import argparse
import random
import sys
import time

from _common import load_client, load_manifest, logger_for, Shutdown


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("agent_id", help="<org>::<name>")
    ap.add_argument("--interval", type=float, default=3.0,
                    help="base seconds between sends")
    ap.add_argument("--jitter", type=float, default=2.0,
                    help="uniform +/- jitter added to interval")
    args = ap.parse_args()

    log = logger_for("chatter", args.agent_id)
    stop = Shutdown()

    try:
        client = load_client(args.agent_id)
    except Exception as exc:
        log.write(event="startup_fail", error=f"{type(exc).__name__}: {exc}")
        return 1

    manifest = load_manifest()
    peers = [e["agent_id"] for e in manifest if e["agent_id"] != args.agent_id]
    log.write(event="start", agent=args.agent_id, peers=len(peers),
              interval=args.interval, jitter=args.jitter)

    sent = 0
    fail = 0
    while not stop.stopped:
        target = random.choice(peers)
        payload = {"seq": sent, "from": args.agent_id, "ts": time.time()}
        t0 = time.monotonic()
        try:
            resp = client.send_oneshot(target, payload)
            latency_ms = int((time.monotonic() - t0) * 1000)
            log.write(event="send_ok", target=target, latency_ms=latency_ms,
                      msg_id=resp.get("msg_id"), status=resp.get("status"))
            sent += 1
        except Exception as exc:
            latency_ms = int((time.monotonic() - t0) * 1000)
            log.write(event="send_fail", target=target, latency_ms=latency_ms,
                      error=f"{type(exc).__name__}: {exc}")
            fail += 1

        delay = max(0.1, args.interval + random.uniform(-args.jitter, args.jitter))
        stop.wait(delay)

    log.write(event="stop", sent=sent, fail=fail)
    log.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
