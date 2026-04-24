"""Spammer — one agent, periodic burst of one-shots to every other peer
in parallel. Produces the spike pattern that exercises the Mastio
concurrency path (the DPoP serialization the smoke already surfaced).

Usage:
    python spammer.py <agent_id> [--burst-interval 30] [--parallel 10]

Log: logs/<run-ts>/spammer-<agent>.jsonl — one record per send, plus
per-burst summary records with event=burst_end.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import sys
import time

from _common import load_client, load_manifest, logger_for, Shutdown


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("agent_id", help="<org>::<name>")
    ap.add_argument("--burst-interval", type=float, default=30.0,
                    help="seconds between bursts")
    ap.add_argument("--parallel", type=int, default=10,
                    help="concurrent send threads per burst")
    args = ap.parse_args()

    log = logger_for("spammer", args.agent_id)
    stop = Shutdown()

    try:
        client = load_client(args.agent_id)
    except Exception as exc:
        log.write(event="startup_fail", error=f"{type(exc).__name__}: {exc}")
        return 1

    manifest = load_manifest()
    peers = [e["agent_id"] for e in manifest if e["agent_id"] != args.agent_id]
    log.write(event="start", agent=args.agent_id, peers=len(peers),
              burst_interval=args.burst_interval, parallel=args.parallel)

    def _send(target: str, burst_seq: int) -> tuple[str, int, str]:
        t0 = time.monotonic()
        try:
            resp = client.send_oneshot(
                target,
                {"burst": burst_seq, "from": args.agent_id, "ts": time.time()},
            )
            ms = int((time.monotonic() - t0) * 1000)
            return (target, ms, f"ok:{resp.get('status', '?')}")
        except Exception as exc:
            ms = int((time.monotonic() - t0) * 1000)
            return (target, ms, f"fail:{type(exc).__name__}:{exc}")

    burst_seq = 0
    total_ok = 0
    total_fail = 0
    while not stop.stopped:
        burst_seq += 1
        t0 = time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.parallel) as pool:
            results = list(pool.map(lambda p: _send(p, burst_seq), peers))

        ok = sum(1 for _, _, s in results if s.startswith("ok:"))
        fail = len(results) - ok
        total_ok += ok
        total_fail += fail
        latencies = [ms for _, ms, _ in results]
        p50 = sorted(latencies)[len(latencies) // 2] if latencies else 0
        p99 = sorted(latencies)[max(0, int(len(latencies) * 0.99) - 1)] if latencies else 0

        for target, ms, status in results:
            event = "send_ok" if status.startswith("ok:") else "send_fail"
            log.write(event=event, burst=burst_seq, target=target,
                      latency_ms=ms, detail=status)

        log.write(
            event="burst_end", burst=burst_seq,
            duration_ms=int((time.monotonic() - t0) * 1000),
            ok=ok, fail=fail, p50_ms=p50, p99_ms=p99,
        )

        stop.wait(args.burst_interval)

    log.write(event="stop", bursts=burst_seq, total_ok=total_ok, total_fail=total_fail)
    log.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
