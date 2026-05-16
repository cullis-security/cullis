"""Aggregate intra-org burst k6 ndjson + monitor logs into a per-plateau table.

Reads:
  - ``intra-org-results.ndjson``  (k6 --out json= raw stream)
  - ``intra-org-summary.json``    (k6 handleSummary dump)
  - ``docker-stats.log``          (5s docker stats sampler)
  - ``audit-rate.log``            (10s audit_log count + db/wal size)

Emits a CSV + markdown table keyed by ramp plateau. Plateau bounds are
inferred from the default DEFAULT_STAGES in ``intra-org-mastio-burst.js``
unless overridden via env.

Run::

    python scripts/stress/_analyze_burst.py > /tmp/c2-a1-plateau.md
"""
from __future__ import annotations

import json
import os
import statistics as stats
import sys
from datetime import datetime, timedelta
from pathlib import Path

HERE = Path(__file__).resolve().parent
NDJSON_PATH = HERE / "intra-org-results.ndjson"
SUMMARY_PATH = HERE / "intra-org-summary.json"
DOCKER_LOG = HERE / "docker-stats.log"
AUDIT_LOG = HERE / "audit-rate.log"

# (label, target_vus, duration_s, kind). ``kind`` is 'ramp' or 'plateau'.
PLATEAUS = [
    ("ramp_0_to_50",      50,   60,  "ramp"),
    ("plateau_50",        50,   300, "plateau"),
    ("ramp_50_to_500",    500,  60,  "ramp"),
    ("plateau_500",       500,  300, "plateau"),
    ("ramp_500_to_2k",    2000, 60,  "ramp"),
    ("plateau_2k",        2000, 300, "plateau"),
    ("ramp_2k_to_5k",     5000, 60,  "ramp"),
    ("plateau_5k",        5000, 600, "plateau"),
    ("ramp_5k_to_0",      0,    60,  "ramp"),
]


def find_run_window():
    """Return (start_ts, end_ts) from the ndjson — used to align with
    the host-clock-based monitor logs.
    """
    start_ts = None
    end_ts = None
    if not NDJSON_PATH.exists():
        sys.exit(f"missing {NDJSON_PATH}")
    with NDJSON_PATH.open() as fh:
        for line in fh:
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get("type") != "Point":
                continue
            t = obj["data"]["time"]
            if start_ts is None:
                start_ts = t
            end_ts = t
    return start_ts, end_ts


_TS_RE = __import__("re").compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
    r"(?:\.(?P<frac>\d+))?"
    r"(?P<tz>Z|[+-]\d{2}:?\d{2})?$"
)


def parse_ts(s: str) -> datetime:
    # k6 emits RFC3339 with up to nanosecond fractional + numeric TZ
    # (e.g. ``+02:00``). datetime.fromisoformat in 3.11 accepts numeric
    # TZ but rejects >6-digit fractional seconds, so we truncate.
    m = _TS_RE.match(s)
    if not m:
        return datetime.fromisoformat(s)  # let it raise upstream
    date = m["date"]
    frac = (m["frac"] or "0")[:6].ljust(6, "0")
    tz = m["tz"] or "+00:00"
    if tz == "Z":
        tz = "+00:00"
    return datetime.fromisoformat(f"{date}.{frac}{tz}")


def assign_plateau(t: datetime, run_start: datetime):
    elapsed = (t - run_start).total_seconds()
    cursor = 0.0
    for label, target, duration, kind in PLATEAUS:
        if cursor <= elapsed < cursor + duration:
            return label, target, kind
        cursor += duration
    return None, None, None


def aggregate_ndjson(run_start: datetime):
    """Returns dict[plateau_label] = {http_req_duration, mint_lat, ingress_lat,
                                       mint_err, ingress_err, reqs}."""
    if not NDJSON_PATH.exists():
        return {}
    buckets: dict[str, dict] = {}
    with NDJSON_PATH.open() as fh:
        for line in fh:
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get("type") != "Point":
                continue
            data = obj["data"]
            metric = obj.get("metric", "")
            t = parse_ts(data["time"])
            label, target, kind = assign_plateau(t, run_start)
            if label is None:
                continue
            bucket = buckets.setdefault(label, {
                "label": label, "target_vus": target, "kind": kind,
                "http_req_duration": [],
                "cullis_mint_latency_ms": [],
                "cullis_ingress_latency_ms": [],
                "mint_err_count": 0, "mint_err_total": 0,
                "ingress_err_count": 0, "ingress_err_total": 0,
                "auth_token_reqs": 0, "ingress_execute_reqs": 0,
                "auth_token_2xx": 0, "ingress_execute_2xx": 0,
                "auth_token_5xx": 0, "ingress_execute_5xx": 0,
            })
            tags = data.get("tags", {}) or {}
            endpoint = tags.get("endpoint", "")
            value = data.get("value", 0)
            if metric == "http_req_duration":
                bucket["http_req_duration"].append(value)
                if endpoint == "auth_token":
                    bucket["auth_token_reqs"] += 1
                elif endpoint == "ingress_execute":
                    bucket["ingress_execute_reqs"] += 1
            elif metric == "cullis_mint_latency_ms":
                bucket["cullis_mint_latency_ms"].append(value)
            elif metric == "cullis_ingress_latency_ms":
                bucket["cullis_ingress_latency_ms"].append(value)
            elif metric == "cullis_mint_error_rate":
                bucket["mint_err_total"] += 1
                if value:
                    bucket["mint_err_count"] += 1
            elif metric == "cullis_ingress_error_rate":
                bucket["ingress_err_total"] += 1
                if value:
                    bucket["ingress_err_count"] += 1
            elif metric == "http_req_failed":
                expected = (tags.get("expected_response") == "true")
                if endpoint == "auth_token":
                    if not value and expected:
                        bucket["auth_token_2xx"] += 1
                    if data.get("value") and value:
                        bucket["auth_token_5xx"] += 1
                elif endpoint == "ingress_execute":
                    if not value and expected:
                        bucket["ingress_execute_2xx"] += 1
    return buckets


def pct(values, q):
    if not values:
        return 0
    values_sorted = sorted(values)
    idx = max(0, min(len(values_sorted) - 1, int(q * len(values_sorted))))
    return values_sorted[idx]


def assign_plateau_for_host_ts(host_hms: str, run_start: datetime):
    # Monitor logs come from the VM where TZ is UTC (``ls -la /etc/
    # localtime`` → ``Etc/UTC``). Normalize the run_start to UTC and
    # diff the HH:MM:SS against that.
    from datetime import timezone
    run_start_utc = run_start.astimezone(timezone.utc)
    today = run_start_utc.date()
    t = datetime.combine(today,
                         datetime.strptime(host_hms, "%H:%M:%S").time(),
                         tzinfo=timezone.utc)
    elapsed = (t - run_start_utc).total_seconds()
    cursor = 0.0
    for label, target, duration, kind in PLATEAUS:
        if cursor <= elapsed < cursor + duration:
            return label
        cursor += duration
    return None


def aggregate_docker_stats(run_start: datetime):
    if not DOCKER_LOG.exists():
        return {}
    out: dict[str, dict] = {}
    with DOCKER_LOG.open() as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                ts, payload = line.split(" ", 1)
            except ValueError:
                continue
            label = assign_plateau_for_host_ts(ts, run_start)
            if not label:
                continue
            bucket = out.setdefault(label, {
                "mcp_cpu": [], "mcp_mem_mib": [],
                "nginx_cpu": [], "nginx_mem_mib": [],
                "mcp_net_tx_mb": [], "mcp_block_w_mb": [],
            })
            # payload format: name|cpu%|mem|net|block;...
            for part in payload.split(";"):
                if not part:
                    continue
                cols = part.split("|")
                if len(cols) < 5:
                    continue
                name, cpu, mem, net, block = cols[:5]
                cpu = float(cpu.rstrip("%"))
                mem_mib = parse_size_mib(mem.split("/")[0].strip())
                if "nginx" in name:
                    bucket["nginx_cpu"].append(cpu)
                    bucket["nginx_mem_mib"].append(mem_mib)
                else:
                    bucket["mcp_cpu"].append(cpu)
                    bucket["mcp_mem_mib"].append(mem_mib)
                    # Parse net I/O total in MB (tx side after slash).
                    try:
                        _, tx = net.split("/")
                        bucket["mcp_net_tx_mb"].append(parse_size_mib(tx.strip()) / 1024 * 1024)
                    except Exception:
                        pass
                    try:
                        _, w = block.split("/")
                        bucket["mcp_block_w_mb"].append(parse_size_mib(w.strip()) / 1024 * 1024)
                    except Exception:
                        pass
    return out


def parse_size_mib(s: str) -> float:
    s = s.strip()
    if not s:
        return 0
    unit = ""
    n = ""
    for c in s:
        if c.isdigit() or c == ".":
            n += c
        else:
            unit += c
    try:
        v = float(n)
    except ValueError:
        return 0
    unit = unit.upper().strip()
    if unit in ("KB", "KIB"):
        return v / 1024
    if unit in ("MB", "MIB"):
        return v
    if unit in ("GB", "GIB"):
        return v * 1024
    if unit in ("B", ""):
        return v / 1024 / 1024
    return v


def aggregate_audit(run_start: datetime):
    if not AUDIT_LOG.exists():
        return {}
    out: dict[str, dict] = {}
    samples = []
    with AUDIT_LOG.open() as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            ts = parts[0]
            try:
                count = int(parts[1])
            except ValueError:
                continue
            db_size = 0
            wal_size = 0
            for tok in parts[2:]:
                if tok.startswith("db="):
                    db_size = int(tok.split("=")[1])
                if tok.startswith("wal="):
                    wal_size = int(tok.split("=")[1])
            samples.append((ts, count, db_size, wal_size))

    for i, (ts, count, db, wal) in enumerate(samples):
        if i == 0:
            continue
        prev_ts, prev_count, prev_db, prev_wal = samples[i - 1]
        # Wall-time delta in seconds (assume same day).
        h1, m1, s1 = map(int, ts.split(":"))
        h0, m0, s0 = map(int, prev_ts.split(":"))
        dt = (h1 * 3600 + m1 * 60 + s1) - (h0 * 3600 + m0 * 60 + s0)
        if dt <= 0:
            continue
        rate = (count - prev_count) / dt
        label = assign_plateau_for_host_ts(ts, run_start)
        if not label:
            continue
        bucket = out.setdefault(label, {
            "audit_rate": [], "db_mb": [], "wal_mb": [],
            "audit_total": 0,
        })
        bucket["audit_rate"].append(rate)
        bucket["db_mb"].append(db / 1024 / 1024)
        bucket["wal_mb"].append(wal / 1024 / 1024)
        bucket["audit_total"] = count
    return out


def main() -> None:
    start_ts_str, end_ts_str = find_run_window()
    if not start_ts_str:
        sys.exit("no ndjson points found")
    run_start = parse_ts(start_ts_str)
    print(f"<!-- run window: {start_ts_str} .. {end_ts_str} (local start "
          f"{run_start.astimezone().strftime('%H:%M:%S')}) -->", file=sys.stderr)

    k6 = aggregate_ndjson(run_start)
    dstats = aggregate_docker_stats(run_start)
    audit = aggregate_audit(run_start)

    # Print markdown plateau table.
    print("| Plateau | VUs | mints | ingress calls | mint p50/p95/p99 ms | "
          "ingress p50/p95/p99 ms | mint err% | ingress err% | "
          "mcp CPU% | mcp MEM MiB | nginx CPU% | audit/s | db MB | wal MB |")
    print("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    for label, target, duration, kind in PLATEAUS:
        if kind != "plateau":
            continue
        kb = k6.get(label, {})
        db = dstats.get(label, {})
        ab = audit.get(label, {})
        mint = kb.get("cullis_mint_latency_ms", [])
        ingress = kb.get("cullis_ingress_latency_ms", [])
        mint_err = (kb.get("mint_err_count", 0) /
                    max(1, kb.get("mint_err_total", 1))) * 100
        ingress_err = (kb.get("ingress_err_count", 0) /
                       max(1, kb.get("ingress_err_total", 1))) * 100
        mints = kb.get("auth_token_reqs", 0)
        ingress_calls = kb.get("ingress_execute_reqs", 0)
        mcp_cpu_avg = stats.mean(db["mcp_cpu"]) if db.get("mcp_cpu") else 0
        mcp_mem_avg = stats.mean(db["mcp_mem_mib"]) if db.get("mcp_mem_mib") else 0
        nginx_cpu_avg = stats.mean(db["nginx_cpu"]) if db.get("nginx_cpu") else 0
        audit_rate = stats.mean(ab["audit_rate"]) if ab.get("audit_rate") else 0
        db_mb = max(ab["db_mb"]) if ab.get("db_mb") else 0
        wal_mb = max(ab["wal_mb"]) if ab.get("wal_mb") else 0
        print(
            f"| {label} | {target} | {mints} | {ingress_calls} | "
            f"{pct(mint, 0.50):.1f}/{pct(mint, 0.95):.1f}/"
            f"{pct(mint, 0.99):.1f} | "
            f"{pct(ingress, 0.50):.1f}/{pct(ingress, 0.95):.1f}/"
            f"{pct(ingress, 0.99):.1f} | "
            f"{mint_err:.2f} | {ingress_err:.2f} | "
            f"{mcp_cpu_avg:.0f} | {mcp_mem_avg:.0f} | {nginx_cpu_avg:.1f} | "
            f"{audit_rate:.0f} | {db_mb:.0f} | {wal_mb:.0f} |"
        )

    # Throughput per plateau (RPS sustained by Mastio).
    print()
    print("## Throughput per plateau")
    print()
    print("| Plateau | duration s | total ingress | RPS sustained |")
    print("|---|---|---|---|")
    for label, target, duration, kind in PLATEAUS:
        if kind != "plateau":
            continue
        kb = k6.get(label, {})
        ic = kb.get("ingress_execute_reqs", 0)
        rps = ic / max(1, duration)
        print(f"| {label} | {duration} | {ic} | {rps:.0f} |")


if __name__ == "__main__":
    main()
