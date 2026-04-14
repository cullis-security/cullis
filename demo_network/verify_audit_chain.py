"""
Recompute each audit entry's sha256 and verify the chain link-by-link.
Mounted read-only from the host into a python:3.11-slim container by
smoke.sh's A7 assertion.

Two chain regimes coexist:
  - Legacy rows (chain_seq is None): single global chain, linked by id
    order. Canonical hash format predates per-org chains.
  - Per-org rows (chain_seq is not None): one chain per org_id, linked
    by chain_seq. Canonical format binds chain_seq + peer_org_id so
    those columns can't be rewritten silently.
"""
import hashlib
import json
import sys
from collections import defaultdict


def canonical(entry: dict, previous_hash: str | None) -> str:
    base = "|".join([
        str(entry["id"]),
        entry["timestamp"] or "",
        entry["event_type"],
        entry.get("agent_id") or "",
        entry.get("session_id") or "",
        entry.get("org_id") or "",
        entry["result"],
        entry.get("details") or "",
        previous_hash or "genesis",
    ])
    chain_seq = entry.get("chain_seq")
    if chain_seq is None:
        return base
    return f"{base}|seq={chain_seq}|peer={entry.get('peer_org_id') or ''}"


entries = []
with open("/in/audit.ndjson") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        entries.append(json.loads(line))

# ── Legacy global chain (chain_seq is None) ───────────────────────
prev = None
legacy_count = 0
for e in entries:
    if e.get("chain_seq") is not None:
        continue
    if e.get("entry_hash") is None:
        continue  # pre-hash-chain row
    expected = canonical(e, prev)
    computed = hashlib.sha256(expected.encode("utf-8")).hexdigest()
    if computed != e["entry_hash"]:
        print(f"MISMATCH legacy id={e['id']} event={e['event_type']}")
        print(f"  expected: {e['entry_hash']}")
        print(f"  computed: {computed}")
        sys.exit(2)
    if e.get("previous_hash") != prev:
        print(f"CHAIN BREAK legacy id={e['id']}: "
              f"previous_hash={e.get('previous_hash')} expected={prev}")
        sys.exit(3)
    prev = e["entry_hash"]
    legacy_count += 1

# ── Per-org chains (chain_seq is not None) ────────────────────────
# For each org's genesis row (chain_seq=1), previous_hash should point
# to that org's last legacy entry_hash (if any) or None.
last_legacy_per_org: dict[str, str] = {}
for e in entries:
    if e.get("chain_seq") is None and e.get("entry_hash") is not None:
        last_legacy_per_org[e.get("org_id") or ""] = e["entry_hash"]

per_org: dict[str, list] = defaultdict(list)
for e in entries:
    if e.get("chain_seq") is not None:
        per_org[e.get("org_id") or ""].append(e)

per_org_count = 0
for org, rows in per_org.items():
    rows.sort(key=lambda r: r["chain_seq"])
    expected_prev = last_legacy_per_org.get(org)
    for e in rows:
        expected = canonical(e, expected_prev)
        computed = hashlib.sha256(expected.encode("utf-8")).hexdigest()
        if computed != e["entry_hash"]:
            print(f"MISMATCH per-org id={e['id']} org={org} seq={e['chain_seq']}")
            print(f"  expected: {e['entry_hash']}")
            print(f"  computed: {computed}")
            sys.exit(2)
        if e.get("previous_hash") != expected_prev:
            print(f"CHAIN BREAK per-org id={e['id']} org={org} seq={e['chain_seq']}: "
                  f"previous_hash={e.get('previous_hash')} expected={expected_prev}")
            sys.exit(3)
        expected_prev = e["entry_hash"]
        per_org_count += 1

print(f"OK {legacy_count + per_org_count}")
