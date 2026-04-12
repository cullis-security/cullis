"""
Recompute each audit entry's sha256 and verify the chain link-by-link.
Mounted read-only from the host into a python:3.11-slim container by
smoke.sh's A7 assertion.
"""
import hashlib
import json
import sys

prev = None
count = 0
with open("/in/audit.ndjson") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        e = json.loads(line)
        canonical = "|".join([
            str(e["id"]),
            e["timestamp"] or "",
            e["event_type"],
            e.get("agent_id") or "",
            e.get("session_id") or "",
            e.get("org_id") or "",
            e["result"],
            e.get("details") or "",
            prev or "genesis",
        ])
        computed = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        if computed != e["entry_hash"]:
            print(f"MISMATCH id={e['id']} event={e['event_type']}")
            print(f"  expected: {e['entry_hash']}")
            print(f"  computed: {computed}")
            sys.exit(2)
        if e.get("previous_hash") != prev:
            print(f"CHAIN BREAK id={e['id']}: previous_hash={e.get('previous_hash')} expected={prev}")
            sys.exit(3)
        prev = e["entry_hash"]
        count += 1

print(f"OK {count}")
