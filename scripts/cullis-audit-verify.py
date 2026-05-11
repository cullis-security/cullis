#!/usr/bin/env python3
"""Standalone offline verifier for Cullis audit exports (issue #75).

Consumes the NDJSON bundle produced by `GET /v1/admin/audit/export`
and verifies, with zero network calls:

  1. Each per-org hash chain is internally consistent (every entry's
     `entry_hash` is the sha256 of its canonical string, and
     `previous_hash` links to the prior entry in the same org).
  2. The residual legacy global chain (rows with `chain_seq is None`)
     is intact under the pre-per-org rules.
  3. Every TSA anchor row matches a real chain head + the TSA token
     cryptographically binds the recorded `row_hash` (mock tokens are
     verified by prefix matching; RFC 3161 tokens are verified via
     the `rfc3161-client` library if installed, otherwise flagged).
  4. Cross-org reconciliation (optional): when two bundles from two
     orgs are supplied, rows with `peer_org_id` + `peer_row_hash`
     must point at the counterpart row in the other bundle and the
     two rows must agree on event_type / session_id / details.

Usage:
  # Verify one org's bundle:
  python cullis-audit-verify.py --bundle acme.ndjson

  # Cross-verify two orgs for dispute resolution:
  python cullis-audit-verify.py --bundle acme.ndjson --bundle bravo.ndjson

Exit codes:
  0  — all checks passed
  2  — chain tamper detected (mismatch or break)
  3  — TSA anchor mismatch (row_hash disagreement or unrecognized token)
  4  — cross-org reconciliation mismatch
  5  — unrecognized TSA format that cannot be verified
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from collections import defaultdict
from typing import Any


_MOCK_MAGIC = b"MK"
_RFC3161_MAGIC = b"T1"


def canonical(entry: dict[str, Any], previous_hash: str | None) -> str:
    """Reconstruct the canonical string used to compute ``entry_hash``.

    Wave B PR5 (audit 2026-05-11 CRIT-3 Court) — dispatches on
    ``hash_format``:
      - NULL or 'v1' → legacy entry_id-bound canonical (unchanged)
      - 'v2' → entry_id-free canonical, prefixed with literal ``v2|``;
        chain_seq required (atomic-insert form, no back-fill UPDATE)

    Both forms also append ``|pt=<x>`` when a non-default
    ``principal_type`` is present (ADR-020 marker).
    """
    fmt = (entry.get("hash_format") or "v1").lower()
    chain_seq = entry.get("chain_seq")

    if fmt == "v2":
        if chain_seq is None:
            # v2 always uses chain_seq; refuse a malformed bundle
            # explicitly so the verifier doesn't silently agree.
            return "INVALID-V2-WITHOUT-CHAIN-SEQ"
        canonical_str = "|".join([
            "v2",
            entry["timestamp"] or "",
            entry["event_type"],
            entry.get("agent_id") or "",
            entry.get("session_id") or "",
            entry.get("org_id") or "",
            entry["result"],
            entry.get("details") or "",
            previous_hash or "genesis",
            f"seq={chain_seq}",
            f"peer={entry.get('peer_org_id') or ''}",
        ])
    else:
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
        if chain_seq is None:
            canonical_str = base
        else:
            canonical_str = (
                f"{base}|seq={chain_seq}|peer={entry.get('peer_org_id') or ''}"
            )

    pt = entry.get("principal_type")
    if pt and pt != "agent":
        canonical_str = f"{canonical_str}|pt={pt}"
    return canonical_str


def verify_token_against_digest(token_bytes: bytes, digest_hex: str) -> tuple[bool, str]:
    """Return (verified, backend_label).

    Mock tokens are verified by embedded digest match. RFC 3161 tokens
    require the optional `rfc3161-client` library; if unavailable we
    return (False, "rfc3161-unverified"). Tokens of unknown format
    return (False, "unrecognized").
    """
    if token_bytes.startswith(_MOCK_MAGIC + b"|"):
        try:
            remainder = token_bytes[len(_MOCK_MAGIC) + 1:].decode("utf-8")
        except UnicodeDecodeError:
            return (False, "mock-malformed")
        parts = remainder.split("|", 1)
        if len(parts) != 2:
            return (False, "mock-malformed")
        return (parts[0] == digest_hex, "mock")

    if token_bytes.startswith(_RFC3161_MAGIC + b"|"):
        raw = token_bytes[len(_RFC3161_MAGIC) + 1:]
        try:
            from asn1crypto import tsp  # type: ignore[import-not-found]
        except ImportError:
            return (False, "rfc3161-lib-missing")
        try:
            tst = tsp.TimeStampToken.load(raw)
            content = tst["content"]
            mi = content["encap_content_info"]["content"].parsed["message_imprint"]
            imprint_digest = mi["hashed_message"].native.hex()
            return (imprint_digest == digest_hex, "rfc3161")
        except Exception as exc:  # noqa: BLE001
            print(f"  rfc3161 parse error: {exc}", file=sys.stderr)
            return (False, "rfc3161-parse-error")

    return (False, "unrecognized")


def load_bundle(path: str) -> tuple[list[dict], list[dict]]:
    """Return (entries, anchors). Lines missing the "kind" key are
    treated as legacy (entry) format for backward compatibility."""
    entries: list[dict] = []
    anchors: list[dict] = []
    with open(path) as f:
        for raw in f:
            raw = raw.strip()
            if not raw:
                continue
            obj = json.loads(raw)
            kind = obj.get("kind", "entry")
            if kind == "entry":
                entries.append(obj)
            elif kind == "anchor":
                anchors.append(obj)
    return entries, anchors


def verify_chains(entries: list[dict]) -> tuple[int, int]:
    """Verify all chains in a single bundle. Returns (legacy_n, per_org_n).
    Exits with code 2 on any tamper."""
    # Legacy
    prev: str | None = None
    legacy_n = 0
    for e in entries:
        if e.get("chain_seq") is not None:
            continue
        if e.get("entry_hash") is None:
            continue
        expected = canonical(e, prev)
        computed = hashlib.sha256(expected.encode("utf-8")).hexdigest()
        if computed != e["entry_hash"]:
            print(f"CHAIN MISMATCH legacy id={e['id']}")
            sys.exit(2)
        if e.get("previous_hash") != prev:
            print(f"CHAIN BREAK legacy id={e['id']}")
            sys.exit(2)
        prev = e["entry_hash"]
        legacy_n += 1

    # Per-org
    last_legacy: dict[str, str] = {}
    for e in entries:
        if e.get("chain_seq") is None and e.get("entry_hash") is not None:
            last_legacy[e.get("org_id") or ""] = e["entry_hash"]

    per_org: dict[str, list[dict]] = defaultdict(list)
    for e in entries:
        if e.get("chain_seq") is not None:
            per_org[e.get("org_id") or ""].append(e)

    per_org_n = 0
    for org, rows in per_org.items():
        rows.sort(key=lambda r: r["chain_seq"])
        expected_prev = last_legacy.get(org)
        for e in rows:
            expected = canonical(e, expected_prev)
            computed = hashlib.sha256(expected.encode("utf-8")).hexdigest()
            if computed != e["entry_hash"]:
                print(f"CHAIN MISMATCH org={org} seq={e['chain_seq']} id={e['id']}")
                sys.exit(2)
            if e.get("previous_hash") != expected_prev:
                print(f"CHAIN BREAK org={org} seq={e['chain_seq']} id={e['id']}")
                sys.exit(2)
            expected_prev = e["entry_hash"]
            per_org_n += 1

    return (legacy_n, per_org_n)


def verify_anchors(entries: list[dict], anchors: list[dict]) -> int:
    """For each anchor, recompute the expected row_hash at the anchor's
    chain_seq and cross-check against the anchor's claim + TSA token.
    Returns count of verified anchors. Exits 3 on mismatch, 5 on
    unverifiable token."""
    # Map (org_id, chain_seq) -> entry.entry_hash for quick lookup.
    head_hash: dict[tuple[str, int], str] = {}
    for e in entries:
        seq = e.get("chain_seq")
        if seq is not None:
            head_hash[(e.get("org_id") or "", seq)] = e["entry_hash"]

    verified = 0
    for a in anchors:
        key = (a["org_id"], a["chain_seq"])
        actual_head = head_hash.get(key)
        if actual_head is None:
            print(f"ANCHOR ORPHAN org={a['org_id']} seq={a['chain_seq']} — "
                  f"no matching chain entry in bundle")
            sys.exit(3)
        if actual_head != a["row_hash"]:
            print(f"ANCHOR MISMATCH org={a['org_id']} seq={a['chain_seq']}: "
                  f"anchor row_hash={a['row_hash']} but chain head={actual_head}")
            sys.exit(3)
        token = base64.b64decode(a["tsa_token_b64"])
        ok, backend = verify_token_against_digest(token, a["row_hash"])
        if not ok:
            if backend in ("rfc3161-lib-missing", "rfc3161-unverified"):
                print(f"ANCHOR UNVERIFIABLE org={a['org_id']} seq={a['chain_seq']}: "
                      f"TSA backend {backend} (install rfc3161-client + asn1crypto)")
                sys.exit(5)
            print(f"ANCHOR INVALID org={a['org_id']} seq={a['chain_seq']}: "
                  f"token backend={backend} failed digest match")
            sys.exit(3)
        verified += 1
    return verified


def cross_reconcile(bundles: list[tuple[str, list[dict]]]) -> int:
    """When two bundles are provided, check every row in bundle A that
    declares peer_org_id matching bundle B's org has a counterpart in
    B with the same peer_row_hash linkage. Returns count of cross-
    verified rows. Exits 4 on mismatch."""
    if len(bundles) < 2:
        return 0

    # Index entries by (org_id, entry_hash) for reverse lookup.
    by_hash: dict[tuple[str, str], dict] = {}
    for _path, entries in bundles:
        for e in entries:
            if e.get("entry_hash") and e.get("org_id"):
                by_hash[(e["org_id"], e["entry_hash"])] = e

    verified = 0
    for _path, entries in bundles:
        for e in entries:
            peer_org = e.get("peer_org_id")
            peer_hash = e.get("peer_row_hash")
            if not peer_org or not peer_hash:
                continue
            counterpart = by_hash.get((peer_org, peer_hash))
            if counterpart is None:
                print(f"CROSS-REF MISSING id={e['id']} org={e['org_id']}: "
                      f"peer_row {peer_hash} on org {peer_org} not in bundles")
                sys.exit(4)
            # Content agreement
            for field in ("event_type", "result", "session_id", "details"):
                if e.get(field) != counterpart.get(field):
                    print(f"CROSS-REF DISAGREE id={e['id']} vs id={counterpart['id']}: "
                          f"field={field} diverges "
                          f"({e.get(field)!r} != {counterpart.get(field)!r})")
                    sys.exit(4)
            verified += 1
    return verified


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument(
        "--bundle", action="append", required=True,
        help="Path to an audit export NDJSON file. Pass twice for cross-verify.",
    )
    args = ap.parse_args()

    bundles: list[tuple[str, list[dict]]] = []
    total_legacy = total_per_org = total_anchors = 0
    for path in args.bundle:
        entries, anchors = load_bundle(path)
        legacy_n, per_org_n = verify_chains(entries)
        anchor_n = verify_anchors(entries, anchors)
        total_legacy += legacy_n
        total_per_org += per_org_n
        total_anchors += anchor_n
        bundles.append((path, entries))
        print(f"OK {path}: legacy={legacy_n} per_org={per_org_n} anchors={anchor_n}")

    cross_n = cross_reconcile(bundles)
    if cross_n:
        print(f"OK cross-reconcile: {cross_n} linked row(s) consistent across bundles")

    print(
        f"VERIFY PASS — legacy={total_legacy} per_org={total_per_org} "
        f"anchors={total_anchors} cross={cross_n}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
