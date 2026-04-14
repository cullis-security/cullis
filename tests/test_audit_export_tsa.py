"""Export bundle + CLI verify round-trip (issue #75 Slice 2)."""
from __future__ import annotations

import base64
import json
import subprocess
import sys
from pathlib import Path

import pytest
from sqlalchemy import delete

from app.audit.tsa_client import MockTsaClient
from app.audit.tsa_worker import anchor_all_orgs_once
from app.config import get_settings
from app.db.audit import AuditLog, AuditTsaAnchor, log_event, log_event_cross_org
from tests.conftest import TestSessionLocal


pytestmark = pytest.mark.asyncio

_SCRIPT = Path(__file__).parent.parent / "scripts" / "cullis-audit-verify.py"


def _admin_headers():
    return {"X-Admin-Secret": get_settings().admin_secret}


async def _reset():
    async with TestSessionLocal() as s:
        await s.execute(delete(AuditTsaAnchor))
        await s.execute(delete(AuditLog))
        await s.commit()


async def test_export_bundle_contains_entries_and_anchors(client):
    await _reset()
    # Create some per-org audit rows + an anchor
    async with TestSessionLocal() as db:
        await log_event(db, "session.open", "ok", org_id="exp-a", agent_id="exp-a::a1")
        await log_event(db, "message.forwarded", "ok", org_id="exp-a", agent_id="exp-a::a1")
    await anchor_all_orgs_once(MockTsaClient(), session_factory=TestSessionLocal)

    resp = await client.get(
        "/v1/admin/audit/export?org_id=exp-a", headers=_admin_headers()
    )
    assert resp.status_code == 200
    lines = [json.loads(ln) for ln in resp.text.strip().split("\n") if ln]
    entry_lines = [ln for ln in lines if ln.get("kind") == "entry"]
    anchor_lines = [ln for ln in lines if ln.get("kind") == "anchor"]
    assert len(entry_lines) >= 2
    assert len(anchor_lines) == 1
    anchor = anchor_lines[0]
    assert anchor["org_id"] == "exp-a"
    assert "tsa_token_b64" in anchor
    assert base64.b64decode(anchor["tsa_token_b64"]).startswith(b"MK")
    await _reset()


async def test_cli_verify_passes_on_clean_bundle(client, tmp_path):
    await _reset()
    async with TestSessionLocal() as db:
        await log_event(db, "e1", "ok", org_id="cli-a")
        await log_event(db, "e2", "ok", org_id="cli-a")
    await anchor_all_orgs_once(MockTsaClient(), session_factory=TestSessionLocal)

    resp = await client.get(
        "/v1/admin/audit/export?org_id=cli-a", headers=_admin_headers()
    )
    bundle = tmp_path / "a.ndjson"
    bundle.write_text(resp.text)

    r = subprocess.run(
        [sys.executable, str(_SCRIPT), "--bundle", str(bundle)],
        capture_output=True, text=True,
    )
    assert r.returncode == 0, r.stdout + r.stderr
    assert "VERIFY PASS" in r.stdout
    await _reset()


async def test_cli_verify_detects_tamper(client, tmp_path):
    await _reset()
    async with TestSessionLocal() as db:
        await log_event(db, "e", "ok", org_id="cli-t", details={"original": True})
        await log_event(db, "e", "ok", org_id="cli-t")

    resp = await client.get(
        "/v1/admin/audit/export?org_id=cli-t", headers=_admin_headers()
    )
    lines = [json.loads(ln) for ln in resp.text.strip().split("\n") if ln]
    # Tamper: rewrite the details of the first entry in-place
    for ln in lines:
        if ln.get("kind") == "entry" and ln.get("details"):
            ln["details"] = '{"tampered": true}'
            break
    bundle = tmp_path / "tampered.ndjson"
    bundle.write_text("\n".join(json.dumps(ln) for ln in lines) + "\n")

    r = subprocess.run(
        [sys.executable, str(_SCRIPT), "--bundle", str(bundle)],
        capture_output=True, text=True,
    )
    assert r.returncode == 2, r.stdout + r.stderr
    assert "CHAIN MISMATCH" in r.stdout
    await _reset()


async def test_cli_cross_verify_two_orgs_succeeds(client, tmp_path):
    await _reset()
    # A cross-org event lands on both org chains with matching peer refs
    async with TestSessionLocal() as db:
        await log_event_cross_org(
            db, "session.opened", "ok",
            org_a="cx-a", org_b="cx-b",
            session_id="sess-xv",
            details={"initiator": "cx-a::alice", "target": "cx-b::bob"},
        )
    await anchor_all_orgs_once(MockTsaClient(), session_factory=TestSessionLocal)

    resp_a = await client.get(
        "/v1/admin/audit/export?org_id=cx-a", headers=_admin_headers()
    )
    resp_b = await client.get(
        "/v1/admin/audit/export?org_id=cx-b", headers=_admin_headers()
    )
    file_a = tmp_path / "cx-a.ndjson"
    file_b = tmp_path / "cx-b.ndjson"
    file_a.write_text(resp_a.text)
    file_b.write_text(resp_b.text)

    r = subprocess.run(
        [
            sys.executable, str(_SCRIPT),
            "--bundle", str(file_a), "--bundle", str(file_b),
        ],
        capture_output=True, text=True,
    )
    assert r.returncode == 0, r.stdout + r.stderr
    assert "cross-reconcile" in r.stdout
    await _reset()


async def test_cli_cross_verify_detects_content_divergence(client, tmp_path):
    """No anchors in this scenario — we test that cross-ref detection
    catches tampered B-side content when the chain itself still looks
    valid (attacker recomputed entry_hash but peer_row_hash on A still
    references the original B hash)."""
    await _reset()
    async with TestSessionLocal() as db:
        await log_event_cross_org(
            db, "session.opened", "ok",
            org_a="cd-a", org_b="cd-b",
            session_id="sess-div",
            details={"x": 1},
        )

    resp_a = await client.get(
        "/v1/admin/audit/export?org_id=cd-a", headers=_admin_headers()
    )
    resp_b = await client.get(
        "/v1/admin/audit/export?org_id=cd-b", headers=_admin_headers()
    )

    # Tamper B's details — CLI cross-reconcile must catch the divergence
    lines_b = [json.loads(ln) for ln in resp_b.text.strip().split("\n") if ln]
    for ln in lines_b:
        if ln.get("kind") == "entry":
            ln["details"] = '{"x": 999}'
            # Recompute this line's entry_hash so chain verification
            # passes (so the failure bubbles up at cross-ref stage
            # rather than chain stage). We re-canonicalize in the same
            # way the broker does.
            import hashlib
            base = "|".join([
                str(ln["id"]),
                ln["timestamp"] or "",
                ln["event_type"],
                ln.get("agent_id") or "",
                ln.get("session_id") or "",
                ln.get("org_id") or "",
                ln["result"],
                ln.get("details") or "",
                ln.get("previous_hash") or "genesis",
            ])
            if ln.get("chain_seq") is not None:
                canon = f"{base}|seq={ln['chain_seq']}|peer={ln.get('peer_org_id') or ''}"
            else:
                canon = base
            ln["entry_hash"] = hashlib.sha256(canon.encode()).hexdigest()
            break

    file_a = tmp_path / "cd-a.ndjson"
    file_b = tmp_path / "cd-b.ndjson"
    file_a.write_text(resp_a.text)
    file_b.write_text("\n".join(json.dumps(ln) for ln in lines_b) + "\n")

    r = subprocess.run(
        [
            sys.executable, str(_SCRIPT),
            "--bundle", str(file_a), "--bundle", str(file_b),
        ],
        capture_output=True, text=True,
    )
    # Because we recomputed entry_hash for the tampered row, it is now
    # "internally consistent" but its peer_row_hash reference from A
    # points at the ORIGINAL hash (before tamper), which no longer
    # matches any entry in B. That should trip CROSS-REF MISSING.
    assert r.returncode == 4, r.stdout + r.stderr
    assert "CROSS-REF" in r.stdout
    await _reset()
