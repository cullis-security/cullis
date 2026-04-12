"""
Smoke-test sender. Two phases in one container:

  Phase 1 — happy path: open a session with demo-org-b::checker, send the
            nonce, continue.

  Phase 2 — DENY assertion: log in as demo-org-a::banned-sender and attempt
            the same session. proxy-b's PDP must refuse with 403. If the
            session opens successfully, the smoke fails (exit 1) — that
            means policy enforcement is silently broken.

Both phases run serially in the same container; exits 0 only when phase 1
delivered AND phase 2 was refused.
"""
import os
import sys
import time

import httpx as _h

from cullis_sdk import CullisClient

BROKER_URL  = os.environ["BROKER_URL"]
AGENT_ID    = os.environ["AGENT_ID"]              # demo-org-a::sender
ORG_ID      = os.environ["ORG_ID"]                # demo-org-a
PEER_AGENT  = os.environ["PEER_AGENT_ID"]         # demo-org-b::checker
PEER_ORG    = os.environ["PEER_ORG_ID"]           # demo-org-b
CERT_PATH   = os.environ["AGENT_CERT_PATH"]
KEY_PATH    = os.environ["AGENT_KEY_PATH"]
NONCE       = os.environ["SMOKE_NONCE"]
CA_BUNDLE   = os.environ.get("CA_BUNDLE", "/certs/ca.crt")

# Phase 2 — banned agent, must be rejected by the PDP.
BANNED_AGENT_ID  = os.environ.get("BANNED_AGENT_ID", "")
BANNED_CERT_PATH = os.environ.get("BANNED_AGENT_CERT_PATH", "")
BANNED_KEY_PATH  = os.environ.get("BANNED_AGENT_KEY_PATH", "")

# Phase 3 — agent whose cert has been admin-revoked. Login must 401.
REVOKED_AGENT_ID  = os.environ.get("REVOKED_AGENT_ID", "")
REVOKED_CERT_PATH = os.environ.get("REVOKED_AGENT_CERT_PATH", "")
REVOKED_KEY_PATH  = os.environ.get("REVOKED_AGENT_KEY_PATH", "")

# Phase 4 — agent with valid cert but revoked binding. Login succeeds, but
# session open must fail 403.
UNBOUND_AGENT_ID  = os.environ.get("UNBOUND_AGENT_ID", "")
UNBOUND_CERT_PATH = os.environ.get("UNBOUND_AGENT_CERT_PATH", "")
UNBOUND_KEY_PATH  = os.environ.get("UNBOUND_AGENT_KEY_PATH", "")


def _phase1() -> None:
    print(f"sender: [phase1] logging in as {AGENT_ID}")
    client = CullisClient(BROKER_URL, verify_tls=CA_BUNDLE)
    try:
        client.login(AGENT_ID, ORG_ID, CERT_PATH, KEY_PATH)

        print(f"sender: [phase1] opening session with {PEER_AGENT}")
        try:
            session_id = client.open_session(
                target_agent_id=PEER_AGENT,
                target_org_id=PEER_ORG,
                capabilities=["message.exchange"],
            )
        except _h.HTTPStatusError as exc:
            print(f"sender: [phase1] open_session failed body: {exc.response.text[:500]}")
            raise

        # Session is pending until checker accepts — wait up to 30s.
        for _ in range(30):
            sessions = client.list_sessions()
            s = next((x for x in sessions if x.session_id == session_id), None)
            if s and getattr(s, "status", "") == "active":
                break
            time.sleep(1)
        else:
            raise SystemExit(f"sender: [phase1] session {session_id} not accepted within 30s")

        payload = {
            "nonce":   NONCE,
            "sent_at": int(time.time()),
            "from":    AGENT_ID,
        }
        print(f"sender: [phase1] sending payload {payload!r}")
        client.send(
            session_id=session_id,
            sender_agent_id=AGENT_ID,
            payload=payload,
            recipient_agent_id=PEER_AGENT,
        )
        print(f"sender: [phase1] OK — delivered to {PEER_AGENT} (session {session_id})")
    finally:
        client.close()


def _phase2() -> None:
    """Assert that the PDP refuses the banned agent.

    The banned agent is still fully credentialed — binding approved, cert
    valid — so login works. The refusal must come from the /pdp/policy
    webhook call, not from a broken binding. That exercises the full
    policy webhook path end-to-end.
    """
    if not BANNED_AGENT_ID or not BANNED_CERT_PATH or not BANNED_KEY_PATH:
        print("sender: [phase2] skipped (BANNED_AGENT_* not set)")
        return

    print(f"sender: [phase2] logging in as {BANNED_AGENT_ID}")
    client = CullisClient(BROKER_URL, verify_tls=CA_BUNDLE)
    try:
        client.login(BANNED_AGENT_ID, ORG_ID, BANNED_CERT_PATH, BANNED_KEY_PATH)

        print(f"sender: [phase2] attempting session with {PEER_AGENT} — expect DENY")
        try:
            client.open_session(
                target_agent_id=PEER_AGENT,
                target_org_id=PEER_ORG,
                capabilities=["message.exchange"],
            )
        except _h.HTTPStatusError as exc:
            if exc.response.status_code == 403:
                print(f"sender: [phase2] OK — PDP refused session (body: {exc.response.text[:200]})")
                return
            raise SystemExit(
                f"sender: [phase2] expected 403 from PDP, got {exc.response.status_code}: "
                f"{exc.response.text[:300]}"
            )

        raise SystemExit(
            "sender: [phase2] session OPENED for banned agent — policy "
            "enforcement is broken. Smoke fails."
        )
    finally:
        client.close()


def _phase3() -> None:
    """Assert that a revoked cert can no longer log in (A5)."""
    if not REVOKED_AGENT_ID or not REVOKED_CERT_PATH or not REVOKED_KEY_PATH:
        print("sender: [phase3] skipped (REVOKED_AGENT_* not set)")
        return

    print(f"sender: [phase3] logging in as {REVOKED_AGENT_ID} — expect 401")
    client = CullisClient(BROKER_URL, verify_tls=CA_BUNDLE)
    try:
        try:
            client.login(REVOKED_AGENT_ID, ORG_ID, REVOKED_CERT_PATH, REVOKED_KEY_PATH)
        except PermissionError as exc:
            # SDK wraps httpx HTTPStatusError into PermissionError with HTTP code in msg.
            if "401" in str(exc) or "revoked" in str(exc).lower():
                print(f"sender: [phase3] OK — revoked cert refused: {str(exc)[:200]}")
                return
            raise SystemExit(f"sender: [phase3] expected 401 revoked-cert refusal, got: {exc}")
        except _h.HTTPStatusError as exc:
            if exc.response.status_code == 401:
                print(f"sender: [phase3] OK — revoked cert refused (body: {exc.response.text[:200]})")
                return
            raise SystemExit(
                f"sender: [phase3] expected 401 from /auth/token, got {exc.response.status_code}: "
                f"{exc.response.text[:300]}"
            )

        raise SystemExit(
            "sender: [phase3] login SUCCEEDED for revoked agent — revocation "
            "not enforced. Smoke fails."
        )
    finally:
        client.close()


def _phase4() -> None:
    """Assert that a revoked binding blocks session open (A6)."""
    if not UNBOUND_AGENT_ID or not UNBOUND_CERT_PATH or not UNBOUND_KEY_PATH:
        print("sender: [phase4] skipped (UNBOUND_AGENT_* not set)")
        return

    print(f"sender: [phase4] logging in as {UNBOUND_AGENT_ID} — expect 403 at login or session")
    client = CullisClient(BROKER_URL, verify_tls=CA_BUNDLE)
    try:
        try:
            client.login(UNBOUND_AGENT_ID, ORG_ID, UNBOUND_CERT_PATH, UNBOUND_KEY_PATH)
        except PermissionError as exc:
            if "403" in str(exc) or "binding" in str(exc).lower():
                print(f"sender: [phase4] OK — login refused (binding gate): {str(exc)[:200]}")
                return
            raise SystemExit(f"sender: [phase4] expected 403 binding refusal at login, got: {exc}")
        except _h.HTTPStatusError as exc:
            if exc.response.status_code in (401, 403):
                print(f"sender: [phase4] OK — login refused (HTTP {exc.response.status_code}, body: {exc.response.text[:200]})")
                return
            raise

        # If login somehow succeeded (older broker version), session open
        # must still fail.
        print(f"sender: [phase4] login surprisingly OK, expect refusal on session open")
        try:
            client.open_session(
                target_agent_id=PEER_AGENT,
                target_org_id=PEER_ORG,
                capabilities=["message.exchange"],
            )
        except _h.HTTPStatusError as exc:
            if exc.response.status_code in (401, 403):
                print(f"sender: [phase4] OK — session refused (HTTP {exc.response.status_code})")
                return
            raise SystemExit(
                f"sender: [phase4] expected 401/403 for revoked binding, got "
                f"{exc.response.status_code}: {exc.response.text[:300]}"
            )

        raise SystemExit(
            "sender: [phase4] both login and session OPENED for agent with "
            "revoked binding — binding revocation not enforced. Smoke fails."
        )
    finally:
        client.close()


def main() -> int:
    os.environ["SSL_CERT_FILE"] = CA_BUNDLE
    _phase1()
    _phase2()
    _phase3()
    _phase4()
    return 0


if __name__ == "__main__":
    sys.exit(main())
