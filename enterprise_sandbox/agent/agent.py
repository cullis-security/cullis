"""Sandbox demo agent — ADR-011 unified API-key+DPoP auth + A2A messaging.

Each agent authenticates to the Mastio with the API key + DPoP key the
bootstrap stage enrolled for it, drains the one-shot inbox, and (when
``AGENT_AUTO_SEND=true``) fires a nonce at every peer listed in
``/state/peers.json``. Received nonces land in ``/tmp/received.json``
for the smoke suite to inspect.

Env:
    BROKER_URL                e.g. http://proxy-a:9100
    ORG_ID                    e.g. orga
    AGENT_NAME                short name (becomes {ORG_ID}::{AGENT_NAME})
    IDENTITY_DIR              /state/{ORG_ID}/agents/{AGENT_NAME} by default
    PEERS_FILE                /state/peers.json (written by bootstrap)
    AGENT_AUTO_SEND           'true' to trigger the legacy nonce round-trip
"""
from __future__ import annotations

import json
import os
import pathlib
import sys
import threading
import time
import uuid

from cullis_sdk import CullisClient


RECEIVED_FILE = pathlib.Path("/tmp/received.json")
_received_lock = threading.Lock()
_received_nonces: list[str] = []


def _persist_received() -> None:
    with _received_lock:
        data = {"nonces": list(_received_nonces)}
    tmp = RECEIVED_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data))
    tmp.rename(RECEIVED_FILE)


def _record(nonce: str) -> None:
    with _received_lock:
        _received_nonces.append(nonce)
    _persist_received()


def wait_for_http(url: str, timeout: float = 60.0) -> bool:
    import urllib.request
    import urllib.error
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            urllib.request.urlopen(url, timeout=2)
            return True
        except (urllib.error.URLError, OSError):
            time.sleep(1)
    return False


def _receive_loop(client: CullisClient, self_id: str) -> None:
    """Drain the proxy's one-shot inbox and record nonce payloads.

    ADR-011 Phase 4b — replaces the old session-based poll loop. The
    egress one-shot inbox lives on the Mastio (``/v1/egress/message/inbox``
    under API-key + DPoP auth) for intra-org deliveries short-circuited
    by ADR-001, and mirrors cross-org rows the broker pushed back after
    the publisher replay. ``decrypt_oneshot`` verifies the envelope
    signature and returns the inner payload.
    """
    seen: set[str] = set()
    while True:
        try:
            rows = client.receive_oneshot()
            for row in rows:
                msg_id = row.get("msg_id")
                if not msg_id or msg_id in seen:
                    continue
                try:
                    payload = client.decrypt_oneshot(row)
                except Exception as exc:
                    print(f"[{self_id}] decrypt_oneshot {msg_id[:8]} failed: {exc!r}",
                          flush=True)
                    continue
                # ``decrypt_oneshot`` wraps the inner payload under
                # ``payload`` and attaches verification metadata
                # (``sender_verified``, ``mode``). Fall back to the bare
                # key for legacy callers that already dropped the
                # envelope before handing us the row.
                nested = payload.get("payload") if isinstance(payload, dict) else None
                inner = nested if isinstance(nested, dict) and "nonce" in nested else payload
                if isinstance(inner, dict) and "nonce" in inner:
                    _record(inner["nonce"])
                    sender = row.get("sender_agent_id", "?")
                    print(f"[{self_id}] received nonce from {sender}: "
                          f"{inner['nonce']}", flush=True)
                seen.add(msg_id)
                # Dedup via the ``seen`` set is enough for the sandbox —
                # the inbox endpoint returns every undelivered row on
                # each poll, and the demo's nonce set is bounded + small.
                # A production runtime would also ack so pg/broker state
                # can reclaim the row (ADR-008 Phase 2 work).
        except Exception as exc:
            print(f"[{self_id}] receive_oneshot failed: {exc!r}", flush=True)
        time.sleep(1)


def _send_to_peers(client: CullisClient, self_id: str, peers: list[str]) -> None:
    """Send one nonce per peer via the ADR-008 sessionless one-shot path.

    ADR-011 Phase 4b — replaced ``open_session`` + ``send`` with
    ``send_oneshot``. The call hits ``/v1/egress/resolve`` + ``/v1/egress/
    message/send`` on the Mastio (API-key + DPoP), which triggers the
    ADR-001 intra-org short-circuit when ``PROXY_INTRA_ORG=true`` and the
    peer lives on the same proxy — the Court never sees intra-org
    traffic. Cross-org targets resolve to ``envelope`` transport and
    ride the ADR-009 counter-signature chain end-to-end.
    """
    for peer_id in peers:
        nonce = f"{self_id}->{peer_id}:{uuid.uuid4().hex[:8]}"
        try:
            client.send_oneshot(peer_id, {"nonce": nonce})
            print(f"[{self_id}] sent oneshot nonce to {peer_id}", flush=True)
        except Exception as exc:
            print(f"[{self_id}] send_oneshot {peer_id} failed: {exc!r}",
                  flush=True)


def _auth_api_key_file(mastio_url: str, identity_dir: str, self_id: str) -> CullisClient:
    """ADR-011 Phase 4 — runtime agents read the credentials the
    bootstrap-mastio stage enrolled for them.

    Layout matches what ``_enroll_agents_via_byoca`` writes under
    ``/state/{org}/agents/{name}/``: ``api-key`` + ``dpop.jwk`` (both
    required for egress DPoP enforcement).
    """
    api_key_path = pathlib.Path(identity_dir) / "api-key"
    dpop_key_path = pathlib.Path(identity_dir) / "dpop.jwk"
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if api_key_path.exists() and dpop_key_path.exists():
            break
        time.sleep(0.5)
    else:
        raise RuntimeError(
            f"[{self_id}] api-key or dpop.jwk missing under {identity_dir} "
            "— did bootstrap-mastio run?"
        )
    client = CullisClient.from_api_key_file(
        mastio_url,
        api_key_path=api_key_path,
        dpop_key_path=dpop_key_path,
        agent_id=self_id,
        org_id=self_id.split("::", 1)[0],
    )
    # Session APIs (``list_sessions`` / ``open_session`` / ``send``) still
    # require a broker JWT. ``login_via_proxy`` converts the API key into
    # one by asking the Mastio to mint a client_assertion on the agent's
    # behalf + forwarding it to the Court — the agent never handles a
    # cert. Egress / ``send_oneshot`` calls continue to use the API-key
    # + DPoP path directly.
    client.login_via_proxy()
    # ``client.send`` signs each A2A message with the agent's private
    # key (end-to-end non-repudiation layer sitting on top of the
    # session envelope). Under ADR-011 the agent keeps reading its
    # cert/key from the identity dir alongside ``api-key`` + ``dpop.jwk``
    # — the key is bound to the same row the Mastio enrolled, so the
    # broker verifies the inner signature against the public half it
    # already has. Enrollment via Connector/admin-token would persist
    # its own ``agent-key.pem`` here; BYOCA/SPIFFE enrollment reuses
    # the cert the operator submitted.
    key_path = pathlib.Path(identity_dir) / "agent-key.pem"
    if key_path.exists():
        client._signing_key_pem = key_path.read_text()
    return client


def main() -> int:
    broker = os.environ["BROKER_URL"].rstrip("/")
    org_id = os.environ["ORG_ID"]
    name = os.environ["AGENT_NAME"]
    peers_file = os.environ.get("PEERS_FILE", "/state/peers.json")
    # ADR-011 Phase 4 — auto-send demo traffic on boot is opt-in now.
    # Default is idle (auto_accept + receive loops run in background,
    # no sessions opened until an explicit scenario triggers traffic).
    # This keeps ``demo.sh full`` observation-friendly — the Court
    # dashboard stays empty until the user drives a scenario.
    auto_send = os.environ.get("AGENT_AUTO_SEND", "false").lower() in ("1", "true", "yes")
    self_id = f"{org_id}::{name}"

    if not wait_for_http(f"{broker}/health", timeout=60):
        print(f"[{self_id}] FAIL: broker {broker} not reachable",
              file=sys.stderr, flush=True)
        return 1

    try:
        identity_dir = os.environ.get(
            "IDENTITY_DIR", f"/state/{org_id}/agents/{name}",
        )
        client = _auth_api_key_file(broker, identity_dir, self_id)
    except Exception as exc:
        print(f"[{self_id}] FAIL: api-key auth: {exc!r}",
              file=sys.stderr, flush=True)
        return 2

    token_preview = (
        client.token[:24] if getattr(client, "token", None) else "(api-key only)"
    )
    print(f"[{self_id}] API-key+DPoP auth OK — token={token_preview}...",
          flush=True)
    pathlib.Path("/tmp/ready").write_text(self_id + "\n")
    _persist_received()  # initialize empty /tmp/received.json

    # Load peer list written by bootstrap.
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if pathlib.Path(peers_file).exists():
            break
        time.sleep(0.5)
    try:
        topology = json.loads(pathlib.Path(peers_file).read_text())
        peers = topology.get(self_id, [])
    except Exception as exc:
        print(f"[{self_id}] WARN: peers file unreadable ({exc!r}), no sends",
              flush=True)
        peers = []
    print(f"[{self_id}] peers: {peers}", flush=True)

    # ADR-011 Phase 4b — no ``_auto_accept_loop`` anymore. One-shot
    # envelopes are fire-and-forget on the sender side and inbox-polled
    # on the receiver side; there is no session handshake to accept.
    threading.Thread(
        target=_receive_loop, args=(client, self_id), daemon=True,
    ).start()

    if auto_send and peers:
        # Give peer containers a head start so their auto_accept loop is
        # running when we open sessions toward them.
        time.sleep(5)
        _send_to_peers(client, self_id, peers)
    else:
        print(f"[{self_id}] idle — AGENT_AUTO_SEND=false (set to 'true' to "
              "trigger the legacy demo nonce round-trip on boot)",
              flush=True)

    # Keep the process alive — daemons handle accept + receive in background.
    while True:
        time.sleep(30)


if __name__ == "__main__":
    sys.exit(main())
