"""Sandbox demo agent — ADR-014 mTLS client cert + DPoP + A2A messaging.

Each agent authenticates to the Mastio with the TLS client cert + DPoP
key the bootstrap stage enrolled for it, drains the one-shot inbox, and
(when ``AGENT_AUTO_SEND=true``) fires a nonce at every peer listed in
``/state/peers.json``. Received nonces land in ``/tmp/received.json``
for the smoke suite to inspect.

Env:
    BROKER_URL                e.g. https://proxy-a:9443
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
    # ``url`` is the Mastio's https endpoint behind the per-org nginx
    # sidecar (ADR-014); the Org CA is self-signed in the sandbox, so
    # we disable cert verification here (matches the SDK's
    # ``verify_tls=False``).
    import httpx
    deadline = time.monotonic() + timeout
    with httpx.Client(verify=False, timeout=2.0) as client:
        while time.monotonic() < deadline:
            try:
                r = client.get(url)
                if r.status_code < 500:
                    return True
            except httpx.HTTPError:
                pass
            time.sleep(1)
    return False


def _receive_loop(client: CullisClient, self_id: str) -> None:
    """Drain the proxy's one-shot inbox and record nonce payloads.

    ADR-011 Phase 4b — replaces the old session-based poll loop. The
    egress one-shot inbox lives on the Mastio (``/v1/egress/message/inbox``
    under mTLS client-cert + DPoP auth) for intra-org deliveries
    short-circuited by ADR-001, and mirrors cross-org rows the broker
    pushed back after the publisher replay. ``decrypt_oneshot`` verifies
    the envelope signature and returns the inner payload.
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
    message/send`` on the Mastio (mTLS client-cert + DPoP), which
    triggers the ADR-001 intra-org short-circuit when
    ``PROXY_INTRA_ORG=true`` and the peer lives on the same proxy — the
    Court never sees intra-org traffic. Cross-org targets resolve to
    ``envelope`` transport and ride the ADR-009 counter-signature chain
    end-to-end.
    """
    for peer_id in peers:
        nonce = f"{self_id}->{peer_id}:{uuid.uuid4().hex[:8]}"
        try:
            client.send_oneshot(peer_id, {"nonce": nonce})
            print(f"[{self_id}] sent oneshot nonce to {peer_id}", flush=True)
        except Exception as exc:
            print(f"[{self_id}] send_oneshot {peer_id} failed: {exc!r}",
                  flush=True)


def _auth_identity_dir(mastio_url: str, identity_dir: str, self_id: str) -> CullisClient:
    """ADR-014 — runtime agents authenticate via TLS client cert + DPoP.

    Layout matches what bootstrap + bootstrap-mastio writes under
    ``/state/{org}/agents/{name}/``: ``agent.pem`` (cert) +
    ``agent-key.pem`` (private key) + ``dpop.jwk`` (egress proof key).

    ``verify_tls=False`` because the sandbox's Org CA is self-signed
    (no system trust store entry); a real deploy points at a CA-trusted
    hostname or a custom ``CULLIS_CA_BUNDLE``.
    """
    cert_path = pathlib.Path(identity_dir) / "agent.pem"
    key_path = pathlib.Path(identity_dir) / "agent-key.pem"
    dpop_key_path = pathlib.Path(identity_dir) / "dpop.jwk"
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if cert_path.exists() and key_path.exists() and dpop_key_path.exists():
            break
        time.sleep(0.5)
    else:
        raise RuntimeError(
            f"[{self_id}] missing identity material under {identity_dir} "
            "(need agent.pem, agent-key.pem, dpop.jwk) — "
            "did bootstrap-mastio + bootstrap run?"
        )
    client = CullisClient.from_identity_dir(
        mastio_url,
        cert_path=cert_path,
        key_path=key_path,
        dpop_key_path=dpop_key_path,
        agent_id=self_id,
        org_id=self_id.split("::", 1)[0],
        verify_tls=False,
    )
    # Session APIs (``list_sessions`` / ``open_session`` / ``send``)
    # require a broker JWT. ``login_via_proxy`` asks the Mastio to mint
    # a client_assertion on the agent's behalf (PR-C: the auth dep on
    # ``/v1/auth/sign-assertion`` resolves the agent from the TLS client
    # cert nginx forwards in ``X-SSL-Client-Cert``) and forwards it to
    # the Court for a DPoP-bound access token. Egress / ``send_oneshot``
    # calls continue under the same client-cert + DPoP path.
    client.login_via_proxy()
    # ``client.send`` signs each A2A message with the agent's private
    # key (end-to-end non-repudiation layer sitting on top of the
    # session envelope). The TLS key on disk doubles as the signing
    # key — the broker verifies the inner signature against the public
    # half pinned in ``internal_agents.cert_pem``.
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
        client = _auth_identity_dir(broker, identity_dir, self_id)
    except Exception as exc:
        print(f"[{self_id}] FAIL: client-cert auth: {exc!r}",
              file=sys.stderr, flush=True)
        return 2

    token_preview = (
        client.token[:24] if getattr(client, "token", None) else "(cert-auth only)"
    )
    print(f"[{self_id}] mTLS+DPoP auth OK — token={token_preview}...",
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
