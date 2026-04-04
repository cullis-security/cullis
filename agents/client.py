"""
Agent Trust Network — Agent Client

Starts an AI agent that registers with the broker, obtains a JWT,
and participates in inter-organizational supply chain sessions using Claude as its brain.

Configuration via .env file (--config) or environment variables:

  BROKER_URL          Broker URL,          default: http://localhost:8000
  AGENT_ID            e.g. "buyer::procurement-agent"
  ORG_ID              e.g. "buyer"
  AGENT_CERT_PATH     path to the agent's PEM certificate
  AGENT_KEY_PATH      path to the agent's PEM private key
  AGENT_ROLE          "initiator" | "responder"
  TARGET_AGENT_ID     initiator only — target agent_id
  TARGET_ORG_ID       initiator only — target org_id
  ANTHROPIC_API_KEY   Anthropic API key
  POLL_INTERVAL       seconds between polls, default: 2
  MAX_TURNS           maximum exchanges before closing, default: 8

Usage:
  python agents/client.py --config agents/manufacturer.env
  python agents/client.py --config agents/buyer.env
"""
import argparse
import base64
import datetime
import json
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any

import httpx
import anthropic
from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import serialization
from jose import jwt as jose_jwt


# ─────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────

def load_env_file(path: str, override: bool = False) -> None:
    """Load KEY=VALUE pairs from a .env file into the current process.

    If override=True, non-empty values overwrite existing env vars.
    Empty values are never written — they let a previously loaded value through.
    """
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, _, value = line.partition("=")
        key   = key.strip()
        value = value.strip()
        if not value:
            continue  # skip empty — let fallback files fill it
        if override or key not in os.environ:
            os.environ[key] = value


def cfg(key: str, default: str | None = None) -> str:
    value = os.environ.get(key, default)
    if value is None:
        print(f"[ERROR] missing variable: {key}", flush=True)
        sys.exit(1)
    return value


# ─────────────────────────────────────────────
# Broker HTTP client
# ─────────────────────────────────────────────

class BrokerClient:
    def __init__(self, base_url: str):
        self.base = base_url.rstrip("/")
        self._http = httpx.Client(timeout=10)
        self.token: str | None = None
        self._label: str = "agent"
        self._signing_key_pem: str | None = None   # private key for signing messages

    def _headers(self) -> dict:
        if not self.token:
            raise RuntimeError("Not authenticated — call login() first")
        return {"Authorization": f"Bearer {self.token}"}

    def _ws_url(self) -> str:
        """Convert the base HTTP URL to WebSocket (ws:// or wss://)."""
        return self.base.replace("https://", "wss://").replace("http://", "ws://")

    # --- registry ---

    def register(self, agent_id: str, org_id: str, display_name: str,
                 capabilities: list[str]) -> bool:
        resp = self._http.post(f"{self.base}/registry/agents", json={
            "agent_id": agent_id,
            "org_id": org_id,
            "display_name": display_name,
            "capabilities": capabilities,
        })
        if resp.status_code == 409:
            return False  # already registered, ok
        resp.raise_for_status()
        return True

    # --- auth ---

    def login(self, agent_id: str, org_id: str, cert_path: str, key_path: str) -> None:
        """Authenticate the agent via client_assertion x509 (RS256).
        The private key is kept in memory for signing messages."""
        self._label = agent_id
        try:
            # Load the agent's private key and certificate
            priv_key_pem = Path(key_path).read_text()
            self._signing_key_pem = priv_key_pem
            cert_pem = Path(cert_path).read_bytes()
            cert = crypto_x509.load_pem_x509_certificate(cert_pem)
            cert_der = cert.public_bytes(serialization.Encoding.DER)
            x5c = [base64.b64encode(cert_der).decode()]

            now = datetime.datetime.now(datetime.timezone.utc)
            payload = {
                "sub": agent_id,
                "iss": agent_id,
                "aud": "agent-trust-broker",
                "iat": int(now.timestamp()),
                "exp": int((now + datetime.timedelta(minutes=5)).timestamp()),
                "jti": str(uuid.uuid4()),
            }
            assertion = jose_jwt.encode(
                payload, priv_key_pem, algorithm="RS256", headers={"x5c": x5c}
            )

            resp = self._http.post(f"{self.base}/auth/token",
                                   json={"client_assertion": assertion})
            resp.raise_for_status()
            self.token = resp.json()["access_token"]
        except (httpx.ConnectError, httpx.TimeoutException) as e:
            print(f"[{agent_id}] Broker unreachable during login: {e}", flush=True)
            sys.exit(1)
        except httpx.HTTPStatusError as e:
            print(f"[{agent_id}] Login failed (HTTP {e.response.status_code}): {e.response.text}", flush=True)
            sys.exit(1)

    # --- discovery ---

    def discover(self, capabilities: list[str]) -> list[dict]:
        """Search for agents in other orgs that have ALL the requested capabilities."""
        resp = self._http.get(
            f"{self.base}/registry/agents/search",
            params=[("capability", c) for c in capabilities],
            headers=self._headers(),
        )
        resp.raise_for_status()
        return resp.json().get("agents", [])

    # --- sessions ---

    def open_session(self, target_agent_id: str, target_org_id: str,
                     capabilities: list[str]) -> str:
        resp = self._http.post(f"{self.base}/broker/sessions", json={
            "target_agent_id": target_agent_id,
            "target_org_id": target_org_id,
            "requested_capabilities": capabilities,
        }, headers=self._headers())
        resp.raise_for_status()
        return resp.json()["session_id"]

    def accept_session(self, session_id: str) -> None:
        resp = self._http.post(
            f"{self.base}/broker/sessions/{session_id}/accept",
            headers=self._headers(),
        )
        resp.raise_for_status()

    def close_session(self, session_id: str) -> None:
        resp = self._http.post(
            f"{self.base}/broker/sessions/{session_id}/close",
            headers=self._headers(),
        )
        resp.raise_for_status()

    def list_sessions(self, status_filter: str | None = None) -> list[dict]:
        params = {}
        if status_filter:
            params["status"] = status_filter
        resp = self._http.get(f"{self.base}/broker/sessions",
                              headers=self._headers(), params=params)
        resp.raise_for_status()
        return resp.json()

    # --- messaggi ---

    def send(self, session_id: str, sender_agent_id: str, payload: dict) -> None:
        from app.auth.message_signer import sign_message as _sign_message
        nonce = str(uuid.uuid4())
        if not self._signing_key_pem:
            raise RuntimeError("Signing key not available — call login() before send()")
        signature = _sign_message(self._signing_key_pem, session_id, sender_agent_id, nonce, payload)
        envelope = {
            "session_id": session_id,
            "sender_agent_id": sender_agent_id,
            "payload": payload,
            "nonce": nonce,
            "signature": signature,
        }
        max_retries = 3
        for attempt in range(max_retries):
            try:
                resp = self._http.post(
                    f"{self.base}/broker/sessions/{session_id}/messages",
                    json=envelope,
                    headers=self._headers(),
                )
                resp.raise_for_status()
                return
            except (httpx.ConnectError, httpx.TimeoutException):
                if attempt < max_retries - 1:
                    print(f"[{self._label}] Broker unreachable — retrying in 2s...", flush=True)
                    time.sleep(2)
                else:
                    print(f"[{self._label}] Broker unreachable after {max_retries} attempts, exiting.", flush=True)
                    sys.exit(1)

    def poll(self, session_id: str, after: int = -1, poll_interval: int = 2) -> list[dict]:
        max_retries = 5
        for attempt in range(max_retries):
            try:
                resp = self._http.get(
                    f"{self.base}/broker/sessions/{session_id}/messages",
                    params={"after": after},
                    headers=self._headers(),
                )
                resp.raise_for_status()
                return resp.json()
            except (httpx.ConnectError, httpx.TimeoutException):
                if attempt < max_retries - 1:
                    print(f"[{self._label}] Broker unreachable — retrying in {poll_interval}s...", flush=True)
                    time.sleep(poll_interval)
                else:
                    print(f"[{self._label}] Broker unreachable, exiting.", flush=True)
                    sys.exit(1)
        return []

    # --- WebSocket ---

    def listen_ws(self, callback, session_id: str | None = None, max_retries: int = 3) -> bool:
        """
        Open an authenticated WebSocket connection and call callback(msg: dict) for each
        message received from the broker. callback must return True to continue,
        False to close the connection.

        Handles automatic reconnection (up to max_retries attempts).
        Returns True if the connection ended normally, False if it failed.
        """
        from websockets.sync.client import connect as ws_connect

        ws_url = self._ws_url() + "/v1/broker/ws"
        for attempt in range(max_retries):
            try:
                with ws_connect(ws_url, open_timeout=5) as ws:
                    ws.send(json.dumps({"type": "auth", "token": self.token}))
                    resp = json.loads(ws.recv())
                    if resp.get("type") != "auth_ok":
                        raise RuntimeError(f"WS auth failed: {resp}")
                    for raw in ws:
                        if not callback(json.loads(raw)):
                            return True
                return True
            except Exception:
                if attempt < max_retries - 1:
                    time.sleep(2)
                else:
                    return False
        return False

    def close(self) -> None:
        self._http.close()


# ─────────────────────────────────────────────
# WebSocket connection helper
# ─────────────────────────────────────────────

def _open_ws(broker: BrokerClient, agent_id: str):
    """
    Attempt to open an authenticated WebSocket connection.
    Returns the connection object if successful, None otherwise (polling fallback).
    """
    try:
        from websockets.sync.client import connect as ws_connect
        ws_url = broker._ws_url() + "/v1/broker/ws"
        ws = ws_connect(ws_url, open_timeout=5)
        ws.send(json.dumps({"type": "auth", "token": broker.token}))
        resp = json.loads(ws.recv())
        if resp.get("type") == "auth_ok":
            log(agent_id, "WebSocket connected.", GREEN)
            return ws
        ws.close()
        log(agent_id, "WebSocket unavailable, falling back to REST polling.", YELLOW)
        return None
    except Exception as e:
        log(agent_id, f"WebSocket unavailable, falling back to REST polling: {e}", YELLOW)
        return None


# ─────────────────────────────────────────────
# Claude
# ─────────────────────────────────────────────

def ask_llm(system_prompt: str, conversation: list[dict], new_message: str) -> str:
    llm_base_url = os.environ.get("LLM_BASE_URL", "").strip()
    messages = conversation + [{"role": "user", "content": new_message}]

    if llm_base_url:
        # OpenAI-compatible backend (Ollama, vLLM, LM Studio, OpenAI, ...)
        from openai import OpenAI
        llm_client = OpenAI(
            base_url=llm_base_url,
            api_key=os.environ.get("LLM_API_KEY", "not-needed"),
        )
        model = os.environ.get("LLM_MODEL", "gpt-4o")
        response = llm_client.chat.completions.create(
            model=model,
            max_tokens=1024,
            messages=[{"role": "system", "content": system_prompt}] + messages,
        )
        return response.choices[0].message.content
    else:
        # Default: Anthropic Claude
        llm_client = anthropic.Anthropic(api_key=cfg("ANTHROPIC_API_KEY"))
        response = llm_client.messages.create(
            model=os.environ.get("LLM_MODEL", "claude-sonnet-4-6"),
            max_tokens=1024,
            system=system_prompt,
            messages=messages,
        )
        return response.content[0].text


# ─────────────────────────────────────────────
# Colored logging
# ─────────────────────────────────────────────

RESET  = "\033[0m"
BOLD   = "\033[1m"
CYAN   = "\033[36m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
RED    = "\033[31m"
GRAY   = "\033[90m"

def log(label: str, msg: str, color: str = RESET) -> None:
    print(f"{color}{BOLD}[{label}]{RESET} {msg}", flush=True)

def log_msg(direction: str, payload: dict) -> None:
    text = payload.get("text") or json.dumps(payload, ensure_ascii=False)
    arrow = f"{GREEN}→{RESET}" if direction == "OUT" else f"{YELLOW}←{RESET}"
    print(f"  {arrow} {text}", flush=True)

def _contains_fine(text: str, last_n: int = 5) -> bool:
    """Check whether the text ends with the word FINE (case-insensitive)."""
    return "FINE" in text.upper().split()[-last_n:]


# ─────────────────────────────────────────────
# System prompts
# ─────────────────────────────────────────────

# Default system prompt templates — override with AGENT_SYSTEM_PROMPT in .env
# Template variables: {buyer_name}, {supplier_name}, {order_item}, {order_quantity}

_SYSTEM_INITIATOR_TEMPLATE = """\
You are the procurement agent for {buyer_name}, a B2B buyer. Your task is to \
place a purchase order with the sales agent of the supplier, \
negotiate price and delivery terms, and confirm the order.

The order to process is:
  - Product: {order_item}
  - Quantity: {order_quantity} units
  - Order reference: provided in the initial message

Rules:
- Always communicate in English.
- Be precise and professional, as in a B2B context.
- Your responses are sent directly to the supplier's agent via the broker.
- Before confirming the order, make sure you have ALL of the following information:
    1. Confirmed availability for the requested quantity
    2. Unit price with any applicable discount
    3. Total price calculated
    4. Exact delivery lead time (date or business days)
    5. Payment terms
- Do not say "ORDER CONFIRMED" on the supplier's first response if information is missing.
  Ask clarifying questions until all the points above are satisfied.
- Only once you have received answers to all points, close with "ORDER CONFIRMED" \
  followed by a summary (product, quantity, unit price, total price, delivery date, \
  payment terms).
- When concluding, end with the word FINE on the final line.
"""

_SYSTEM_RESPONDER_TEMPLATE = """\
You are the sales agent for {supplier_name}, a supplier of industrial components. \
You receive purchase orders from buyer agents and manage the negotiation: \
you confirm availability, communicate prices, delivery lead times, and payment terms.

Your product catalog (use this data in your responses):

  Zinc-plated M8 bolts:
    SKU: BLT-M8-ZN
    Stock: 8,500 units in warehouse
    List price: €0.048/unit (5% discount for orders ≥ 500 units, 10% for ≥ 2000 units)
    Lead time: 2 business days (from stock)
    Minimum order: 100 units
    Payment terms: Net 30 from invoice date

  Zinc-plated M10 bolts:
    SKU: BLT-M10-ZN
    Stock: 3,200 units in warehouse
    List price: €0.075/unit (5% discount for orders ≥ 500 units)
    Lead time: 3 business days
    Minimum order: 50 units

  Stainless M6 screws:
    SKU: SCR-M6-IX
    Stock: 12,000 units
    List price: €0.032/unit
    Lead time: 1 business day

Rules:
- Always communicate in English.
- Reply only with data from your catalog. If a product is unavailable, say so.
- Apply discounts automatically based on the requested quantity.
- Be precise and commercially professional.
- Your responses are sent to the broker and then to the buyer agent.
- Do NOT say FINE until you have received an explicit order confirmation from the buyer \
  (a message containing "ORDER CONFIRMED"). Until then, keep answering questions, \
  provide clarifications, and negotiate.
- The correct flow is: buyer sends RFQ → you respond with an offer → buyer asks \
  for clarifications → you respond → buyer says "ORDER CONFIRMED" → you say "ORDER ACCEPTED" + FINE.
- Only after receiving "ORDER CONFIRMED" from the buyer, close with "ORDER ACCEPTED" \
  followed by a summary (SKU, quantity, discounted unit price, total, delivery date).
- When concluding, end with the word FINE on the final line.
"""


# ─────────────────────────────────────────────
# Shared message logic
# ─────────────────────────────────────────────

def _process_received_message(
    broker: BrokerClient,
    agent_id: str,
    session_id: str,
    received_text: str,
    sender_id: str,
    system_prompt: str,
    conversation: list[dict],
    turns: int,
    max_turns: int,
    payload_type: str,
    extra_payload: dict,
) -> tuple[bool, int]:
    """
    Process a received message: generate reply, send, update state.
    Returns (should_continue: bool, turns: int).
    """
    log(agent_id, f"Received from {sender_id}:", YELLOW)
    log_msg("IN", {"text": received_text})

    if _contains_fine(received_text):
        log(agent_id, "Conversation ended by the other agent.", GREEN)
        try:
            broker.close_session(session_id)
        except Exception:
            pass
        return False, turns

    reply = ask_llm(system_prompt, conversation, received_text)
    log(agent_id, "Replying:", CYAN)
    log_msg("OUT", {"text": reply})

    payload = {"type": payload_type, "text": reply}
    payload.update(extra_payload)
    broker.send(session_id, agent_id, payload)
    conversation.append({"role": "user",      "content": received_text})
    conversation.append({"role": "assistant", "content": reply})
    turns += 1

    if _contains_fine(reply):
        log(agent_id, "Conversation concluded.", GREEN)
        try:
            broker.close_session(session_id)
        except Exception:
            pass
        return False, turns

    if turns >= max_turns:
        log(agent_id, f"Maximum turn limit reached ({max_turns}), closing session.", YELLOW)
        try:
            broker.close_session(session_id)
        except Exception:
            pass
        return False, turns

    return True, turns


# ─────────────────────────────────────────────
# Role: INITIATOR (Buyer)
# ─────────────────────────────────────────────

def run_initiator(broker: BrokerClient, agent_id: str, max_turns: int,
                  poll_interval: int, system_prompt: str) -> None:
    target_agent_id = os.environ.get("TARGET_AGENT_ID")
    target_org_id   = os.environ.get("TARGET_ORG_ID")
    order_id        = cfg("ORDER_ID", "ORD-2026-001")
    order_item      = cfg("ORDER_ITEM", "zinc-plated M8 bolts")
    order_quantity  = cfg("ORDER_QUANTITY", "1000")

    # ── Discovery: if TARGET_AGENT_ID is not set, search the network ──────
    if not target_agent_id:
        needed_caps = cfg("CAPABILITIES", "order.read,order.write").split(",")
        log(agent_id, f"No TARGET_AGENT_ID set — searching network for {needed_caps}...", CYAN)
        candidates = broker.discover(needed_caps)
        if not candidates:
            log(agent_id, "No agents found with the required capabilities. Exiting.", RED)
            return
        # Take the first available (future: ranking, preferences, etc.)
        chosen = candidates[0]
        target_agent_id = chosen["agent_id"]
        target_org_id   = chosen["org_id"]
        log(agent_id,
            f"Found {len(candidates)} candidate(s) — connecting to "
            f"{target_agent_id} ({chosen['display_name']}, org: {target_org_id})", GREEN)

    conversation: list[dict] = []
    turns = 0
    session_id: str | None = None

    # ── Check whether an active session with the target already exists (post-restart) ─
    existing = broker.list_sessions()
    resumed = next(
        (s for s in existing
         if s["target_agent_id"] == target_agent_id and s["status"] == "active"),
        None,
    )

    if resumed:
        session_id = resumed["session_id"]
        log(agent_id, f"Active session restored: {session_id}", YELLOW)

        queued = broker.poll(session_id, after=-1)
        last_seq = max((m["seq"] for m in queued), default=-1)

        if queued:
            # Responder reply already present — process it
            for msg in queued:
                received_text = msg["payload"].get("text", json.dumps(msg["payload"]))
                ok, turns = _process_received_message(
                    broker, agent_id, session_id,
                    received_text, msg["sender_agent_id"],
                    system_prompt, conversation, turns, max_turns,
                    "order_negotiation", {"order_id": order_id},
                )
                if not ok:
                    return
        else:
            # Empty inbox: no message sent before restart → send the RFQ
            log(agent_id, "Empty inbox — sending initial order request.", CYAN)
            initial_user_msg = (
                f"I need to place order {order_id}: {order_quantity} {order_item}. "
                f"Draft the formal purchase request to the supplier, asking for "
                f"availability, unit price, delivery lead time and payment terms."
            )
            first_message = ask_llm(system_prompt, [], initial_user_msg)
            log_msg("OUT", {"text": first_message})
            broker.send(session_id, agent_id, {"type": "order_request", "text": first_message,
                                                "order_id": order_id})
            conversation = [
                {"role": "user",      "content": initial_user_msg},
                {"role": "assistant", "content": first_message},
            ]
            turns = 1
    else:
        # ── No active session: open a new one ────────────────────────────────
        log(agent_id, f"Opening session towards {target_agent_id}...", CYAN)

        for attempt in range(10):
            try:
                session_id = broker.open_session(
                    target_agent_id, target_org_id, ["order.write"]
                )
                break
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 404 and attempt < 9:
                    log(agent_id, f"Target not yet registered, retrying ({attempt+1}/10)...", GRAY)
                    time.sleep(3)
                else:
                    raise

        log(agent_id, f"Session created: {session_id}", GREEN)
        log(agent_id, "Waiting for the responder to accept...", GRAY)

        for _ in range(30):
            sessions = broker.list_sessions()
            s = next((x for x in sessions if x["session_id"] == session_id), None)
            if s and s["status"] == "active":
                break
            time.sleep(poll_interval)
        else:
            log(agent_id, "Timeout: the responder did not accept the session.", RED)
            return

        log(agent_id, "Session active — starting order negotiation.", GREEN)

        initial_user_msg = (
            f"I need to place order {order_id}: {order_quantity} {order_item}. "
            f"Draft the formal purchase request to the supplier, asking for "
            f"availability, unit price, delivery lead time and payment terms."
        )
        first_message = ask_llm(system_prompt, [], initial_user_msg)
        log(agent_id, "Sending order request:", CYAN)
        log_msg("OUT", {"text": first_message})
        broker.send(session_id, agent_id, {"type": "order_request", "text": first_message,
                                            "order_id": order_id})

        conversation = [
            {"role": "user",      "content": initial_user_msg},
            {"role": "assistant", "content": first_message},
        ]
        turns = 1
        last_seq = -1

    # Attempt WS connection to receive responses
    ws = _open_ws(broker, agent_id)

    if ws is not None:
        # ── WS receive loop ──
        try:
            for raw in ws:
                msg = json.loads(raw)
                if msg.get("type") != "new_message":
                    continue
                if msg.get("session_id") != session_id:
                    continue

                m = msg["message"]
                received_text = m["payload"].get("text", json.dumps(m["payload"]))
                ok, turns = _process_received_message(
                    broker, agent_id, session_id,
                    received_text, m["sender_agent_id"],
                    system_prompt, conversation, turns, max_turns,
                    "order_negotiation", {"order_id": order_id},
                )
                if not ok:
                    return
        except Exception as e:
            log(agent_id, f"WS interrupted: {e}", YELLOW)
        finally:
            try:
                ws.close()
            except Exception:
                pass
    else:
        # ── Polling fallback ──
        while turns < max_turns:
            time.sleep(poll_interval)
            messages = broker.poll(session_id, after=last_seq, poll_interval=poll_interval)
            for msg in messages:
                last_seq = msg["seq"]
                received_text = msg["payload"].get("text", json.dumps(msg["payload"]))
                ok, turns = _process_received_message(
                    broker, agent_id, session_id,
                    received_text, msg["sender_agent_id"],
                    system_prompt, conversation, turns, max_turns,
                    "order_negotiation", {"order_id": order_id},
                )
                if not ok:
                    return

        log(agent_id, f"Turn limit of {max_turns} reached.", YELLOW)


# ─────────────────────────────────────────────
# Role: RESPONDER (Manufacturer) — 24/7
# ─────────────────────────────────────────────

def _responder_handle_session(broker: BrokerClient, agent_id: str,
                               session_id: str, max_turns: int,
                               poll_interval: int, system_prompt: str) -> None:
    """Handle a single session from start to finish, then return."""
    conversation: list[dict] = []
    turns = 0

    # Drain any messages already queued before we started listening
    queued = broker.poll(session_id, after=-1)
    last_seq = max((m["seq"] for m in queued), default=-1)
    for msg in queued:
        received_text = msg["payload"].get("text", json.dumps(msg["payload"]))
        ok, turns = _process_received_message(
            broker, agent_id, session_id,
            received_text, msg["sender_agent_id"],
            system_prompt, conversation, turns, max_turns,
            "order_response", {},
        )
        if not ok:
            return

    # Poll until session closes or turn limit
    while True:
        time.sleep(poll_interval)

        # Check if session is still active
        sessions = broker.list_sessions()
        current = next((s for s in sessions if s["session_id"] == session_id), None)
        if current is None or current["status"] == "closed":
            log(agent_id, f"Session {session_id} closed — ready for next client.", GREEN)
            return

        messages = broker.poll(session_id, after=last_seq, poll_interval=poll_interval)
        for msg in messages:
            last_seq = msg["seq"]
            received_text = msg["payload"].get("text", json.dumps(msg["payload"]))
            ok, turns = _process_received_message(
                broker, agent_id, session_id,
                received_text, msg["sender_agent_id"],
                system_prompt, conversation, turns, max_turns,
                "order_response", {},
            )
            if not ok:
                return

        if turns >= max_turns:
            log(agent_id, f"Turn limit reached for session {session_id} — closing.", YELLOW)
            try:
                broker.close_session(session_id)
            except Exception:
                pass
            return


def run_responder(broker: BrokerClient, agent_id: str, max_turns: int,
                  poll_interval: int, system_prompt: str) -> None:
    """
    Infinite loop: accepts sessions, handles the conversation, then returns
    to wait for the next one. Stops only with Ctrl+C.
    """
    log(agent_id, "Online — waiting for incoming sessions (press Ctrl+C to stop).", CYAN)

    # Retrieve pre-existing active sessions (responder restart)
    active = broker.list_sessions(status_filter="active")
    my_active = [s for s in active if s["target_agent_id"] == agent_id]
    if my_active:
        session_id = my_active[0]["session_id"]
        log(agent_id, f"Resuming active session: {session_id}", YELLOW)
        _responder_handle_session(broker, agent_id, session_id, max_turns, poll_interval, system_prompt)

    while True:
        try:
            ws = _open_ws(broker, agent_id)
        except Exception:
            ws = None

        if ws is not None:
            # ── WS mode ──
            try:
                # Check for pending sessions queued before the WS connected
                pending = broker.list_sessions(status_filter="pending")
                my_pending = [s for s in pending if s["target_agent_id"] == agent_id]
                if my_pending:
                    session_id = my_pending[0]["session_id"]
                    broker.accept_session(session_id)
                    log(agent_id, f"Session accepted (pre-WS): {session_id}", GREEN)
                    ws.close()
                    _responder_handle_session(broker, agent_id, session_id,
                                              max_turns, poll_interval)
                    continue

                log(agent_id, "Listening on WebSocket...", GRAY)
                for raw in ws:
                    msg = json.loads(raw)
                    if msg.get("type") == "session_pending":
                        session_id = msg["session_id"]
                        initiator  = msg.get("initiator_agent_id", "unknown")
                        broker.accept_session(session_id)
                        log(agent_id,
                            f"New session from {initiator}: {session_id}", GREEN)
                        ws.close()
                        _responder_handle_session(broker, agent_id, session_id,
                                                  max_turns, poll_interval)
                        break  # reconnect WS after handling

            except KeyboardInterrupt:
                raise
            except Exception as e:
                log(agent_id, f"WS error: {e} — switching to polling.", YELLOW)
            finally:
                try:
                    ws.close()
                except Exception:
                    pass

        else:
            # ── Polling fallback ──
            time.sleep(poll_interval)
            pending = broker.list_sessions(status_filter="pending")
            my_pending = [s for s in pending if s["target_agent_id"] == agent_id]
            if my_pending:
                session_id = my_pending[0]["session_id"]
                initiator  = my_pending[0]["initiator_agent_id"]
                broker.accept_session(session_id)
                log(agent_id,
                    f"New session from {initiator}: {session_id}", GREEN)
                _responder_handle_session(broker, agent_id, session_id,
                                          max_turns, poll_interval)


# ─────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Agent Trust Network — Agent Client")
    parser.add_argument("--config", help="Path to the .env configuration file")
    args = parser.parse_args()

    # Load root .env first (base defaults), then --config with override=True
    # so agent-specific values take priority, but empty values in --config
    # do not block keys already set by the root .env.
    root_env = Path(__file__).parent.parent / ".env"
    if root_env.exists():
        load_env_file(str(root_env))

    if args.config:
        load_env_file(args.config, override=True)

    agent_id      = cfg("AGENT_ID")
    org_id        = cfg("ORG_ID")
    cert_path     = cfg("AGENT_CERT_PATH")
    key_path      = cfg("AGENT_KEY_PATH")
    role          = cfg("AGENT_ROLE")
    broker_url    = cfg("BROKER_URL", "http://localhost:8000")
    poll_interval = int(cfg("POLL_INTERVAL", "2"))
    max_turns     = int(cfg("MAX_TURNS", "8"))
    display_name  = cfg("DISPLAY_NAME", agent_id)
    capabilities  = cfg("CAPABILITIES", "order.read,order.write").split(",")

    # System prompt: AGENT_SYSTEM_PROMPT overrides the default template.
    # Template variables filled from ORG_DISPLAY_NAME, ORDER_ITEM, ORDER_QUANTITY.
    org_display   = cfg("ORG_DISPLAY_NAME", org_id)
    order_item    = cfg("ORDER_ITEM", "zinc-plated M8 bolts")
    order_quantity = cfg("ORDER_QUANTITY", "1000")

    _custom_prompt = os.environ.get("AGENT_SYSTEM_PROMPT", "").strip()
    if _custom_prompt:
        system_prompt = _custom_prompt
    elif role == "initiator":
        system_prompt = _SYSTEM_INITIATOR_TEMPLATE.format(
            buyer_name=org_display,
            order_item=order_item,
            order_quantity=order_quantity,
        )
    else:
        system_prompt = _SYSTEM_RESPONDER_TEMPLATE.format(
            supplier_name=org_display,
        )

    broker = BrokerClient(broker_url)

    try:
        log(agent_id, f"Registering with broker ({broker_url})...", CYAN)
        created = broker.register(agent_id, org_id, display_name, capabilities)
        if created:
            log(agent_id, "Registration complete.", GREEN)
        else:
            log(agent_id, "Agent already present in broker registry.", GREEN)

        log(agent_id, "Logging in...", CYAN)
        broker.login(agent_id, org_id, cert_path, key_path)
        log(agent_id, "JWT token obtained.", GREEN)

        print(flush=True)

        if role == "initiator":
            run_initiator(broker, agent_id, max_turns, poll_interval, system_prompt)
        elif role == "responder":
            run_responder(broker, agent_id, max_turns, poll_interval, system_prompt)
        else:
            log(agent_id, f"Invalid AGENT_ROLE: '{role}' — use 'initiator' or 'responder'", RED)
            sys.exit(1)

    except KeyboardInterrupt:
        print()
        log(agent_id, "Interrupted by user.", GRAY)
    finally:
        broker.close()


if __name__ == "__main__":
    main()
