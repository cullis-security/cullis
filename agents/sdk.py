"""
Agent Trust Network — SDK condiviso

Infrastruttura comune per gli agenti: autenticazione x509, BrokerClient,
firma messaggi, WebSocket, polling, LLM, logging.

Import da buyer.py / manufacturer.py (o qualsiasi altro agente).
"""
import base64
import datetime
import hashlib
import json
import os
import sys
import time
import uuid
from pathlib import Path

import httpx
import anthropic
from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec as _ec
from jose import jwt as jose_jwt


# ─────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────

def load_env_file(path: str, override: bool = False) -> None:
    """Carica KEY=VALUE da un file .env nel processo corrente."""
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, _, value = line.partition("=")
        key   = key.strip()
        value = value.strip()
        if not value:
            continue
        if override or key not in os.environ:
            os.environ[key] = value


def cfg(key: str, default: str | None = None) -> str:
    value = os.environ.get(key, default)
    if value is None:
        print(f"[ERROR] variabile mancante: {key}", flush=True)
        sys.exit(1)
    return value


# ─────────────────────────────────────────────
# Logging colorato
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
    text  = payload.get("text") or json.dumps(payload, ensure_ascii=False)
    arrow = f"{GREEN}→{RESET}" if direction == "OUT" else f"{YELLOW}←{RESET}"
    print(f"  {arrow} {text}", flush=True)


def _contains_fine(text: str, last_n: int = 5) -> bool:
    return "FINE" in text.upper().split()[-last_n:]


# ─────────────────────────────────────────────
# LLM
# ─────────────────────────────────────────────

def ask_llm(system_prompt: str, conversation: list[dict], new_message: str) -> str:
    llm_base_url = os.environ.get("LLM_BASE_URL", "").strip()
    messages = conversation + [{"role": "user", "content": new_message}]

    if llm_base_url:
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
        llm_client = anthropic.Anthropic(api_key=cfg("ANTHROPIC_API_KEY"))
        response = llm_client.messages.create(
            model=os.environ.get("LLM_MODEL", "claude-sonnet-4-6"),
            max_tokens=1024,
            system=system_prompt,
            messages=messages,
        )
        return response.content[0].text


# ─────────────────────────────────────────────
# BrokerClient
# ─────────────────────────────────────────────

class BrokerClient:
    def __init__(self, base_url: str, verify_tls: bool = True):
        self.base = base_url.rstrip("/")
        self._verify_tls = verify_tls
        self._http = httpx.Client(timeout=10, verify=verify_tls)
        self.token: str | None = None
        self._label: str = "agent"
        self._signing_key_pem: str | None = None
        self._pubkey_cache: dict[str, tuple[str, float]] = {}  # agent_id → (pubkey_pem, fetched_at)

        # Ephemeral DPoP key pair — generated once per client instance (per login).
        # Separate from the x509 authentication key.
        self._dpop_privkey: _ec.EllipticCurvePrivateKey | None = None
        self._dpop_pubkey_jwk: dict | None = None
        # Server nonce for DPoP proofs (RFC 9449 §8)
        self._dpop_nonce: str | None = None

    def _init_dpop_key(self) -> None:
        """Generate an ephemeral EC P-256 key pair for DPoP proofs."""
        priv = _ec.generate_private_key(_ec.SECP256R1())
        pub = priv.public_key()
        nums = pub.public_numbers()
        x = base64.urlsafe_b64encode(nums.x.to_bytes(32, "big")).rstrip(b"=").decode()
        y = base64.urlsafe_b64encode(nums.y.to_bytes(32, "big")).rstrip(b"=").decode()
        self._dpop_privkey = priv
        self._dpop_pubkey_jwk = {"kty": "EC", "crv": "P-256", "x": x, "y": y}

    def _dpop_proof(self, method: str, url: str, access_token: str | None = None) -> str:
        """
        Build a DPoP proof JWT for the given method + URL.
        access_token: when provided, adds ath = base64url(SHA-256(token)).
        """
        if self._dpop_privkey is None or self._dpop_pubkey_jwk is None:
            raise RuntimeError("DPoP key not initialized — call login() first")

        priv_pem = self._dpop_privkey.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()

        now = int(time.time())
        claims: dict = {
            "jti": str(uuid.uuid4()),
            "htm": method.upper(),
            "htu": url,
            "iat": now,
        }
        if access_token:
            claims["ath"] = (
                base64.urlsafe_b64encode(
                    hashlib.sha256(access_token.encode()).digest()
                ).rstrip(b"=").decode()
            )
        if self._dpop_nonce:
            claims["nonce"] = self._dpop_nonce

        return jose_jwt.encode(
            claims,
            priv_pem,
            algorithm="ES256",
            headers={"typ": "dpop+jwt", "jwk": self._dpop_pubkey_jwk},
        )

    def _update_nonce(self, response) -> None:
        """Extract DPoP-Nonce from response header if present."""
        nonce = response.headers.get("dpop-nonce")
        if nonce:
            self._dpop_nonce = nonce

    def _headers(self, method: str, path: str) -> dict:
        """
        Return authentication headers for an authenticated request.
        Includes Authorization: DPoP <token> and a per-request DPoP proof.
        """
        if not self.token:
            raise RuntimeError("Non autenticato — chiama login() prima")
        url = f"{self.base}{path}"
        return {
            "Authorization": f"DPoP {self.token}",
            "DPoP": self._dpop_proof(method, url, self.token),
        }

    def _authed_request(self, method: str, path: str, **kwargs):
        """Make an authenticated request with automatic nonce retry."""
        resp = self._http.request(
            method, f"{self.base}{path}",
            headers=self._headers(method, path), **kwargs,
        )
        self._update_nonce(resp)
        # Retry once if server requires a new nonce
        if resp.status_code == 401 and "use_dpop_nonce" in resp.text:
            resp = self._http.request(
                method, f"{self.base}{path}",
                headers=self._headers(method, path), **kwargs,
            )
            self._update_nonce(resp)
        return resp

    def _ws_url(self) -> str:
        return self.base.replace("https://", "wss://").replace("http://", "ws://")

    def register(self, agent_id: str, org_id: str, display_name: str,
                 capabilities: list[str]) -> bool:
        body: dict = {
            "agent_id":     agent_id,
            "org_id":       org_id,
            "display_name": display_name,
            "capabilities": capabilities,
        }
        resp = self._http.post(f"{self.base}/registry/agents", json=body)
        if resp.status_code == 409:
            return False
        resp.raise_for_status()
        return True

    def login(self, agent_id: str, org_id: str, cert_path: str, key_path: str) -> None:
        """Authenticate the agent via x509 client_assertion + DPoP proof (RFC 9449)."""
        self._label = agent_id
        try:
            priv_key_pem = Path(key_path).read_text()
            self._signing_key_pem = priv_key_pem
            cert_pem = Path(cert_path).read_bytes()
            cert     = crypto_x509.load_pem_x509_certificate(cert_pem)
            cert_der = cert.public_bytes(serialization.Encoding.DER)
            x5c      = [base64.b64encode(cert_der).decode()]

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

            # Generate ephemeral DPoP key for this session
            self._init_dpop_key()
            token_url = f"{self.base}/auth/token"

            # First attempt — may fail with 401 use_dpop_nonce (RFC 9449 §8)
            dpop_proof = self._dpop_proof("POST", token_url, access_token=None)
            resp = self._http.post(
                token_url,
                json={"client_assertion": assertion},
                headers={"DPoP": dpop_proof},
            )

            # Handle server nonce requirement — retry once with the nonce
            if resp.status_code == 401 and "use_dpop_nonce" in resp.text:
                self._update_nonce(resp)
                dpop_proof = self._dpop_proof("POST", token_url, access_token=None)
                resp = self._http.post(
                    token_url,
                    json={"client_assertion": assertion},
                    headers={"DPoP": dpop_proof},
                )

            resp.raise_for_status()
            self._update_nonce(resp)
            self.token = resp.json()["access_token"]
        except (httpx.ConnectError, httpx.TimeoutException) as e:
            print(f"[{agent_id}] Broker non raggiungibile: {e}", flush=True)
            sys.exit(1)
        except httpx.HTTPStatusError as e:
            print(f"[{agent_id}] Login fallito (HTTP {e.response.status_code}): {e.response.text}", flush=True)
            sys.exit(1)

    _PUBKEY_CACHE_TTL = 300  # seconds — force refresh after 5 minutes

    def get_agent_public_key(self, agent_id: str, force_refresh: bool = False) -> str:
        """Retrieve agent PEM public key from the broker (TTL-cached)."""
        if not force_refresh and agent_id in self._pubkey_cache:
            pubkey_pem, fetched_at = self._pubkey_cache[agent_id]
            if time.time() - fetched_at < self._PUBKEY_CACHE_TTL:
                return pubkey_pem
        path = f"/registry/agents/{agent_id}/public-key"
        resp = self._authed_request("GET", path)
        resp.raise_for_status()
        pubkey_pem = resp.json()["public_key_pem"]
        self._pubkey_cache[agent_id] = (pubkey_pem, time.time())
        return pubkey_pem

    def discover(self, capabilities: list[str]) -> list[dict]:
        path = "/registry/agents/search"
        resp = self._authed_request("GET", path, params=[("capability", c) for c in capabilities])
        resp.raise_for_status()
        return resp.json().get("agents", [])

    def open_session(self, target_agent_id: str, target_org_id: str,
                     capabilities: list[str]) -> str:
        path = "/broker/sessions"
        resp = self._authed_request("POST", path, json={
            "target_agent_id":        target_agent_id,
            "target_org_id":          target_org_id,
            "requested_capabilities": capabilities,
        })
        resp.raise_for_status()
        return resp.json()["session_id"]

    def accept_session(self, session_id: str) -> None:
        path = f"/broker/sessions/{session_id}/accept"
        resp = self._authed_request("POST", path)
        resp.raise_for_status()

    def close_session(self, session_id: str) -> None:
        path = f"/broker/sessions/{session_id}/close"
        resp = self._authed_request("POST", path)
        resp.raise_for_status()

    def list_sessions(self, status_filter: str | None = None) -> list[dict]:
        path = "/broker/sessions"
        params = {}
        if status_filter:
            params["status"] = status_filter
        resp = self._authed_request("GET", path, params=params)
        resp.raise_for_status()
        return resp.json()

    def send(self, session_id: str, sender_agent_id: str, payload: dict,
             recipient_agent_id: str | None = None) -> None:
        from app.auth.message_signer import sign_message as _sign_message
        from app.e2e_crypto import encrypt_for_agent
        nonce = str(uuid.uuid4())
        timestamp = int(time.time())
        if not self._signing_key_pem:
            raise RuntimeError("Chiave di firma non disponibile — chiama login() prima")

        if not recipient_agent_id:
            raise ValueError(
                "recipient_agent_id is required — plaintext messages are not allowed. "
                "All messages must be E2E encrypted."
            )

        # Inner signature on plaintext (non-repudiation for the recipient)
        inner_sig = _sign_message(self._signing_key_pem, session_id, sender_agent_id, nonce, timestamp, payload)
        # Encrypt payload + inner signature with recipient's public key
        recipient_pubkey = self.get_agent_public_key(recipient_agent_id)
        cipher_blob = encrypt_for_agent(recipient_pubkey, payload, inner_sig, session_id, sender_agent_id)
        # Outer signature on ciphertext (transport integrity for the broker)
        outer_sig = _sign_message(self._signing_key_pem, session_id, sender_agent_id, nonce, timestamp, cipher_blob)
        envelope_payload = cipher_blob
        envelope_sig = outer_sig

        envelope = {
            "session_id":       session_id,
            "sender_agent_id":  sender_agent_id,
            "payload":          envelope_payload,
            "nonce":            nonce,
            "timestamp":        timestamp,
            "signature":        envelope_sig,
        }
        path = f"/broker/sessions/{session_id}/messages"
        for attempt in range(3):
            try:
                resp = self._authed_request("POST", path, json=envelope)
                resp.raise_for_status()
                return
            except (httpx.ConnectError, httpx.TimeoutException):
                if attempt < 2:
                    print(f"[{self._label}] Broker non raggiungibile — retry in 2s...", flush=True)
                    time.sleep(2)
                else:
                    print(f"[{self._label}] Broker non raggiungibile dopo 3 tentativi.", flush=True)
                    sys.exit(1)

    def decrypt_payload(self, msg: dict, session_id: str | None = None) -> dict:
        """
        Decrypt the payload of a received message.

        session_id must be supplied explicitly: the REST InboxMessage and the
        WebSocket inner message dict do NOT include it, so falling back to
        msg.get("session_id") would produce an empty string and cause an
        AES-GCM AAD mismatch.  If left as None and not present in the dict,
        decryption is skipped and the raw payload is returned unchanged.
        """
        if not self._signing_key_pem:
            return msg
        p = msg.get("payload", {})
        if not isinstance(p, dict) or "ciphertext" not in p:
            return msg
        sid = session_id or msg.get("session_id", "")
        if not sid:
            return msg  # cannot decrypt without session_id — skip silently
        try:
            from app.e2e_crypto import decrypt_from_agent
            sender_agent_id = msg.get("sender_agent_id", "")
            plaintext_dict, _inner_sig = decrypt_from_agent(
                self._signing_key_pem, p, sid, sender_agent_id
            )
            msg = dict(msg)
            msg["payload"] = plaintext_dict
        except Exception as exc:
            log("sdk", f"E2E decryption failed for session {sid} — message rejected", RED)
            raise ValueError(f"E2E decryption failed: message integrity cannot be verified") from exc
        return msg

    def poll(self, session_id: str, after: int = -1, poll_interval: int = 2) -> list[dict]:
        path = f"/broker/sessions/{session_id}/messages"
        for attempt in range(5):
            try:
                resp = self._authed_request("GET", path, params={"after": after})
                resp.raise_for_status()
                messages = resp.json()
                return [self.decrypt_payload(m, session_id=session_id) for m in messages]
            except (httpx.ConnectError, httpx.TimeoutException):
                if attempt < 4:
                    time.sleep(poll_interval)
                else:
                    print(f"[{self._label}] Broker non raggiungibile.", flush=True)
                    sys.exit(1)
        return []

    def close(self) -> None:
        self._http.close()


# ─────────────────────────────────────────────
# WebSocket helper
# ─────────────────────────────────────────────

def _open_ws(broker: BrokerClient, agent_id: str):
    """Open an authenticated WebSocket connection. Returns None if unavailable."""
    try:
        import ssl as _ssl
        from websockets.sync.client import connect as ws_connect
        ws_url = broker._ws_url() + "/broker/ws"
        ws_kwargs: dict = {"open_timeout": 5}
        if ws_url.startswith("wss://") and not broker._verify_tls:
            ssl_ctx = _ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = _ssl.CERT_NONE
            ws_kwargs["ssl"] = ssl_ctx
        ws = ws_connect(ws_url, **ws_kwargs)

        # DPoP proof for the WS upgrade: htm=GET, htu=HTTP equivalent of ws_url
        http_htu = ws_url.replace("wss://", "https://").replace("ws://", "http://")
        dpop_proof = broker._dpop_proof("GET", http_htu, broker.token)

        ws.send(json.dumps({
            "type": "auth",
            "token": broker.token,
            "dpop_proof": dpop_proof,
        }))
        resp = json.loads(ws.recv())
        if resp.get("type") == "auth_ok":
            log(agent_id, "WebSocket connesso.", GREEN)
            return ws
        ws.close()
        log(agent_id, "WebSocket non disponibile, fallback su REST polling.", YELLOW)
        return None
    except Exception as e:
        log(agent_id, f"WebSocket non disponibile: {e}", YELLOW)
        return None


# ─────────────────────────────────────────────
# Logica messaggi condivisa
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
    """Elabora un messaggio ricevuto: genera risposta, invia, aggiorna stato.
    Restituisce (continua: bool, turns: int).
    """
    log(agent_id, f"Ricevuto da {sender_id}:", YELLOW)
    log_msg("IN", {"text": received_text})

    if _contains_fine(received_text):
        log(agent_id, "Conversazione terminata dall'altro agente.", GREEN)
        try:
            broker.close_session(session_id)
        except Exception:
            pass
        return False, turns

    reply = ask_llm(system_prompt, conversation, received_text)
    log(agent_id, "Rispondo:", CYAN)
    log_msg("OUT", {"text": reply})

    payload = {"type": payload_type, "text": reply}
    payload.update(extra_payload)
    broker.send(session_id, agent_id, payload, recipient_agent_id=sender_id)
    conversation.append({"role": "user",      "content": received_text})
    conversation.append({"role": "assistant", "content": reply})
    turns += 1

    if _contains_fine(reply):
        log(agent_id, "Conversazione conclusa.", GREEN)
        try:
            broker.close_session(session_id)
        except Exception:
            pass
        return False, turns

    if turns >= max_turns:
        log(agent_id, f"Limite massimo di turni raggiunto ({max_turns}), chiudo sessione.", YELLOW)
        try:
            broker.close_session(session_id)
        except Exception:
            pass
        return False, turns

    return True, turns


# ─────────────────────────────────────────────
# Runner: INITIATOR
# ─────────────────────────────────────────────

def run_initiator(broker: BrokerClient, agent_id: str, max_turns: int,
                  poll_interval: int, system_prompt: str) -> None:
    target_agent_id = os.environ.get("TARGET_AGENT_ID")
    target_org_id   = os.environ.get("TARGET_ORG_ID")
    order_id        = cfg("ORDER_ID", "ORD-2026-001")
    order_item      = cfg("ORDER_ITEM", "zinc-plated M8 bolts")
    order_quantity  = cfg("ORDER_QUANTITY", "1000")

    if not target_agent_id:
        needed_caps = cfg("CAPABILITIES", "order.read,order.write").split(",")
        log(agent_id, f"TARGET_AGENT_ID non impostato — cerco nel network {needed_caps}...", CYAN)
        candidates = broker.discover(needed_caps)
        if not candidates:
            log(agent_id, "Nessun agente trovato con le capabilities richieste.", RED)
            return
        chosen          = candidates[0]
        target_agent_id = chosen["agent_id"]
        target_org_id   = chosen["org_id"]
        log(agent_id,
            f"Trovati {len(candidates)} candidati — connessione a "
            f"{target_agent_id} ({chosen['display_name']}, org: {target_org_id})", GREEN)

    conversation: list[dict] = []
    turns = 0
    session_id: str | None = None
    last_seq = -1

    existing = broker.list_sessions()
    resumed  = next(
        (s for s in existing
         if s["target_agent_id"] == target_agent_id and s["status"] == "active"),
        None,
    )

    if resumed:
        session_id = resumed["session_id"]
        log(agent_id, f"Sessione attiva ripristinata: {session_id}", YELLOW)
        queued   = broker.poll(session_id, after=-1)
        last_seq = max((m["seq"] for m in queued), default=-1)
        if queued:
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
            log(agent_id, "Inbox vuota — invio richiesta ordine iniziale.", CYAN)
            initial_user_msg = (
                f"Devo piazzare l'ordine {order_id}: {order_quantity} {order_item}. "
                f"Prepara la richiesta formale al fornitore."
            )
            first_message = ask_llm(system_prompt, [], initial_user_msg)
            log_msg("OUT", {"text": first_message})
            broker.send(session_id, agent_id,
                        {"type": "order_request", "text": first_message, "order_id": order_id},
                        recipient_agent_id=target_agent_id)
            conversation = [
                {"role": "user",      "content": initial_user_msg},
                {"role": "assistant", "content": first_message},
            ]
            turns = 1
    else:
        log(agent_id, f"Apertura sessione verso {target_agent_id}...", CYAN)
        for attempt in range(10):
            try:
                session_id = broker.open_session(
                    target_agent_id, target_org_id, ["order.write"]
                )
                break
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 404 and attempt < 9:
                    log(agent_id, f"Target non ancora registrato, retry ({attempt+1}/10)...", GRAY)
                    time.sleep(3)
                else:
                    raise

        log(agent_id, f"Sessione creata: {session_id}", GREEN)
        log(agent_id, "Attendo che il responder accetti...", GRAY)

        for _ in range(30):
            sessions = broker.list_sessions()
            s = next((x for x in sessions if x["session_id"] == session_id), None)
            if s and s["status"] == "active":
                break
            time.sleep(poll_interval)
        else:
            log(agent_id, "Timeout: il responder non ha accettato la sessione.", RED)
            return

        log(agent_id, "Sessione attiva — avvio negoziazione.", GREEN)
        initial_user_msg = (
            f"Devo piazzare l'ordine {order_id}: {order_quantity} {order_item}. "
            f"Prepara la richiesta formale al fornitore, chiedendo disponibilità, "
            f"prezzo unitario, tempi di consegna e condizioni di pagamento."
        )
        first_message = ask_llm(system_prompt, [], initial_user_msg)
        log(agent_id, "Invio richiesta ordine:", CYAN)
        log_msg("OUT", {"text": first_message})
        broker.send(session_id, agent_id,
                    {"type": "order_request", "text": first_message, "order_id": order_id},
                    recipient_agent_id=target_agent_id)
        conversation = [
            {"role": "user",      "content": initial_user_msg},
            {"role": "assistant", "content": first_message},
        ]
        turns    = 1
        last_seq = -1

    ws = _open_ws(broker, agent_id)
    if ws is not None:
        try:
            for raw in ws:
                msg = json.loads(raw)
                if msg.get("type") != "new_message":
                    continue
                if msg.get("session_id") != session_id:
                    continue
                m = broker.decrypt_payload(msg["message"], session_id=session_id)
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
            log(agent_id, f"WS interrotto: {e}", YELLOW)
        finally:
            try:
                ws.close()
            except Exception:
                pass
    else:
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
        log(agent_id, f"Limite di {max_turns} turni raggiunto.", YELLOW)


# ─────────────────────────────────────────────
# Runner: RESPONDER
# ─────────────────────────────────────────────

def _responder_handle_session(broker: BrokerClient, agent_id: str,
                               session_id: str, max_turns: int,
                               poll_interval: int, system_prompt: str) -> None:
    """Gestisce una singola sessione dall'inizio alla fine."""
    conversation: list[dict] = []
    turns = 0

    queued   = broker.poll(session_id, after=-1)
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

    while True:
        time.sleep(poll_interval)
        sessions = broker.list_sessions()
        current  = next((s for s in sessions if s["session_id"] == session_id), None)
        if current is None or current["status"] == "closed":
            log(agent_id, f"Sessione {session_id} chiusa — pronto per il prossimo.", GREEN)
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
            log(agent_id, f"Limite turni raggiunto per sessione {session_id} — chiudo.", YELLOW)
            try:
                broker.close_session(session_id)
            except Exception:
                pass
            return


def run_responder(broker: BrokerClient, agent_id: str, max_turns: int,
                  poll_interval: int, system_prompt: str) -> None:
    """Loop infinito: accetta sessioni, gestisce la conversazione, riparte."""
    log(agent_id, "Online — in attesa di sessioni in arrivo (Ctrl+C per fermare).", CYAN)

    active    = broker.list_sessions(status_filter="active")
    my_active = [s for s in active if s["target_agent_id"] == agent_id]
    if my_active:
        session_id = my_active[0]["session_id"]
        log(agent_id, f"Ripristino sessione attiva: {session_id}", YELLOW)
        _responder_handle_session(broker, agent_id, session_id,
                                  max_turns, poll_interval, system_prompt)

    while True:
        try:
            ws = _open_ws(broker, agent_id)
        except Exception:
            ws = None

        if ws is not None:
            try:
                pending    = broker.list_sessions(status_filter="pending")
                my_pending = [s for s in pending if s["target_agent_id"] == agent_id]
                if my_pending:
                    session_id = my_pending[0]["session_id"]
                    broker.accept_session(session_id)
                    log(agent_id, f"Sessione accettata (pre-WS): {session_id}", GREEN)
                    ws.close()
                    _responder_handle_session(broker, agent_id, session_id,
                                              max_turns, poll_interval, system_prompt)
                    continue

                log(agent_id, "In ascolto su WebSocket...", GRAY)
                for raw in ws:
                    msg = json.loads(raw)
                    if msg.get("type") == "session_pending":
                        session_id = msg["session_id"]
                        initiator  = msg.get("initiator_agent_id", "unknown")
                        broker.accept_session(session_id)
                        log(agent_id, f"Nuova sessione da {initiator}: {session_id}", GREEN)
                        ws.close()
                        _responder_handle_session(broker, agent_id, session_id,
                                                  max_turns, poll_interval, system_prompt)
                        break
            except KeyboardInterrupt:
                raise
            except Exception as e:
                log(agent_id, f"Errore WS: {e} — switching a polling.", YELLOW)
            finally:
                try:
                    ws.close()
                except Exception:
                    pass
        else:
            time.sleep(poll_interval)
            pending    = broker.list_sessions(status_filter="pending")
            my_pending = [s for s in pending if s["target_agent_id"] == agent_id]
            if my_pending:
                session_id = my_pending[0]["session_id"]
                initiator  = my_pending[0]["initiator_agent_id"]
                broker.accept_session(session_id)
                log(agent_id, f"Nuova sessione da {initiator}: {session_id}", GREEN)
                _responder_handle_session(broker, agent_id, session_id,
                                          max_turns, poll_interval, system_prompt)
