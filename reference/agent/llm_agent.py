"""LLM-driven Cullis agent for the reference deployment.

Each container instance runs ONE agent. Identity comes from the TLS
client cert + private key + DPoP keypair (ADR-014) parked under
``/state/{org}/agents/{name}/``: bootstrap mints the cert/key, and
bootstrap-mastio drops the matching private DPoP JWK alongside after
verifying the Mastio-side enrollment. The role (BUYER / INVENTORY /
BROKER / SUPPLIER) selects the system prompt that frames the LLM's
decision-making each turn.

Loop:
  1. (optional, once) inject ``INITIAL_PROMPT`` env as if it were a
     user-side message — kicks off the scenario for the seeding agent.
  2. Poll Mastio inbox for new oneshot envelopes.
  3. For each new envelope: decrypt, extract content, build an LLM
     prompt (system = role file, user = "<sender> says: <content>"),
     call Ollama with structured-output ``format`` schema → get back a
     strict JSON object describing one tool call.
  4. Execute the tool call against Cullis SDK (``send_oneshot`` /
     ``discover``) and log the result. ``done`` ends the turn.
  5. Sleep, loop.

Hop counter in the payload caps multi-agent chains at MAX_HOPS so a
chatty model can't trigger infinite ping-pong.
"""
from __future__ import annotations

import json
import logging
import os
import pathlib
import sys
import time
from typing import Any

import httpx

from cullis_sdk import CullisClient

# ── Configuration (env-driven) ──────────────────────────────────────

BROKER_URL = os.environ["BROKER_URL"].rstrip("/")
ORG_ID = os.environ["ORG_ID"]
AGENT_NAME = os.environ["AGENT_NAME"]
ROLE = os.environ.get("AGENT_ROLE", "agent")  # buyer/inventory/broker/supplier
SELF_ID = f"{ORG_ID}::{AGENT_NAME}"

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://host.docker.internal:11434").rstrip("/")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "gemma3:1b")

INITIAL_PROMPT = os.environ.get("INITIAL_PROMPT", "").strip() or None

POLL_INTERVAL_S = float(os.environ.get("POLL_INTERVAL_S", "2.0"))
LLM_TIMEOUT_S = float(os.environ.get("LLM_TIMEOUT_S", "30.0"))
MAX_HOPS = int(os.environ.get("MAX_HOPS", "8"))

PROMPTS_DIR = pathlib.Path(os.environ.get("PROMPTS_DIR", "/app/prompts"))
IDENTITY_DIR = pathlib.Path(
    os.environ.get("IDENTITY_DIR", f"/state/{ORG_ID}/agents/{AGENT_NAME}")
)

# ── Logging ─────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format=f"%(asctime)s [{SELF_ID}|{ROLE}] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger(__name__)


# ── Ollama integration ─────────────────────────────────────────────

# JSON Schema enforced by Ollama's `format` parameter. Per the personal-
# agent's stress test (2026-04-26), this produced 100% valid JSON across
# 18 calls × 6 concurrent on gemma3:1b. We do not use Ollama's tool-
# calling protocol — issue #14493 hangs qwen3.5 runners on the Hermes
# template mismatch, and gemma3 doesn't natively support tool calls.
TOOL_SCHEMA = {
    "type": "object",
    "properties": {
        "tool": {
            "type": "string",
            # cullis_discover removed — it hits /v1/federation/agents/search
            # which requires a Court-issued JWT; under ADR-012 local-first
            # auth, login_via_proxy issues a local Mastio JWT that the Court
            # rejects with 401. The reference scenario doesn't need real
            # discovery: every prompt names its target peer explicitly.
            "enum": ["cullis_send", "done"],
        },
        "args": {
            "type": "object",
            "properties": {
                "to": {"type": "string"},
                "content": {"type": "string"},
                "reason": {"type": "string"},
            },
        },
    },
    "required": ["tool", "args"],
}


def _ollama_decide(system_prompt: str, user_message: str) -> dict:
    """Single LLM call with structured-output schema → strict JSON tool call."""
    body = {
        "model": OLLAMA_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ],
        "format": TOOL_SCHEMA,
        "stream": False,
        "options": {"temperature": 0},
    }
    started = time.monotonic()
    r = httpx.post(
        f"{OLLAMA_HOST}/api/chat", json=body, timeout=LLM_TIMEOUT_S,
    )
    elapsed = time.monotonic() - started
    if r.status_code != 200:
        raise RuntimeError(
            f"Ollama HTTP {r.status_code}: {r.text[:200]}"
        )
    response_msg = r.json().get("message", {}).get("content", "")
    log.info(f"llm.decide t={elapsed:.2f}s response={response_msg[:200]}")
    try:
        return json.loads(response_msg)
    except json.JSONDecodeError as exc:
        # Should never happen with format schema, but guard so a model
        # quirk doesn't kill the agent loop.
        raise RuntimeError(
            f"Ollama returned non-JSON despite format schema: {exc} → {response_msg[:200]}"
        ) from exc


# ── Cullis tool execution ───────────────────────────────────────────

def _exec_tool(client: CullisClient, decision: dict, hops: int) -> None:
    """Apply the LLM's decision via the Cullis SDK."""
    tool = decision.get("tool")
    args = decision.get("args", {})
    reason = args.get("reason", "")[:120]

    if tool == "done":
        log.info(f"tool.done reason={reason!r}")
        return

    if tool == "cullis_send":
        to = args.get("to", "").strip()
        content = args.get("content", "").strip()
        if not to or not content:
            log.warning(f"tool.cullis_send missing to/content args={args!r}")
            return
        payload = {"content": content, "from": SELF_ID, "hops": hops}
        try:
            resp = client.send_oneshot(to, payload, ttl_seconds=300)
            log.info(
                f"tool.cullis_send OK to={to} hops={hops} "
                f"msg_id={resp.get('msg_id', '?')[:12]} reason={reason!r}"
            )
        except Exception as exc:
            log.error(f"tool.cullis_send FAILED to={to} err={exc!r}")
        return

    log.warning(f"tool.unknown {tool!r} args={args!r}")


# ── Main loop ───────────────────────────────────────────────────────

def _load_prompt() -> str:
    """Read the role-specific system prompt from PROMPTS_DIR."""
    candidate = PROMPTS_DIR / f"{ROLE}.txt"
    if not candidate.exists():
        log.warning(f"prompt file {candidate} missing — using stub")
        return f"You are {SELF_ID} (role={ROLE}). Always respond with {{\"tool\": \"done\", \"args\": {{\"reason\": \"no prompt\"}}}}."
    return candidate.read_text()


def _wait_identity(timeout_s: float = 60.0) -> None:
    """Block until bootstrap + bootstrap-mastio have written cert+key+dpop.jwk."""
    deadline = time.monotonic() + timeout_s
    cert = IDENTITY_DIR / "agent.pem"
    key = IDENTITY_DIR / "agent-key.pem"
    dpop = IDENTITY_DIR / "dpop.jwk"
    while time.monotonic() < deadline:
        if cert.exists() and key.exists() and dpop.exists():
            return
        time.sleep(0.5)
    raise SystemExit(
        f"identity not provisioned at {IDENTITY_DIR} after {timeout_s:.0f}s"
    )


def _load_client() -> CullisClient:
    """Build a CullisClient from the on-disk credentials.

    ADR-014 — TLS client cert authenticates against the per-org nginx
    sidecar on ``https://proxy-X:9443``. ``verify_tls=False`` because
    the reference deployment's Org CA is self-signed.
    """
    _wait_identity()
    cert_path = IDENTITY_DIR / "agent.pem"
    key_path = IDENTITY_DIR / "agent-key.pem"
    client = CullisClient.from_identity_dir(
        BROKER_URL,
        cert_path=cert_path,
        key_path=key_path,
        dpop_key_path=IDENTITY_DIR / "dpop.jwk",
        agent_id=SELF_ID,
        org_id=ORG_ID,
        verify_tls=False,
    )
    client.login_via_proxy()
    # send_oneshot signs each envelope with the agent's private key for
    # end-to-end non-repudiation. The TLS key doubles as the signing
    # key — the broker verifies the inner signature against the public
    # half pinned in ``internal_agents.cert_pem``.
    client._signing_key_pem = key_path.read_text()
    log.info(f"signing key loaded ({key_path})")
    log.info(f"identity loaded; logged in via proxy ({BROKER_URL})")
    return client


def _format_user_msg(sender: str, content: str, hops: int) -> str:
    """Frame an inbound message for the LLM.

    gemma3:1b is small enough that placeholder text in the system prompt
    (e.g. "<sender's agent_id>") sometimes gets copy-pasted verbatim into
    the tool call instead of being substituted. We anchor the literal
    values inline so the model can quote them directly.
    """
    return (
        f"You ARE the agent {SELF_ID}.\n"
        f"You just received a message from sender_agent_id={sender!r} "
        f"(hop {hops}/{MAX_HOPS}).\n\n"
        f"Message content: {content!r}\n\n"
        f"To reply to the sender, your tool call MUST use exactly:\n"
        f"  \"to\": {sender!r}\n\n"
        f"Decide what to do next. Respond with one tool call as JSON."
    )


def main() -> int:
    log.info(f"booting agent role={ROLE} ollama={OLLAMA_HOST} model={OLLAMA_MODEL}")
    system_prompt = _load_prompt()
    log.info(f"loaded role prompt ({len(system_prompt)} chars)")
    client = _load_client()
    pathlib.Path("/tmp/ready").write_text(SELF_ID + "\n")

    # Optional kick-off: scenarios/widget-hunt.sh sets INITIAL_PROMPT on
    # the seeding agent so the conversation has somewhere to start.
    if INITIAL_PROMPT:
        log.info(f"kick-off prompt={INITIAL_PROMPT!r}")
        try:
            decision = _ollama_decide(
                system_prompt,
                f"You ({SELF_ID}) have been given this task by your operator:\n\n"
                f"\"{INITIAL_PROMPT}\"\n\n"
                f"Decide your first action. Respond with one tool call as JSON.",
            )
            _exec_tool(client, decision, hops=1)
        except Exception as exc:
            log.error(f"kick-off failed: {exc!r}")

    seen: set[str] = set()
    while True:
        try:
            rows = client.receive_oneshot()
        except Exception as exc:
            log.error(f"receive_oneshot failed: {exc!r}")
            time.sleep(POLL_INTERVAL_S)
            continue

        for row in rows:
            msg_id = row.get("msg_id")
            if not msg_id or msg_id in seen:
                continue
            seen.add(msg_id)

            try:
                payload = client.decrypt_oneshot(row)
            except Exception as exc:
                log.warning(f"decrypt_oneshot {msg_id[:8]} failed: {exc!r}")
                continue

            inner = payload.get("payload") if isinstance(payload, dict) else {}
            if not isinstance(inner, dict):
                inner = {}
            content = str(inner.get("content", ""))
            sender = row.get("sender_agent_id", "?")
            hops = int(inner.get("hops", 0)) + 1

            log.info(
                f"inbox.recv msg_id={msg_id[:12]} from={sender} hops={hops} "
                f"content={content[:120]!r}"
            )

            if hops > MAX_HOPS:
                log.warning(
                    f"max_hops={MAX_HOPS} reached on msg_id={msg_id[:12]} from={sender} — dropping"
                )
                continue

            try:
                decision = _ollama_decide(system_prompt, _format_user_msg(sender, content, hops))
                _exec_tool(client, decision, hops=hops)
            except Exception as exc:
                log.error(f"decide/exec failed for {msg_id[:8]}: {exc!r}")

        time.sleep(POLL_INTERVAL_S)


if __name__ == "__main__":
    sys.exit(main())
