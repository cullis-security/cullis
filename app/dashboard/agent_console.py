"""
Agent Console — interactive chat UI for org users.

Allows a human to interact with a buyer LLM agent that autonomously uses
Cullis broker tools (discover, open_session, send_message, check_responses)
to negotiate with supplier agents on the network.

The BrokerClient runs server-side; the browser is a thin chat interface.
"""
import json
import logging
import os
import sys
import time
import threading
from dataclasses import dataclass, field
from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import RedirectResponse

from app.dashboard.session import require_login, verify_csrf, DashboardSession
from app.db.database import get_db

_log = logging.getLogger("agent_trust")

_TEMPLATE_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATE_DIR))

router = APIRouter(prefix="/dashboard/agent-console", tags=["agent-console"])

# ─────────────────────────────────────────────────────────────────────────────
# In-memory console sessions (keyed by org_id)
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class ConsoleMessage:
    role: str          # "human", "assistant", "system", "tool"
    content: str
    tool_name: str | None = None


@dataclass
class AgentConsoleSession:
    org_id: str
    agent_id: str
    broker: object | None = None     # BrokerClient instance
    session_id: str | None = None    # Active broker session
    target_agent_id: str | None = None
    target_org_id: str | None = None
    messages: list[ConsoleMessage] = field(default_factory=list)
    llm_conversation: list[dict] = field(default_factory=list)
    last_seq: int = -1
    is_processing: bool = False


_console_sessions: dict[str, AgentConsoleSession] = {}


# ─────────────────────────────────────────────────────────────────────────────
# Anthropic tool definitions for the buyer LLM
# ─────────────────────────────────────────────────────────────────────────────

BUYER_TOOLS = [
    {
        "name": "discover_suppliers",
        "description": (
            "Search the Cullis federated trust network for supplier agents "
            "matching the given capabilities. Returns a list of available agents."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "capabilities": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Capabilities to search for, e.g. ['order.write', 'manufacturing']",
                },
            },
            "required": ["capabilities"],
        },
    },
    {
        "name": "open_session",
        "description": (
            "Open a trusted, policy-evaluated session with a supplier agent "
            "via the Cullis broker. Both organisations' policies are checked."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target_agent_id": {"type": "string", "description": "The supplier agent ID"},
                "target_org_id": {"type": "string", "description": "The supplier organisation ID"},
                "capabilities": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Capabilities requested for this session",
                },
            },
            "required": ["target_agent_id", "target_org_id", "capabilities"],
        },
    },
    {
        "name": "send_message_to_supplier",
        "description": (
            "Send a signed and E2E-encrypted message to the supplier through "
            "the active Cullis session. The message is cryptographically signed "
            "with your private key and encrypted with the supplier's public key."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "message": {
                    "type": "string",
                    "description": "The message text to send to the supplier",
                },
            },
            "required": ["message"],
        },
    },
    {
        "name": "check_supplier_responses",
        "description": (
            "Check if the supplier has sent any new messages in the active session. "
            "Messages are E2E-encrypted and will be decrypted with your private key."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "check_pending_sessions",
        "description": (
            "Check if any other agents on the Cullis network have requested "
            "a session with you. Returns a list of pending session requests."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "accept_session",
        "description": (
            "Accept an incoming session request from another agent. "
            "This makes the session active so you can exchange messages."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "The session ID to accept",
                },
            },
            "required": ["session_id"],
        },
    },
]

BUYER_SYSTEM_PROMPT = """\
You are a procurement assistant for {org_id}, operating through the Cullis \
federated trust broker. You help your human operator purchase industrial \
components from verified suppliers on the network.

You have tools to:
1. **discover_suppliers** — search the Cullis network for matching suppliers
2. **open_session** — open a cryptographically secured session with a supplier
3. **send_message_to_supplier** — send E2E-encrypted messages to the supplier
4. **check_supplier_responses** — check for new replies from the supplier

Workflow:
- When the human asks for something, use discover_suppliers to find matching suppliers.
- Open a session with the best match.
- Negotiate on behalf of the human: ask for pricing, availability, delivery, payment terms.
- Report results back to the human and ask for confirmation before finalising.
- Always communicate with the human in their language. With suppliers, use English.

Important:
- Always check for supplier responses before reporting "no answer" — the supplier \
  agent may need a few seconds to respond.
- Be precise and professional in B2B communications.
- When the session with the supplier is waiting for a response, tell the human \
  you're waiting and they can check back.
"""


# ─────────────────────────────────────────────────────────────────────────────
# Tool execution
# ─────────────────────────────────────────────────────────────────────────────

def _execute_tool(console: AgentConsoleSession, tool_name: str, tool_input: dict) -> str:
    """Execute a broker tool and return the result as a string."""
    broker = console.broker
    if broker is None:
        return json.dumps({"error": "Broker not connected. Start the console first."})

    try:
        if tool_name == "discover_suppliers":
            caps = tool_input.get("capabilities", ["order.write"])
            agents = broker.discover(caps)
            if not agents:
                return json.dumps({"result": "No suppliers found matching the requested capabilities."})
            return json.dumps({"result": agents})

        elif tool_name == "open_session":
            target_agent = tool_input["target_agent_id"]
            target_org = tool_input["target_org_id"]
            caps = tool_input.get("capabilities", ["order.write"])

            session_id = broker.open_session(target_agent, target_org, caps)
            console.session_id = session_id
            console.target_agent_id = target_agent
            console.target_org_id = target_org

            # Wait for session to be accepted (up to 30s)
            for _ in range(15):
                sessions = broker.list_sessions()
                s = next((x for x in sessions if x["session_id"] == session_id), None)
                if s and s["status"] == "active":
                    return json.dumps({"result": f"Session {session_id} is now active with {target_agent} ({target_org})."})
                time.sleep(2)

            return json.dumps({"result": f"Session {session_id} created but target has not accepted yet. Try check_supplier_responses later."})

        elif tool_name == "send_message_to_supplier":
            if not console.session_id or not console.target_agent_id:
                return json.dumps({"error": "No active session. Use open_session first."})
            message = tool_input["message"]
            payload = {"type": "order_negotiation", "text": message}
            broker.send(console.session_id, console.agent_id, payload,
                        recipient_agent_id=console.target_agent_id)
            return json.dumps({"result": f"Message sent to {console.target_agent_id}."})

        elif tool_name == "check_supplier_responses":
            if not console.session_id:
                return json.dumps({"error": "No active session."})
            messages = broker.poll(console.session_id, after=console.last_seq)
            if not messages:
                return json.dumps({"result": "No new messages from the supplier."})
            texts = []
            for m in messages:
                console.last_seq = max(console.last_seq, m.get("seq", console.last_seq))
                text = m.get("payload", {}).get("text", json.dumps(m.get("payload", {})))
                texts.append({"from": m.get("sender_agent_id", "unknown"), "text": text})
            return json.dumps({"result": texts})

        elif tool_name == "check_pending_sessions":
            sessions_list = broker.list_sessions()
            pending = [
                s for s in sessions_list
                if s["status"] == "pending"
                and s["target_agent_id"] == console.agent_id
            ]
            if not pending:
                return json.dumps({"result": "No pending session requests."})
            items = [
                {
                    "session_id": s["session_id"],
                    "from_agent": s["initiator_agent_id"],
                    "from_org": s["initiator_org_id"],
                    "capabilities": s.get("requested_capabilities", []),
                }
                for s in pending
            ]
            return json.dumps({"result": items})

        elif tool_name == "accept_session":
            sid = tool_input["session_id"]
            broker.accept_session(sid)
            sessions_list = broker.list_sessions()
            s = next((x for x in sessions_list if x["session_id"] == sid), None)
            if s:
                console.session_id = sid
                console.target_agent_id = s["initiator_agent_id"]
                console.target_org_id = s["initiator_org_id"]
            return json.dumps({"result": f"Session {sid} accepted."})

        else:
            return json.dumps({"error": f"Unknown tool: {tool_name}"})

    except Exception as e:
        _log.exception("Tool execution error: %s", tool_name)
        return json.dumps({"error": str(e)})


# ─────────────────────────────────────────────────────────────────────────────
# LLM interaction with tool loop
# ─────────────────────────────────────────────────────────────────────────────

def _call_llm_with_tools(console: AgentConsoleSession, user_message: str) -> str:
    """Call Claude with tools, execute tool calls in a loop, return final text."""
    import anthropic

    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        from app.config import get_settings
        api_key = get_settings().anthropic_api_key
    if not api_key:
        return "Error: ANTHROPIC_API_KEY not configured."

    client = anthropic.Anthropic(api_key=api_key)
    system = BUYER_SYSTEM_PROMPT.format(org_id=console.org_id)

    console.llm_conversation.append({"role": "user", "content": user_message})

    messages = list(console.llm_conversation)
    max_iterations = 10  # safety limit for tool loops

    for _ in range(max_iterations):
        response = client.messages.create(
            model=os.environ.get("LLM_MODEL", "claude-sonnet-4-6"),
            max_tokens=2048,
            system=system,
            tools=BUYER_TOOLS,
            messages=messages,
        )

        # Collect text and tool_use blocks
        text_parts = []
        tool_calls = []
        for block in response.content:
            if block.type == "text":
                text_parts.append(block.text)
            elif block.type == "tool_use":
                tool_calls.append(block)

        if not tool_calls:
            # No more tools — final response
            final_text = "\n".join(text_parts)
            console.llm_conversation.append({"role": "assistant", "content": response.content})
            return final_text

        # Add assistant message with all content blocks
        console.llm_conversation.append({"role": "assistant", "content": response.content})
        messages = list(console.llm_conversation)

        # Execute each tool and add results
        tool_results = []
        for tc in tool_calls:
            console.messages.append(ConsoleMessage(
                role="tool",
                content=f"Calling {tc.name}...",
                tool_name=tc.name,
            ))
            result = _execute_tool(console, tc.name, tc.input)
            console.messages.append(ConsoleMessage(
                role="tool",
                content=f"{tc.name} → {result}",
                tool_name=tc.name,
            ))
            tool_results.append({
                "type": "tool_result",
                "tool_use_id": tc.id,
                "content": result,
            })

        console.llm_conversation.append({"role": "user", "content": tool_results})
        messages = list(console.llm_conversation)

    return "Reached maximum tool iterations. Please try again."


# ─────────────────────────────────────────────────────────────────────────────
# Context helper
# ─────────────────────────────────────────────────────────────────────────────

def _ctx(request: Request, session: DashboardSession, **kwargs) -> dict:
    return {"request": request, "session": session, "csrf_token": session.csrf_token, **kwargs}


# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────

@router.get("", response_class=HTMLResponse)
async def agent_console_page(request: Request, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if session.is_admin:
        return RedirectResponse(url="/dashboard", status_code=303)

    org_id = session.org_id
    console = _console_sessions.get(org_id)
    connected = console is not None and console.broker is not None and console.broker.token is not None
    msgs = console.messages if console else []

    # Get agents for this org
    from sqlalchemy import select
    from app.registry.store import AgentRecord
    result = await db.execute(
        select(AgentRecord).where(AgentRecord.org_id == org_id, AgentRecord.is_active.is_(True))
    )
    agents = result.scalars().all()

    return templates.TemplateResponse("agent_console.html",
        _ctx(request, session, active="agent_console", connected=connected,
             messages=msgs, agents=agents))


@router.post("/start", response_class=HTMLResponse)
async def agent_console_start(request: Request, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return session
    if session.is_admin:
        return RedirectResponse(url="/dashboard", status_code=303)
    if not await verify_csrf(request, session):
        return RedirectResponse(url="/dashboard/agent-console", status_code=303)

    form = await request.form()
    agent_id = str(form.get("agent_id", "")).strip()
    if not agent_id:
        return RedirectResponse(url="/dashboard/agent-console", status_code=303)

    org_id = session.org_id

    # Look up agent's cert and key from the KMS
    from app.registry.store import get_agent_by_id
    agent = await get_agent_by_id(db, agent_id)
    if not agent or agent.org_id != org_id:
        return RedirectResponse(url="/dashboard/agent-console", status_code=303)

    # Try to load cert/key from filesystem (certs/{org_id}/{agent_id}/)
    cert_pem = None
    key_pem = None

    # Check for credentials in KMS (local filesystem)
    from app.config import get_settings
    settings = get_settings()

    # Try standard cert paths
    for base in [Path("certs"), Path(f"certs/{org_id}")]:
        for pattern in [f"{agent_id}-cert.pem", f"{agent_id}.pem", "cert.pem"]:
            p = base / pattern
            if p.exists():
                cert_pem = p.read_text()
                break
        for pattern in [f"{agent_id}-key.pem", f"{agent_id}.key", "key.pem"]:
            p = base / pattern
            if p.exists():
                key_pem = p.read_text()
                break
        if cert_pem and key_pem:
            break

    # Also try the agent env file pattern from join_agent
    if not cert_pem or not key_pem:
        # Scan for .env files that contain this agent's credentials
        for env_file in Path("certs").rglob("*.env"):
            try:
                env_content = env_file.read_text()
                if f"AGENT_ID={agent_id}" in env_content:
                    for line in env_content.splitlines():
                        if line.startswith("AGENT_CERT_PATH="):
                            cp = Path(line.split("=", 1)[1].strip())
                            if cp.exists():
                                cert_pem = cp.read_text()
                        elif line.startswith("AGENT_KEY_PATH="):
                            kp = Path(line.split("=", 1)[1].strip())
                            if kp.exists():
                                key_pem = kp.read_text()
                    if cert_pem and key_pem:
                        break
            except Exception:
                continue

    if not cert_pem or not key_pem:
        _log.warning("Cannot find cert/key for agent %s — console start failed", agent_id)
        return RedirectResponse(url="/dashboard/agent-console", status_code=303)

    # Create BrokerClient and authenticate
    # Import here to avoid circular imports at module level
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))
    from agents.sdk import BrokerClient

    broker_url = settings.broker_public_url or f"http://127.0.0.1:{settings.broker_port}"
    broker = BrokerClient(broker_url, verify_tls=False)

    try:
        broker.register(agent_id, org_id, agent.display_name or agent_id,
                        agent.capabilities or [])
    except Exception:
        pass  # Already registered

    try:
        broker.login_from_pem(agent_id, org_id, cert_pem, key_pem)
    except Exception as e:
        _log.exception("Agent console login failed for %s", agent_id)
        return RedirectResponse(url="/dashboard/agent-console", status_code=303)

    console = AgentConsoleSession(
        org_id=org_id,
        agent_id=agent_id,
        broker=broker,
    )
    console.messages.append(ConsoleMessage(
        role="system",
        content=f"Connected as {agent_id} ({org_id}). You can now interact with suppliers on the Cullis network.",
    ))
    _console_sessions[org_id] = console

    return RedirectResponse(url="/dashboard/agent-console", status_code=303)


@router.post("/send")
async def agent_console_send(request: Request, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    if session.is_admin:
        return JSONResponse({"error": "Admin cannot use agent console"}, status_code=403)
    if not await verify_csrf(request, session):
        return JSONResponse({"error": "CSRF token invalid"}, status_code=403)

    org_id = session.org_id
    console = _console_sessions.get(org_id)
    if not console or not console.broker:
        return JSONResponse({"error": "Console not started"}, status_code=400)

    form = await request.form()
    user_msg = str(form.get("message", "")).strip()
    if not user_msg:
        return JSONResponse({"error": "Empty message"}, status_code=400)

    if console.is_processing:
        return JSONResponse({"error": "Already processing a request"}, status_code=429)

    console.is_processing = True
    console.messages.append(ConsoleMessage(role="human", content=user_msg))

    try:
        # Auto-check for pending supplier responses before processing
        if console.session_id:
            try:
                pending = console.broker.poll(console.session_id, after=console.last_seq)
                if pending:
                    for m in pending:
                        console.last_seq = max(console.last_seq, m.get("seq", console.last_seq))
                    # Inject into context so LLM knows about new messages
                    pending_texts = [m.get("payload", {}).get("text", "") for m in pending]
                    if any(pending_texts):
                        user_msg += f"\n\n[System: New supplier messages received: {json.dumps(pending_texts)}]"
            except Exception:
                pass

        reply = _call_llm_with_tools(console, user_msg)
        console.messages.append(ConsoleMessage(role="assistant", content=reply))
    except Exception as e:
        _log.exception("Agent console LLM error")
        reply = f"Error: {e}"
        console.messages.append(ConsoleMessage(role="system", content=reply))
    finally:
        console.is_processing = False

    return JSONResponse({"reply": reply, "message_count": len(console.messages)})


@router.get("/messages")
async def agent_console_messages(request: Request):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return JSONResponse({"error": "Not authenticated"}, status_code=401)

    org_id = session.org_id
    console = _console_sessions.get(org_id)
    if not console:
        return JSONResponse({"messages": [], "connected": False, "processing": False})

    # Auto-check for new supplier messages
    if console.session_id and console.broker and not console.is_processing:
        try:
            pending = console.broker.poll(console.session_id, after=console.last_seq)
            for m in pending:
                console.last_seq = max(console.last_seq, m.get("seq", console.last_seq))
                text = m.get("payload", {}).get("text", json.dumps(m.get("payload", {})))
                sender = m.get("sender_agent_id", "supplier")
                console.messages.append(ConsoleMessage(
                    role="system",
                    content=f"[Supplier message from {sender}]: {text}",
                ))
        except Exception:
            pass

    msgs = [
        {"role": m.role, "content": m.content, "tool_name": m.tool_name}
        for m in console.messages
    ]
    return JSONResponse({
        "messages": msgs,
        "connected": console.broker is not None and console.broker.token is not None,
        "processing": console.is_processing,
        "session_id": console.session_id,
        "target": console.target_agent_id,
    })


@router.post("/disconnect")
async def agent_console_disconnect(request: Request, db: AsyncSession = Depends(get_db)):
    session = require_login(request)
    if isinstance(session, RedirectResponse):
        return RedirectResponse(url="/dashboard/login", status_code=303)
    if not await verify_csrf(request, session):
        return RedirectResponse(url="/dashboard/agent-console", status_code=303)

    org_id = session.org_id
    console = _console_sessions.pop(org_id, None)
    if console and console.broker:
        try:
            if console.session_id:
                console.broker.close_session(console.session_id)
        except Exception:
            pass
        try:
            console.broker.close()
        except Exception:
            pass

    return RedirectResponse(url="/dashboard/agent-console", status_code=303)
