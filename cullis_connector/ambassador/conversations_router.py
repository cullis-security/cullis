"""ADR-019 Step 6, REST surface for the Connector-local chat history.

The SPA's left sidebar lists past conversations and lets the user
rename / delete / open one. This module is the REST backing it,
mounted next to the rest of the ambassador on the same loopback +
bearer auth gate so the surface is reachable only from the local
host (or, in Frontdesk shared mode, from the cookie-authenticated
user once the cert middleware has bound `request.state.user_credentials`).

Endpoints, all under ``/v1/conversations``:

    GET    /                    list (paginated, principal-scoped)
    POST   /                    create empty conversation
    GET    /{conv_id}           fetch one + its messages
    PATCH  /{conv_id}           rename title
    DELETE /{conv_id}           soft delete
    POST   /{conv_id}/messages  append a message

The append endpoint is what the SPA hits at the end of each chat
completion turn so the history is captured by the Connector even if
the SPA tab is closed before the next turn.
"""
from __future__ import annotations

import json
import logging
import secrets
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select, update

from cullis_connector.ambassador.router import (
    _enforce_bearer,
    _enforce_loopback,
    _per_user_credentials,
)
from cullis_connector.conversations.db import get_session
from cullis_connector.conversations.models import Conversation, Message

_log = logging.getLogger("cullis_connector.ambassador.conversations")

router = APIRouter(prefix="/v1/conversations", tags=["conversations"])


# ── auth + dependency helpers ───────────────────────────────────────


def _ambassador_state(request: Request) -> dict:
    state = getattr(request.app.state, "ambassador", None)
    if state is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="ambassador not installed on this app",
        )
    return state


def _config_dir(request: Request):
    config = getattr(request.app.state, "connector_config", None)
    if config is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="connector_config not bound on app.state",
        )
    return config.config_dir


def _authenticate(request: Request) -> str:
    """Run the ambassador's loopback + bearer gate and return the
    principal_id to scope the operation by.

    The principal is the per-user credential when present (ADR-025
    shared mode), otherwise the Connector agent id (single-user mode).
    Conversations are always partitioned by principal so a user in
    Frontdesk shared mode cannot see another user's history.
    """
    _enforce_loopback(request)
    state = _ambassador_state(request)
    _enforce_bearer(request, state)
    creds = _per_user_credentials(request)
    if creds is not None and getattr(creds, "principal_id", None):
        return creds.principal_id
    agent_id = state.get("agent_id") or ""
    if not agent_id:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="no principal id available",
        )
    return agent_id


def _new_id() -> str:
    """40-char URL-safe random conversation id.

    Random rather than autoincrement: an attacker on the loopback gate
    cannot walk the id space, the SPA cannot accidentally probe other
    users' conversations by guessing integers."""
    return secrets.token_urlsafe(30)[:40]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ── pydantic IO models ──────────────────────────────────────────────


class ConversationSummary(BaseModel):
    id: str
    title: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class ConversationMessage(BaseModel):
    role: str
    content: str
    tool_calls: Optional[list[dict]] = None
    trace_id: Optional[str] = None
    created_at: datetime


class ConversationDetail(BaseModel):
    id: str
    title: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    messages: list[ConversationMessage]


class RenameRequest(BaseModel):
    title: Optional[str] = Field(default=None, max_length=200)


class AppendMessageRequest(BaseModel):
    role: str = Field(..., max_length=16)
    content: str = Field(default="")
    tool_calls: Optional[list[dict]] = None
    trace_id: Optional[str] = Field(default=None, max_length=64)


# ── endpoints ───────────────────────────────────────────────────────


@router.get("", response_model=list[ConversationSummary])
async def list_conversations(
    request: Request, limit: int = 20, offset: int = 0,
) -> list[ConversationSummary]:
    """Sidebar list, principal-scoped, soft-delete-aware, paginated."""
    principal_id = _authenticate(request)
    if limit < 1 or limit > 100:
        raise HTTPException(status_code=400, detail="limit must be 1..100")
    if offset < 0:
        raise HTTPException(status_code=400, detail="offset must be >= 0")
    cd = _config_dir(request)
    async with get_session(cd) as session:
        rows = (await session.execute(
            select(Conversation)
            .where(
                Conversation.principal_id == principal_id,
                Conversation.deleted_at.is_(None),
            )
            .order_by(Conversation.updated_at.desc())
            .limit(limit)
            .offset(offset)
        )).scalars().all()
    return [
        ConversationSummary(
            id=r.id, title=r.title,
            created_at=r.created_at, updated_at=r.updated_at,
        ) for r in rows
    ]


@router.post(
    "",
    response_model=ConversationSummary,
    status_code=status.HTTP_201_CREATED,
)
async def create_conversation(request: Request) -> ConversationSummary:
    """Mint an empty conversation, return its id so the SPA can start
    appending messages."""
    principal_id = _authenticate(request)
    cd = _config_dir(request)
    now = _utcnow()
    conv = Conversation(
        id=_new_id(),
        principal_id=principal_id,
        title=None,
        created_at=now,
        updated_at=now,
    )
    async with get_session(cd) as session:
        session.add(conv)
    return ConversationSummary(
        id=conv.id, title=conv.title,
        created_at=conv.created_at, updated_at=conv.updated_at,
    )


@router.get("/{conv_id}", response_model=ConversationDetail)
async def get_conversation(conv_id: str, request: Request) -> ConversationDetail:
    """Fetch one conversation + its messages. 404 when the id does not
    exist or belongs to another principal (do not leak existence)."""
    principal_id = _authenticate(request)
    cd = _config_dir(request)
    async with get_session(cd) as session:
        row = (await session.execute(
            select(Conversation).where(
                Conversation.id == conv_id,
                Conversation.principal_id == principal_id,
                Conversation.deleted_at.is_(None),
            )
        )).scalar_one_or_none()
        if row is None:
            raise HTTPException(status_code=404, detail="conversation not found")
        messages = (await session.execute(
            select(Message).where(Message.conversation_id == conv_id)
            .order_by(Message.created_at)
        )).scalars().all()
    return ConversationDetail(
        id=row.id, title=row.title,
        created_at=row.created_at, updated_at=row.updated_at,
        messages=[
            ConversationMessage(
                role=m.role,
                content=m.content,
                tool_calls=json.loads(m.tool_calls_json) if m.tool_calls_json else None,
                trace_id=m.trace_id,
                created_at=m.created_at,
            ) for m in messages
        ],
    )


@router.patch("/{conv_id}", response_model=ConversationSummary)
async def rename_conversation(
    conv_id: str, body: RenameRequest, request: Request,
) -> ConversationSummary:
    """Update the title only. Any other field on the request is ignored
    so the SPA cannot accidentally clobber principal_id / timestamps."""
    principal_id = _authenticate(request)
    cd = _config_dir(request)
    now = _utcnow()
    async with get_session(cd) as session:
        row = (await session.execute(
            select(Conversation).where(
                Conversation.id == conv_id,
                Conversation.principal_id == principal_id,
                Conversation.deleted_at.is_(None),
            )
        )).scalar_one_or_none()
        if row is None:
            raise HTTPException(status_code=404, detail="conversation not found")
        row.title = body.title
        row.updated_at = now
    return ConversationSummary(
        id=row.id, title=row.title,
        created_at=row.created_at, updated_at=row.updated_at,
    )


@router.delete("/{conv_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_conversation(conv_id: str, request: Request) -> None:
    """Soft delete. The row stays in the DB so an undo path is possible
    later; this endpoint just hides it from list / get."""
    principal_id = _authenticate(request)
    cd = _config_dir(request)
    now = _utcnow()
    async with get_session(cd) as session:
        result = await session.execute(
            update(Conversation)
            .where(
                Conversation.id == conv_id,
                Conversation.principal_id == principal_id,
                Conversation.deleted_at.is_(None),
            )
            .values(deleted_at=now, updated_at=now)
        )
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="conversation not found")
    return None


@router.post(
    "/{conv_id}/messages",
    response_model=ConversationMessage,
    status_code=status.HTTP_201_CREATED,
)
async def append_message(
    conv_id: str, body: AppendMessageRequest, request: Request,
) -> ConversationMessage:
    """Append one message to a conversation. The SPA calls this after
    each chat completion turn (user prompt + assistant response, or
    just the assistant when the prompt was already pushed)."""
    principal_id = _authenticate(request)
    if body.role not in ("user", "assistant", "tool", "system"):
        raise HTTPException(status_code=400, detail="invalid role")
    cd = _config_dir(request)
    now = _utcnow()
    tool_calls_blob: Optional[str] = None
    if body.tool_calls is not None:
        tool_calls_blob = json.dumps(body.tool_calls, separators=(",", ":"))
    async with get_session(cd) as session:
        conv = (await session.execute(
            select(Conversation).where(
                Conversation.id == conv_id,
                Conversation.principal_id == principal_id,
                Conversation.deleted_at.is_(None),
            )
        )).scalar_one_or_none()
        if conv is None:
            raise HTTPException(status_code=404, detail="conversation not found")
        msg = Message(
            conversation_id=conv_id,
            role=body.role,
            content=body.content,
            tool_calls_json=tool_calls_blob,
            trace_id=body.trace_id,
            created_at=now,
        )
        session.add(msg)
        conv.updated_at = now
    return ConversationMessage(
        role=msg.role,
        content=msg.content,
        tool_calls=body.tool_calls,
        trace_id=msg.trace_id,
        created_at=msg.created_at,
    )
