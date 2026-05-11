"""SQLAlchemy ORM for the Connector's chat conversation store."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Declarative base scoped to conversations.db.

    Kept separate from ``cullis_connector.identity.users.Base`` so
    ``Base.metadata.create_all`` on this module only touches the
    conversation tables. Mirrors the users.db pattern.
    """


def _utcnow() -> datetime:
    """Timezone-aware UTC default for created_at / updated_at."""
    return datetime.now(timezone.utc)


class Conversation(Base):
    __tablename__ = "conversations"

    # Random opaque id rather than autoincrement so the URL surface is
    # not enumerable (an attacker on the loopback gets to /v1/
    # conversations/{id} and would be able to walk the space otherwise).
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    # Principal who created the conversation. In single-user Connector
    # mode this is the agent id; in shared mode (ADR-019) it's the
    # user principal id resolved via cookie auth. Storing it gives
    # the future multi-user UI the filter it needs.
    principal_id: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    # Optional title. Generated client-side from the first user turn
    # (e.g. truncated 60 char) or left null for "untitled".
    title: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow,
    )
    # Soft delete: a row stays in the DB but is hidden from list /
    # fetch responses. Hard delete is reserved for an admin sweep.
    deleted_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )

    messages: Mapped[list["Message"]] = relationship(
        back_populates="conversation",
        cascade="all, delete-orphan",
        order_by="Message.created_at",
    )

    __table_args__ = (
        # Sidebar list query: most recently updated conversations for
        # this principal, excluding soft-deleted rows. Single composite
        # index keeps that path index-only.
        Index(
            "ix_conversations_principal_updated",
            "principal_id", "updated_at",
        ),
    )


class Message(Base):
    __tablename__ = "messages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    conversation_id: Mapped[str] = mapped_column(
        String(40),
        ForeignKey("conversations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # OpenAI-style role. user | assistant | tool | system.
    role: Mapped[str] = mapped_column(String(16), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # JSON-encoded list of tool calls observed during the turn. Null
    # when no tool was invoked. Stored as text so SQLite can stay
    # JSON1-agnostic; the router does the json.dumps / json.loads.
    tool_calls_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # Mastio trace_id propagated by the SSE stream. Lets the UI cross
    # reference an assistant message with the audit dashboard.
    trace_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow,
    )

    conversation: Mapped[Conversation] = relationship(back_populates="messages")
