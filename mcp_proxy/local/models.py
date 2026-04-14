"""Shared enums for the local mini-broker. Intentionally mirrors
`app/broker/models.py` so the two stacks can be compared side by side."""
from enum import Enum


class SessionStatus(str, Enum):
    pending = "pending"
    active = "active"
    closed = "closed"
    denied = "denied"


class SessionCloseReason(str, Enum):
    """Why a session was terminated. Mirrors the broker semantics."""
    normal = "normal"
    idle_timeout = "idle_timeout"
    ttl_expired = "ttl_expired"
    peer_lost = "peer_lost"
    policy_revoked = "policy_revoked"
    pending_timeout = "pending_timeout"
    rejected = "rejected"
