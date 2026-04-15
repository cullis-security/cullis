"""
Internal API key authentication for egress (internal agents -> proxy -> broker).

API key format: sk_local_{agent_name}_{32 random hex chars}
Hashed with bcrypt for storage. Rate-limited per agent_id.
"""
import logging
import os
import time
from collections import defaultdict

import bcrypt
from fastapi import HTTPException, Request, status

from mcp_proxy.config import get_settings
from mcp_proxy.db import get_agent_by_key_hash
from mcp_proxy.models import InternalAgent

_log = logging.getLogger("mcp_proxy")

# ─────────────────────────────────────────────────────────────────────────────
# Key generation and hashing
# ─────────────────────────────────────────────────────────────────────────────


def generate_api_key(agent_name: str) -> str:
    """Generate a new API key for an internal agent.

    Format: sk_local_{agent_name}_{32 random hex chars}
    """
    random_part = os.urandom(16).hex()
    return f"sk_local_{agent_name}_{random_part}"


def hash_api_key(key: str) -> str:
    """Hash an API key with bcrypt for secure storage."""
    return bcrypt.hashpw(key.encode(), bcrypt.gensalt()).decode()


def verify_api_key(key: str, stored_hash: str) -> bool:
    """Verify an API key against a stored bcrypt hash."""
    try:
        return bcrypt.checkpw(key.encode(), stored_hash.encode())
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Rate limiting — sliding window per agent_id
# ─────────────────────────────────────────────────────────────────────────────

# agent_id -> list of request timestamps (monotonic)
_rate_limit_windows: dict[str, list[float]] = defaultdict(list)


def _check_rate_limit(agent_id: str) -> bool:
    """Check if the agent is within the rate limit.

    Returns True if allowed, False if rate-limited.
    Uses a sliding window of 60 seconds.
    """
    settings = get_settings()
    now = time.monotonic()
    window_start = now - 60.0  # 1-minute sliding window

    timestamps = _rate_limit_windows[agent_id]

    # Remove expired entries
    _rate_limit_windows[agent_id] = [t for t in timestamps if t > window_start]

    if len(_rate_limit_windows[agent_id]) >= settings.rate_limit_per_minute:
        return False

    _rate_limit_windows[agent_id].append(now)
    return True


# ─────────────────────────────────────────────────────────────────────────────
# FastAPI dependency
# ─────────────────────────────────────────────────────────────────────────────


async def get_agent_from_api_key(request: Request) -> InternalAgent:
    """Authenticate an internal agent via X-API-Key header.

    Steps:
      1. Extract X-API-Key header
      2. Look up in DB by trying each active agent's bcrypt hash
      3. Check rate limit
      4. Return InternalAgent or raise 401/429
    """
    api_key = request.headers.get("X-API-Key")
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="X-API-Key header required",
        )

    # Validate key format (basic sanity check before hitting DB)
    if not api_key.startswith("sk_local_"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key format",
        )

    # Look up agent by verifying against stored hashes
    agent_data = await get_agent_by_key_hash(api_key)
    if agent_data is None:
        _log.warning("API key authentication failed: no matching agent")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )

    agent_id = agent_data["agent_id"]

    # Rate limit check
    if not _check_rate_limit(agent_id):
        _log.warning("Rate limit exceeded for agent: %s", agent_id)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded",
            headers={"Retry-After": "60"},
        )

    _log.debug("API key authenticated agent: %s", agent_id)
    return InternalAgent(
        agent_id=agent_data["agent_id"],
        display_name=agent_data["display_name"],
        capabilities=agent_data["capabilities"],
        created_at=agent_data["created_at"],
        is_active=agent_data["is_active"],
        cert_pem=agent_data.get("cert_pem"),
    )
