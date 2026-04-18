"""
Internal API key authentication for egress (internal agents -> proxy -> broker).

API key format: sk_local_{agent_name}_{32 random hex chars}
Hashed with bcrypt for storage. Rate-limited per agent_id via the dual-backend
limiter in ``mcp_proxy.auth.rate_limit`` (in-memory by default, Redis when
``MCP_PROXY_REDIS_URL`` is configured — audit F-B-12).
"""
import logging
import os

import bcrypt
from fastapi import HTTPException, Request, status

from mcp_proxy.auth.rate_limit import get_agent_rate_limiter
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

    # Rate limit check (in-memory or Redis depending on availability).
    settings = get_settings()
    if not await get_agent_rate_limiter().check(agent_id, settings.rate_limit_per_minute):
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
        dpop_jkt=agent_data.get("dpop_jkt"),
        reach=agent_data.get("reach") or "both",
    )
