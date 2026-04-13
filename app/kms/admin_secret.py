"""
Admin secret management — stores the admin password hash in the KMS backend.

First-boot flow (shake-out P0-06):
  A fresh deploy stores no hash and no "user-set" flag.  The plaintext
  ADMIN_SECRET from .env is accepted exactly once on the login page as a
  bootstrap credential, and the admin is then forced onto /dashboard/setup
  to pick a real password.  Once the admin submits that form the chosen
  password is bcrypt-hashed, persisted, and the "user-set" flag is marked
  true — from that moment on .env ADMIN_SECRET is no longer accepted for
  dashboard login.

  ADMIN_SECRET remains useful for other purposes (bootstrap automation,
  CI where the full dashboard setup is skipped, and initial access when a
  deploy's Vault is unreachable): callers that need the plaintext secret
  still read it from settings.admin_secret directly.

The dashboard "change admin password" feature calls set_admin_secret_hash()
which updates both the backend and the in-memory cache atomically.
"""
import logging
import os
import pathlib

import bcrypt
import httpx

_log = logging.getLogger("agent_trust.admin_secret")

_cached_hash: str | None = None
_cached_user_set: bool | None = None
_VAULT_TIMEOUT = 10
_LOCAL_HASH_PATH = pathlib.Path("certs/.admin_secret_hash")
_LOCAL_USER_SET_PATH = pathlib.Path("certs/.admin_password_user_set")

# Dummy hash for constant-time verification when no hash is available.
_DUMMY_HASH: str = bcrypt.hashpw(b"dummy", bcrypt.gensalt(rounds=12)).decode()


# ---------------------------------------------------------------------------
# Vault helpers
# ---------------------------------------------------------------------------

async def _vault_headers() -> dict[str, str]:
    from app.config import get_settings
    return {"X-Vault-Token": get_settings().vault_token, "Content-Type": "application/json"}


async def _read_vault_secret() -> dict | None:
    """Read the full secret dict from Vault KV v2.  Returns None on failure."""
    from app.config import get_settings
    s = get_settings()
    url = f"{s.vault_addr.rstrip('/')}/v1/{s.vault_secret_path}"
    try:
        async with httpx.AsyncClient(timeout=_VAULT_TIMEOUT) as client:
            resp = await client.get(url, headers=await _vault_headers())
            if resp.status_code != 200:
                _log.warning("Vault read returned HTTP %d", resp.status_code)
                return None
            return resp.json()["data"]
    except Exception as exc:
        _log.warning("Vault read failed: %s", exc)
        return None


async def _write_vault_field(field: str, value: str) -> bool:
    """Merge-write a single field into the existing Vault secret (KV v2).

    KV v2 PUT replaces the entire secret, so we must read first, merge,
    then write back using check-and-set (cas) to prevent race conditions.
    """
    from app.config import get_settings
    s = get_settings()
    url = f"{s.vault_addr.rstrip('/')}/v1/{s.vault_secret_path}"
    headers = await _vault_headers()
    try:
        async with httpx.AsyncClient(timeout=_VAULT_TIMEOUT) as client:
            # Read current secret + metadata
            resp = await client.get(url, headers=headers)
            if resp.status_code == 200:
                payload = resp.json()["data"]
                current_data = payload.get("data", {})
                version = payload.get("metadata", {}).get("version", 0)
                current_data[field] = value
                body: dict = {"options": {"cas": version}, "data": current_data}
            else:
                # Secret path doesn't exist yet — first write (no CAS)
                body = {"data": {field: value}}

            resp = await client.post(url, headers=headers, json=body)
            if resp.status_code in (200, 204):
                _log.info("Vault field '%s' written successfully", field)
                return True
            _log.error("Vault write returned HTTP %d: %s", resp.status_code, resp.text)
            return False
    except Exception as exc:
        _log.error("Vault write failed: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Local file helpers
# ---------------------------------------------------------------------------

def _read_local_hash() -> str | None:
    if _LOCAL_HASH_PATH.exists():
        return _LOCAL_HASH_PATH.read_text().strip()
    return None


def _write_local_hash(hash_str: str) -> None:
    _LOCAL_HASH_PATH.parent.mkdir(parents=True, exist_ok=True)
    _LOCAL_HASH_PATH.write_text(hash_str + "\n")
    os.chmod(_LOCAL_HASH_PATH, 0o600)


def _read_local_user_set() -> bool:
    if _LOCAL_USER_SET_PATH.exists():
        return _LOCAL_USER_SET_PATH.read_text().strip().lower() == "true"
    return False


def _write_local_user_set(value: bool) -> None:
    _LOCAL_USER_SET_PATH.parent.mkdir(parents=True, exist_ok=True)
    _LOCAL_USER_SET_PATH.write_text(("true" if value else "false") + "\n")
    os.chmod(_LOCAL_USER_SET_PATH, 0o600)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def get_admin_secret_hash() -> str | None:
    """Return the cached admin secret bcrypt hash, fetching from backend if needed."""
    global _cached_hash
    if _cached_hash is not None:
        return _cached_hash

    from app.config import get_settings
    backend = get_settings().kms_backend.lower()

    if backend == "vault":
        secret = await _read_vault_secret()
        if secret and "data" in secret:
            _cached_hash = secret["data"].get("admin_secret_hash")
    else:
        _cached_hash = _read_local_hash()

    return _cached_hash


async def set_admin_secret_hash(new_hash: str) -> None:
    """Persist a new admin secret hash and update the in-memory cache.

    This function only stores the hash — the "user-set" flag is set
    explicitly by mark_admin_password_user_set() after a successful
    first-boot setup form submission.
    """
    global _cached_hash
    from app.config import get_settings
    backend = get_settings().kms_backend.lower()

    if backend == "vault":
        ok = await _write_vault_field("admin_secret_hash", new_hash)
        if not ok:
            raise RuntimeError("Failed to write admin_secret_hash to Vault")
    else:
        _write_local_hash(new_hash)

    _cached_hash = new_hash
    _log.info("Admin secret hash updated in %s backend", backend)


async def is_admin_password_user_set() -> bool:
    """Return True if the admin explicitly set a password via the setup form.

    A hash may exist in the backend from a previous deploy even when the
    user never went through the setup flow on *this* instance — that is
    why we track the "user set" state as a separate flag rather than
    inferring it from hash presence.
    """
    global _cached_user_set
    if _cached_user_set is not None:
        return _cached_user_set

    from app.config import get_settings
    backend = get_settings().kms_backend.lower()

    if backend == "vault":
        secret = await _read_vault_secret()
        if secret and "data" in secret:
            raw = secret["data"].get("admin_password_user_set", "false")
            _cached_user_set = str(raw).strip().lower() == "true"
        else:
            _cached_user_set = False
    else:
        _cached_user_set = _read_local_user_set()

    return _cached_user_set


async def mark_admin_password_user_set() -> None:
    """Flip the "user has picked a password" flag to true and cache it."""
    global _cached_user_set
    from app.config import get_settings
    backend = get_settings().kms_backend.lower()

    if backend == "vault":
        ok = await _write_vault_field("admin_password_user_set", "true")
        if not ok:
            raise RuntimeError(
                "Failed to write admin_password_user_set to Vault"
            )
    else:
        _write_local_user_set(True)

    _cached_user_set = True
    _log.info("Admin password marked as user-set in %s backend", backend)


async def ensure_bootstrapped() -> None:
    """First-boot hook.

    Historically this hashed the .env ADMIN_SECRET and stored it in the
    KMS backend, which meant a fresh operator never had to set a password
    — they simply inherited whatever was in .env.  Shake-out P0-06 made
    that a P0 UX problem: a stranger who cloned the repo had no on-screen
    hint about credentials and had to grep the .env file.

    The broker dashboard now forces the operator through /dashboard/setup
    on the first login, so there is nothing to bootstrap here.  We keep
    the function name for compatibility with app.main's lifespan and for
    tooling that may import it.
    """
    _log.info(
        "Admin secret bootstrap: skipping auto-hash from .env "
        "(first-boot password is set via /dashboard/setup)"
    )


def verify_admin_password(password: str, stored_hash: str | None = None) -> bool:
    """Verify a password against the stored bcrypt hash (constant-time)."""
    if stored_hash is None:
        bcrypt.checkpw(password.encode(), _DUMMY_HASH.encode())
        return False
    return bcrypt.checkpw(password.encode(), stored_hash.encode())
