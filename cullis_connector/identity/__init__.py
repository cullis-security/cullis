"""Identity handling for cullis-connector — keypair generation + on-disk store.

Phase 2b introduces persistent identity: a private key and Org-CA-signed
certificate live under ``<config_dir>/identity/`` and are loaded at server
start. The private key is generated locally and never leaves the machine;
the Site only ever sees the public half submitted during enrollment.

ADR-025 Phase 1 also adds a ``users.db`` next to the identity dir for
local user accounts (Frontdesk shared-mode dual auth). The user table
is gated behind ``AUTH_MODE=local`` at the web layer — see
``cullis_connector/web.py``.
"""

from cullis_connector.identity.keypair import (
    generate_keypair,
    private_key_to_pem,
    public_key_to_pem,
)
from cullis_connector.identity.store import (
    IdentityBundle,
    IdentityNotFound,
    has_identity,
    load_identity,
    save_identity,
)
from cullis_connector.identity.users import (
    User,
    create_user,
    delete_user,
    get_user_by_name,
    list_users,
    mark_password_changed,
    reset_password,
    set_password_hash,
    verify_password,
)
from cullis_connector.identity.users_db import (
    USERS_DB_FILENAME,
    get_users_session,
    init_users_db,
)

__all__ = [
    "IdentityBundle",
    "IdentityNotFound",
    "USERS_DB_FILENAME",
    "User",
    "create_user",
    "delete_user",
    "generate_keypair",
    "get_user_by_name",
    "get_users_session",
    "has_identity",
    "init_users_db",
    "list_users",
    "load_identity",
    "mark_password_changed",
    "private_key_to_pem",
    "public_key_to_pem",
    "reset_password",
    "save_identity",
    "set_password_hash",
    "verify_password",
]
