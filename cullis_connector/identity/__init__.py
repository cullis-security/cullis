"""Identity handling for cullis-connector — keypair generation + on-disk store.

Phase 2b introduces persistent identity: a private key and Org-CA-signed
certificate live under ``<config_dir>/identity/`` and are loaded at server
start. The private key is generated locally and never leaves the machine;
the Site only ever sees the public half submitted during enrollment.
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

__all__ = [
    "IdentityBundle",
    "IdentityNotFound",
    "generate_keypair",
    "has_identity",
    "load_identity",
    "private_key_to_pem",
    "public_key_to_pem",
    "save_identity",
]
