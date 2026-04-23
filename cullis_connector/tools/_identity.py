"""Sender-identity helpers shared by Connector tool modules.

Both ``oneshot.py`` and the dashboard inbox poller need to read the
sender's own org from the loaded identity bundle (cert subject
``O=<org_id>``) and to canonicalise bare recipient handles into the
``<org>::<agent>`` form the Mastio's ``/v1/egress/*`` endpoints
require.

Identity is passed as an **explicit parameter** — these helpers do
not read process-global state. Production callers attach the loaded
``IdentityBundle`` via ``CullisClient.identity`` and forward
``client.identity`` here. The previous variant read
``get_state().extra["identity"]`` and silently returned the input
unchanged when state had not been populated, which masked a
bootstrap bug in the dashboard poller (M2.4).
"""
from __future__ import annotations

import logging
from typing import Any

from cryptography import x509

_log = logging.getLogger("cullis_connector.tools._identity")


def own_org_id(identity: Any | None) -> str | None:
    """Return the sender's org_id from an identity bundle's cert subject.

    Duck-typed on ``identity.cert`` — any object with a ``cert`` whose
    ``subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)`` returns
    a non-empty list works. Returns ``None`` when ``identity`` is
    ``None``, has no cert, or the cert subject has no ``O=`` attribute.
    """
    if identity is None:
        return None
    cert = getattr(identity, "cert", None)
    if cert is None:
        return None
    attrs = cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
    if not attrs:
        return None
    return attrs[0].value or None


def canonical_recipient(recipient_id: str, identity: Any | None) -> str:
    """Prefix sender's org when recipient is bare; pass through if already qualified.

    ``identity=None`` is accepted deliberately (e.g. diagnostic tools
    before enrollment completes), but calling with ``identity=None``
    AND a bare ``recipient_id`` logs a warning and returns the input
    unchanged — the Mastio will then reject with 400 ``"internal id
    must be 'org::agent'"``. Production code paths always attach
    identity via ``CullisClient.identity = load_identity(config_dir)``.
    """
    if "::" in recipient_id:
        return recipient_id
    if identity is None:
        _log.warning(
            "canonical_recipient: bare recipient %r with identity=None; "
            "passing through as-is — server will likely 400. Production "
            "callers must attach identity via CullisClient.identity.",
            recipient_id,
        )
        return recipient_id
    org = own_org_id(identity)
    if not org:
        return recipient_id
    return f"{org}::{recipient_id}"
