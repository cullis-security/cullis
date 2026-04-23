"""Sender-identity helpers shared by Connector tool modules.

Both ``oneshot.py`` and ``intent.py`` need to read the sender's own org
from the loaded identity bundle (cert subject ``O=<org_id>``) and to
canonicalise bare recipient handles into the ``<org>::<agent>`` form
the Mastio's ``/v1/egress/*`` endpoints require. Keeping the helpers
here avoids the circular import that would happen if ``intent.py``
tried to pull them from ``oneshot.py``.
"""
from __future__ import annotations

from cryptography import x509

from cullis_connector.state import get_state


def own_org_id() -> str | None:
    """Return the sender's org_id from the loaded identity's cert subject.

    The Mastio's ``/v1/egress/resolve`` rejects bare recipient names —
    it needs ``org::agent``. Enrollment writes the agent's cert with
    ``O=<org_id>`` so we can recover the sender's org even when
    ``metadata.json`` stored only the short agent_id.
    """
    state = get_state()
    identity = state.extra.get("identity")
    cert = getattr(identity, "cert", None)
    if cert is None:
        return None
    attrs = cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
    if not attrs:
        return None
    return attrs[0].value or None


def canonical_recipient(recipient_id: str) -> str:
    """Prefix the sender's org when the caller gave a bare agent name."""
    if "::" in recipient_id:
        return recipient_id
    org = own_org_id()
    if not org:
        return recipient_id
    return f"{org}::{recipient_id}"
