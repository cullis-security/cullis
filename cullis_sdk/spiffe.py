"""
SPIFFE Workload API integration for Cullis SDK.

Lets Cullis agents fetch their X.509-SVID identity from a local SPIRE agent
(or any SPIFFE Workload API provider) over a Unix domain socket, instead of
reading cert/key from disk.

Requires the optional ``[spiffe]`` extra::

    pip install cullis-agent-sdk[spiffe]

Design notes:
- Thin wrapper over the ``spiffe`` package (py-spiffe) — all heavy lifting
  (gRPC, rotation streams) is upstream. We only expose what the SDK needs: fetch a single SVID and
  return PEM bundles.
- The enterprise operator decides the SPIFFE ID → Cullis agent_id mapping.
  See ``parse_spiffe_id()`` for the default convention.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import serialization

if TYPE_CHECKING:
    from cryptography.x509 import Certificate


_INSTALL_HINT = (
    "SPIFFE support requires the optional dependency. Install with:\n"
    "    pip install cullis-agent-sdk[spiffe]"
)


@dataclass
class SpiffeSvid:
    """An X.509-SVID fetched from the Workload API."""

    spiffe_id: str
    cert_pem: str
    key_pem: str
    trust_bundle_pem: str


def fetch_x509_svid(socket_path: str | None = None) -> SpiffeSvid:
    """Fetch a single X.509-SVID from the local Workload API.

    Args:
        socket_path: Path to the Workload API Unix socket. If ``None``, falls
            back to the ``SPIFFE_ENDPOINT_SOCKET`` environment variable
            (the SPIFFE standard convention).

    Returns:
        SpiffeSvid with the PEM cert, key, trust bundle, and the SPIFFE ID URI.

    Raises:
        ImportError: if the ``[spiffe]`` extra is not installed.
        RuntimeError: if no socket path is provided or the Workload API
            returns no SVID for this workload.
    """
    try:
        from spiffe import WorkloadApiClient
    except ImportError as e:  # pragma: no cover — tested via monkeypatch
        raise ImportError(_INSTALL_HINT) from e

    endpoint = socket_path or os.environ.get("SPIFFE_ENDPOINT_SOCKET")
    if not endpoint:
        raise RuntimeError(
            "No Workload API socket provided. Pass socket_path=... or set "
            "SPIFFE_ENDPOINT_SOCKET environment variable."
        )

    if not endpoint.startswith("unix://"):
        endpoint = f"unix://{endpoint}"

    # WorkloadApiClient reads SPIFFE_ENDPOINT_SOCKET from env; override it
    # locally so callers can pass socket_path explicitly.
    old = os.environ.get("SPIFFE_ENDPOINT_SOCKET")
    os.environ["SPIFFE_ENDPOINT_SOCKET"] = endpoint
    try:
        with WorkloadApiClient() as client:
            svid = client.fetch_x509_svid()
            bundle_set = client.fetch_x509_bundles()
    finally:
        if old is None:
            os.environ.pop("SPIFFE_ENDPOINT_SOCKET", None)
        else:
            os.environ["SPIFFE_ENDPOINT_SOCKET"] = old

    return _to_pem_bundle(svid, bundle_set)


def _to_pem_bundle(svid, bundle_set) -> SpiffeSvid:
    """Convert py-spiffe objects into our PEM-based SpiffeSvid.

    Kept as a separate function so tests can exercise the conversion without
    a real Workload API socket.
    """
    leaf: Certificate = svid.cert_chain[0]
    cert_pem_parts = [
        c.public_bytes(serialization.Encoding.PEM).decode()
        for c in svid.cert_chain
    ]
    key_pem = svid.private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()

    spiffe_id = str(svid.spiffe_id)
    trust_domain = svid.spiffe_id.trust_domain
    bundle = bundle_set.get_bundle_for_trust_domain(trust_domain)
    bundle_pem = "\n".join(
        c.public_bytes(serialization.Encoding.PEM).decode()
        for c in bundle.x509_authorities
    )

    del leaf  # only used for type narrowing above
    return SpiffeSvid(
        spiffe_id=spiffe_id,
        cert_pem="".join(cert_pem_parts),
        key_pem=key_pem,
        trust_bundle_pem=bundle_pem,
    )


def parse_spiffe_id(spiffe_id: str) -> tuple[str, str]:
    """Split a SPIFFE ID URI into (trust_domain, path).

    Example:
        >>> parse_spiffe_id("spiffe://orga.sandbox/agents/agent-a")
        ('orga.sandbox', 'agents/agent-a')
    """
    if not spiffe_id.startswith("spiffe://"):
        raise ValueError(f"Not a SPIFFE ID URI: {spiffe_id!r}")
    rest = spiffe_id[len("spiffe://"):]
    if "/" not in rest:
        raise ValueError(f"SPIFFE ID has no path: {spiffe_id!r}")
    td, path = rest.split("/", 1)
    return td, path


def default_agent_id(spiffe_id: str, org_id: str) -> str:
    """Default SPIFFE ID → Cullis agent_id mapping.

    Takes the *last* path segment as the agent short name and prefixes it
    with ``org_id::``. Operators with a different naming convention can
    parse ``spiffe_id`` themselves and build the agent_id manually.

    Example:
        spiffe://orga.sandbox/agent-a   → orga::agent-a
        spiffe://orga.sandbox/prod/api  → orga::api
    """
    _, path = parse_spiffe_id(spiffe_id)
    name = path.rsplit("/", 1)[-1]
    return f"{org_id}::{name}"
