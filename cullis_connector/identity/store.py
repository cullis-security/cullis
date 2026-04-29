"""On-disk identity store under ``<config_dir>/identity/``.

Layout::

    <config_dir>/identity/
    ├── agent.crt        PEM cert issued by Org CA (chmod 644)
    ├── agent.key        PEM private key, PKCS#8 unencrypted (chmod 600)
    ├── ca-chain.pem     Optional CA chain for verifying Site responses
    └── metadata.json    agent_id + capabilities + issued_at (human-readable)

The private key is the only file that must never leak. Enforce 0600 at
write time and refuse to load if the permission bits are wider on systems
where it matters (POSIX only — Windows NTFS ACLs are out of scope for v1).
"""
from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

CERT_FILENAME = "agent.crt"
KEY_FILENAME = "agent.key"
CA_CHAIN_FILENAME = "ca-chain.pem"
METADATA_FILENAME = "metadata.json"
# F-B-11 Phase 3d (#181) — per-identity DPoP keypair. Persisted as a
# private JWK; the SDK reads it back via ``cullis_sdk.DpopKey.load``.
DPOP_KEY_FILENAME = "dpop.jwk"


class IdentityNotFound(Exception):
    """Raised when the expected identity files are missing from disk."""


@dataclass(frozen=True)
class IdentityMetadata:
    agent_id: str
    capabilities: list[str]
    site_url: str
    issued_at: str  # ISO-8601 UTC

    def to_dict(self) -> dict[str, object]:
        return {
            "agent_id": self.agent_id,
            "capabilities": list(self.capabilities),
            "site_url": self.site_url,
            "issued_at": self.issued_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "IdentityMetadata":
        return cls(
            agent_id=str(data.get("agent_id", "")),
            capabilities=list(data.get("capabilities") or []),
            site_url=str(data.get("site_url", "")),
            issued_at=str(data.get("issued_at", "")),
        )


@dataclass
class IdentityBundle:
    """In-memory view of the identity loaded from disk."""

    private_key: PrivateKeyTypes
    cert: x509.Certificate
    cert_pem: str
    ca_chain_pem: str | None
    metadata: IdentityMetadata


def _identity_dir(config_dir: Path) -> Path:
    return config_dir / "identity"


def has_identity(config_dir: Path) -> bool:
    identity_dir = _identity_dir(config_dir)
    return (identity_dir / CERT_FILENAME).exists() and (
        identity_dir / KEY_FILENAME
    ).exists()


def save_identity(
    *,
    config_dir: Path,
    cert_pem: str,
    private_key: PrivateKeyTypes,
    ca_chain_pem: str | None,
    metadata: IdentityMetadata,
    dpop_private_jwk: dict | None = None,
) -> None:
    """Persist the full identity bundle atomically per-file.

    The private key and the DPoP private JWK (audit F-B-11 Phase 3d,
    #181) are written with ``chmod 600``; the public cert and metadata
    stay world-readable (they contain no secret material).

    ADR-014 PR-C: the cert/key pair IS the agent credential. No
    api_key file is persisted — earlier Connector layouts that wrote
    one are inert (the SDK's ``from_connector`` ignores it).

    ``dpop_private_jwk`` is optional — legacy Connectors that predate
    F-B-11 omit it, and the SDK's ``from_connector`` path falls back
    to generating a fresh keypair on first run in that case.
    """
    identity_dir = _identity_dir(config_dir)
    identity_dir.mkdir(parents=True, exist_ok=True)

    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    key_path = identity_dir / KEY_FILENAME
    _write_atomic(key_path, key_pem, mode=0o600)

    _write_atomic(identity_dir / CERT_FILENAME, cert_pem.encode(), mode=0o644)

    if ca_chain_pem:
        _write_atomic(
            identity_dir / CA_CHAIN_FILENAME, ca_chain_pem.encode(), mode=0o644
        )
    # Note: when ``ca_chain_pem`` is ``None`` we deliberately leave the
    # file alone. ADR-015 introduced TOFU pinning, which writes
    # ``ca-chain.pem`` from the dashboard's /setup/pin-ca handler
    # BEFORE the enrollment exchange. The earlier "cleanup stale
    # chain" branch here was deleting the operator-pinned PEM the
    # moment ``api_status`` called ``save_identity`` post-approval,
    # leaving the SDK's proxy http client with no trust store and
    # every authenticated egress call failing
    # CERTIFICATE_VERIFY_FAILED. If a caller actually needs to clear
    # a stale chain, ``wipe_identity`` (full profile reset) is the
    # right tool — save_identity must not be destructive on a field
    # it didn't receive.

    _write_atomic(
        identity_dir / METADATA_FILENAME,
        json.dumps(metadata.to_dict(), indent=2).encode(),
        mode=0o644,
    )

    # F-B-11 Phase 3d — DPoP private JWK. Stored as a JSON wrapper the
    # SDK's ``DpopKey.load`` accepts: ``{"private_jwk": {...}}``.
    if dpop_private_jwk is not None:
        if "d" not in dpop_private_jwk:
            raise ValueError(
                "dpop_private_jwk is missing the 'd' field — refusing "
                "to persist a public-only JWK at dpop.jwk"
            )
        _write_atomic(
            identity_dir / DPOP_KEY_FILENAME,
            json.dumps(
                {"private_jwk": dpop_private_jwk},
                separators=(",", ":"),
            ).encode(),
            mode=0o600,
        )


def load_identity(config_dir: Path) -> IdentityBundle:
    identity_dir = _identity_dir(config_dir)
    cert_path = identity_dir / CERT_FILENAME
    key_path = identity_dir / KEY_FILENAME

    if not cert_path.exists() or not key_path.exists():
        raise IdentityNotFound(
            f"No identity at {identity_dir} — run `cullis-connector enroll` first"
        )

    _ensure_private_key_permissions(key_path)

    key_pem_bytes = key_path.read_bytes()
    private_key = serialization.load_pem_private_key(key_pem_bytes, password=None)

    cert_pem = cert_path.read_text()
    cert = x509.load_pem_x509_certificate(cert_pem.encode())

    ca_chain_path = identity_dir / CA_CHAIN_FILENAME
    ca_chain_pem = ca_chain_path.read_text() if ca_chain_path.exists() else None

    metadata_path = identity_dir / METADATA_FILENAME
    if metadata_path.exists():
        metadata = IdentityMetadata.from_dict(
            json.loads(metadata_path.read_text())
        )
    else:
        # Fallback — derive a minimal metadata from the cert itself. Happens
        # for certs issued outside the enrollment flow (e.g. hand-placed).
        agent_id = _common_name_from_cert(cert)
        metadata = IdentityMetadata(
            agent_id=agent_id,
            capabilities=[],
            site_url="",
            issued_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        )

    return IdentityBundle(
        private_key=private_key,
        cert=cert,
        cert_pem=cert_pem,
        ca_chain_pem=ca_chain_pem,
        metadata=metadata,
    )


# ── Internals ────────────────────────────────────────────────────────────


def _write_atomic(path: Path, data: bytes, *, mode: int) -> None:
    """Write ``data`` to ``path`` via a tmp file + rename for crash safety."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "wb") as fh:
        fh.write(data)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def _ensure_private_key_permissions(path: Path) -> None:
    """Best-effort check on POSIX that the key file is not world-readable."""
    if os.name != "posix":
        return
    try:
        mode = path.stat().st_mode
    except OSError:
        return
    # Any group or other read/write/execute bit is too permissive.
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        os.chmod(path, 0o600)


def _common_name_from_cert(cert: x509.Certificate) -> str:
    try:
        attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    except x509.AttributeNotFound:
        return ""
    return attrs[0].value if attrs else ""
