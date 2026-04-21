"""
Internal agent identity lifecycle — x509 certificate issuance, API key
management, Vault key storage, and broker registration.

Each internal agent gets:
  - An RSA-2048 x509 certificate signed by the Org CA (SPIFFE SAN URI)
  - A private key stored in Vault (or DB fallback)
  - A local API key (sk_local_{name}_{hex}) for authenticating to the proxy
"""
import hashlib
import logging
from datetime import datetime, timedelta, timezone

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509 import (
    SubjectAlternativeName,
    UniformResourceIdentifier,
)
from cryptography.x509.oid import NameOID

from mcp_proxy.auth.api_key import generate_api_key, hash_api_key
from mcp_proxy.auth.local_keystore import LocalKeyStore, MastioKey, compute_kid
from mcp_proxy.auth.mastio_rotation import ContinuityProof, build_proof
from mcp_proxy.config import get_settings, vault_tls_verify
from mcp_proxy.db import (
    create_agent as db_create_agent,
    deactivate_agent as db_deactivate_agent,
    get_agent as db_get_agent,
    get_config,
    insert_mastio_key,
    set_config,
    swap_active_mastio_key,
)

from typing import Awaitable, Callable

logger = logging.getLogger("mcp_proxy.egress.agent_manager")


def _priv_to_pem(key) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


def _cert_to_pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


class AgentManager:
    """Manages internal agent identity lifecycle.

    Creates x509 certificates signed by the Org CA, stores private keys
    in Vault (or locally in the DB), and generates local API keys for
    internal auth.
    """

    def __init__(self, org_id: str, trust_domain: str = "cullis.local"):
        self._org_id = org_id
        self._trust_domain = trust_domain
        self._org_ca_key: rsa.RSAPrivateKey | None = None
        self._org_ca_cert: x509.Certificate | None = None
        # ADR-009 Phase 1 — Mastio CA (intermediate). Persisted in
        # ``proxy_config.mastio_ca_{key,cert}``, loaded lazily at boot
        # via ``ensure_mastio_identity()``.
        self._mastio_ca_key: ec.EllipticCurvePrivateKey | None = None
        self._mastio_ca_cert: x509.Certificate | None = None
        # ADR-012 Phase 2.0 — the active leaf ``MastioKey`` pulled from
        # the keystore. Exposes ``cert_pem`` / ``pubkey_pem`` /
        # ``privkey_pem`` + ``load_private_key()`` for the ADR-009
        # counter-signature path. Rotation (Phase 2.1) will invalidate
        # this cache; callers invoke ``refresh_active_key()`` to pick
        # up the new row.
        self._keystore = LocalKeyStore()
        self._active_key: MastioKey | None = None

    # ── CA loading ──────────────────────────────────────────────────

    async def load_org_ca(self, ca_key_pem: str, ca_cert_pem: str) -> None:
        """Load org CA key+cert from PEM strings (fetched from Vault or config)."""
        self._org_ca_key = serialization.load_pem_private_key(
            ca_key_pem.encode(), password=None,
        )
        self._org_ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode())
        logger.info(
            "Org CA loaded — issuer CN=%s",
            self._org_ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
        )

    async def load_org_ca_from_config(self) -> bool:
        """Try to load Org CA from proxy_config DB table (keys: org_ca_key, org_ca_cert).

        Returns True if loaded successfully, False otherwise.
        """
        ca_key_pem = await get_config("org_ca_key")
        ca_cert_pem = await get_config("org_ca_cert")
        if ca_key_pem and ca_cert_pem:
            await self.load_org_ca(ca_key_pem, ca_cert_pem)
            return True
        logger.warning("Org CA not found in proxy_config — agent cert issuance unavailable")
        return False

    async def generate_org_ca(
        self,
        *,
        validity_days: int = 3650,
        derive_org_id: bool = False,
    ) -> None:
        """Generate a fresh self-signed Org CA and persist it to proxy_config.

        Intended for standalone deploys (#115) where there is no broker to
        run the attach-ca flow against. The CA is a long-lived root
        (10 years by default); BasicConstraints(ca=True, path_length=1)
        so a future SPIRE UpstreamAuthority can mint one intermediate
        underneath without re-rooting.

        When ``derive_org_id`` is True, the proxy's ``org_id`` is derived
        from the CA public key (``sha256(pubkey_DER).hex()[:16]``) and
        persisted into ``proxy_config.org_id``. This is ADR-006 §2.2:
        a deterministic identity that survives proxy restarts / redeploys
        and that the broker's attach-ca flow can pin at invite-creation
        time. Without it, the proxy would pick a random UUID and any
        pre-shared ``linked_org_id`` would drift on the next boot.

        Safe to call only when no Org CA is already loaded — callers should
        gate on :attr:`ca_loaded` to avoid overwriting an attached CA.
        """
        if self.ca_loaded:
            raise RuntimeError("Org CA already loaded — refusing to overwrite")

        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        if derive_org_id:
            pubkey_der = ca_key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            derived = hashlib.sha256(pubkey_der).hexdigest()[:16]
            self._org_id = derived
            await set_config("org_id", derived)
            logger.info("Derived deterministic org_id=%s from Org CA public key", derived)

        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, f"{self._org_id} CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self._org_id),
        ])

        now = datetime.now(timezone.utc)
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=validity_days))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=1),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )

        ca_key_pem = ca_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
        ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode()

        await set_config("org_ca_key", ca_key_pem)
        await set_config("org_ca_cert", ca_cert_pem)

        self._org_ca_key = ca_key
        self._org_ca_cert = ca_cert

        logger.info(
            "Self-signed Org CA generated (CN=%s, validity=%dd)",
            f"{self._org_id} CA", validity_days,
        )

    @property
    def ca_loaded(self) -> bool:
        return self._org_ca_key is not None and self._org_ca_cert is not None

    @property
    def org_id(self) -> str:
        return self._org_id

    def derive_org_id_from_ca(self) -> str | None:
        """SHA-256(pubkey DER)[:16] of the currently loaded Org CA.

        Returns ``None`` if no CA is loaded. This is the value the admin
        copies from the proxy dashboard into a broker attach-ca invite
        (ADR-006 §2.2) — it doesn't read from ``proxy_config.org_id``,
        it recomputes from the cert, so tampering with the config row
        wouldn't let an attacker convince the broker the proxy is
        a different org.
        """
        if self._org_ca_cert is None:
            return None
        pubkey_der = self._org_ca_cert.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return hashlib.sha256(pubkey_der).hexdigest()[:16]

    # ── Certificate generation ──────────────────────────────────────

    def _generate_agent_cert(self, agent_name: str) -> tuple[str, str]:
        """Generate RSA-2048 key + x509 cert for an internal agent.

        Cert fields:
          - CN: {org_id}::{agent_name}
          - O:  {org_id}
          - SAN URI: spiffe://{trust_domain}/{org_id}/{agent_name}
          - Signed by Org CA
          - Valid 365 days

        Returns (cert_pem, key_pem).
        """
        if not self.ca_loaded:
            raise RuntimeError("Org CA not loaded — call load_org_ca() first")

        # Generate agent key pair
        agent_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        agent_id = f"{self._org_id}::{agent_name}"
        spiffe_uri = f"spiffe://{self._trust_domain}/{self._org_id}/{agent_name}"

        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, agent_id),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self._org_id),
        ])

        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._org_ca_cert.subject)
            .public_key(agent_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=365))
            .add_extension(
                SubjectAlternativeName([
                    UniformResourceIdentifier(spiffe_uri),
                ]),
                critical=False,
            )
            .sign(self._org_ca_key, hashes.SHA256())
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        key_pem = agent_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()

        logger.info("Generated x509 cert for %s (SAN %s)", agent_id, spiffe_uri)
        return cert_pem, key_pem

    def sign_external_pubkey(self, *, pubkey_pem: str, agent_name: str) -> str:
        """Sign an externally-generated public key with the Org CA.

        Used by the Connector enrollment flow: the Connector keeps its
        private key on the user's machine and only submits the public key,
        the admin approves, and the proxy issues a cert bound to that key.

        Raises ``RuntimeError`` if the Org CA is not loaded or the PEM is
        malformed. Accepts any key type the ``cryptography`` library can
        load (RSA, EC, Ed25519); the resulting cert signature is always
        SHA-256 per the existing convention.
        """
        if not self.ca_loaded:
            raise RuntimeError("Org CA not loaded — call load_org_ca() first")

        public_key = serialization.load_pem_public_key(pubkey_pem.encode())

        agent_id = f"{self._org_id}::{agent_name}"
        spiffe_uri = f"spiffe://{self._trust_domain}/{self._org_id}/{agent_name}"

        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, agent_id),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self._org_id),
        ])

        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._org_ca_cert.subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=365))
            .add_extension(
                SubjectAlternativeName([
                    UniformResourceIdentifier(spiffe_uri),
                ]),
                critical=False,
            )
            .sign(self._org_ca_key, hashes.SHA256())
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        logger.info(
            "Signed external pubkey for %s (SAN %s)", agent_id, spiffe_uri
        )
        return cert_pem

    # ── Agent CRUD ──────────────────────────────────────────────────

    async def create_agent(
        self,
        agent_name: str,
        display_name: str,
        capabilities: list[str],
    ) -> tuple[dict, str]:
        """Create a new internal agent.

        Steps:
          1. Generate x509 cert+key (signed by Org CA)
          2. Store key in Vault (or DB if Vault not available)
          3. Generate API key (sk_local_{name}_{hex})
          4. Store agent record in DB (with bcrypt hash of API key, cert PEM)
          5. Register agent with broker via HTTP (best-effort)
          6. Return (agent_info_dict, api_key_plaintext)

        The API key plaintext is shown ONCE — never stored or retrievable.
        """
        agent_id = f"{self._org_id}::{agent_name}"

        # 1. Generate cert + key
        cert_pem, key_pem = self._generate_agent_cert(agent_name)

        # 2. Store private key
        try:
            await self._store_key_vault(agent_id, key_pem)
            logger.info("Private key for %s stored in Vault", agent_id)
        except Exception as exc:
            logger.warning(
                "Vault unavailable for %s — storing key in DB: %s", agent_id, exc,
            )
            # Key will be stored in proxy_config as fallback
            await set_config(f"agent_key:{agent_id}", key_pem)

        # 3. Generate API key
        api_key = generate_api_key(agent_name)
        api_key_hash = hash_api_key(api_key)

        # 4. Store agent record in DB
        await db_create_agent(
            agent_id=agent_id,
            display_name=display_name,
            capabilities=capabilities,
            api_key_hash=api_key_hash,
            cert_pem=cert_pem,
        )

        # ADR-010 Phase 6a-4 — broker registration used to happen here via
        # the legacy ``POST /v1/registry/agents`` (with org_secret). That
        # endpoint is gone; the Mastio is authoritative for its own org
        # and the federation publisher carries federated=true rows to the
        # Court asynchronously. Per D1 the flag is opt-in — the dashboard
        # and ``/v1/admin/agents`` set it explicitly when the operator
        # wants the agent exposed cross-org.

        agent_info = {
            "agent_id": agent_id,
            "display_name": display_name,
            "capabilities": capabilities,
            "cert_pem": cert_pem,
        }

        logger.info("Internal agent created: %s", agent_id)
        return agent_info, api_key

    async def rotate_api_key(self, agent_id: str) -> str:
        """Generate new API key for existing agent. Invalidates old key.

        Returns new API key plaintext (shown once).
        """
        agent = await db_get_agent(agent_id)
        if agent is None:
            raise ValueError(f"Agent not found: {agent_id}")
        if not agent["is_active"]:
            raise ValueError(f"Agent is deactivated: {agent_id}")

        # Extract agent_name from agent_id (org::name)
        agent_name = agent_id.split("::")[-1] if "::" in agent_id else agent_id

        new_key = generate_api_key(agent_name)
        new_hash = hash_api_key(new_key)

        # Update hash in DB
        from sqlalchemy import text

        from mcp_proxy.db import get_db
        async with get_db() as db:
            await db.execute(
                text("UPDATE internal_agents SET api_key_hash = :api_key_hash WHERE agent_id = :agent_id"),
                {"api_key_hash": new_hash, "agent_id": agent_id},
            )

        logger.info("API key rotated for agent: %s", agent_id)
        return new_key

    async def deactivate_agent(self, agent_id: str) -> None:
        """Deactivate agent.

        ADR-010 Phase 6a-4 — the HTTP ``DELETE /v1/registry/agents/{id}``
        to the Court has been removed. The federation publisher picks up
        the ``is_active=0`` flip (bumps ``federation_revision``) and
        pushes a revocation to the Court via ADR-009 counter-signed
        ``/v1/federation/publish-agent``. Un-federated agents never
        appeared on the Court, so there's nothing to unregister.
        """
        found = await db_deactivate_agent(agent_id)
        if not found:
            raise ValueError(f"Agent not found: {agent_id}")
        logger.info("Agent deactivated: %s", agent_id)

    # ── Mastio identity (ADR-009 Phase 1) ───────────────────────────

    @property
    def mastio_loaded(self) -> bool:
        return (
            self._mastio_ca_cert is not None
            and self._active_key is not None
        )

    async def refresh_active_key(self) -> None:
        """Re-read the active Mastio leaf from the keystore.

        Called by the proxy lifespan after a Phase 2.1 rotation event so
        cached holders (issuer, counter-sign path) can observe the new
        current signer.
        """
        self._active_key = await self._keystore.current_signer()

    async def ensure_mastio_identity(self) -> None:
        """Load or generate the Mastio CA + leaf identity (EC P-256 / ES256).

        Intermediate CA lives in ``proxy_config`` under
        ``mastio_ca_key`` / ``mastio_ca_cert``. The leaf key + cert live
        in ``mastio_keys`` (ADR-012 Phase 2.0) as a row that is either
        active (current signer) or deprecated-in-grace. Idempotent:
        when both CA and an active key exist the method just caches
        them; otherwise it mints whichever piece is missing.

        Raises ``RuntimeError`` if the Org CA is not loaded — the caller
        must gate on :attr:`ca_loaded`.
        """
        if not self.ca_loaded:
            raise RuntimeError(
                "Org CA not loaded — cannot issue Mastio intermediate CA",
            )

        ca_key_pem = await get_config("mastio_ca_key")
        ca_cert_pem = await get_config("mastio_ca_cert")

        if ca_key_pem and ca_cert_pem:
            self._mastio_ca_key = serialization.load_pem_private_key(
                ca_key_pem.encode(), password=None,
            )
            self._mastio_ca_cert = x509.load_pem_x509_certificate(
                ca_cert_pem.encode(),
            )

        try:
            self._active_key = await self._keystore.current_signer()
        except RuntimeError:
            self._active_key = None

        # ADR-012 Phase 2.0 — one-shot data migration from the pre-2.0
        # ``proxy_config.mastio_leaf_{key,cert}`` pair to the
        # ``mastio_keys`` table. Kept out of the Alembic migration so
        # schema bootstrap doesn't need to parse PEMs (the standalone
        # proxy-init container ships an alembic-only environment).
        if self._active_key is None:
            await self._migrate_legacy_leaf_to_keystore()
            try:
                self._active_key = await self._keystore.current_signer()
            except RuntimeError:
                self._active_key = None

        if self.mastio_loaded:
            logger.info("Mastio identity loaded (ca + active key)")
            return

        await self._generate_mastio_identity()

    async def _migrate_legacy_leaf_to_keystore(self) -> None:
        """Seed ``mastio_keys`` from ``proxy_config.mastio_leaf_{key,cert}``.

        No-op when the legacy rows are absent or already migrated.
        Idempotent: leaves the legacy rows in place so a rollback only
        needs to drop the new table.
        """
        leaf_key_pem = await get_config("mastio_leaf_key")
        leaf_cert_pem = await get_config("mastio_leaf_cert")
        if not leaf_key_pem or not leaf_cert_pem:
            return
        try:
            cert = x509.load_pem_x509_certificate(leaf_cert_pem.encode())
        except ValueError:
            logger.warning(
                "Legacy mastio_leaf_cert is malformed — skipping migration; "
                "a fresh identity will be generated",
            )
            return
        pubkey_pem = cert.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        kid = compute_kid(pubkey_pem)
        if await self._keystore.find_by_kid(kid) is not None:
            return
        now_iso = datetime.now(timezone.utc).isoformat()
        await insert_mastio_key(
            kid=kid,
            pubkey_pem=pubkey_pem,
            privkey_pem=leaf_key_pem,
            cert_pem=leaf_cert_pem,
            created_at=now_iso,
            activated_at=now_iso,
        )
        logger.info(
            "Migrated legacy mastio leaf into mastio_keys (kid=%s)", kid,
        )

    async def _generate_mastio_identity(self) -> None:
        """Mint whichever Mastio pieces are missing — CA and/or leaf.

        Runs idempotently against partial state so a crashed boot (CA
        persisted, leaf insert failed) or a planned key rotation can
        complete the identity without re-rooting the intermediate.
        """
        now = datetime.now(timezone.utc)

        if self._mastio_ca_key is None or self._mastio_ca_cert is None:
            await self._mint_mastio_ca(now)

        if self._active_key is None:
            await self._mint_mastio_leaf(now)

    async def _mint_mastio_ca(self, now: datetime) -> None:
        """Mint a fresh EC P-256 intermediate CA and persist it.

        3y validity: online signer intended to be rotated ahead of
        expiry (NIST SP 800-57 Part 1 §5.3.6 guidance for signing keys
        in active use). Automatic rotation is tracked in issue #261.
        """
        mastio_ca_key = ec.generate_private_key(ec.SECP256R1())
        mastio_ca_subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, f"{self._org_id} Mastio CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self._org_id),
        ])
        mastio_ca_cert = (
            x509.CertificateBuilder()
            .subject_name(mastio_ca_subject)
            .issuer_name(self._org_ca_cert.subject)
            .public_key(mastio_ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=365 * 3))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(mastio_ca_key.public_key()),
                critical=False,
            )
            .sign(self._org_ca_key, hashes.SHA256())
        )

        await set_config("mastio_ca_key", _priv_to_pem(mastio_ca_key))
        await set_config("mastio_ca_cert", _cert_to_pem(mastio_ca_cert))
        self._mastio_ca_key = mastio_ca_key
        self._mastio_ca_cert = mastio_ca_cert
        logger.info("Mastio intermediate CA minted (CN=%s)", mastio_ca_subject)

    async def _mint_mastio_leaf(self, now: datetime) -> None:
        """Mint a fresh EC P-256 leaf under the existing intermediate CA.

        The keypair + cert are inserted into ``mastio_keys`` with
        ``activated_at=now`` (no previous active row in the Phase 2.0
        cold-start path — multi-row transitions land in Phase 2.1).
        The cached ``self._active_key`` is refreshed so subsequent
        signing / counter-signing calls see the new row.
        """
        if self._mastio_ca_key is None or self._mastio_ca_cert is None:
            raise RuntimeError("Mastio CA not loaded — cannot sign leaf")

        leaf_key = ec.generate_private_key(ec.SECP256R1())
        proxy_spiffe = f"spiffe://{self._trust_domain}/proxy/{self._org_id}"
        leaf_subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, f"proxy:{self._org_id}"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self._org_id),
        ])
        leaf_cert = (
            x509.CertificateBuilder()
            .subject_name(leaf_subject)
            .issuer_name(self._mastio_ca_cert.subject)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(
                SubjectAlternativeName([UniformResourceIdentifier(proxy_spiffe)]),
                critical=False,
            )
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .sign(self._mastio_ca_key, hashes.SHA256())
        )

        priv_pem = _priv_to_pem(leaf_key)
        cert_pem = _cert_to_pem(leaf_cert)
        pub_pem = leaf_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        kid = compute_kid(pub_pem)
        now_iso = now.isoformat()

        await insert_mastio_key(
            kid=kid,
            pubkey_pem=pub_pem,
            privkey_pem=priv_pem,
            cert_pem=cert_pem,
            created_at=now_iso,
            activated_at=now_iso,
        )
        self._active_key = await self._keystore.find_by_kid(kid)

        logger.info(
            "Mastio leaf minted — kid=%s, SAN=%s", kid, proxy_spiffe,
        )

    def _require_active(self) -> MastioKey:
        if self._active_key is None or self._mastio_ca_cert is None:
            raise RuntimeError(
                "Mastio identity not loaded — call ensure_mastio_identity() first",
            )
        return self._active_key

    def get_mastio_credentials(self) -> tuple[str, str]:
        """Return ``(leaf_cert_pem, leaf_key_pem)`` for counter-signing.

        Raises ``RuntimeError`` if :meth:`ensure_mastio_identity` has not run,
        or if the active keystore row lacks an accompanying cert (partial
        state that shouldn't occur in normal operation).
        """
        active = self._require_active()
        if active.cert_pem is None:
            raise RuntimeError(
                f"active mastio key {active.kid!r} has no cert_pem",
            )
        return active.cert_pem, active.privkey_pem

    def get_mastio_pubkey_pem(self) -> str:
        """Return the leaf EC P-256 public key in PEM format.

        This is what gets pinned to the Court at onboarding (join/attach
        ``mastio_pubkey``). The Court verifies the counter-signature
        header against this key.
        """
        return self._require_active().pubkey_pem

    async def rotate_mastio_key(
        self,
        *,
        grace_days: int = 7,
        propagator: "Callable[[ContinuityProof, str], Awaitable[None]] | None" = None,
    ) -> MastioKey:
        """Rotate the Mastio leaf key (ADR-012 Phase 2.1, issue #261).

        Mints a fresh EC P-256 leaf under the existing intermediate CA,
        signs a continuity proof with the current (old) key, propagates
        the new pubkey + proof to the Court via ``propagator``, and then
        atomically swaps the active row in ``mastio_keys``.

        ``grace_days`` controls how long the old kid stays
        verifier-accepted after deprecation. Callers that want a
        different cadence override it; the default of 7 is the
        repository-wide baseline for signing-key rotations.

        ``propagator`` receives the built ``ContinuityProof`` plus the
        new cert PEM and is expected to call the Court. If it raises,
        no DB mutation happens (Court-first ordering). If it is
        ``None`` (tests / offline bootstrap), the Court step is
        skipped entirely — the resulting rotation is purely local and
        will leave the Court out of sync; callers **must** pass a real
        propagator in production.

        Returns the freshly-activated :class:`MastioKey` (already
        cached as ``self._active_key``).

        Raises:
            RuntimeError: if identity is not loaded (gate on
                :attr:`mastio_loaded`), if ``grace_days`` is not
                positive, or if the DB swap finds an inconsistent
                state.
        """
        if grace_days <= 0:
            raise ValueError("grace_days must be a positive integer")
        old = self._require_active()
        if self._mastio_ca_key is None or self._mastio_ca_cert is None:
            raise RuntimeError("Mastio intermediate CA not loaded")

        now = datetime.now(timezone.utc)
        new_leaf_key = ec.generate_private_key(ec.SECP256R1())
        proxy_spiffe = f"spiffe://{self._trust_domain}/proxy/{self._org_id}"
        leaf_subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, f"proxy:{self._org_id}"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self._org_id),
        ])
        new_cert = (
            x509.CertificateBuilder()
            .subject_name(leaf_subject)
            .issuer_name(self._mastio_ca_cert.subject)
            .public_key(new_leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(
                SubjectAlternativeName([UniformResourceIdentifier(proxy_spiffe)]),
                critical=False,
            )
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .sign(self._mastio_ca_key, hashes.SHA256())
        )

        new_priv_pem = _priv_to_pem(new_leaf_key)
        new_cert_pem = _cert_to_pem(new_cert)
        new_pub_pem = new_leaf_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        new_kid = compute_kid(new_pub_pem)

        proof = build_proof(
            old_priv_key=old.load_private_key(),
            old_kid=old.kid,
            new_kid=new_kid,
            new_pubkey_pem=new_pub_pem,
            issued_at=now,
        )

        # Court-first: if propagation fails, no local state change.
        if propagator is not None:
            await propagator(proof, new_cert_pem)
        else:
            logger.warning(
                "rotate_mastio_key: no propagator provided — Court will "
                "stay pinned on the old pubkey; production callers must "
                "supply one",
            )

        now_iso = now.isoformat()
        grace_end_iso = (now + timedelta(days=grace_days)).isoformat()
        await swap_active_mastio_key(
            new_kid=new_kid,
            new_pubkey_pem=new_pub_pem,
            new_privkey_pem=new_priv_pem,
            new_cert_pem=new_cert_pem,
            new_activated_at=now_iso,
            new_created_at=now_iso,
            old_kid=old.kid,
            old_deprecated_at=now_iso,
            old_expires_at=grace_end_iso,
        )

        await self.refresh_active_key()
        logger.info(
            "Mastio key rotated — old_kid=%s, new_kid=%s, grace_days=%d",
            old.kid, new_kid, grace_days,
        )
        assert self._active_key is not None
        return self._active_key

    def countersign(self, data: bytes) -> str:
        """ES256 counter-signature over ``data``, base64url no-pad.

        Used by ``BrokerBridge`` to attest every ``/v1/auth/token`` call
        as proxied through this mastio. The signature goes into the
        ``X-Cullis-Mastio-Signature`` header; the Court verifies it
        against the PEM pinned at onboarding in
        ``organizations.mastio_pubkey``.

        Raises ``RuntimeError`` if :meth:`ensure_mastio_identity` has not run.
        """
        import base64
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec as _ec

        active = self._require_active()
        priv_key = active.load_private_key()
        sig = priv_key.sign(data, _ec.ECDSA(hashes.SHA256()))
        return base64.urlsafe_b64encode(sig).rstrip(b"=").decode()

    # ── Credential retrieval ────────────────────────────────────────

    async def get_agent_credentials(self, agent_id: str) -> tuple[str, str]:
        """Retrieve cert_pem and key_pem for an agent.

        Tries Vault first, then falls back to DB/proxy_config.
        Used by BrokerBridge to authenticate to the broker.
        """
        # Get cert from agent record
        agent = await db_get_agent(agent_id)
        if agent is None:
            raise ValueError(f"Agent not found: {agent_id}")
        if not agent["is_active"]:
            raise ValueError(f"Agent is deactivated: {agent_id}")

        cert_pem = agent.get("cert_pem")
        if not cert_pem:
            raise ValueError(f"No certificate found for agent: {agent_id}")

        # Try Vault first for the private key
        try:
            key_pem = await self._fetch_key_vault(agent_id)
            return cert_pem, key_pem
        except Exception:
            pass

        # Fallback: proxy_config table
        key_pem = await get_config(f"agent_key:{agent_id}")
        if key_pem:
            return cert_pem, key_pem

        raise ValueError(f"Private key not found for agent: {agent_id}")

    # ── Vault operations ────────────────────────────────────────────

    async def _store_key_vault(self, agent_id: str, key_pem: str) -> None:
        """Store private key in Vault at {prefix}/agents/{agent_id}."""
        settings = get_settings()
        if settings.secret_backend != "vault" or not settings.vault_addr:
            raise RuntimeError("Vault backend not configured")

        path = f"{settings.vault_secret_prefix}/agents/{agent_id}"
        url = f"{settings.vault_addr}/v1/{path}"

        async with httpx.AsyncClient(
            verify=vault_tls_verify(settings), timeout=5.0,
        ) as http:
            resp = await http.post(
                url,
                json={"data": {"key_pem": key_pem}},
                headers={"X-Vault-Token": settings.vault_token},
            )
            resp.raise_for_status()

    async def _fetch_key_vault(self, agent_id: str) -> str:
        """Fetch private key from Vault."""
        settings = get_settings()
        if settings.secret_backend != "vault" or not settings.vault_addr:
            raise RuntimeError("Vault backend not configured")

        path = f"{settings.vault_secret_prefix}/agents/{agent_id}"
        url = f"{settings.vault_addr}/v1/{path}"

        async with httpx.AsyncClient(
            verify=vault_tls_verify(settings), timeout=5.0,
        ) as http:
            resp = await http.get(
                url,
                headers={"X-Vault-Token": settings.vault_token},
            )
            resp.raise_for_status()
            data = resp.json()
            return data["data"]["data"]["key_pem"]

    # ADR-010 Phase 6a-4 — ``_login_to_broker``, ``_register_with_broker``,
    # ``_get_broker_url`` and ``_get_org_secret`` lived here to mirror agent
    # state onto the Court via the legacy ``POST /v1/registry/agents`` +
    # org_secret-auth ``POST /v1/registry/bindings`` pair. That whole path
    # is gone — cross-org exposure flows through the Mastio admin API and
    # the federation publisher instead.
