"""
Internal agent identity lifecycle — x509 certificate issuance, API key
management, Vault key storage, and broker registration.

Each internal agent gets:
  - An RSA-2048 x509 certificate signed by the Org CA (SPIFFE SAN URI)
  - A private key stored in Vault (or DB fallback)
  - A local API key (sk_local_{name}_{hex}) for authenticating to the proxy
"""
import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import (
    SubjectAlternativeName,
    UniformResourceIdentifier,
)
from cryptography.x509.oid import NameOID

from mcp_proxy.auth.api_key import generate_api_key, hash_api_key
from mcp_proxy.config import get_settings
from mcp_proxy.db import (
    create_agent as db_create_agent,
    deactivate_agent as db_deactivate_agent,
    get_agent as db_get_agent,
    get_config,
    set_config,
)

logger = logging.getLogger("mcp_proxy.egress.agent_manager")


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

        # 5. Register with broker (best-effort)
        await self._register_with_broker(agent_id, display_name, capabilities)

        # 6. Login to broker to pin cert thumbprint + register public key
        await self._login_to_broker(agent_id, cert_pem, key_pem)

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
        """Deactivate agent. Revokes broker registration (best-effort)."""
        found = await db_deactivate_agent(agent_id)
        if not found:
            raise ValueError(f"Agent not found: {agent_id}")

        # Try to unregister from broker (best-effort, don't fail if broker down)
        settings = get_settings()
        if settings.broker_url:
            try:
                async with httpx.AsyncClient(verify=False, timeout=5.0) as http:
                    resp = await http.delete(
                        f"{settings.broker_url}/v1/registry/agents/{agent_id}",
                        headers={
                            "X-Org-Id": self._org_id,
                            "X-Org-Secret": settings.org_secret,
                        },
                    )
                    if resp.is_success:
                        logger.info("Agent unregistered from broker: %s", agent_id)
                    else:
                        logger.warning(
                            "Broker unregister returned %d for %s", resp.status_code, agent_id,
                        )
            except Exception as exc:
                logger.warning("Could not unregister %s from broker: %s", agent_id, exc)

        logger.info("Agent deactivated: %s", agent_id)

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

        async with httpx.AsyncClient(verify=False, timeout=5.0) as http:
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

        async with httpx.AsyncClient(verify=False, timeout=5.0) as http:
            resp = await http.get(
                url,
                headers={"X-Vault-Token": settings.vault_token},
            )
            resp.raise_for_status()
            data = resp.json()
            return data["data"]["data"]["key_pem"]

    # ── Broker registration (best-effort) ───────────────────────────

    async def _login_to_broker(self, agent_id: str, cert_pem: str, key_pem: str) -> None:
        """Login to broker to pin certificate thumbprint and register public key.

        The broker saves the agent's public key on first login (from the x5c
        header in the client_assertion JWT). This makes the agent discoverable
        and allows other agents to encrypt messages to it.
        Non-fatal on failure.
        """
        settings = get_settings()
        broker_url = settings.broker_url
        if not broker_url:
            # Try from DB config
            broker_url = await get_config("broker_url") or ""
        if not broker_url:
            return

        try:
            import asyncio
            from cullis_sdk.client import CullisClient

            def _do_login():
                client = CullisClient(broker_url, verify_tls=False)
                client.login_from_pem(agent_id, self._org_id, cert_pem, key_pem)
                client.close()

            await asyncio.to_thread(_do_login)
            logger.info("Agent %s logged into broker — cert pinned", agent_id)
        except Exception as exc:
            logger.warning("Broker login for %s failed (cert not pinned): %s", agent_id, exc)

    async def _get_broker_url(self) -> str:
        """Get broker URL from settings or DB config."""
        settings = get_settings()
        url = settings.broker_url
        if not url:
            url = await get_config("broker_url") or ""
        return url

    async def _get_org_secret(self) -> str:
        """Get org secret from DB config."""
        return await get_config("org_secret") or ""

    async def _register_with_broker(
        self, agent_id: str, display_name: str, capabilities: list[str],
    ) -> None:
        """Register agent in broker registry. Non-fatal on failure."""
        broker_url = await self._get_broker_url()
        if not broker_url:
            logger.info("No broker_url configured — skipping broker registration")
            return

        org_secret = await self._get_org_secret()
        headers = {"X-Org-Id": self._org_id, "X-Org-Secret": org_secret}

        try:
            async with httpx.AsyncClient(verify=False, timeout=5.0) as http:
                resp = await http.post(
                    f"{broker_url}/v1/registry/agents",
                    headers=headers,
                    json={
                        "agent_id": agent_id,
                        "org_id": self._org_id,
                        "display_name": display_name,
                        "capabilities": capabilities,
                    },
                )
                if resp.status_code == 409:
                    logger.info("Agent %s already registered in broker", agent_id)
                elif resp.is_success:
                    logger.info("Agent %s registered in broker", agent_id)
                else:
                    logger.warning(
                        "Broker registration for %s returned %d: %s",
                        agent_id, resp.status_code, resp.text,
                    )

                # Create binding + auto-approve
                resp2 = await http.post(
                    f"{broker_url}/v1/registry/bindings",
                    headers=headers,
                    json={
                        "org_id": self._org_id,
                        "agent_id": agent_id,
                        "scope": capabilities,
                    },
                )
                if resp2.status_code == 201:
                    binding_id = resp2.json().get("id")
                    if binding_id:
                        await http.post(
                            f"{broker_url}/v1/registry/bindings/{binding_id}/approve",
                            headers=headers,
                        )
                        logger.info("Binding %s created and approved for %s", binding_id, agent_id)
                elif resp2.status_code == 409:
                    logger.info("Binding already exists for %s", agent_id)

        except Exception as exc:
            logger.warning("Broker unreachable for registration of %s: %s", agent_id, exc)
