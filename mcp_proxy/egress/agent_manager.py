"""
Internal agent identity lifecycle — x509 certificate issuance, Vault
key storage, and broker registration.

Each internal agent gets:
  - An RSA-2048 x509 certificate signed by the Org CA (SPIFFE SAN URI).
    This cert IS the agent's credential at the TLS layer (ADR-014).
  - A private key stored in Vault (or DB fallback).
"""
import asyncio
import hashlib
import ipaddress
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

from mcp_proxy.auth.local_keystore import LocalKeyStore, MastioKey, compute_kid
from mcp_proxy.auth.mastio_rotation import ContinuityProof, build_proof
from mcp_proxy.config import get_settings, vault_tls_verify
from mcp_proxy.db import (
    activate_staged_and_deprecate_old,
    create_agent as db_create_agent,
    deactivate_agent as db_deactivate_agent,
    delete_staged_mastio_key,
    get_agent as db_get_agent,
    get_config,
    insert_mastio_key,
    set_config,
)
from mcp_proxy.telemetry_metrics import (
    LEGACY_CA_PATHLEN_ZERO,
    MASTIO_ROTATION_STAGED,
)

from typing import Awaitable, Callable

logger = logging.getLogger("mcp_proxy.egress.agent_manager")


def _strict_pki_enabled() -> bool:
    """Issue #285 — ``MCP_PROXY_STRICT_PKI=1`` opts the proxy into
    refuse-to-boot-on-legacy-PKI semantics. Default OFF; flipping it
    ON as the default would brick legacy proxies that ``docker pull``
    a newer image before an operator has a chance to rotate their
    Org CA. Accept only the exact strings ``1``, ``true``, ``yes``
    (case-insensitive) so a stray empty / malformed value cannot
    surprise an operator.
    """
    import os
    raw = os.environ.get("MCP_PROXY_STRICT_PKI", "").strip().lower()
    return raw in ("1", "true", "yes")


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
        # Issue #281 — serialize rotations in-process so a dashboard
        # double-click or admin+scheduler collision can't interleave
        # two rotate flows. Multi-process/replica serialization lives
        # in ``db.activate_staged_and_deprecate_old`` via a Postgres
        # advisory lock on the same tx.
        self._rotation_lock = asyncio.Lock()
        # Issue #281 — sign-halt state. Set when boot detects a staged
        # row (``activated_at IS NULL``) left behind by a crashed
        # rotation, or when ``rotate_mastio_key`` observes a
        # post-Court-ACK local-activation failure. While halted,
        # ``countersign`` raises and ``main.py`` declines to build
        # ``LocalIssuer``, so both intra-org local tokens and
        # cross-org counter-sigs error out cleanly instead of
        # producing signatures the Court would reject.
        self._sign_halted = False
        self._staged_kid: str | None = None
        # PR 2 federation updates — reason string populated by
        # ``mark_sign_halted`` so the boot detector and the (future)
        # dashboard recovery page can explain *why* signing stopped
        # beyond the #281 staged-row case. None when the halt was set
        # by legacy paths that pre-date the reason field (#281 branches
        # above still set ``_sign_halted`` directly and leave this None;
        # the dashboard treats None as "staged rotation recovery").
        self._sign_halt_reason: str | None = None
        # Issue #285 — diagnostic flag set at boot when the Org CA in
        # ``proxy_config.org_ca_cert`` has ``BasicConstraints(pathLen=0)``
        # but the proxy mints a Mastio intermediate CA underneath it at
        # runtime (``_mint_mastio_ca``). That chain violates RFC 5280
        # §4.2.1.9 — stdlib verifiers (OpenSSL, Go crypto/x509, webpki,
        # browser, kubectl mTLS) reject it during cross-org federation,
        # even though #280's verifier fix now catches it locally too.
        # The flag surfaces in ``/health`` warnings and on the
        # ``cullis_proxy_legacy_ca_pathlen_zero`` Prometheus gauge so
        # operators see a clear signal before a design partner trips
        # over silent federation failures.
        self._legacy_ca_pathlen_zero = False

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

    # ── ADR-014: nginx sidecar TLS material ──────────────────────────

    async def ensure_nginx_server_cert(
        self,
        *,
        out_dir: str,
        sans: list[str] | None = None,
        validity_days: int = 365,
        renew_within_days: int = 30,
    ) -> bool:
        """Emit / refresh the TLS server cert that the nginx sidecar uses.

        Writes three files into ``out_dir``:

        - ``org-ca.crt`` — the Org CA's public certificate (the trust
          bundle nginx uses as ``ssl_client_certificate`` to verify
          Connector certs at the TLS handshake).
        - ``mastio-server.crt`` — the leaf cert nginx serves on 9443,
          signed by the Org CA, with the requested SANs.
        - ``mastio-server.key`` — the leaf's private key.

        Idempotent: at every boot the method checks whether the existing
        files are still valid (parseable, not expiring within
        ``renew_within_days``, SAN list matches, issued by the current
        Org CA). If yes, nothing changes. If no, a fresh leaf is minted
        and the trust bundle is rewritten.

        Returns ``True`` if files were rewritten, ``False`` if the
        existing material was reused.
        """
        if not self.ca_loaded:
            raise RuntimeError("Org CA not loaded — cannot emit nginx server cert")

        from pathlib import Path

        def _aware(dt: datetime) -> datetime:
            """cryptography <42 returns naive UTC datetimes from cert
            properties; ≥42 returns aware. Normalize to aware for math
            and ISO formatting."""
            return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt

        san_list = list(sans) if sans else ["mastio.local"]

        # Split SANs into IP literals vs hostnames. RFC 6125 / RFC 5280:
        # an IP-literal request URL is validated against ``iPAddress`` SAN,
        # never ``dNSName`` — Python's ssl module enforces this strictly,
        # so a leaf with ``DNS:192.168.122.154`` only fails ``hostname
        # 192.168.122.154 doesn't match`` even though the string is "in"
        # the cert. This was the standalone-bundle bug a non-tech operator
        # hit on first deploy (Site URL filled in with the VM IP, agent
        # then refuses every request with CERTIFICATE_VERIFY_FAILED).
        san_ips: list[str] = []
        san_hosts: list[str] = []
        for entry in san_list:
            try:
                ipaddress.ip_address(entry)
                san_ips.append(entry)
            except ValueError:
                san_hosts.append(entry)

        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)

        ca_path = out / "org-ca.crt"
        crt_path = out / "mastio-server.crt"
        key_path = out / "mastio-server.key"

        # ── Reuse path: validate existing files in one shot ─────────
        reuse = False
        if ca_path.exists() and crt_path.exists() and key_path.exists():
            try:
                existing = x509.load_pem_x509_certificate(crt_path.read_bytes())
                # SAN match — read DNSName + IPAddress because the same
                # ``san_list`` may contain both (now that we split). A
                # cert that already carries the right entries — even if
                # we used to write IPs as DNSName before this fix —
                # should NOT trigger a regeneration here; the post-
                # mint reuse check below catches the type mismatch.
                try:
                    san_ext = existing.extensions.get_extension_for_class(
                        SubjectAlternativeName,
                    ).value
                    existing_hosts = set(san_ext.get_values_for_type(x509.DNSName))
                    existing_ips = {
                        str(ip) for ip in san_ext.get_values_for_type(x509.IPAddress)
                    }
                except x509.ExtensionNotFound:
                    existing_hosts, existing_ips = set(), set()
                # Issuer match (current Org CA's subject)
                issuer_ok = (
                    existing.issuer.rfc4514_string()
                    == self._org_ca_cert.subject.rfc4514_string()
                )
                # Expiry guard
                now = datetime.now(timezone.utc)
                expires_in = _aware(existing.not_valid_after) - now
                expiry_ok = expires_in > timedelta(days=renew_within_days)
                # CA bundle file matches the in-memory CA
                ca_ondisk = x509.load_pem_x509_certificate(ca_path.read_bytes())
                ca_ok = (
                    ca_ondisk.public_bytes(serialization.Encoding.DER)
                    == self._org_ca_cert.public_bytes(serialization.Encoding.DER)
                )

                # Strict equality: same hosts AND same IPs in the right
                # SAN type. A pre-fix cert that had IPs in ``DNSName``
                # falls through to the mint path, which is the right
                # outcome — that cert is the bug we're closing.
                sans_ok = (
                    existing_hosts == set(san_hosts)
                    and existing_ips == set(san_ips)
                )

                if issuer_ok and expiry_ok and ca_ok and sans_ok:
                    reuse = True
            except Exception as exc:  # treat any parse failure as "regenerate"
                logger.info(
                    "nginx server cert on disk failed validation (%s) — "
                    "will regenerate",
                    exc,
                )

        if reuse:
            logger.info(
                "nginx server cert reused (sans=%s, expiring=%s)",
                ",".join(san_list),
                _aware(existing.not_valid_after).isoformat(timespec="seconds"),
            )
            return False

        # ── Mint path ───────────────────────────────────────────────
        # ECDSA P-256 leaf — fast, modern, matches the Connector cert
        # algorithm so nginx negotiates TLS 1.3 + ECDSA cleanly.
        leaf_key = ec.generate_private_key(ec.SECP256R1())

        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, san_list[0]),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self._org_id or "cullis"),
        ])

        now = datetime.now(timezone.utc)
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._org_ca_cert.subject)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=validity_days))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,  # required for TLS RSA-style ciphers
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
            .add_extension(
                SubjectAlternativeName(
                    [x509.DNSName(h) for h in san_hosts]
                    + [x509.IPAddress(ipaddress.ip_address(ip)) for ip in san_ips],
                ),
                critical=False,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self._org_ca_cert.public_key(),
                ),
                critical=False,
            )
        )
        leaf_cert = builder.sign(self._org_ca_key, hashes.SHA256())

        # Write atomically: tmp file then rename. nginx watches the
        # files and reload (SIGHUP) is the operator's job; mid-boot
        # we just need the writes consistent so a restart-within-restart
        # never observes a torn pair.
        ca_pem = self._org_ca_cert.public_bytes(serialization.Encoding.PEM)
        crt_pem = leaf_cert.public_bytes(serialization.Encoding.PEM)
        key_pem = leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

        for path, payload, mode in (
            (ca_path, ca_pem, 0o644),
            (crt_path, crt_pem, 0o644),
            (key_path, key_pem, 0o600),
        ):
            tmp = path.with_suffix(path.suffix + ".tmp")
            tmp.write_bytes(payload)
            tmp.chmod(mode)
            tmp.replace(path)

        logger.info(
            "nginx server cert minted (sans=%s, valid_until=%s, dir=%s)",
            ",".join(san_list),
            _aware(leaf_cert.not_valid_after).isoformat(timespec="seconds"),
            out_dir,
        )
        return True

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
          1. Generate x509 cert+key (signed by Org CA) — the cert IS
             the agent's credential at the TLS layer (ADR-014).
          2. Store key in Vault (or DB if Vault not available).
          3. Store agent record in DB.
          4. Return ``(agent_info_dict, key_pem)`` so the caller can
             hand the freshly-minted private key to the agent process.

        The private key plaintext is shown ONCE — Vault stores the
        canonical copy; this method returns the same bytes only so the
        synchronous caller (dashboard / sandbox bootstrap) can ship it
        to the agent's filesystem.
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

        # 3. Store agent record in DB
        await db_create_agent(
            agent_id=agent_id,
            display_name=display_name,
            capabilities=capabilities,
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
            "private_key_pem": key_pem,
        }

        logger.info("Internal agent created: %s", agent_id)
        return agent_info, key_pem

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

        # Issue #285 — legacy-CA detection runs before identity check so
        # the flag is set even when the proxy generates a fresh Mastio
        # identity on first boot with a legacy Org CA inherited from
        # pre-#280 bootstrap.
        self._detect_legacy_ca_pathlen_zero()

        if self.mastio_loaded:
            # Issue #281 — detect staged rotation rows left behind by a
            # crash between propagator-ACK and local activation. Court
            # does hard-swap (no grace window on mastio_pubkey — see
            # #286), so if the crash happened *after* the Court ACK, the
            # old local key can no longer counter-sign successfully.
            # The safe recovery is to refuse to sign at all until the
            # admin resolves via POST /proxy/mastio-key/complete-staged,
            # rather than emit signatures the Court would 403.
            await self._detect_staged_and_maybe_halt()
            logger.info("Mastio identity loaded (ca + active key)")
            return

        await self._generate_mastio_identity()

    def _detect_legacy_ca_pathlen_zero(self) -> None:
        """Issue #285 — flag a pre-#280 bootstrap Org CA.

        Before PR #284 (closes #280), the dashboard setup wizard and
        the Court admin-generated CA flow emitted Org CAs with
        ``BasicConstraints(pathLen=0)``. Proxies that bootstrapped
        during that window still carry that CA in
        ``proxy_config.org_ca_cert`` and cannot produce a chain that
        stdlib verifiers accept — the Mastio intermediate CA minted
        under the Org CA violates the pathLen constraint, and every
        cross-org federation handshake that terminates at a peer
        running OpenSSL / Go / webpki silently 401s.

        This method inspects the loaded Org CA, raises ``RuntimeError``
        when ``MCP_PROXY_STRICT_PKI=1`` is set (opt-in for sandbox /
        CI / strict-enforcement deployments — not the default, because
        a legacy proxy that ``docker pull``s a new image would then
        refuse to boot without a remediation framework in place), and
        otherwise just records the state for ``/health`` + the
        Prometheus gauge to surface. Remediation is operator action:
        ``POST /pki/rotate-ca`` rotates the Org CA in place.
        """
        if self._org_ca_cert is None:
            return
        try:
            bc = self._org_ca_cert.extensions.get_extension_for_class(
                x509.BasicConstraints
            ).value
        except x509.ExtensionNotFound:
            # Unusual — a CA that skipped BasicConstraints. Leave
            # without flagging; other validation will reject it.
            return
        if bc.path_length != 0:
            # pathLen=1 (post-#280) or pathLen=None (unbounded). Either
            # is OK for the current 3-tier chain.
            LEGACY_CA_PATHLEN_ZERO.set(0)
            return

        self._legacy_ca_pathlen_zero = True
        LEGACY_CA_PATHLEN_ZERO.set(1)

        # Pull the subject CN for the log. Fall back to empty string
        # if the CA lacks CN — the serial + org_id alone are enough
        # to identify the CA.
        cn = ""
        try:
            cn_attrs = self._org_ca_cert.subject.get_attributes_for_oid(
                NameOID.COMMON_NAME
            )
            if cn_attrs:
                cn = cn_attrs[0].value
        except Exception:
            pass

        logger.warning(
            "org_ca_legacy_pathlen_zero: Org CA has pathLen=0 but the "
            "proxy mints a Mastio intermediate under it. Stdlib "
            "verifiers (OpenSSL, Go crypto/x509, webpki) reject the "
            "chain during cross-org federation. Remediation: POST "
            "/pki/rotate-ca. (org_id=%s ca_serial=%s cn=%s)",
            self._org_id,
            self._org_ca_cert.serial_number,
            cn,
        )

        if _strict_pki_enabled():
            raise RuntimeError(
                "MCP_PROXY_STRICT_PKI=1 refuses boot on legacy Org CA "
                "with pathLen=0 — run POST /pki/rotate-ca and restart, "
                "or unset MCP_PROXY_STRICT_PKI to boot with a warning "
                f"(org_id={self._org_id!r}, "
                f"ca_serial={self._org_ca_cert.serial_number})"
            )

    @property
    def has_legacy_ca_pathlen_zero(self) -> bool:
        """True when the loaded Org CA has ``BasicConstraints(pathLen=0)``.

        Set at boot by ``_detect_legacy_ca_pathlen_zero``. Consumers:
          - ``/health`` — surfaces ``"org_ca_legacy_pathlen_zero"``
            in the ``warnings`` array.
          - ``cullis_proxy_legacy_ca_pathlen_zero`` Prometheus gauge
            (via the ``LEGACY_CA_PATHLEN_ZERO`` metric in
            ``telemetry_metrics``).
        """
        return self._legacy_ca_pathlen_zero

    async def _detect_staged_and_maybe_halt(self) -> None:
        """Boot-time check for an orphaned staged rotation row.

        Sets ``self._sign_halted = True`` and records the staged kid
        when found. Caller (``main.py``) inspects ``is_sign_halted``
        after ``ensure_mastio_identity`` returns and skips
        ``LocalIssuer`` construction so local-token issuance is
        disabled until the operator calls
        ``complete_staged_rotation``.
        """
        try:
            staged = await self._keystore.find_staged()
        except RuntimeError as exc:
            # Multiple staged rows — invariant violation, halt loudly.
            self._sign_halted = True
            MASTIO_ROTATION_STAGED.set(1)
            logger.error(
                "rotation state corrupt at boot: %s; refusing to sign "
                "until manual DB cleanup + POST /proxy/mastio-key/"
                "complete-staged",
                exc,
            )
            return

        if staged is None:
            MASTIO_ROTATION_STAGED.set(0)
            return

        self._sign_halted = True
        self._staged_kid = staged.kid
        MASTIO_ROTATION_STAGED.set(1)
        logger.error(
            "rotation state inconsistent at boot: staged kid=%s found "
            "without activation. LocalIssuer disabled and countersign "
            "halted. Resolve via POST /proxy/mastio-key/complete-staged "
            "(activate if Court already pinned new, drop if still on old).",
            staged.kid,
        )

    @property
    def is_sign_halted(self) -> bool:
        """True while a staged row blocks signing (issue #281).

        Callers:
          - ``main.py`` — skips ``LocalIssuer`` construction when True.
          - ``countersign`` — raises RuntimeError when True.
          - Dashboard (future #287) — renders the recovery banner.
        """
        return self._sign_halted

    @property
    def staged_kid(self) -> str | None:
        """Kid of the blocking staged row, or None."""
        return self._staged_kid

    @property
    def sign_halt_reason(self) -> str | None:
        """Human-readable reason the halt was engaged, or None.

        Set by ``mark_sign_halted``; the #281 legacy branches leave it
        None because their state is fully captured by ``staged_kid``.
        """
        return self._sign_halt_reason

    def mark_sign_halted(self, reason: str) -> None:
        """Engage the sign-halt degraded mode with a structured reason.

        Used by callers outside the rotation-race path (PR 2 federation
        update boot detector) that need to declare "signing is unsafe
        until the operator intervenes" without touching ``_staged_kid``.
        Idempotent: re-marking with a new reason overwrites the reason
        but leaves the halt engaged, so callers composed on top of the
        #281 halt path don't accidentally clear state.

        Logs ERROR so the operator finds the trigger in logs immediately
        — the dashboard banner (PR 5) is the user-friendly surface, but
        logs are the baseline.
        """
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("mark_sign_halted requires a non-empty reason")
        self._sign_halted = True
        self._sign_halt_reason = reason
        logger.error("sign-halt engaged: %s", reason)

    def clear_sign_halt(self) -> None:
        """Release the sign-halt degraded mode unconditionally.

        Used by the PR 4 admin endpoint after a federation-update apply
        or rollback succeeds. The caller is expected to immediately
        re-run :func:`mcp_proxy.updates.boot.detect_pending_migrations`
        — if another critical migration is still pending, the halt
        re-engages with a fresh reason; otherwise the proxy returns to
        normal.

        Idempotent: calling on an already-clear state is a silent no-op.
        Does NOT touch ``_staged_kid`` — the #281 staged-row recovery
        path owns that field; clearing it here would mask a genuine
        rotation recovery state.
        """
        if not self._sign_halted and self._sign_halt_reason is None:
            return
        prior_reason = self._sign_halt_reason
        self._sign_halted = False
        self._sign_halt_reason = None
        logger.info(
            "sign-halt cleared (prior reason: %s)",
            prior_reason or "<legacy #281 path, no reason>",
        )

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

        Race-safe, crash-safe flow (issue #281):

        1. Serialize on ``self._rotation_lock`` — kills double-click and
           dashboard+cron collisions in the same process.
        2. Under the lock, re-read the current signer and refuse to
           start if (a) the active signer changed since ``__init__``
           handed us ``old``, or (b) a staged row is already present
           (incomplete prior rotation — admin must resolve first).
        3. Mint the new leaf and build the continuity proof with the
           *old* private key.
        4. INSERT the new row as **staged** (``activated_at IS NULL``)
           so ``new_privkey_pem`` is durable on disk before we tell the
           Court anything — a crash between here and step 6 leaves the
           staged row visible to the next boot's recovery.
        5. Call the propagator. On raise, delete the staged row so the
           next rotation can start clean.
        6. Atomically activate the staged row and deprecate the old one
           (``activate_staged_and_deprecate_old`` takes a pg advisory
           lock on Postgres to serialize across replicas). On raise,
           leave the staged row intact and sign-halt — the Court has
           pinned the new pubkey at this point, so the admin must
           reconcile via ``complete_staged_rotation``.
        7. Refresh the cached active key and return it.

        ``grace_days`` controls how long the old kid stays
        verifier-accepted after deprecation. Default 7.

        ``propagator`` receives the built ``ContinuityProof`` plus the
        new cert PEM and is expected to call the Court. When ``None``
        (tests / offline bootstrap) the Court step is skipped and a
        warning logged — useful for unit tests, never safe in
        production.

        Returns the freshly-activated :class:`MastioKey` (also cached
        as ``self._active_key``).
        """
        if grace_days <= 0:
            raise ValueError("grace_days must be a positive integer")
        old = self._require_active()
        if self._mastio_ca_key is None or self._mastio_ca_cert is None:
            raise RuntimeError("Mastio intermediate CA not loaded")

        async with self._rotation_lock:
            return await self._rotate_locked(old, grace_days, propagator)

    async def _rotate_locked(
        self,
        old: MastioKey,
        grace_days: int,
        propagator: "Callable[[ContinuityProof, str], Awaitable[None]] | None",
    ) -> MastioKey:
        """Body of :meth:`rotate_mastio_key`, executed under the
        rotation lock. Split out so the test suite can drive the
        individual steps without re-acquiring the lock in
        fault-injection scenarios.
        """
        # Re-check state under the lock: a concurrent rotation may
        # have completed between ``_require_active`` above and us
        # acquiring the lock. Refuse to start if the active signer
        # has changed.
        current_active = await self._keystore.current_signer()
        if current_active.kid != old.kid:
            raise RuntimeError(
                f"rotation aborted: active signer changed under us "
                f"({old.kid!r} → {current_active.kid!r}); a concurrent "
                f"rotation succeeded"
            )
        existing_staged = await self._keystore.find_staged()
        if existing_staged is not None:
            raise RuntimeError(
                f"rotation aborted: a staged row (kid={existing_staged.kid!r}) "
                f"is already present from a prior rotation; resolve it via "
                f"POST /proxy/mastio-key/complete-staged before retrying"
            )

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

        now_iso = now.isoformat()
        grace_end_iso = (now + timedelta(days=grace_days)).isoformat()

        # Step 4 — stage the new row on disk *before* telling the Court.
        # If the process dies after this INSERT, the next boot's
        # ``_detect_staged_and_maybe_halt`` picks it up and sign-halts
        # until the operator resolves.
        await insert_mastio_key(
            kid=new_kid,
            pubkey_pem=new_pub_pem,
            privkey_pem=new_priv_pem,
            cert_pem=new_cert_pem,
            created_at=now_iso,
            activated_at=None,
            deprecated_at=None,
            expires_at=None,
        )

        # Step 5 — propagate to Court.
        if propagator is not None:
            try:
                await propagator(proof, new_cert_pem)
            except BaseException:
                # Court rejected or unreachable → nothing is pinned on
                # their side yet, so the staged row is safe to drop.
                # BaseException catches asyncio.CancelledError too.
                try:
                    await delete_staged_mastio_key(new_kid)
                except Exception as cleanup_exc:
                    # Cleanup is best-effort; failure here means boot
                    # recovery will pick it up as a staged row.
                    logger.warning(
                        "staged row cleanup failed after propagator error "
                        "(kid=%s): %s — boot recovery will handle it",
                        new_kid, cleanup_exc,
                    )
                raise
        else:
            logger.warning(
                "rotate_mastio_key: no propagator provided — Court will "
                "stay pinned on the old pubkey; production callers must "
                "supply one",
            )

        # Step 6 — atomic commit. On Postgres, this takes
        # ``pg_advisory_xact_lock`` so a concurrent rotation from
        # another replica (which passed our in-process asyncio.Lock but
        # not this one) serializes instead of interleaving.
        try:
            await activate_staged_and_deprecate_old(
                new_kid=new_kid,
                new_activated_at=now_iso,
                old_kid=old.kid,
                old_deprecated_at=now_iso,
                old_expires_at=grace_end_iso,
            )
        except BaseException:
            # Court has already pinned ``new_pub_pem``. Any token we
            # countersign right now uses the old key — Court 403s.
            # Sign-halt so downstream callers get a clear error and the
            # admin resolves via ``complete_staged_rotation``. Do *not*
            # drop the staged row: ``complete_staged_rotation`` needs
            # it to offer the activate branch.
            self._sign_halted = True
            self._staged_kid = new_kid
            MASTIO_ROTATION_STAGED.set(1)
            logger.error(
                "rotation mid-flight failure after Court ACK: local "
                "activation failed for kid=%s. Sign-halted. Admin must "
                "resolve via POST /proxy/mastio-key/complete-staged.",
                new_kid,
            )
            raise

        await self.refresh_active_key()
        # Clear any prior halt state — we completed a clean rotation.
        self._sign_halted = False
        self._staged_kid = None
        MASTIO_ROTATION_STAGED.set(0)
        logger.info(
            "Mastio key rotated — old_kid=%s, new_kid=%s, grace_days=%d",
            old.kid, new_kid, grace_days,
        )
        assert self._active_key is not None
        return self._active_key

    async def complete_staged_rotation(self, decision: str) -> dict:
        """Resolve an orphaned staged row (issue #281 recovery path).

        Serialized on ``self._rotation_lock`` — the same primitive that
        serializes fresh rotations, so a racing rotation cannot overlap
        with recovery.

        ``decision`` must be ``"activate"`` or ``"drop"``. The operator
        chooses based on Court state:

        - ``"activate"`` when the Court has already pinned the staged
          pubkey (propagator had succeeded, only local activation
          failed). Activates the staged row and deprecates the current
          active, using the configured ``grace_days``.
        - ``"drop"`` when the Court is still on the current active
          (propagator had not succeeded or rotated back). Deletes the
          staged row.

        Returns a dict with ``{"decision", "kid", "old_kid"?,
        "grace_days"?}`` so the caller (dashboard / CLI) can surface
        the outcome to the operator. On success, clears the sign-halt
        flag.

        Raises RuntimeError if no staged row exists or if the current
        active signer has somehow gone missing (malformed state).
        """
        if decision not in ("activate", "drop"):
            raise ValueError(
                f"decision must be 'activate' or 'drop', got {decision!r}"
            )

        async with self._rotation_lock:
            staged = await self._keystore.find_staged()
            if staged is None:
                raise RuntimeError(
                    "no staged row present — nothing to complete. The "
                    "halt state may be stale; restart the proxy or "
                    "re-run rotation."
                )

            if decision == "drop":
                deleted = await delete_staged_mastio_key(staged.kid)
                if deleted != 1:
                    raise RuntimeError(
                        f"staged row {staged.kid!r} vanished during drop "
                        f"(rowcount={deleted}); likely a concurrent "
                        f"recovery call"
                    )
                self._sign_halted = False
                self._staged_kid = None
                MASTIO_ROTATION_STAGED.set(0)
                logger.info(
                    "complete_staged_rotation(drop): staged kid=%s deleted; "
                    "signing resumed with prior active",
                    staged.kid,
                )
                return {"decision": "drop", "kid": staged.kid}

            # decision == "activate"
            current = await self._keystore.current_signer()
            # Default grace_days matches rotate_mastio_key default (7);
            # keeping a fixed value here because the original caller's
            # choice is already lost to the crash — the operator is
            # resolving from a standing start. Callers that want a
            # different cadence can drop + re-rotate.
            grace_days = 7
            now = datetime.now(timezone.utc)
            now_iso = now.isoformat()
            grace_end_iso = (now + timedelta(days=grace_days)).isoformat()

            await activate_staged_and_deprecate_old(
                new_kid=staged.kid,
                new_activated_at=now_iso,
                old_kid=current.kid,
                old_deprecated_at=now_iso,
                old_expires_at=grace_end_iso,
            )
            await self.refresh_active_key()
            self._sign_halted = False
            self._staged_kid = None
            MASTIO_ROTATION_STAGED.set(0)
            logger.info(
                "complete_staged_rotation(activate): old_kid=%s → new_kid=%s "
                "(grace_days=%d); signing resumed",
                current.kid, staged.kid, grace_days,
            )
            return {
                "decision": "activate",
                "kid": staged.kid,
                "old_kid": current.kid,
                "grace_days": grace_days,
            }

    def countersign(self, data: bytes) -> str:
        """ES256 counter-signature over ``data``, base64url no-pad.

        Used by ``BrokerBridge`` to attest every ``/v1/auth/token`` call
        as proxied through this mastio. The signature goes into the
        ``X-Cullis-Mastio-Signature`` header; the Court verifies it
        against the PEM pinned at onboarding in
        ``organizations.mastio_pubkey``.

        Raises:
            RuntimeError: if :meth:`ensure_mastio_identity` has not run,
                or if signing is halted (issue #281: a staged rotation
                row is present and needs admin resolution via
                ``complete_staged_rotation`` — producing a signature
                with the old key while Court may have pinned the new
                one would 403 anyway, and surfacing a clear local error
                is strictly better than an opaque Court rejection).
        """
        import base64
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec as _ec

        if self._sign_halted:
            raise RuntimeError(
                "mastio signing halted — staged rotation row "
                f"(kid={self._staged_kid!r}) awaiting resolution. "
                "POST /proxy/mastio-key/complete-staged to recover."
            )
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
