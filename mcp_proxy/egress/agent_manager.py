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
    archive_legacy_pki,
    create_agent as db_create_agent,
    deactivate_agent as db_deactivate_agent,
    delete_proxy_config,
    delete_staged_mastio_key,
    get_agent as db_get_agent,
    get_config,
    insert_mastio_key,
    log_audit,
    set_config,
)
from mcp_proxy.telemetry_metrics import (
    LEGACY_CA_PATHLEN_ZERO,
    MASTIO_ROTATION_STAGED,
)

from typing import Awaitable, Callable

logger = logging.getLogger("mcp_proxy.egress.agent_manager")


# ── PKI durations (three-tier hardening, audit 2026-05-18) ──────────────
# Rebalanced from the historic 10/3/1/1/1y profile to spread expiry
# risk across the chain. Org Root is cold so length is operational
# only (rotation event is rare and disruptive). Intermediate is the
# hot online signer so its 5y window matches NIST SP 800-57 §5.3.6
# for active signing keys with automated rotation hooks. Leaves
# inherit the shorter end of the curve.
ORG_CA_VALIDITY_DAYS = 365 * 15  # 15 years (cold root)
INTERMEDIATE_CA_VALIDITY_DAYS = 365 * 5  # 5 years (hot signer, auto-rotation)
MASTIO_LEAF_VALIDITY_DAYS = 365  # 1 year (existing ADR-012 Phase 2.1 rotation cadence)
AGENT_CERT_VALIDITY_DAYS = 365  # 1 year (Wave 2 narrows further with grace-period support)
NGINX_SERVER_CERT_VALIDITY_DAYS = 90  # 90 days (was 1y, audit 2026-05-18 short-lived TLS)


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


class _OrgRootUnsealCtx:
    """Async context manager produced by :meth:`AgentManager._unseal_org_root`.

    Loads the Org Root private key from the configured KMS provider on
    ``__aenter__``, emits an ``org_root_unsealed`` audit row, yields,
    then scrubs the cached private key reference on ``__aexit__``. The
    cert pointer stays loaded (it's public material) so subsequent
    daily-ops can still read CN / subject / pathLen without re-fetching.

    Concurrent unseals (e.g. boot Intermediate mint + admin manual
    rotation racing) serialize on ``AgentManager._org_root_lock`` so
    the private key cache is single-owner during the sensitive window.
    """

    def __init__(self, mgr: "AgentManager", *, reason: str, operator: str):
        self._mgr = mgr
        self._reason = reason
        self._operator = operator
        self._start_ns: int = 0
        self._previous_key = None
        self._previous_was_cached = False

    async def __aenter__(self):
        import time

        await self._mgr._org_root_lock.acquire()
        self._start_ns = time.monotonic_ns()
        # If the legacy path already cached a key, remember it so we
        # don't accidentally scrub material the caller still wants.
        # In the post-hardening flow ``_org_ca_key`` is None at entry.
        self._previous_key = self._mgr._org_ca_key
        self._previous_was_cached = self._previous_key is not None
        if not self._previous_was_cached:
            from mcp_proxy.kms import get_kms_provider
            loaded = await get_kms_provider().load_org_ca()
            if loaded is None:
                self._mgr._org_root_lock.release()
                raise RuntimeError(
                    "Org Root not present in KMS provider — cannot "
                    f"unseal for reason={self._reason!r}. Either "
                    "first-boot has not run, or the provider lost the "
                    "key (Vault path missing, cloud KMS unreachable).",
                )
            key_pem, _cert_pem = loaded
            self._mgr._org_ca_key = serialization.load_pem_private_key(
                key_pem.encode(), password=None,
            )
            logger.info(
                "Org Root unsealed (reason=%s, operator=%s) — key in memory",
                self._reason, self._operator,
            )
        return self._mgr._org_ca_key

    async def __aexit__(self, exc_type, exc, tb):
        import gc
        import time

        try:
            if not self._previous_was_cached:
                # Belt-and-braces scrub: clear the reference, force gc
                # so the OpenSSL-backed buffer is freed promptly. Note
                # that ``cryptography`` does not expose a public clear()
                # API for private-key material, so we rely on Python's
                # reference counting + the C extension's destructor.
                self._mgr._org_ca_key = None
                gc.collect()
                duration_ms = (time.monotonic_ns() - self._start_ns) / 1_000_000

                # Audit row: best-effort. If audit chain is unavailable
                # (early boot, multi-worker init race) the unseal still
                # happened, log loudly so the operator notices. Only
                # logged when the unseal actually loaded the private
                # key from KMS (cold-path); the dev fallback that
                # kept the key cached is a back-compat no-op and does
                # not represent a real "unseal event".
                try:
                    await log_audit(
                        agent_id=self._operator,
                        action="pki.org_root_unsealed",
                        status="success" if exc is None else "error",
                        detail=(
                            f"reason={self._reason} "
                            f"duration_ms={duration_ms:.1f}"
                            + (f" error={type(exc).__name__}" if exc is not None else "")
                        ),
                    )
                except Exception as audit_exc:
                    logger.warning(
                        "org_root_unsealed audit row failed (reason=%s, "
                        "duration_ms=%.1f): %s, unseal completed but "
                        "trail missing",
                        self._reason, duration_ms, audit_exc,
                    )
        finally:
            self._mgr._org_root_lock.release()
        return False


class AgentManager:
    """Manages internal agent identity lifecycle.

    Creates x509 certificates signed by the Org CA, stores private keys
    in Vault (or locally in the DB), and generates local API keys for
    internal auth.
    """

    def __init__(self, org_id: str, trust_domain: str = "cullis.local"):
        self._org_id = org_id
        self._trust_domain = trust_domain
        # M-crypto-2 audit fix — Org CA generation defaults to EC P-256
        # (see ``generate_self_signed_ca``) but legacy deployments may
        # have an RSA Org CA on disk; the type annotation accepts both
        # so loading legacy material doesn't trip a type guard.
        self._org_ca_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | None = None
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
        # Three-tier PKI hardening (audit 2026-05-18) — Org Root cold path.
        # ``_org_root_lock`` serializes unseal calls so two operations
        # that need the root (boot Intermediate mint + admin manual
        # rotation racing) don't tear each other's private-key cache.
        self._org_root_lock = asyncio.Lock()

    # ── CA loading ──────────────────────────────────────────────────

    async def load_org_ca(self, ca_key_pem: str, ca_cert_pem: str) -> None:
        """Load org CA key+cert from PEM strings (fetched from Vault or config).

        Pre-three-tier-hardening this method retained the private key in
        ``self._org_ca_key`` for the full process lifetime. Post-fix the
        private key is loaded on-demand via :meth:`_unseal_org_root` and
        scrubbed immediately after use, so the steady-state holds only
        the public cert. Tests + legacy bootstrap paths that pass the
        key PEM in explicitly still see it cached (back-compat); the
        ``load_org_ca_from_config`` path that runs at boot deliberately
        skips loading the private key and leaves ``_org_ca_key`` None.
        """
        self._org_ca_key = serialization.load_pem_private_key(
            ca_key_pem.encode(), password=None,
        )
        self._org_ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode())
        logger.info(
            "Org CA loaded (with private key cached) — issuer CN=%s",
            self._org_ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
        )

    def _unseal_org_root(self, *, reason: str, operator: str = "system"):
        """Async context manager: load Org Root private key, yield, scrub.

        Three-tier PKI hardening (audit 2026-05-18) — Org Root is cold
        by default. Daily operations (sign agent cert, sign nginx leaf,
        sign Mastio Leaf rotation) all use the Intermediate CA via
        ``self._mastio_ca_key``. Only rare operations need the root:

        * Initial mint of the Intermediate (first boot).
        * Intermediate rotation (Phase 4, weekly leader-elected watcher
          + manual admin trigger).
        * Generating the CA bundle for export (read of cert only, no
          private key needed — that path does NOT call this helper).

        Each unseal emits an ``org_root_unsealed`` audit row with the
        operator + reason so post-incident reviews can correlate any
        Intermediate signature back to the operator who triggered it.

        Usage:

        ```
        async with self._unseal_org_root(reason="mint_intermediate"):
            # sign the cert using self._org_ca_key
            ...
        ```

        Scrubbing: we ``del`` the private key reference and force a GC
        pass so the heap copy drops out of resident memory before the
        next request. ``cryptography``'s C-backed key objects also wipe
        their internal buffer in their ``__del__`` for OpenSSL backend
        builds; the Python-level scrub is belt-and-braces.

        Synchronous return (NOT a coroutine) so callers use
        ``async with self._unseal_org_root(...)`` directly without an
        intermediate ``await``.
        """
        return _OrgRootUnsealCtx(self, reason=reason, operator=operator)

    async def load_org_ca_from_config(self) -> bool:
        """Try to load the Org CA via the configured KMS provider.

        Default provider is :class:`mcp_proxy.kms.LocalKMSProvider` which
        reads ``proxy_config[org_ca_key]`` and ``proxy_config[org_ca_cert]``
        — same surface as before this method got refactored to route
        through the KMS factory. cullis-enterprise plugins (cloud KMS,
        Key Vault, etc.) plug in via ``MCP_PROXY_KMS_BACKEND`` + the
        ``kms_factory`` plugin hook.

        P3 MAJOR-B (2026-05-17 dogfood) — after the load, cross-check
        cert subject CN against ``proxy_config.org_id``. The Mastio CA
        in :meth:`generate_org_ca` always carries CN ``"{org_id} CA"``;
        a mismatch means a DB swap or stale pin, and every client cert
        chain validation downstream silently 400/401's otherwise. We
        also DER-compare the on-disk ``nginx_cert_dir/org-ca.crt`` to
        the DB cert and WARN on divergence (advisory only —
        ``ensure_nginx_server_cert`` re-syncs it later in the lifespan).

        Returns True on successful load, False on missing-CA or mismatch.
        """
        from mcp_proxy.kms import get_kms_provider
        loaded = await get_kms_provider().load_org_ca()
        if loaded is None:
            logger.warning("Org CA not found via KMS provider — agent cert issuance unavailable")
            return False

        # Three-tier PKI hardening (audit 2026-05-18) — at boot we only
        # cache the Org Root **cert** (public material). The private key
        # stays cold; daily-ops paths (sign agent / nginx / Mastio leaf
        # rotation) go through the Intermediate. Rare root-needing
        # paths (mint Intermediate, rotate Intermediate) unseal via
        # :meth:`_unseal_org_root`.
        _ca_key_pem, ca_cert_pem = loaded
        self._org_ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode())
        # _org_ca_key stays None — cold storage by default.
        self._org_ca_key = None
        logger.info(
            "Org Root cert cached (cold private key) — CN=%s",
            self._org_ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
        )

        # Primary check: CN vs proxy_config.org_id. Skip when org_id is
        # env-pinned only (proxy_config row absent).
        persisted_org_id = await get_config("org_id")
        if persisted_org_id and self._org_ca_cert is not None:
            try:
                cn_attrs = self._org_ca_cert.subject.get_attributes_for_oid(
                    NameOID.COMMON_NAME,
                )
                cert_cn = cn_attrs[0].value if cn_attrs else ""
            except Exception:
                cert_cn = ""
            expected_cn = f"{persisted_org_id} CA"
            if cert_cn != expected_cn:
                logger.critical(
                    "Org CA subject mismatch — refusing to load. "
                    "proxy_config.org_id=%r expected CN=%r, loaded CN=%r "
                    "(cert serial=%s). DB state inconsistent: either "
                    "org_id was rewritten without re-issuing the Org CA, "
                    "or a stale CA from a previous deploy is pinned. "
                    "Agent cert issuance + mTLS will fail until resolved.",
                    persisted_org_id, expected_cn, cert_cn,
                    self._org_ca_cert.serial_number,
                )
                # Roll back so ca_loaded reports False — same degraded
                # branch as the "no CA found" path above.
                self._org_ca_key = None
                self._org_ca_cert = None
                return False

        # Secondary check: nginx-certs bind mount DER. Advisory only.
        await self._verify_nginx_cert_dir_matches_db(ca_cert_pem)

        return True

    async def _verify_nginx_cert_dir_matches_db(self, db_ca_cert_pem: str) -> None:
        """DER-compare the on-disk ``org-ca.crt`` against the DB cert.

        No-op when ``settings.nginx_cert_dir`` is unset (pytest in-
        process lifespan) or the file doesn't exist yet (pre-first
        ``ensure_nginx_server_cert`` write).
        """
        try:
            cert_dir = get_settings().nginx_cert_dir
            if not cert_dir:
                return
            from pathlib import Path
            ca_path = Path(cert_dir) / "org-ca.crt"
            if not ca_path.exists():
                return
            on_disk_der = x509.load_pem_x509_certificate(
                ca_path.read_bytes(),
            ).public_bytes(serialization.Encoding.DER)
            db_der = x509.load_pem_x509_certificate(
                db_ca_cert_pem.encode(),
            ).public_bytes(serialization.Encoding.DER)
            if on_disk_der != db_der:
                logger.warning(
                    "Org CA on-disk vs DB mismatch — %s differs from "
                    "proxy_config.org_ca_cert. The nginx sidecar will "
                    "serve a stale trust bundle until ensure_nginx_server_cert "
                    "rewrites it. If divergence persists, re-run deploy.sh "
                    "to re-export nginx-certs from the current DB state.",
                    ca_path,
                )
        except Exception as exc:  # noqa: BLE001 — diagnostic only
            logger.debug(
                "nginx-certs DER check skipped (%s) — primary CN check "
                "already gates the load, this is advisory only",
                exc,
            )

    async def generate_org_ca(
        self,
        *,
        validity_days: int = ORG_CA_VALIDITY_DAYS,
        derive_org_id: bool = False,
    ) -> None:
        """Generate a fresh self-signed Org CA and persist it via the KMS provider.

        Intended for standalone deploys (#115) where there is no broker to
        run the attach-ca flow against. Three-tier PKI hardening
        (audit 2026-05-18) extends validity to ``ORG_CA_VALIDITY_DAYS``
        (15 years cold root); BasicConstraints(ca=True, path_length=1)
        so a SPIRE UpstreamAuthority can mint one intermediate
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

        # M-crypto-2 audit fix — Org CA is a 15-year root, so it must
        # use a key size that survives its full lifetime under NIST
        # SP 800-57 (>=3072-bit RSA or EC P-256). EC P-256 is also the
        # SPIFFE/SPIRE convention and matches what the Mastio
        # intermediate (``_mint_mastio_ca``) and leaf (``leaf_key``)
        # already use. Verifiers stay dual-stack; legacy Org CAs
        # issued under RSA-2048 keep working until they expire.
        ca_key = ec.generate_private_key(ec.SECP256R1())

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

        # Route through the KMS provider so enterprise backends (cloud
        # KMS / Key Vault / Secrets Manager) get to persist this without
        # touching agent_manager. The LocalKMSProvider default writes
        # the encrypted PEM into ``pki_key_store`` under the Fernet
        # at-rest envelope (three-tier PKI hardening, audit 2026-05-18).
        from mcp_proxy.kms import get_kms_provider
        from mcp_proxy.kms.pki_at_rest import pki_master_key_configured

        provider = get_kms_provider()
        if provider.name == "local" and not pki_master_key_configured():
            # Legacy dev/test path: keep the plaintext
            # ``proxy_config.org_ca_key`` / ``org_ca_cert`` rows so
            # ``/pki/ca.crt`` + bootstrap endpoints still serve. Validate
            # _config refuses this in production.
            logger.warning(
                "MCP_PROXY_DB_ENCRYPTION_KEY not set, falling back to "
                "legacy plaintext org_ca_{key,cert} rows in proxy_config. "
                "Dev/test only.",
            )
            await set_config("org_ca_key", ca_key_pem)
            await set_config("org_ca_cert", ca_cert_pem)
        else:
            await provider.store_org_ca(ca_key_pem, ca_cert_pem)
            # The /pki/ca.crt endpoint still reads org_ca_cert from
            # proxy_config for back-compat; write the cert (public
            # material, no privacy concern) so legacy callers keep
            # working. The private key NEVER lands in proxy_config.
            await set_config("org_ca_cert", ca_cert_pem)

        # Three-tier PKI hardening — cache only the cert at steady state
        # when the encrypted KMS path is active (the unseal helper can
        # re-load from ``pki_key_store``). When the dev/test fallback
        # wrote plaintext into ``proxy_config.org_ca_key``, leave the
        # private key cached so the immediate next call to
        # ``_mint_mastio_ca`` doesn't have to scaffold a fake unseal.
        self._org_ca_cert = ca_cert
        if provider.name == "local" and not pki_master_key_configured():
            # Dev fallback: keep the key in memory (matches pre-fix
            # behavior so existing tests + dev sandbox keep booting).
            self._org_ca_key = ca_key
            logger.info(
                "Self-signed Org CA generated (CN=%s, validity=%dd, "
                "dev fallback, key cached)",
                f"{self._org_id} CA", validity_days,
            )
        else:
            # Encrypted path: scrub the private key. Future operations
            # that need the root unseal via ``_unseal_org_root``.
            self._org_ca_key = None
            import gc
            del ca_key
            gc.collect()
            logger.info(
                "Self-signed Org CA generated (CN=%s, validity=%dd, "
                "cold root)",
                f"{self._org_id} CA", validity_days,
            )

    @property
    def ca_loaded(self) -> bool:
        """True when the Org Root *cert* is available.

        Three-tier PKI hardening (audit 2026-05-18) — pre-fix this also
        required the private key in memory, which leaked the root
        across the whole process lifetime. Post-fix the cert alone is
        the steady-state requirement; the private key is unsealed on
        demand via :meth:`_unseal_org_root` for rare rotation events.
        """
        return self._org_ca_cert is not None

    @property
    def org_id(self) -> str:
        return self._org_id

    @property
    def trust_domain(self) -> str:
        return self._trust_domain

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
        validity_days: int = NGINX_SERVER_CERT_VALIDITY_DAYS,
        renew_within_days: int = 30,
    ) -> bool:
        """Emit / refresh the TLS server cert that the nginx sidecar uses.

        Writes three files into ``out_dir``:

        - ``org-ca.crt`` — the Org CA's public certificate (the trust
          bundle nginx uses as ``ssl_client_certificate`` to verify
          Connector certs at the TLS handshake).
        - ``mastio-server.crt`` — the **full chain bundle** nginx serves
          on 9443: leaf (Intermediate-signed, with the requested SANs)
          followed by the Mastio Intermediate cert. Without the
          Intermediate in the bundle, a client whose trust store holds
          only the Org Root cannot build the path ``Leaf -> Intermediate
          -> Org Root`` and rejects the handshake with
          ``unable to get local issuer certificate``.
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
        if self._mastio_ca_key is None or self._mastio_ca_cert is None:
            raise RuntimeError(
                "Mastio Intermediate CA not loaded, cannot emit nginx "
                "server cert. Three-tier PKI hardening (audit 2026-05-18) "
                "requires the nginx server cert to be signed by the "
                "Intermediate, not the Org Root. Call ensure_mastio_identity() first.",
            )

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
                # The on-disk crt is a bundle (leaf + Intermediate, audit
                # 2026-05-18 follow-up #2). A pre-fix single-cert file
                # falls through to the mint path because it is missing
                # the Intermediate that strict TLS clients need to build
                # the chain.
                existing_bundle_bytes = crt_path.read_bytes()
                bundle_blocks = existing_bundle_bytes.count(
                    b"-----BEGIN CERTIFICATE-----",
                )
                existing = x509.load_pem_x509_certificate(existing_bundle_bytes)
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
                # Issuer match (current Mastio Intermediate's subject).
                # Pre-three-tier-hardening this checked against the Org
                # CA subject; after PR fix the leaf is signed by the
                # Intermediate. Either issuer counts as a hit during
                # the rollout window so a freshly-upgraded Mastio
                # doesn't unnecessarily regenerate when the prior
                # nginx leaf was Org-issued.
                issuer_ok = (
                    existing.issuer.rfc4514_string()
                    == self._mastio_ca_cert.subject.rfc4514_string()
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

                bundle_ok = bundle_blocks == 2
                if issuer_ok and expiry_ok and ca_ok and sans_ok and bundle_ok:
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
            .issuer_name(self._mastio_ca_cert.subject)
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
                    self._mastio_ca_cert.public_key(),
                ),
                critical=False,
            )
        )
        leaf_cert = builder.sign(self._mastio_ca_key, hashes.SHA256())

        # Write atomically: tmp file then rename. The mtime change is
        # the signal the sidecar ``nginx-reload-watcher.sh`` (Wave 2
        # fix 6) picks up to trigger ``nginx -s reload`` — no SIGHUP
        # from this side, no docker socket. At boot we still need the
        # writes consistent so a restart-within-restart never observes
        # a torn pair.
        #
        # Three-tier PKI hardening (audit 2026-05-18): ``org-ca.crt`` now
        # holds the **full chain** (Org Root || Intermediate) so a
        # client doing strict path validation against an arbitrary
        # leaf still sees the issuer chain. The legacy single-cert
        # mode (Root only) would fail validation now that leaves are
        # Intermediate-issued.
        ca_pem = (
            self._org_ca_cert.public_bytes(serialization.Encoding.PEM)
            + self._mastio_ca_cert.public_bytes(serialization.Encoding.PEM)
        )
        # Three-tier PKI hardening (audit 2026-05-18) follow-up #2:
        # ``mastio-server.crt`` is now a full chain bundle
        # (leaf || Intermediate). Strict TLS clients (Python ssl,
        # OpenSSL, Go crypto/tls) require the Intermediate to build the
        # path ``Leaf -> Intermediate -> Org Root`` when only the Org
        # Root is in the trust store. Standard PEM ordering: leaf first,
        # then Intermediate; the root is omitted because it lives in the
        # client trust store.
        crt_pem = (
            leaf_cert.public_bytes(serialization.Encoding.PEM)
            + self._mastio_ca_cert.public_bytes(serialization.Encoding.PEM)
        )
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
        """Generate EC P-256 key + x509 cert for an internal agent.

        Cert fields:
          - CN: {org_id}::{agent_name}
          - O:  {org_id}
          - SAN URI: spiffe://{trust_domain}/{org_id}/{agent_name}
          - Signed by the Mastio Intermediate CA (three-tier hardening,
            audit 2026-05-18: was signed by Org Root pre-fix).
          - Valid ``AGENT_CERT_VALIDITY_DAYS`` (1 year).

        Returns (cert_pem, key_pem).

        Signing path: ``self._mastio_ca_key`` (the Intermediate). The
        Org Root stays cold; agent cert issuance must not unseal it.
        Callers gate on :attr:`mastio_loaded` to ensure the
        Intermediate is available; the lifespan's
        ``ensure_mastio_identity`` mints it under the Root on first
        boot (the only path that legitimately unseals the Root).

        M-crypto-2 audit fix: agent leaves are EC P-256, matching the
        Mastio leaf (``leaf_key``) and DPoP keypair. RSA-2048 was
        below NIST SP 800-57's >=3072-bit recommendation for new keys.
        Verifiers stay dual-stack so existing RSA-issued agents keep
        working until their cert expires (1 year), then auto-renew
        in EC at the next enrollment.
        """
        if self._mastio_ca_key is None or self._mastio_ca_cert is None:
            raise RuntimeError(
                "Mastio Intermediate CA not loaded, cannot sign agent cert. "
                "Call ensure_mastio_identity() first.",
            )

        # Generate agent key pair
        agent_key = ec.generate_private_key(ec.SECP256R1())

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
            .issuer_name(self._mastio_ca_cert.subject)
            .public_key(agent_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=AGENT_CERT_VALIDITY_DAYS))
            .add_extension(
                SubjectAlternativeName([
                    UniformResourceIdentifier(spiffe_uri),
                ]),
                critical=False,
            )
            .sign(self._mastio_ca_key, hashes.SHA256())
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        key_pem = agent_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()

        logger.info(
            "Generated x509 cert for %s (SAN %s, issuer=Intermediate)",
            agent_id, spiffe_uri,
        )
        return cert_pem, key_pem

    def sign_external_pubkey(self, *, pubkey_pem: str, agent_name: str) -> str:
        """Sign an externally-generated public key with the Mastio Intermediate CA.

        Used by the Connector enrollment flow: the Connector keeps its
        private key on the user's machine and only submits the public key,
        the admin approves, and the proxy issues a cert bound to that key.

        Three-tier PKI hardening (audit 2026-05-18) — signs with the
        Intermediate (was Org Root pre-fix). Accepts any key type the
        ``cryptography`` library can load (RSA, EC, Ed25519); the
        resulting cert signature is always SHA-256 per the existing
        convention.

        Raises ``RuntimeError`` if the Mastio Intermediate CA is not
        loaded or the PEM is malformed.
        """
        if self._mastio_ca_key is None or self._mastio_ca_cert is None:
            raise RuntimeError(
                "Mastio Intermediate CA not loaded, cannot sign external pubkey. "
                "Call ensure_mastio_identity() first.",
            )

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
            .issuer_name(self._mastio_ca_cert.subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=AGENT_CERT_VALIDITY_DAYS))
            .add_extension(
                SubjectAlternativeName([
                    UniformResourceIdentifier(spiffe_uri),
                ]),
                critical=False,
            )
            .sign(self._mastio_ca_key, hashes.SHA256())
        )

        leaf_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        # Three-tier PKI hardening (audit 2026-05-18) — the leaf is
        # signed by the Mastio Intermediate, not the Org CA directly.
        # Without the intermediate concatenated alongside the leaf,
        # the SDK's ``build_client_assertion`` packs only the leaf into
        # the JWT ``x5c`` header, and ``mcp_proxy/auth/challenge_response.py``
        # (``/v1/auth/login-challenge-response``) cannot walk the
        # chain back to the Org CA — every
        # ``login_via_proxy_with_local_key`` call comes back HTTP 401
        # ``x509 chain verification failed``. Discovered during ADR-034
        # dogfood rc2 when the Frontdesk user-login provisioning
        # surfaced the deferred state via the cert middleware.
        intermediate_pem = self._mastio_ca_cert.public_bytes(
            serialization.Encoding.PEM,
        ).decode()
        cert_pem = leaf_pem + intermediate_pem
        logger.info(
            "Signed external pubkey for %s (SAN %s, issuer=Intermediate, "
            "chain=leaf+intermediate)",
            agent_id, spiffe_uri,
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

        # Three-tier PKI hardening (audit 2026-05-18) — Intermediate
        # now routes through the KMS provider (LocalKMSProvider lands
        # in pki_key_store with Fernet at-rest). Legacy
        # proxy_config.mastio_ca_{key,cert} rows are the dev/test
        # fallback when the at-rest master key is absent.
        ca_key_pem: str | None = None
        ca_cert_pem: str | None = None
        try:
            from mcp_proxy.kms import get_kms_provider
            loaded = await get_kms_provider().load_intermediate_ca()
            if loaded is not None:
                ca_key_pem, ca_cert_pem = loaded
        except Exception as exc:  # noqa: BLE001 — defensive on KMS failure
            logger.warning(
                "KMSProvider.load_intermediate_ca failed: %s — falling "
                "back to legacy proxy_config rows",
                exc,
            )
        if not ca_key_pem or not ca_cert_pem:
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

    async def wipe_legacy_pki_if_present(self) -> bool:
        """Phase 0 migrate-then-wipe: relocate legacy plaintext PKI rows.

        Three-tier PKI hardening (audit 2026-05-18). The historic shape
        of this helper was a pure wipe (archive + delete), on the
        assumption that the caller would either re-issue a fresh chain
        (standalone first-boot) or had already populated the encrypted
        ``pki_key_store`` via an earlier boot. Both assumptions break
        on the sandbox / federated path: ``proxy-init/seed.py`` writes
        plaintext ``proxy_config.org_ca_key`` rows when the Mastio has
        never booted, ``settings.standalone=False`` short-circuits the
        ``generate_org_ca`` fallback in the lifespan, and the broker
        ``/attach-ca`` flow is only consumed *after* the Mastio is
        already reachable. The pure-wipe variant therefore archived
        the only copy of the Org Root keypair and the next boot tried
        to mint the Mastio Intermediate without a parent.

        Post-fix (PR #794 follow-up, Wave 1-A bootstrap regeneration)
        this helper:

        1. Detects either legacy row.
        2. **Migrates** the plaintext keypair into ``pki_key_store``
           under the Fernet at-rest envelope via the configured
           ``KMSProvider`` — preserving the Org Root pubkey that the
           Court / broker pinned during attach-ca. A regen would
           silently break federation; the migration keeps trust
           continuity intact.
        3. Archives the legacy PEM into ``legacy_pki_archive`` with
           audit trail (operator can still recover from a bad upgrade
           if they keep the DB row around).
        4. Deletes the legacy ``proxy_config`` rows (private key only
           for ``org_ca``; both rows for ``mastio_ca`` since the
           public Mastio Intermediate cert is not consumed by any
           legacy endpoint).
        5. Returns True so the caller knows a wipe happened.

        Idempotent: when the encrypted row is already in place from a
        previous boot, the migration step is a no-op (the
        ``store_org_ca`` / ``store_intermediate_ca`` provider methods
        short-circuit on identical material). When no legacy rows are
        present at all, the whole helper is a no-op.

        Returns True when a wipe happened, False when no legacy material
        was present (steady-state) or when the migration was deferred
        (master key absent).
        """
        legacy_org_key = await get_config("org_ca_key")
        legacy_org_cert = await get_config("org_ca_cert")
        legacy_int_key = await get_config("mastio_ca_key")
        legacy_int_cert = await get_config("mastio_ca_cert")

        wiped = False
        now_iso = datetime.now(timezone.utc).isoformat()

        # Without the at-rest master key we cannot encrypt the legacy
        # material into ``pki_key_store``; deleting the plaintext now
        # would strand the Mastio on the next boot. Skip with a
        # warning so the operator sets the env var and retries.
        from mcp_proxy.kms.pki_at_rest import pki_master_key_configured
        if not pki_master_key_configured():
            if legacy_org_key or legacy_int_key:
                logger.warning(
                    "Legacy plaintext PKI rows detected but "
                    "MCP_PROXY_DB_ENCRYPTION_KEY is not set. Phase 0 "
                    "wipe deferred. Set the env var and restart to "
                    "complete the three-tier hardening migration.",
                )
            return False

        from mcp_proxy.kms import get_kms_provider
        provider = get_kms_provider()

        if legacy_org_key and legacy_org_cert:
            # Migrate first — if ``pki_key_store`` already has an
            # active row, ``store_org_ca`` is idempotent on identical
            # material and a no-op on the fast path. If the encrypted
            # store is empty (the common sandbox / federated cold-
            # boot case), this writes the legacy PEM under Fernet
            # at-rest so the lifespan's ``load_org_ca_from_config``
            # finds the keypair on the very next call.
            try:
                await provider.store_org_ca(legacy_org_key, legacy_org_cert)
            except Exception as exc:  # noqa: BLE001 — refuse-to-wipe on failure
                logger.error(
                    "Phase 0 migration failed for org_ca: %s. Aborting "
                    "wipe to avoid losing the only copy of the Org Root "
                    "keypair. Operator action: inspect the KMS provider "
                    "(MCP_PROXY_KMS_BACKEND, pki_key_store schema) and "
                    "restart.",
                    exc,
                )
                return False
            await archive_legacy_pki(
                key_id=f"legacy-org-ca-{now_iso}",
                key_type="org_ca",
                legacy_pem=legacy_org_key,
                archived_at=now_iso,
            )
            await delete_proxy_config("org_ca_key")
            # Keep ``org_ca_cert`` row in proxy_config for the legacy
            # ``/pki/ca.crt`` and ``/.well-known/cullis/connector-bootstrap``
            # endpoints that still read it directly. The cert is public
            # material; only the private key needs to disappear.
            try:
                await log_audit(
                    agent_id="system",
                    action="pki.legacy_wipe",
                    status="success",
                    detail=(
                        "key_type=org_ca migrated_to=pki_key_store "
                        "archived_to=legacy_pki_archive"
                    ),
                )
            except Exception:
                pass
            logger.info(
                "Phase 0 migrate+wipe: org_ca_key relocated into "
                "pki_key_store and legacy plaintext archived",
            )
            wiped = True

        if legacy_int_key and legacy_int_cert:
            try:
                await provider.store_intermediate_ca(
                    legacy_int_key, legacy_int_cert,
                )
            except Exception as exc:  # noqa: BLE001 — refuse-to-wipe on failure
                logger.error(
                    "Phase 0 migration failed for intermediate_ca: %s. "
                    "Aborting wipe of the Mastio Intermediate rows. "
                    "Operator action: inspect the KMS provider and "
                    "restart.",
                    exc,
                )
                return wiped
            await archive_legacy_pki(
                key_id=f"legacy-intermediate-{now_iso}",
                key_type="intermediate_ca",
                legacy_pem=legacy_int_key,
                archived_at=now_iso,
            )
            await delete_proxy_config("mastio_ca_key")
            await delete_proxy_config("mastio_ca_cert")
            try:
                await log_audit(
                    agent_id="system",
                    action="pki.legacy_wipe",
                    status="success",
                    detail=(
                        "key_type=intermediate_ca migrated_to=pki_key_store "
                        "archived_to=legacy_pki_archive"
                    ),
                )
            except Exception:
                pass
            logger.info(
                "Phase 0 migrate+wipe: mastio_ca relocated into "
                "pki_key_store and legacy plaintext archived",
            )
            wiped = True

        return wiped

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
        """Mint a fresh EC P-256 Intermediate CA and persist it.

        Three-tier PKI hardening (audit 2026-05-18):

        * Validity ``INTERMEDIATE_CA_VALIDITY_DAYS`` (5 years). Online
          signer rotated ahead of expiry by the leader-elected
          ``mastio_ca_rotation_watcher`` background task + manual
          ``POST /v1/admin/mastio-ca/rotate`` admin endpoint.
        * Org Root unsealed, signed, scrubbed (cold-by-default).
        * Persistence routes through ``KMSProvider.store_intermediate_ca``
          (was direct ``set_config`` pre-fix). LocalKMSProvider lands the
          row in ``pki_key_store`` with Fernet at-rest encryption.

        NIST SP 800-57 Part 1 §5.3.6 covers signing-keys-in-active-use
        cadence. Automatic rotation is tracked in issue #261.
        """
        mastio_ca_key = ec.generate_private_key(ec.SECP256R1())
        mastio_ca_subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, f"{self._org_id} Mastio CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self._org_id),
        ])
        builder = (
            x509.CertificateBuilder()
            .subject_name(mastio_ca_subject)
            .issuer_name(self._org_ca_cert.subject)
            .public_key(mastio_ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=INTERMEDIATE_CA_VALIDITY_DAYS))
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
        )

        # Unseal Org Root only for the brief signing call, scrub immediately.
        async with self._unseal_org_root(
            reason="mint_intermediate", operator="system",
        ) as org_root_key:
            mastio_ca_cert = builder.sign(org_root_key, hashes.SHA256())

        key_pem = _priv_to_pem(mastio_ca_key)
        cert_pem = _cert_to_pem(mastio_ca_cert)

        # Route through KMSProvider (LocalKMSProvider lands in
        # pki_key_store with Fernet at-rest, cloud KMS plugins do
        # whatever they were licensed for). Falls back to direct
        # proxy_config write for back-compat in tests / dev that lack
        # the at-rest master key (``MCP_PROXY_DB_ENCRYPTION_KEY``).
        await self._persist_intermediate_ca(key_pem, cert_pem)

        self._mastio_ca_key = mastio_ca_key
        self._mastio_ca_cert = mastio_ca_cert
        logger.info(
            "Mastio Intermediate CA minted (CN=%s, validity_days=%d)",
            mastio_ca_subject, INTERMEDIATE_CA_VALIDITY_DAYS,
        )

    async def _persist_intermediate_ca(self, key_pem: str, cert_pem: str) -> None:
        """Store the Mastio Intermediate CA via the configured KMS provider.

        Dev-only fallback: if the PKI at-rest master key is missing
        (``MCP_PROXY_DB_ENCRYPTION_KEY`` unset) AND the KMS backend is
        ``local`` (so the encrypted ``pki_key_store`` is the destination),
        log a loud warning and write to the legacy
        ``proxy_config.mastio_ca_{key,cert}`` rows instead. Production
        validate_config refuses to start in that state, so this branch
        only triggers in unit tests + sandbox boots that have not yet
        exported the dev passphrase. Cloud KMS / Vault backends are
        unaffected (they don't depend on the local Fernet envelope).
        """
        from mcp_proxy.kms import get_kms_provider
        from mcp_proxy.kms.pki_at_rest import pki_master_key_configured

        provider = get_kms_provider()
        # Only the local provider depends on the Fernet master key; all
        # others get the PEMs as-is and can store however they prefer.
        if provider.name == "local" and not pki_master_key_configured():
            logger.warning(
                "MCP_PROXY_DB_ENCRYPTION_KEY not set, falling back to "
                "legacy plaintext mastio_ca_{key,cert} rows in proxy_config. "
                "This path is dev/test only — production validate_config "
                "refuses to start without the at-rest passphrase. Set "
                "MCP_PROXY_DB_ENCRYPTION_KEY to land the Intermediate "
                "under Fernet at-rest.",
            )
            await set_config("mastio_ca_key", key_pem)
            await set_config("mastio_ca_cert", cert_pem)
            return

        await provider.store_intermediate_ca(key_pem, cert_pem)

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
            .not_valid_after(now + timedelta(days=MASTIO_LEAF_VALIDITY_DAYS))
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
            .not_valid_after(now + timedelta(days=MASTIO_LEAF_VALIDITY_DAYS))
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

    async def rotate_mastio_ca(
        self,
        *,
        grace_days: int = 14,
        operator: str = "admin",
        dry_run: bool = False,
    ) -> dict:
        """Rotate the Mastio Intermediate CA.

        Three-tier PKI hardening (audit 2026-05-18), Phase 4. Mirrors
        the proven Mastio Leaf rotation pattern (ADR-012 Phase 2.1):

        1. Mint a fresh EC P-256 Intermediate keypair.
        2. Unseal Org Root, sign the new Intermediate, scrub.
        3. Build a continuity proof — the new Intermediate cert signed
           by the *old* Intermediate's private key (so verifiers
           that pinned the old Intermediate's pubkey can still verify
           the chain through the rotation window).
        4. Persist the new keypair as a staged row in ``pki_key_store``
           (``activated_at IS NULL``), durable on disk before any
           atomic-swap so a crash mid-flight leaves the staged row
           visible for boot recovery.
        5. Re-mint the Mastio Leaf under the new Intermediate as
           issuer (so subsequent ES256 counter-signatures verify
           against the new chain).
        6. Atomic-swap under the ``pki_key_store`` activation helper —
           new row becomes active, old row deprecated with
           ``expires_at = now + grace_days``.
        7. Re-cache the Intermediate in-memory and refresh the Mastio
           Leaf cache.

        ``grace_days`` (default 14) controls how long the old
        Intermediate stays verifier-accepted after deprecation, giving
        agents that pinned the old chain a window to receive the new
        CA bundle (out-of-band via the dashboard or the next
        ``/v1/registry/ca-bundle`` poll).

        ``dry_run`` performs all validation + cert minting in memory
        but does NOT persist or atomic-swap; useful for the
        ``POST /v1/admin/mastio-ca/rotate?dry_run=true`` admin
        endpoint to surface validation errors without committing.

        Returns a dict with ``{"old_intermediate_cn", "new_intermediate_cn",
        "new_leaf_kid", "grace_days", "dry_run"}`` so the caller can
        log + display the outcome.
        """
        if grace_days <= 0:
            raise ValueError("grace_days must be a positive integer")
        if self._mastio_ca_key is None or self._mastio_ca_cert is None:
            raise RuntimeError(
                "Mastio Intermediate CA not loaded, cannot rotate. "
                "Call ensure_mastio_identity() first.",
            )
        if not self.ca_loaded:
            raise RuntimeError(
                "Org Root cert not loaded, cannot rotate Intermediate.",
            )

        # Use the same in-process lock as Mastio Leaf rotation so a
        # dashboard click + watcher tick race serializes.
        async with self._rotation_lock:
            return await self._rotate_intermediate_locked(
                grace_days=grace_days,
                operator=operator,
                dry_run=dry_run,
            )

    async def _rotate_intermediate_locked(
        self,
        *,
        grace_days: int,
        operator: str,
        dry_run: bool,
    ) -> dict:
        """Body of :meth:`rotate_mastio_ca`, executed under the rotation lock.

        Split out so the test suite can drive individual steps without
        re-acquiring the lock during fault-injection scenarios.
        """
        from mcp_proxy.db import (
            activate_staged_pki_and_deprecate_old,
            delete_staged_pki_key,
            get_active_pki_key,
            insert_pki_key,
        )
        from mcp_proxy.kms.pki_at_rest import (
            encrypt_pki_payload,
            pki_master_key_configured,
        )

        old_intermediate_key = self._mastio_ca_key
        old_intermediate_cert = self._mastio_ca_cert
        old_intermediate_cn = old_intermediate_cert.subject.rfc4514_string()

        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()
        grace_end_iso = (now + timedelta(days=grace_days)).isoformat()

        # 1. Mint new Intermediate keypair + cert.
        new_int_key = ec.generate_private_key(ec.SECP256R1())
        new_int_subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, f"{self._org_id} Mastio CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self._org_id),
        ])
        new_int_builder = (
            x509.CertificateBuilder()
            .subject_name(new_int_subject)
            .issuer_name(self._org_ca_cert.subject)
            .public_key(new_int_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=INTERMEDIATE_CA_VALIDITY_DAYS))
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
                x509.SubjectKeyIdentifier.from_public_key(new_int_key.public_key()),
                critical=False,
            )
        )

        # 2. Unseal Org Root, sign new Intermediate, scrub.
        async with self._unseal_org_root(
            reason="rotate_intermediate", operator=operator,
        ) as org_root_key:
            new_int_cert = new_int_builder.sign(org_root_key, hashes.SHA256())

        new_int_key_pem = _priv_to_pem(new_int_key)
        new_int_cert_pem = _cert_to_pem(new_int_cert)

        # 3. Continuity proof: sign the new Intermediate cert with the
        # old Intermediate's private key. Verifiers that pinned the old
        # Intermediate can confirm the rotation was authorised by the
        # holder of the old key, not a stranger who got hold of the Org
        # Root by other means.
        import base64
        cont_proof_bytes = old_intermediate_key.sign(
            new_int_cert.public_bytes(serialization.Encoding.DER),
            ec.ECDSA(hashes.SHA256()),
        )
        continuity_proof_b64 = base64.urlsafe_b64encode(
            cont_proof_bytes,
        ).rstrip(b"=").decode()

        if dry_run:
            logger.info(
                "rotate_mastio_ca dry-run OK (old CN=%s, new CN=%s, "
                "grace_days=%d)",
                old_intermediate_cn, new_int_subject.rfc4514_string(),
                grace_days,
            )
            return {
                "old_intermediate_cn": old_intermediate_cn,
                "new_intermediate_cn": new_int_subject.rfc4514_string(),
                "new_leaf_kid": None,
                "grace_days": grace_days,
                "dry_run": True,
                "continuity_proof": continuity_proof_b64,
            }

        # 4. Persist new Intermediate as staged row. Only the encrypted
        # path is supported here (Phase 4 is post-migration; the dev
        # fallback is for boot/cold-start, not for operator rotation).
        if not pki_master_key_configured():
            raise RuntimeError(
                "rotate_mastio_ca requires MCP_PROXY_DB_ENCRYPTION_KEY. "
                "The new Intermediate cannot be stored without the "
                "at-rest envelope master key.",
            )
        envelope = encrypt_pki_payload(
            key_pem=new_int_key_pem, cert_pem=new_int_cert_pem,
        )
        import hashlib
        new_int_pubkey_der = new_int_cert.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        new_int_key_id = (
            "intermediate-" + hashlib.sha256(new_int_pubkey_der).hexdigest()[:16]
        )
        current_row = await get_active_pki_key("intermediate_ca")
        old_key_id = current_row["key_id"] if current_row else None

        await insert_pki_key(
            key_id=new_int_key_id,
            key_type="intermediate_ca",
            ciphertext=envelope,
            cert_pem=new_int_cert_pem,
            created_at=now_iso,
            activated_at=None,
        )

        # 5. Re-mint the Mastio Leaf under the new Intermediate.
        # The existing rotate_mastio_key flow assumes the Intermediate
        # is unchanged; here we have to do the leaf re-issue inline,
        # bypassing the propagator (Court would be talking through a
        # cross-org rotation event; standalone-mode Mastio has no
        # Court). The leaf is staged as inactive, atomic-swapped
        # together with the Intermediate below.
        try:
            new_leaf_kid = await self._reissue_mastio_leaf_under(
                new_int_key=new_int_key,
                new_int_cert=new_int_cert,
                now=now,
                grace_days=grace_days,
            )
        except Exception:
            # Roll back the staged Intermediate so the next boot
            # doesn't see an orphaned row.
            try:
                await delete_staged_pki_key(new_int_key_id)
            except Exception as cleanup_exc:
                logger.warning(
                    "staged Intermediate cleanup failed after leaf "
                    "re-issue error (key_id=%s): %s — boot recovery "
                    "will handle it",
                    new_int_key_id, cleanup_exc,
                )
            raise

        # 6. Atomic-swap Intermediate. The leaf was already activated
        # inside `_reissue_mastio_leaf_under` via the existing
        # activate_staged_and_deprecate_old helper.
        try:
            await activate_staged_pki_and_deprecate_old(
                key_type="intermediate_ca",
                new_key_id=new_int_key_id,
                new_activated_at=now_iso,
                old_key_id=old_key_id,
                old_deprecated_at=now_iso,
                old_expires_at=grace_end_iso,
            )
        except Exception:
            logger.error(
                "rotate_mastio_ca: Intermediate atomic-swap failed "
                "AFTER leaf re-issue succeeded. Manual recovery: "
                "either revert the leaf via /proxy/mastio-key/complete-"
                "staged drop, or replay the swap with the staged row "
                "(key_id=%s).",
                new_int_key_id,
            )
            raise

        # 7. Refresh in-memory caches.
        self._mastio_ca_key = new_int_key
        self._mastio_ca_cert = new_int_cert
        await self.refresh_active_key()

        # Audit row + telemetry.
        try:
            await log_audit(
                agent_id=operator,
                action="pki.intermediate_rotated",
                status="success",
                detail=(
                    f"old_key_id={old_key_id} new_key_id={new_int_key_id} "
                    f"grace_days={grace_days}"
                ),
            )
        except Exception:
            pass

        logger.info(
            "Mastio Intermediate CA rotated (old CN=%s, new CN=%s, "
            "grace_days=%d, operator=%s)",
            old_intermediate_cn, new_int_subject.rfc4514_string(),
            grace_days, operator,
        )

        return {
            "old_intermediate_cn": old_intermediate_cn,
            "new_intermediate_cn": new_int_subject.rfc4514_string(),
            "new_leaf_kid": new_leaf_kid,
            "grace_days": grace_days,
            "dry_run": False,
            "continuity_proof": continuity_proof_b64,
        }

    async def _reissue_mastio_leaf_under(
        self,
        *,
        new_int_key: ec.EllipticCurvePrivateKey,
        new_int_cert: x509.Certificate,
        now: datetime,
        grace_days: int,
    ) -> str:
        """Mint a fresh Mastio Leaf under a new Intermediate.

        Atomic-swap variant of ``_mint_mastio_leaf`` used during
        Intermediate rotation. Inserts the new leaf as staged
        (``activated_at IS NULL``) then activates it under the
        existing ``activate_staged_and_deprecate_old`` advisory lock,
        deprecating the prior active leaf with the same grace window.
        Returns the new leaf's ``kid``.
        """
        leaf_key = ec.generate_private_key(ec.SECP256R1())
        proxy_spiffe = f"spiffe://{self._trust_domain}/proxy/{self._org_id}"
        leaf_subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, f"proxy:{self._org_id}"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self._org_id),
        ])
        leaf_cert = (
            x509.CertificateBuilder()
            .subject_name(leaf_subject)
            .issuer_name(new_int_cert.subject)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=MASTIO_LEAF_VALIDITY_DAYS))
            .add_extension(
                SubjectAlternativeName([UniformResourceIdentifier(proxy_spiffe)]),
                critical=False,
            )
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .sign(new_int_key, hashes.SHA256())
        )

        priv_pem = _priv_to_pem(leaf_key)
        cert_pem = _cert_to_pem(leaf_cert)
        pub_pem = leaf_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        kid = compute_kid(pub_pem)
        now_iso = now.isoformat()
        grace_end_iso = (now + timedelta(days=grace_days)).isoformat()

        # Current active leaf (if any) — captured before insert so the
        # atomic-swap helper knows who to deprecate.
        current_leaf = await self._keystore.current_signer()

        await insert_mastio_key(
            kid=kid,
            pubkey_pem=pub_pem,
            privkey_pem=priv_pem,
            cert_pem=cert_pem,
            created_at=now_iso,
            activated_at=None,
        )
        await activate_staged_and_deprecate_old(
            new_kid=kid,
            new_activated_at=now_iso,
            old_kid=current_leaf.kid,
            old_deprecated_at=now_iso,
            old_expires_at=grace_end_iso,
        )
        logger.info(
            "Mastio Leaf re-issued under new Intermediate (kid=%s)", kid,
        )
        return kid

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
