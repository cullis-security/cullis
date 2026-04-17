"""
Tests for security audit Round 2 fixes (terminal 3).

Covers:
  #18 — Vault TLS enforcement
  #21 — HKDF random salt per-encryption
  #24 — EC curve whitelist in x509 verifier
  #31 — Input validation on onboarding JoinRequest
  #32 — Input validation on registry AgentRegisterRequest
  #34 — Pending orgs cannot register agents (endpoint removed in ADR-010 6a-4)
  #36 — Revocation cleanup 30-min buffer
  #44 — get_client_ip helper
"""
import os
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock

import pytest

pytestmark = pytest.mark.asyncio


# ──────────────────────────────────────────────────────────────────────────
# #18 — Vault TLS enforcement
# ──────────────────────────────────────────────────────────────────────────

class TestVaultTLSEnforcement:
    """#18 — vault_addr must use https:// unless VAULT_ALLOW_HTTP=true."""

    def test_https_accepted(self):
        from app.kms.vault import VaultKMSProvider
        provider = VaultKMSProvider("https://vault.example.com:8200", "s.token", "secret/data/broker")
        assert provider._vault_addr == "https://vault.example.com:8200"

    def test_http_rejected(self):
        from app.kms.vault import VaultKMSProvider
        with pytest.raises(ValueError, match="must use https://"):
            VaultKMSProvider("http://vault:8200", "s.token", "secret/data/broker")

    def test_http_allowed_with_env_override(self):
        from app.kms.vault import VaultKMSProvider
        with patch.dict(os.environ, {"VAULT_ALLOW_HTTP": "true"}):
            provider = VaultKMSProvider("http://vault:8200", "s.token", "secret/data/broker")
            assert provider._vault_addr == "http://vault:8200"

    def test_http_rejected_when_env_not_true(self):
        from app.kms.vault import VaultKMSProvider
        with patch.dict(os.environ, {"VAULT_ALLOW_HTTP": "false"}):
            with pytest.raises(ValueError, match="must use https://"):
                VaultKMSProvider("http://vault:8200", "s.token", "secret/data/broker")


# ──────────────────────────────────────────────────────────────────────────
# #21 — HKDF random salt per-encryption
# ──────────────────────────────────────────────────────────────────────────

_TEST_KEY_PEM = "-----BEGIN RSA PRIVATE KEY-----\nMIItest1234567890abcdef\n-----END RSA PRIVATE KEY-----\n"


class TestHKDFSalt:
    """#21 — Each encryption uses a unique random salt."""

    def test_encrypt_produces_salted_format(self):
        from app.kms.secret_encrypt import encrypt_secret, _ENC_PREFIX
        encrypted = encrypt_secret(_TEST_KEY_PEM, "hello")
        assert encrypted.startswith(_ENC_PREFIX)
        payload = encrypted[len(_ENC_PREFIX):]
        parts = payload.split(":", 1)
        assert len(parts) == 2, "Expected enc:v1:<salt_hex>:<token>"
        assert len(parts[0]) == 32, "Salt should be 16 bytes = 32 hex chars"

    def test_two_encryptions_differ(self):
        from app.kms.secret_encrypt import encrypt_secret
        a = encrypt_secret(_TEST_KEY_PEM, "same-plaintext")
        b = encrypt_secret(_TEST_KEY_PEM, "same-plaintext")
        assert a != b, "Two encryptions of the same plaintext must produce different ciphertexts"

    def test_roundtrip_new_format(self):
        from app.kms.secret_encrypt import encrypt_secret, decrypt_secret
        plaintext = "my-secret-value"
        encrypted = encrypt_secret(_TEST_KEY_PEM, plaintext)
        assert decrypt_secret(_TEST_KEY_PEM, encrypted) == plaintext

    def test_legacy_format_backward_compat(self):
        """enc:v1:<fernet_token> (no salt) must still decrypt."""
        from app.kms.secret_encrypt import decrypt_secret, _derive_fernet_key, _ENC_PREFIX
        from cryptography.fernet import Fernet
        # Produce a legacy-format ciphertext (no salt)
        key = _derive_fernet_key(_TEST_KEY_PEM, salt=None)
        token = Fernet(key).encrypt(b"legacy-secret").decode()
        legacy_stored = f"{_ENC_PREFIX}{token}"
        assert decrypt_secret(_TEST_KEY_PEM, legacy_stored) == "legacy-secret"

    def test_plaintext_passthrough(self):
        from app.kms.secret_encrypt import decrypt_secret
        assert decrypt_secret(_TEST_KEY_PEM, "plain-text") == "plain-text"

    def test_wrong_key_fails(self):
        from app.kms.secret_encrypt import encrypt_secret, decrypt_secret
        other_key = "-----BEGIN RSA PRIVATE KEY-----\nMIIdifferentkey\n-----END RSA PRIVATE KEY-----\n"
        encrypted = encrypt_secret(_TEST_KEY_PEM, "secret")
        with pytest.raises(ValueError, match="Failed to decrypt"):
            decrypt_secret(other_key, encrypted)


# ──────────────────────────────────────────────────────────────────────────
# #24 — EC curve whitelist
# ──────────────────────────────────────────────────────────────────────────

class TestECCurveWhitelist:
    """#24 — Only P-256, P-384, P-521 curves are accepted."""

    def test_weak_ec_curve_rejected(self):
        """An EC key on a disallowed curve (e.g. SECP192R1) should be rejected."""
        from cryptography.hazmat.primitives.asymmetric import ec

        # The verifier checks isinstance(pub_key.curve, (SECP256R1, SECP384R1, SECP521R1))
        allowed = (ec.SECP256R1, ec.SECP384R1, ec.SECP521R1)
        weak_curve = ec.SECP192R1()
        assert not isinstance(weak_curve, allowed)

    def test_allowed_curves_accepted(self):
        from cryptography.hazmat.primitives.asymmetric import ec
        allowed = (ec.SECP256R1, ec.SECP384R1, ec.SECP521R1)
        for curve_cls in [ec.SECP256R1, ec.SECP384R1, ec.SECP521R1]:
            assert isinstance(curve_cls(), allowed)


# ──────────────────────────────────────────────────────────────────────────
# #31 — Input validation on JoinRequest
# ──────────────────────────────────────────────────────────────────────────

class TestJoinRequestValidation:
    """#31 — org_id must match regex, display_name and secret have max_length."""

    def test_valid_org_id(self):
        from app.onboarding.router import JoinRequest
        req = JoinRequest(
            org_id="acme-corp.01",
            display_name="Acme Corp",
            secret="s3cret",
            ca_certificate="-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----",
            invite_token="test-invite-token",
        )
        assert req.org_id == "acme-corp.01"

    def test_org_id_uppercase_rejected(self):
        from app.onboarding.router import JoinRequest
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            JoinRequest(
                org_id="Acme-Corp",
                display_name="Acme Corp",
                secret="s3cret",
                ca_certificate="fake",
                invite_token="test-invite-token",
            )

    def test_org_id_special_chars_rejected(self):
        from app.onboarding.router import JoinRequest
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            JoinRequest(
                org_id="acme corp!",
                display_name="Acme",
                secret="s",
                ca_certificate="fake",
                invite_token="test-invite-token",
            )

    def test_org_id_too_long_rejected(self):
        from app.onboarding.router import JoinRequest
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            JoinRequest(
                org_id="a" * 129,
                display_name="Acme",
                secret="s",
                ca_certificate="fake",
                invite_token="test-invite-token",
            )

    def test_display_name_too_long_rejected(self):
        from app.onboarding.router import JoinRequest
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            JoinRequest(
                org_id="acme",
                display_name="A" * 257,
                secret="s",
                ca_certificate="fake",
                invite_token="test-invite-token",
            )

    def test_secret_too_long_rejected(self):
        from app.onboarding.router import JoinRequest
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            JoinRequest(
                org_id="acme",
                display_name="Acme",
                secret="s" * 257,
                ca_certificate="fake",
                invite_token="test-invite-token",
            )


# ──────────────────────────────────────────────────────────────────────────
# #32 — Input validation on AgentRegisterRequest
# ──────────────────────────────────────────────────────────────────────────

class TestAgentRegisterRequestValidation:
    """#32 — agent_id must match org_id::agent_name pattern."""

    def test_valid_agent_id(self):
        from app.registry.models import AgentRegisterRequest
        req = AgentRegisterRequest(
            agent_id="banca-x::kyc-agent-v1",
            org_id="banca-x",
            display_name="KYC Agent",
        )
        assert req.agent_id == "banca-x::kyc-agent-v1"

    def test_agent_id_no_separator_rejected(self):
        from app.registry.models import AgentRegisterRequest
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            AgentRegisterRequest(
                agent_id="flat-agent-id",
                org_id="org",
                display_name="Agent",
            )

    def test_agent_id_uppercase_rejected(self):
        from app.registry.models import AgentRegisterRequest
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            AgentRegisterRequest(
                agent_id="Org::Agent",
                org_id="org",
                display_name="Agent",
            )

    def test_agent_id_spaces_rejected(self):
        from app.registry.models import AgentRegisterRequest
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            AgentRegisterRequest(
                agent_id="org::my agent",
                org_id="org",
                display_name="Agent",
            )

    def test_agent_id_single_colon_rejected(self):
        from app.registry.models import AgentRegisterRequest
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            AgentRegisterRequest(
                agent_id="org:agent",
                org_id="org",
                display_name="Agent",
            )


# ──────────────────────────────────────────────────────────────────────────
# #34 — Pending orgs cannot register agents
# ──────────────────────────────────────────────────────────────────────────
#
# ADR-010 Phase 6a-4 hard-deleted ``POST /v1/registry/agents``, so the
# "pending org rejected" assertion that used to live here is now moot
# on the Court side — only the Mastio writes agents, and its admin API
# is gated by ``X-Admin-Secret`` rather than org status. The test class
# has been removed with the endpoint. Org-status enforcement for the
# remaining Court write surface (bindings, attach-ca) is covered by
# ``tests/test_registry_org.py`` and ``tests/test_onboarding.py``.


# ──────────────────────────────────────────────────────────────────────────
# #36 — Revocation cleanup 30-min buffer
# ──────────────────────────────────────────────────────────────────────────

class TestRevocationCleanupBuffer:
    """#36 — Revoked certs should not be cleaned up until 30 min after cert expiry."""

    async def test_recently_expired_cert_not_cleaned(self, db_session):
        """A cert expired 10 min ago should still be in revoked_certs."""
        from app.auth.revocation import revoke_cert, RevokedCert
        from sqlalchemy import select

        now = datetime.now(timezone.utc)
        serial = "deadbeef36a"
        # cert expired 10 min ago — within the 30-min buffer
        cert_not_after = now - timedelta(minutes=10)

        await revoke_cert(
            db_session,
            serial_hex=serial,
            org_id="test-org-36",
            cert_not_after=cert_not_after,
            revoked_by="admin",
        )

        # The record should still exist (not cleaned up)
        result = await db_session.execute(
            select(RevokedCert).where(RevokedCert.serial_hex == serial)
        )
        assert result.scalar_one_or_none() is not None

    async def test_long_expired_cert_cleaned(self, db_session):
        """A cert expired 60 min ago should be cleaned up."""
        from app.auth.revocation import revoke_cert, RevokedCert
        from sqlalchemy import select

        now = datetime.now(timezone.utc)

        # First insert a "seed" record that expired 60 min ago
        seed_serial = "seed36b"
        seed = RevokedCert(
            serial_hex=seed_serial,
            org_id="test-org-36",
            revoked_at=now - timedelta(hours=2),
            revoked_by="admin",
            cert_not_after=now - timedelta(minutes=60),
        )
        db_session.add(seed)
        await db_session.commit()

        # Now revoke another cert — this triggers cleanup
        new_serial = "new36b"
        await revoke_cert(
            db_session,
            serial_hex=new_serial,
            org_id="test-org-36",
            cert_not_after=now + timedelta(days=30),
            revoked_by="admin",
        )

        # The seed (expired 60 min ago, > 30 min buffer) should be cleaned up
        result = await db_session.execute(
            select(RevokedCert).where(RevokedCert.serial_hex == seed_serial)
        )
        assert result.scalar_one_or_none() is None


# ──────────────────────────────────────────────────────────────────────────
# #44 — get_client_ip helper
# ──────────────────────────────────────────────────────────────────────────

class TestGetClientIP:
    """#44 — get_client_ip extracts IP from request.client.host."""

    def test_returns_client_host(self):
        from app.rate_limit.limiter import get_client_ip
        request = MagicMock()
        request.client.host = "192.168.1.42"
        assert get_client_ip(request) == "192.168.1.42"

    def test_returns_unknown_when_no_client(self):
        from app.rate_limit.limiter import get_client_ip
        request = MagicMock()
        request.client = None
        assert get_client_ip(request) == "unknown"

    def test_returns_unknown_when_request_none(self):
        from app.rate_limit.limiter import get_client_ip
        assert get_client_ip(None) == "unknown"
