import os
os.environ.setdefault("OTEL_ENABLED", "false")
os.environ["SKIP_ALEMBIC"] = "1"

import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, patch
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.db.database import Base, get_db
from app.db.audit import AuditLog as _AL                          # noqa — registra in Base.metadata
from app.registry.org_store import OrganizationRecord as _OR     # noqa — registra in Base.metadata
from app.registry.store import AgentRecord as _AR                 # noqa — registra in Base.metadata
from app.registry.binding_store import BindingRecord as _BR      # noqa — registra in Base.metadata
from app.policy.store import PolicyRecord as _PR                  # noqa — registra in Base.metadata
from app.auth.jti_blacklist import JtiBlacklist as _JtiBlacklist  # noqa — registra in Base.metadata
from app.auth.revocation import RevokedCert as _RevokedCert       # noqa — registra in Base.metadata
from app.broker.db_models import SessionRecord as _SR, SessionMessageRecord as _SMR  # noqa — registra in Base.metadata
from app.broker.db_models import RfqRecord as _RFQ, RfqResponseRecord as _RFQR  # noqa — registra in Base.metadata
from app.auth.transaction_db import TransactionTokenRecord as _TT  # noqa — registra in Base.metadata
from app.broker.notifications import Notification as _Notification  # noqa — registra in Base.metadata
from app.rate_limit.limiter import rate_limiter

# Admin headers for endpoints that now require admin auth
ADMIN_HEADERS = {"x-admin-secret": "change-me-in-production"}

TEST_DB_URL = "sqlite+aiosqlite:///:memory:"

test_engine = create_async_engine(
    TEST_DB_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
    echo=False,
)
TestSessionLocal = async_sessionmaker(test_engine, expire_on_commit=False)


async def override_get_db():
    async with TestSessionLocal() as session:
        yield session


app.dependency_overrides[get_db] = override_get_db

# Override admin secret check for tests — the test admin secret is "change-me-in-production"
# (the default from Settings). Tests that need to verify admin auth explicitly
# pass the correct header.
from app.registry.org_router import _require_admin as _org_require_admin
app.dependency_overrides[_org_require_admin] = lambda: None

# Patch the module-level engine and session factory so the lifespan
# (which imports them directly) also uses SQLite instead of Postgres.
import app.db.database as _db_module
import app.main as _main_module

_db_module.engine = test_engine
_db_module.AsyncSessionLocal = TestSessionLocal
_main_module.AsyncSessionLocal = TestSessionLocal


# ─────────────────────────────────────────────────────────────────────────────
# Ephemeral broker keys — injected into the jwt module before any test runs
# ─────────────────────────────────────────────────────────────────────────────

def pytest_configure(config):
    """Hook called at pytest startup — injects the test broker keys."""
    from tests.cert_factory import init_broker_keys
    import app.auth.jwt as jwt_module

    priv_pem, pub_pem = init_broker_keys()
    jwt_module._broker_private_key_pem = priv_pem
    jwt_module._broker_public_key_pem = pub_pem


@pytest.fixture(autouse=True)
def _inject_kms_provider():
    """
    Replace the KMS singleton with an in-memory provider backed by the
    ephemeral broker key from cert_factory.  This avoids reading
    certs/broker-ca-key.pem from disk, which doesn't exist in CI.
    """
    from tests.cert_factory import init_broker_keys
    from app.kms.secret_encrypt import encrypt_secret, decrypt_secret

    priv_pem, pub_pem = init_broker_keys()

    class _EphemeralKMS:
        async def get_broker_private_key_pem(self) -> str:
            return priv_pem

        async def get_broker_public_key_pem(self) -> str:
            return pub_pem

        async def encrypt_secret(self, plaintext: str) -> str:
            return encrypt_secret(priv_pem, plaintext)

        async def decrypt_secret(self, stored: str) -> str:
            return decrypt_secret(priv_pem, stored)

    import app.kms.factory as kms_mod
    old = kms_mod._provider
    kms_mod._provider = _EphemeralKMS()
    yield
    kms_mod._provider = old


@pytest_asyncio.fixture(scope="session", autouse=True)
async def setup_db():
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """Reset rate limiter buckets between tests."""
    rate_limiter._windows.clear()
    yield
    rate_limiter._windows.clear()


@pytest.fixture(autouse=True)
def reset_admin_secret_cache():
    """Reset the module-level admin secret cache between tests.

    Without this, a stale bcrypt hash cached by a prior test (or
    bootstrapped from a local file written during a previous CI step)
    can cause admin login to fail: verify_admin_password() rejects
    the password against the wrong hash, and the hmac fallback is
    skipped because stored_hash is not None.
    """
    import app.kms.admin_secret as _admin_mod
    _admin_mod._cached_hash = None
    yield
    _admin_mod._cached_hash = None


@pytest.fixture(autouse=True)
def mock_pdp_webhook():
    """
    Mock the PDP webhook caller for all tests.

    Tests never reach out to real org webhook URLs — the broker calls the
    webhook caller which is patched to always return ALLOW.
    Individual tests that need DENY behavior can override this with their
    own patch on 'app.broker.router.evaluate_session_policy'.
    """
    from app.policy.webhook import WebhookDecision

    allow = WebhookDecision(allowed=True, reason="mocked allow", org_id="broker")
    with patch(
        "app.broker.router.evaluate_session_policy",
        new=AsyncMock(return_value=allow),
    ):
        yield


@pytest_asyncio.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest.fixture
def dpop():
    """Ephemeral DPoP key pair + helpers for authenticated test requests."""
    from tests.cert_factory import DPoPHelper
    return DPoPHelper()


@pytest_asyncio.fixture
async def db_session() -> AsyncSession:
    async with TestSessionLocal() as session:
        yield session
