import os
os.environ.setdefault("OTEL_ENABLED", "false")

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
from app.broker.notifications import Notification as _Notification  # noqa — registra in Base.metadata
from app.rate_limit.limiter import rate_limiter

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
def mock_pdp_webhook():
    """
    Mock the PDP webhook caller for all tests.

    Tests never reach out to real org webhook URLs — the broker calls the
    webhook caller which is patched to always return ALLOW.
    Individual tests that need DENY behavior can override this with their
    own patch on 'app.policy.webhook.evaluate_session_via_webhooks'.
    """
    from app.policy.webhook import WebhookDecision

    allow = WebhookDecision(allowed=True, reason="mocked allow", org_id="broker")
    with patch(
        "app.broker.router.evaluate_session_via_webhooks",
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
