"""
Test per il modulo SPIFFE — mapping bidirezionale, validazione, SAN nei certificati,
claim spiffe_id nel JWT emesso dal broker e verifica SAN nell'autenticazione.
"""
import pytest
from cryptography import x509 as cx509
from httpx import AsyncClient
import jwt as jose_jwt

from app.spiffe import (
    agent_id_to_spiffe,
    spiffe_to_agent_id,
    internal_id_to_spiffe,
    spiffe_to_internal_id,
    validate_spiffe_id,
)
from tests.cert_factory import make_agent_cert, make_assertion, get_org_ca_pem
from tests.conftest import ADMIN_HEADERS, seed_court_agent

# ─────────────────────────────────────────────────────────────────────────────
# Test mapping bidirezionale
# ─────────────────────────────────────────────────────────────────────────────

def test_agent_id_to_spiffe_base():
    assert agent_id_to_spiffe("manufacturer", "sales-agent", "cullis.local") == \
        "spiffe://cullis.local/manufacturer/sales-agent"


def test_agent_id_to_spiffe_dominio_con_punto():
    assert agent_id_to_spiffe("acme", "kyc-agent", "trust.example.com") == \
        "spiffe://trust.example.com/acme/kyc-agent"


def test_spiffe_to_agent_id_base():
    org, agent = spiffe_to_agent_id("spiffe://cullis.local/manufacturer/sales-agent")
    assert org == "manufacturer"
    assert agent == "sales-agent"


def test_roundtrip_internal_to_spiffe_e_ritorno():
    agent_id = "banca-x::kyc-agent-v1"
    spiffe_id = internal_id_to_spiffe(agent_id, "cullis.local")
    assert spiffe_id == "spiffe://cullis.local/banca-x/kyc-agent-v1"
    assert spiffe_to_internal_id(spiffe_id) == agent_id


def test_roundtrip_spiffe_to_internal_e_ritorno():
    spiffe_id = "spiffe://cullis.local/acme-corp/support-agent"
    internal = spiffe_to_internal_id(spiffe_id)
    assert internal == "acme-corp::support-agent"
    assert internal_id_to_spiffe(internal, "cullis.local") == spiffe_id


# ─────────────────────────────────────────────────────────────────────────────
# Test validazione SPIFFE ID
# ─────────────────────────────────────────────────────────────────────────────

def test_validate_spiffe_id_valido():
    assert validate_spiffe_id("spiffe://cullis.local/org/agent") is True


@pytest.mark.parametrize("invalido, descrizione", [
    ("",                              "vuoto"),
    ("http://cullis.local/org/agent",    "schema errato"),
    ("spiffe:///org/agent",           "trust domain mancante"),
    ("spiffe://cullis.local/",           "path vuota"),
    ("spiffe://cullis.local",            "path assente"),
    ("spiffe://ATN.LOCAL/org/agent",  "trust domain con uppercase"),
    ("spiffe://cullis.local/org/agent?x=1", "query string presente"),
    ("spiffe://cullis.local/org/agent#frag", "fragment presente"),
])
def test_validate_spiffe_id_invalido(invalido, descrizione):
    with pytest.raises(ValueError):
        validate_spiffe_id(invalido)


def test_spiffe_to_agent_id_path_troppo_profonda():
    with pytest.raises(ValueError):
        spiffe_to_agent_id("spiffe://cullis.local/org/agent/extra")


def test_internal_id_to_spiffe_formato_errato():
    with pytest.raises(ValueError):
        internal_id_to_spiffe("agent-senza-doppi-due-punti", "cullis.local")


# ─────────────────────────────────────────────────────────────────────────────
# Test SAN URI nel certificato
# ─────────────────────────────────────────────────────────────────────────────

def test_make_agent_cert_senza_trust_domain_non_ha_san():
    """Cert generato senza trust_domain non deve avere SAN URI SPIFFE."""
    _, cert = make_agent_cert("spiffe-org::agent-no-san", "spiffe-org")
    try:
        san = cert.extensions.get_extension_for_class(cx509.SubjectAlternativeName)
        uri_sans = san.value.get_values_for_type(cx509.UniformResourceIdentifier)
        spiffe_sans = [u for u in uri_sans if u.startswith("spiffe://")]
        assert spiffe_sans == []
    except cx509.ExtensionNotFound:
        pass  # Nessun SAN — OK


def test_make_agent_cert_con_trust_domain_ha_spiffe_san():
    """Cert generato con trust_domain deve avere il SAN URI SPIFFE corretto."""
    agent_id = "spiffe-org::agent-with-san"
    org_id = "spiffe-org"
    trust_domain = "cullis.local"

    _, cert = make_agent_cert(agent_id, org_id, trust_domain=trust_domain)

    san_ext = cert.extensions.get_extension_for_class(cx509.SubjectAlternativeName)
    uri_sans = san_ext.value.get_values_for_type(cx509.UniformResourceIdentifier)
    spiffe_sans = [u for u in uri_sans if u.startswith("spiffe://")]

    assert len(spiffe_sans) == 1
    assert spiffe_sans[0] == "spiffe://cullis.local/spiffe-org/agent-with-san"


def test_san_uri_corrisponde_al_cn():
    """Il SAN URI deve essere consistente con il CN del certificato."""
    agent_id = "test-org::my-agent"
    org_id = "test-org"
    trust_domain = "test.local"

    _, cert = make_agent_cert(agent_id, org_id, trust_domain=trust_domain)

    cn = cert.subject.get_attributes_for_oid(cx509.oid.NameOID.COMMON_NAME)[0].value
    san_ext = cert.extensions.get_extension_for_class(cx509.SubjectAlternativeName)
    uri_sans = san_ext.value.get_values_for_type(cx509.UniformResourceIdentifier)
    spiffe_sans = [u for u in uri_sans if u.startswith("spiffe://")]

    # CN = agent_id interno, SAN = SPIFFE URI dello stesso agente
    assert cn == agent_id
    assert spiffe_sans[0] == internal_id_to_spiffe(agent_id, trust_domain)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers di registrazione per i test di integrazione
# ─────────────────────────────────────────────────────────────────────────────

async def _register_agent_with_spiffe(
    client: AsyncClient,
    agent_id: str,
    org_id: str,
    trust_domain: str = "cullis.local",
):
    """Registra org + CA + agente + binding approvato, con SAN SPIFFE nel cert."""
    org_secret = org_id + "-secret"

    await client.post("/v1/registry/orgs", json={
        "org_id": org_id, "display_name": org_id, "secret": org_secret,
    }, headers=ADMIN_HEADERS)
    ca_pem = get_org_ca_pem(org_id)
    await client.post(f"/v1/registry/orgs/{org_id}/certificate",
        json={"ca_certificate": ca_pem},
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    await seed_court_agent(
        agent_id=agent_id,
        org_id=org_id,
        display_name=f'Test Agent {agent_id}',
        capabilities=['test.read'],
    )
    resp = await client.post("/v1/registry/bindings",
        json={"org_id": org_id, "agent_id": agent_id, "scope": ["test.read"]},
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    binding_id = resp.json()["id"]
    await client.post(f"/v1/registry/bindings/{binding_id}/approve",
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )


# ─────────────────────────────────────────────────────────────────────────────
# Test JWT emesso dal broker — claim sub e agent_id
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_jwt_sub_e_spiffe_id(client: AsyncClient, dpop):
    """
    Il JWT emesso dal broker deve avere:
      - sub = SPIFFE ID (spiffe://...)
      - agent_id = formato interno (org::agent)
    """
    agent_id = "spiffe-jwt-org::agent-1"
    org_id = "spiffe-jwt-org"
    trust_domain = "cullis.local"

    await _register_agent_with_spiffe(client, agent_id, org_id, trust_domain)

    assertion = make_assertion(agent_id, org_id, trust_domain=trust_domain)
    proof = dpop.proof("POST", "/v1/auth/token")
    resp = await client.post(
        "/v1/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": proof},
    )
    assert resp.status_code == 200

    token = resp.json()["access_token"]
    # Decoding senza verifica per controllare i claim
    payload = jose_jwt.decode(token, options={"verify_signature": False}, algorithms=["RS256"])

    assert payload["sub"].startswith("spiffe://")
    assert payload["sub"] == f"spiffe://{trust_domain}/{org_id}/agent-1"
    assert payload["agent_id"] == agent_id
    assert payload["org"] == org_id


@pytest.mark.asyncio
async def test_jwt_sub_senza_san_nel_cert(client: AsyncClient, dpop):
    """
    Anche senza SAN nel cert (require_spiffe_san=False per default),
    il broker deve emettere il JWT con sub = SPIFFE ID calcolato dal CN.
    """
    agent_id = "spiffe-nospan-org::agent-1"
    org_id = "spiffe-nospan-org"

    await _register_agent_with_spiffe(client, agent_id, org_id)

    # Cert senza SAN (nessun trust_domain passato)
    assertion = make_assertion(agent_id, org_id)
    proof = dpop.proof("POST", "/v1/auth/token")
    resp = await client.post(
        "/v1/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": proof},
    )
    assert resp.status_code == 200

    token = resp.json()["access_token"]
    payload = jose_jwt.decode(token, options={"verify_signature": False}, algorithms=["RS256"])

    assert payload["sub"].startswith("spiffe://")
    assert payload["agent_id"] == agent_id


# ─────────────────────────────────────────────────────────────────────────────
# Test verifica SAN nel broker (autenticazione)
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_autenticazione_con_san_corretto(client: AsyncClient, dpop):
    """Cert con SAN SPIFFE corretto → autenticazione OK."""
    agent_id = "spiffe-san-org::agent-ok"
    org_id = "spiffe-san-org"

    await _register_agent_with_spiffe(client, agent_id, org_id)

    assertion = make_assertion(agent_id, org_id, trust_domain="cullis.local")
    proof = dpop.proof("POST", "/v1/auth/token")
    resp = await client.post(
        "/v1/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": proof},
    )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_autenticazione_fallisce_con_san_sbagliato(client: AsyncClient, dpop):
    """
    Cert con SAN SPIFFE che non corrisponde all'agente registrato → 401.
    Costruiamo manualmente un cert con SAN del trust domain sbagliato.
    """
    agent_id = "spiffe-san-org::agent-bad-san"
    org_id = "spiffe-san-org"

    # Usa org già registrata dalla fixture precedente (o la registra)
    org_secret = org_id + "-secret"
    await client.post("/v1/registry/orgs", json={
        "org_id": org_id, "display_name": org_id, "secret": org_secret,
    }, headers=ADMIN_HEADERS)
    ca_pem = get_org_ca_pem(org_id)
    await client.post(f"/v1/registry/orgs/{org_id}/certificate",
        json={"ca_certificate": ca_pem},
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    await seed_court_agent(
        agent_id=agent_id,
        org_id=org_id,
        display_name=f'Test Agent {agent_id}',
        capabilities=['test.read'],
    )
    resp = await client.post("/v1/registry/bindings",
        json={"org_id": org_id, "agent_id": agent_id, "scope": ["test.read"]},
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    binding_id = resp.json()["id"]
    await client.post(f"/v1/registry/bindings/{binding_id}/approve",
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )

    # Cert con SAN che punta a un trust domain DIVERSO da cullis.local
    assertion = make_assertion(agent_id, org_id, trust_domain="evil.example.com")
    proof = dpop.proof("POST", "/v1/auth/token")
    resp = await client.post(
        "/v1/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": proof},
    )
    assert resp.status_code == 401
    assert "SPIFFE" in resp.json()["detail"]


# ─────────────────────────────────────────────────────────────────────────────
# Test agent_uri nel registry
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_registry_espone_agent_uri(client: AsyncClient, dpop):
    """Le API pubbliche del registry devono includere agent_uri nella risposta."""
    agent_id = "spiffe-registry-org::agent-1"
    org_id = "spiffe-registry-org"

    await _register_agent_with_spiffe(client, agent_id, org_id)

    # Ottieni token per fare la query
    token = await dpop.get_token(client, agent_id, org_id, trust_domain="cullis.local")

    resp = await client.get(
        "/v1/federation/agents",
        headers=dpop.headers("GET", "/v1/federation/agents", token),
    )
    assert resp.status_code == 200
    agents = resp.json()["agents"]
    assert len(agents) >= 1
    agent = next(a for a in agents if a["agent_id"] == agent_id)
    assert "agent_uri" in agent
    assert agent["agent_uri"].startswith("spiffe://")
    assert agent["agent_uri"] == f"spiffe://cullis.local/{org_id}/agent-1"
