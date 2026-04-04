"""
Test WebSocket endpoint — /broker/ws

Coverage:
  1. Connection with valid token receives auth_ok
  2. Connection with invalid token receives auth_error and connection is closed
"""
from starlette.testclient import TestClient

from app.main import app
from tests.cert_factory import make_assertion, get_org_ca_pem, DPoPHelper


# Starlette's sync TestClient uses "http://testserver" as the base URL, not "http://test".
_TESTSERVER = "http://testserver"


def _setup_agent(client: TestClient, org_id: str, agent_id: str, dpop: DPoPHelper) -> str:
    """Register org + CA + agent + approved binding. Returns the DPoP-bound access token."""
    org_secret = org_id + "-secret"

    client.post("/registry/orgs", json={
        "org_id": org_id, "display_name": org_id, "secret": org_secret,
    })
    ca_pem = get_org_ca_pem(org_id)
    client.post(f"/registry/orgs/{org_id}/certificate",
        json={"ca_certificate": ca_pem},
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    client.post("/registry/agents", json={
        "agent_id": agent_id, "org_id": org_id,
        "display_name": agent_id, "capabilities": ["order.read"],
    })
    resp = client.post("/registry/bindings",
        json={"org_id": org_id, "agent_id": agent_id, "scope": ["order.read"]},
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    binding_id = resp.json()["id"]
    client.post(f"/registry/bindings/{binding_id}/approve",
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )
    assertion = make_assertion(agent_id, org_id)
    dpop_proof = dpop.proof("POST", f"{_TESTSERVER}/auth/token")
    resp = client.post(
        "/auth/token",
        json={"client_assertion": assertion},
        headers={"DPoP": dpop_proof},
    )
    assert resp.status_code == 200, f"Token request failed: {resp.text}"
    return resp.json()["access_token"]


def test_ws_auth_valid():
    """A valid DPoP-bound JWT token must receive auth_ok with the correct agent_id."""
    dpop = DPoPHelper()
    with TestClient(app) as client:
        token = _setup_agent(client, "ws-valid-org", "ws-valid-org::agent", dpop)

        ws_proof = dpop.proof("GET", f"{_TESTSERVER}/broker/ws", access_token=token)
        with client.websocket_connect("/broker/ws") as ws:
            ws.send_json({"type": "auth", "token": token, "dpop_proof": ws_proof})
            data = ws.receive_json()

    assert data["type"] == "auth_ok"
    assert data["agent_id"] == "ws-valid-org::agent"


def test_ws_auth_invalid_token():
    """An invalid token must receive auth_error and the connection is closed."""
    with TestClient(app) as client:
        dpop = DPoPHelper()
        ws_proof = dpop.proof("GET", f"{_TESTSERVER}/broker/ws")
        with client.websocket_connect("/broker/ws") as ws:
            ws.send_json({"type": "auth", "token": "not.a.valid.jwt.token", "dpop_proof": ws_proof})
            data = ws.receive_json()

    assert data["type"] == "auth_error"
    assert "detail" in data
