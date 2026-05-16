"""One-shot auth smoke for a stress-enrolled agent.

Picks the first entry from ``stress_agents.json``, builds
client_assertion + DPoP proof exactly the way ``intra-org-mastio-burst.js``
will, hits ``POST /v1/auth/token`` on the live Mastio and prints the
result. Exits non-zero on any 4xx/5xx so we catch wrong-cert or
DPoP-nonce drift before pointing 5000 VUs at the box.
"""
from __future__ import annotations

import base64
import datetime
import hashlib
import json
import os
import sys
import urllib3
import uuid
from pathlib import Path

import jwt
import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization

HERE = Path(__file__).resolve().parent
BASE_URL = os.environ.get("BASE_URL", "https://192.168.122.170:9443")
DATA_PATH = HERE / "stress_agents.json"

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def main() -> None:
    bundle = json.loads(DATA_PATH.read_text())
    agent = bundle["agents"][0]
    aid = agent["agent_id"]

    cert = x509.load_pem_x509_certificate(agent["cert_pem"].encode())
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    x5c = [base64.b64encode(cert_der).decode()]

    now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    assertion = jwt.encode(
        {
            "sub": aid, "iss": aid, "aud": "agent-trust-broker",
            "iat": now, "exp": now + 300, "jti": str(uuid.uuid4()),
        },
        agent["leaf_priv_pkcs8_pem"],
        algorithm="ES256",
        headers={"x5c": x5c},
    )

    # nginx forwards `Host: $host` which strips the port. Mastio rebuilds
    # request.url without the port, so the DPoP htu we sign must match
    # the port-less form or _maybe_extract_dpop_jkt_at_mint silently
    # falls back to unbound mint (200 + no cnf.jkt).
    htu_url = BASE_URL.replace(":9443", "") + "/v1/auth/token"
    htu = htu_url  # what we sign into the proof
    target_url = f"{BASE_URL}/v1/auth/token"  # what we actually POST to
    dpop_proof = jwt.encode(
        {
            "jti": str(uuid.uuid4()), "htm": "POST", "htu": htu,
            "iat": now,
        },
        agent["dpop_priv_pkcs8_pem"],
        algorithm="ES256",
        headers={"typ": "dpop+jwt", "jwk": agent["dpop_jwk_pub"]},
    )

    sess = requests.Session()
    resp = sess.post(
        target_url,
        json={"client_assertion": assertion},
        headers={"DPoP": dpop_proof},
        verify=False,
        timeout=10,
    )
    if resp.status_code == 401 and "use_dpop_nonce" in resp.text:
        nonce = resp.headers.get("dpop-nonce")
        print(f"  → got 401 use_dpop_nonce, retrying with nonce={nonce!r}",
              file=sys.stderr)
        dpop_proof = jwt.encode(
            {
                "jti": str(uuid.uuid4()), "htm": "POST", "htu": htu,
                "iat": now, "nonce": nonce,
            },
            agent["dpop_priv_pkcs8_pem"],
            algorithm="ES256",
            headers={"typ": "dpop+jwt", "jwk": agent["dpop_jwk_pub"]},
        )
        resp = sess.post(
            htu,
            json={"client_assertion": assertion},
            headers={"DPoP": dpop_proof},
            verify=False,
            timeout=10,
        )

    print(f"status={resp.status_code} agent={aid}")
    body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else resp.text
    print(json.dumps(body, indent=2)[:600])
    if resp.status_code != 200:
        sys.exit(1)

    token = body["access_token"]
    # Validate cnf.jkt binding lands too.
    parts = token.split(".")
    payload_b64 = parts[1] + "=" * (-len(parts[1]) % 4)
    decoded = json.loads(base64.urlsafe_b64decode(payload_b64))
    print(f"\ntoken claims keys: {sorted(decoded.keys())}")
    cnf = decoded.get("cnf", {})
    print(f"cnf.jkt: {cnf.get('jkt')!r}")
    print(f"agent dpop_jkt (expected): {agent['dpop_jkt']!r}")
    if cnf.get("jkt") != agent["dpop_jkt"]:
        print("WARN: cnf.jkt MISMATCH — DPoP binding broken")
        sys.exit(2)
    print("OK: cnf.jkt matches agent's dpop_jkt")


if __name__ == "__main__":
    main()
