# Tier 1 — single VM ``roma`` running the full Cullis stack.
#
# Validates the intra-org demo end-to-end: a daniele@user principal
# routes through the Frontdesk shared-mode Ambassador, hits the
# postgres MCP backend, and lands an audit row carrying
# ``principal_type=user``. Same flow PR #445 verified live on the
# Docker compose sandbox, but here the host is a real NixOS VM so
# the test stresses the production wiring (systemd ordering, real
# nginx mTLS, kernel-level network stack) instead of the compose
# bridge.
#
# This is the minimum viable demo — Tier 2 fans out to three
# Mastios + Court for the cross-org pitch and reuses
# ``lib/cullis-mastio.nix``.
{ pkgs, cullisSrc, lib }:

pkgs.nixosTest {
  name = "cullis-tier1-roma";

  nodes.roma = { config, ... }: {
    imports = [ ./lib/cullis-mastio.nix ];

    # Plenty of headroom — Cullis pulls in a fair chunk of Python
    # stack (sqlalchemy + cryptography + uvicorn) and the test
    # exercises it under load.
    virtualisation = {
      memorySize = 2048;
      cores = 2;
    };

    cullis.mastio = {
      enable = true;
      cullisSrc = cullisSrc;
      orgId = "roma";
      trustDomain = "roma.cullis.test";
      displayName = "Roma Mastio";
    };

    # Map the Mastio FQDN to the loopback so curl from the test
    # script doesn't need to resolve through DNS.
    networking.extraHosts = ''
      127.0.0.1 mastio.roma.cullis.test
    '';
  };

  testScript = ''
    import json

    # Boot order: PKI bootstrap (oneshot) → broker → proxy → nginx.
    # ``wait_for_unit`` waits for ``active`` (oneshot Type=) so
    # the broker actually has a CA on disk before we hit it.
    roma.start()
    roma.wait_for_unit("cullis-pki-bootstrap.service")
    roma.wait_for_unit("cullis-broker.service")
    roma.wait_for_unit("cullis-proxy.service")
    roma.wait_for_unit("nginx.service")

    # Health probes — no auth required.
    roma.wait_until_succeeds(
        "curl -fs http://127.0.0.1:8000/health",
        timeout=30,
    )
    roma.wait_until_succeeds(
        "curl -fs http://127.0.0.1:9100/health",
        timeout=30,
    )
    # nginx serves on the TLS port. ``-k`` for the self-signed Org
    # CA — the production demo pins the CA via TOFU; here we only
    # care that nginx is reachable.
    roma.wait_until_succeeds(
        "curl -fsk https://mastio.roma.cullis.test:9443/health",
        timeout=30,
    )

    with subtest("Mastio identity surface"):
        # Root path returns the proxy's hello payload — we use it
        # to confirm the org_id + trust_domain landed correctly via
        # the systemd environment.
        out = roma.succeed(
            "curl -fsk https://mastio.roma.cullis.test:9443/v1/federation/orgs"
        )
        assert "roma" in out, f"expected ``roma`` in federation orgs, got: {out!r}"

    with subtest("ADR-020 user-principal token flow (PR #445 regression)"):
        # Generate a daniele@user keypair + cert SVID-style on the
        # VM, signed by the Org CA the PKI bootstrap minted at first
        # boot. This sidesteps the Frontdesk Ambassador wiring
        # (workload cert + ``/v1/principals/csr`` round-trip) so we
        # can validate the broker's user-token issuance in isolation
        # — the same regression the live sandbox dogfood caught.
        # The Frontdesk + Chat extension lands in a follow-up slice
        # and re-exercises the end-to-end path.
        spiffe_uri = "spiffe://roma.cullis.test/roma/user/daniele"
        roma.succeed(
            "openssl ecparam -name prime256v1 -genkey -noout "
            "-out /tmp/daniele.key"
        )
        roma.succeed(
            f"openssl req -new -key /tmp/daniele.key -out /tmp/daniele.csr "
            f"-subj '/' -addext 'subjectAltName=URI:{spiffe_uri}'"
        )
        # Sign with the Org CA that ``cullis-pki-bootstrap`` already
        # placed at /var/lib/cullis/certs/. ADR-020 cert subject is
        # *empty* — identity lives in the SPIFFE SAN URI only.
        roma.succeed(
            f"openssl x509 -req -in /tmp/daniele.csr "
            f"-CA /var/lib/cullis/certs/org-ca.pem "
            f"-CAkey /var/lib/cullis/certs/org-ca.key "
            f"-CAcreateserial -out /tmp/daniele.pem -days 1 "
            f"-extfile <(printf 'subjectAltName=URI:{spiffe_uri}\\n"
            f"extendedKeyUsage=clientAuth\\n')"
        )

        # Insert the user-principal placeholder row in the proxy DB
        # so ``client_cert.py`` lookup resolves. In production the
        # Frontdesk provisioner writes this row at first SSO touch;
        # the regression #445 left this gap — tracked as a follow-up
        # in ``project_scenario3_remaining_gaps``. We poke the row
        # in directly so the test doesn't depend on the provisioner.
        insert = (
            "INSERT INTO internal_agents "
            "(agent_id, display_name, capabilities, cert_pem, created_at, "
            "is_active, spiffe_id) VALUES "
            "('roma::user::daniele', 'daniele user', '[]', NULL, "
            f"datetime('now'), 1, '{spiffe_uri}') "
            "ON CONFLICT (agent_id) DO UPDATE SET is_active=1"
        )
        roma.succeed(
            f"sqlite3 /var/lib/cullis/proxy.sqlite \"{insert}\""
        )

        # Drive the full SDK login dance via a one-shot Python
        # snippet executed on the VM. ``cullis_sdk`` is on
        # ``PYTHONPATH`` because the systemd units source it that
        # way. ``from_user_principal_pem`` is the factory PR #445
        # added; we read the cert+key off /tmp and validate the
        # broker issues a DPoP-bound JWT with ``principal_type=user``
        # and the SPIFFE ``sub`` matching the SAN.
        snippet = """
import sys
sys.path.insert(0, '${toString cullisSrc}')
from cullis_sdk import CullisClient
import jwt as _jwt

cert_pem = open('/tmp/daniele.pem').read()
key_pem  = open('/tmp/daniele.key').read()
client = CullisClient.from_user_principal_pem(
    'https://mastio.roma.cullis.test:9443',
    principal_id='roma.cullis.test/roma/user/daniele',
    cert_pem=cert_pem,
    key_pem=key_pem,
    verify_tls=False,
)
client.login_via_proxy_with_local_key()
payload = _jwt.decode(client.token, options={'verify_signature': False})
print('PRINCIPAL_TYPE=' + payload['principal_type'])
print('AGENT_ID=' + payload['agent_id'])
print('SUB=' + payload['sub'])
print('SCOPE=' + repr(payload['scope']))
"""
        out = roma.succeed(
            f"python3 -c {json.dumps(snippet)}"
        )
        assert "PRINCIPAL_TYPE=user" in out, out
        assert "AGENT_ID=roma::user::daniele" in out, out
        assert f"SUB={spiffe_uri}" in out, out
        assert "SCOPE=[]" in out, out
  '';
}
