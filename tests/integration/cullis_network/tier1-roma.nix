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

    # NB. The full daniele@user → MCP query path needs the
    # Frontdesk Ambassador + Cullis Chat SPA + an MCP echo backend
    # wired into the VM. This Tier 1 scaffold validates the
    # broker / proxy / nginx triple comes up clean from a fresh
    # NixOS rootfs; the Frontdesk + Chat extension lands in a
    # follow-up commit so each step ships green.
  '';
}
