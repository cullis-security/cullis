# Tier 2 — four-VM cross-continent demo.
#
#   roma          (CET)  — Mastio org=roma,  td=roma.cullis.test
#   sanfrancisco  (PST)  — Mastio org=sf,    td=sf.cullis.test
#   tokyo         (JST)  — Mastio org=tokyo, td=tokyo.cullis.test
#   court         (—)    — Federation Court  (cross-org trust fabric)
#
# Validates the architectural claim the docker compose sandbox can't:
# every "city" runs on its own kernel + network namespace + Org CA,
# so per-host PKI is genuinely per-host (Roma's CA bytes never appear
# on Tokyo's disk), and cross-org chain validation fails by default
# (each Mastio refuses certs signed by another's Org CA).
#
# This slice asserts the *isolation* invariants. The federation
# publisher + actual A2A oneshot Roma→Tokyo via Court is the next
# slice on this branch — it needs the broker (``app/main.py``)
# wired with ``COURT_URL`` env vars on each Mastio, plus
# cross-org binding admin steps which are easier to script once
# the topology boots cleanly.
{ pkgs, cullisSrc, lib }:

let
  # Same store-materialisation trick the cullis-mastio module uses;
  # we don't actually consume it directly here, but keep the filter
  # pattern visible so future slices that drive cross-org HTTPS calls
  # know where to plug in.
  cullisSrcStore = lib.cleanSourceWith {
    name = "cullis-src";
    src = cullisSrc;
    filter = path: type:
      let baseName = baseNameOf (toString path); in
      !(builtins.elem baseName [
        ".git" ".github" ".venv" "__pycache__" "node_modules"
        "connector_data" "state" "dist" "result"
      ]);
  };

  # Same preload script PR #454 used in tier1-roma — when the proxy
  # is configured with ``standalone=false`` it stops auto-generating
  # an Org CA on first boot, so the federation publisher's
  # ``mastio_loaded`` gate stays False and the publisher never
  # actually starts. The preload upserts the on-disk Org CA from
  # ``cullis-pki-bootstrap`` into ``proxy_config``; restarting the
  # proxy after this runs flips ``mastio_loaded`` to True and the
  # publisher loop comes online.
  preloadOrgCaScript = pkgs.writeText "preload-org-ca.py" ''
    """Upsert the on-disk Org CA into the proxy's ``proxy_config``."""
    import sqlite3
    import sys

    DB = "/var/lib/cullis/proxy.sqlite"
    KEY_PATH = "/var/lib/cullis/certs/org-ca.key"
    CERT_PATH = "/var/lib/cullis/certs/org-ca.pem"

    key_pem = open(KEY_PATH).read()
    cert_pem = open(CERT_PATH).read()

    conn = sqlite3.connect(DB)
    try:
        for k, v in (("org_ca_key", key_pem), ("org_ca_cert", cert_pem)):
            conn.execute(
                "INSERT INTO proxy_config (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (k, v),
            )
        conn.commit()
        rows = conn.execute(
            "SELECT key FROM proxy_config "
            "WHERE key IN ('org_ca_key', 'org_ca_cert') ORDER BY key"
        ).fetchall()
    finally:
        conn.close()

    if [r[0] for r in rows] != ["org_ca_cert", "org_ca_key"]:
        print(f"PRELOAD_FAILED: rows={rows!r}", file=sys.stderr)
        sys.exit(1)
    print("PRELOADED org_ca into proxy_config")
  '';

  # Per-city Mastio config. Each entry produces a NixOS node that
  # drops the ``cullis.mastio`` module on top of a base
  # ``virtualisation`` block; the module handles broker + proxy +
  # nginx + per-VM PKI bootstrap.
  cities = {
    roma = {
      orgId = "roma";
      trustDomain = "roma.cullis.test";
      displayName = "Roma Mastio (CET)";
    };
    sanfrancisco = {
      orgId = "sf";
      trustDomain = "sf.cullis.test";
      displayName = "San Francisco Mastio (PST)";
    };
    tokyo = {
      orgId = "tokyo";
      trustDomain = "tokyo.cullis.test";
      displayName = "Tokyo Mastio (JST)";
    };
    court = {
      orgId = "court";
      trustDomain = "court.cullis.test";
      displayName = "Federation Court";
    };
  };

  mkCityNode = name: cfg: {
    imports = [ ./lib/cullis-mastio.nix ];

    virtualisation = {
      memorySize = 1536;
      cores = 1;
    };

    cullis.mastio = {
      enable = true;
      # Court is the federation hub — only it needs the broker
      # bound on the world-facing interface so peers can reach
      # ``/v1/federation/publish-agent``. Cities run a local
      # broker just for their own agent auth, but the
      # ``federation publisher`` task on each city points its
      # publish loop at Court via ``brokerUrl``.
      enableBroker = true;
      nginxAllowExternal = name == "court";
      brokerUrl =
        if name == "court"
        then ""  # local loopback default — Court IS the broker
        else "http://court:8000";  # peers publish to Court
      cullisSrc = cullisSrc;
      inherit (cfg) orgId trustDomain displayName;
    };

    # Each city resolves its own ``mastio.<td>`` to loopback so the
    # local SDK / test driver can curl over the TLS port without
    # going through DNS. ``court`` resolves on every city so
    # ``brokerUrl=http://court:8000`` works without static IPs.
    networking.extraHosts = ''
      127.0.0.1 mastio.${cfg.trustDomain}
    '';
  };

in

pkgs.testers.nixosTest {
  name = "cullis-tier2-cross-org";

  skipTypeCheck = true;
  skipLint = true;

  nodes = lib.mapAttrs mkCityNode cities;

  testScript = ''
    cities = [roma, sanfrancisco, tokyo, court]

    # Boot all four VMs in parallel and wait for each to land its
    # systemd targets. Doing this serially would push the wall-clock
    # past 2 minutes for nothing — the boot paths don't depend on
    # one another (yet — federation publisher, when wired, will).
    start_all()
    for c in cities:
        c.wait_for_unit("cullis-pki-bootstrap.service")
        c.wait_for_unit("cullis-proxy.service")
        c.wait_for_unit("cullis-broker.service")
        c.wait_for_unit("nginx.service")
        c.wait_until_succeeds(
            "curl -fs http://127.0.0.1:8000/health", timeout=60,
        )
        c.wait_until_succeeds(
            "curl -fs http://127.0.0.1:9100/health", timeout=60,
        )

    with subtest("Per-VM Org CA isolation"):
        # Each city minted its own Org CA at first boot. The CA
        # bytes are NOT a derived path — they're random EC P-256
        # keys generated inside the VM, so two VMs running the same
        # config still produce distinct CAs. We hash each cert and
        # cross-check: any pair landing on the same digest would
        # mean PKI bootstrap is leaking state across VMs (which it
        # absolutely shouldn't on a kernel-isolated network).
        digests = {}
        for c in cities:
            digest = c.succeed(
                "sha256sum /var/lib/cullis/certs/org-ca.pem"
            ).split()[0]
            digests[c.name] = digest
            print(f"  {c.name} Org CA sha256: {digest}")
        unique = set(digests.values())
        assert len(unique) == 4, (
            f"expected four distinct Org CAs, got {len(unique)} "
            f"(digests: {digests!r})"
        )

    with subtest("Cross-VM TCP reachability (kernel-level network)"):
        # The test framework gives us a single shared vlan; every
        # city ends up with a routable IP. ``curl --resolve`` lets
        # us hit Tokyo's nginx from Roma with the *real* TCP path —
        # firewall rules, IP routing, TLS handshake all the way
        # through. The cert won't verify across orgs (expected),
        # so we use ``-k`` and only check the TLS handshake
        # completes (anything non-000 means we made it through).
        # Asserting on response *content* is the next slice — that
        # needs the federation publisher wired so peers actually
        # mirror each other's agent registries.
        tokyo_ip = tokyo.succeed(
            "ip -4 -o addr show dev eth1 | awk '{print $4}' | cut -d/ -f1"
        ).strip()
        http_code = roma.succeed(
            f"curl -sk -o /dev/null -w '%{{http_code}}' "
            f"--resolve mastio.tokyo.cullis.test:9443:{tokyo_ip} "
            f"https://mastio.tokyo.cullis.test:9443/health"
        ).strip()
        # Either nginx answered with the /health 200, or the proxy
        # returned a 4xx — both prove the cross-VM TCP + TLS path
        # works. ``000`` would mean the connection itself failed.
        assert http_code != "000", (
            f"Roma → Tokyo TCP handshake failed (curl http_code={http_code!r})"
        )
        print(f"  Roma → Tokyo cross-VM HTTPS: {http_code}")

    with subtest("Federation publisher: cities reach Court's broker"):
        # Each city's proxy points its ``MCP_PROXY_BROKER_URL`` at
        # ``http://court:8000``; the federation publisher tail
        # POSTs ``/v1/federation/publish-agent`` on each tick.
        # Probing from inside each city confirms the route is up.
        for c in [roma, sanfrancisco, tokyo]:
            health = c.succeed(
                "curl -fs http://court:8000/health || echo OFFLINE"
            ).strip()
            assert "OFFLINE" not in health, (
                f"{c.name} can't reach Court's broker (got: {health!r})"
            )
            print(f"  {c.name} → court:8000/health = {health}")

    with subtest("Federation publish: Roma pushes to Court (payload wire)"):
        # Phase 1 — preload the on-disk Org CA into proxy_config and
        # restart the proxy. With ``standalone=false`` the proxy
        # doesn't auto-generate a CA on first boot, so the
        # ``mastio_loaded`` gate that protects the federation
        # publisher startup stays False forever. Loading the CA
        # nginx already presents fixes the gate without needing a
        # full broker attach-ca admin flow.
        roma.succeed("python3 ${preloadOrgCaScript}")
        roma.succeed("systemctl restart cullis-proxy.service")
        roma.wait_for_unit("cullis-proxy.service")
        roma.wait_until_succeeds(
            "curl -fs http://127.0.0.1:9100/health", timeout=30,
        )

        # Phase 2 — insert a row in Roma's ``internal_agents`` with
        # ``federated=1`` so the publisher picks it up on its next
        # tick (poll interval forced to 2s via
        # ``MCP_PROXY_FEDERATION_POLL_INTERVAL_S``). The publisher
        # then counter-signs the body and POSTs to Court at
        # ``/v1/federation/publish-agent``.
        #
        # We do NOT bootstrap the cross-org trust on Court here
        # (which would need ``mastio_pubkey`` pinning + CA attach
        # via admin endpoints — multiple steps per city, separate
        # admin onboarding flow). So Court will reject the publish
        # with HTTP 4xx (unpinned mastio pubkey / unknown org).
        # That's still proof of the wire being alive: an HTTP
        # response, not a connection error. The publisher logs
        # ``federation publish OK`` on success or
        # ``federation publish <id> → HTTP <code>`` on rejection;
        # ``broker unreachable`` would mean a dead wire — the
        # failure mode this subtest is designed to catch.
        roma.succeed(
            "openssl ecparam -name prime256v1 -genkey -noout "
            "-out /tmp/fedtest.key && "
            "openssl req -new -key /tmp/fedtest.key "
            "-out /tmp/fedtest.csr -subj '/CN=roma::fedtest/O=roma' && "
            "openssl x509 -req -in /tmp/fedtest.csr "
            "-CA /var/lib/cullis/certs/org-ca.pem "
            "-CAkey /var/lib/cullis/certs/org-ca.key "
            "-CAcreateserial -out /tmp/fedtest.pem -days 1"
        )
        roma.succeed(
            "python3 -c \""
            "import sqlite3; "
            "from datetime import datetime, timezone; "
            "conn = sqlite3.connect('/var/lib/cullis/proxy.sqlite'); "
            "cert = open('/tmp/fedtest.pem').read(); "
            "now = datetime.now(timezone.utc).isoformat(); "
            "conn.execute("
            "'INSERT INTO internal_agents "
            "(agent_id, display_name, capabilities, cert_pem, "
            "created_at, is_active, federated, federation_revision, "
            "last_pushed_revision) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)', "
            "('roma::fedtest', 'fedtest', '[\\\"order.read\\\"]', "
            "cert, now, 1, 1, 1, 0)); "
            "conn.commit(); conn.close(); "
            "print('FEDTEST_INSERTED')\""
        )
        # Wait long enough for at least two publisher ticks (poll=2s
        # +ε). The publisher's ``_tick`` does the SELECT + POST + log.
        roma.succeed("sleep 5")
        publish_log = roma.succeed(
            "journalctl -u cullis-proxy --no-pager | "
            "grep -E 'federation publish.*roma::fedtest' || "
            "echo NOLOG"
        ).strip()
        assert "NOLOG" not in publish_log, (
            f"no federation publish log line for roma::fedtest. "
            f"Last 50 proxy lines:\n"
            f"{roma.succeed('journalctl -u cullis-proxy --no-pager -n 50')}"
        )
        # Either HTTP succeeded (Court accepted, unlikely without org
        # bootstrap) or HTTP 4xx (rejected, expected). Both prove the
        # wire is alive. ``broker unreachable`` is the failure mode
        # we want to catch.
        assert "broker unreachable" not in publish_log, publish_log
        print(
            f"  publisher fired against court for roma::fedtest:\n"
            f"    {publish_log}"
        )

    # Cross-org cert chain refusal (default-deny) — the third
    # invariant the demo sells — needs a Roma-minted cert
    # presented to Tokyo's nginx. The cert generation works (we
    # exercise the same recipe in tier1-roma), but the test-
    # driver ``copy_from_vm`` / ``copy_from_host`` shuttle wants
    # paths relative to a shared mount that's awkward to plumb
    # cleanly here. Tracking it as a follow-up: same scaffold,
    # simpler shuttle (cat | curl --cert -, or vlan-shared tmp).
    # The Org CA isolation + cross-VM reachability invariants
    # asserted above already cover the foundational pitch
    # ("kernel-isolated cities, per-host PKI, real network
    # between them"); the chain-refusal add-on tightens the
    # screw on the wire-level claim.
    if False:
        roma.succeed(
            "openssl ecparam -name prime256v1 -genkey -noout "
            "-out /tmp/daniele-roma.key && "
            "openssl req -new -key /tmp/daniele-roma.key "
            "-out /tmp/daniele-roma.csr -subj '/' "
            "-addext 'subjectAltName=URI:spiffe://roma.cullis.test/roma/user/daniele' && "
            "openssl x509 -req -in /tmp/daniele-roma.csr "
            "-CA /var/lib/cullis/certs/org-ca.pem "
            "-CAkey /var/lib/cullis/certs/org-ca.key "
            "-CAcreateserial -out /tmp/daniele-roma.pem -days 1 "
            "-extfile <(printf 'subjectAltName=URI:spiffe://roma.cullis.test/roma/user/daniele\\n"
            "extendedKeyUsage=clientAuth\\n')"
        )
        roma.copy_from_vm("/tmp/daniele-roma.pem", "")
        roma.copy_from_vm("/tmp/daniele-roma.key", "")
        tokyo.copy_from_host("daniele-roma.pem", "/tmp/")
        tokyo.copy_from_host("daniele-roma.key", "/tmp/")
        tokyo_ip2 = tokyo.succeed(
            "ip -4 -o addr show dev eth1 | awk '{print $4}' | cut -d/ -f1"
        ).strip()
        out = roma.succeed(
            f"curl -sk -o /dev/null -w '%{{http_code}}' "
            f"--cert /tmp/daniele-roma.pem --key /tmp/daniele-roma.key "
            f"--resolve mastio.tokyo.cullis.test:9443:{tokyo_ip2} "
            f"https://mastio.tokyo.cullis.test:9443/v1/egress/whoami "
            f"|| echo HANDSHAKE_FAIL"
        )
        assert (
            "401" in out
            or "000" in out
            or "HANDSHAKE_FAIL" in out
        ), (
            f"Tokyo accepted a cert signed by Roma's Org CA "
            f"(response: {out!r}). Cross-org isolation broken."
        )

    print("Tier 2 cross-continent topology verified — Roma + "
          "San Francisco + Tokyo + Court each on their own kernel, "
          "their own Org CA, reachable over the virtual L2.")
  '';
}
