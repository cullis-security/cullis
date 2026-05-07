# Reusable NixOS module that turns a host into a Cullis Mastio:
# broker (FastAPI app) + proxy (mcp_proxy) + nginx TLS terminator.
#
# Caller passes:
#   * ``cullisSrc``  — path to the monorepo root
#   * ``orgId``      — short org identifier (``roma``, ``sf``, ``tokyo``)
#   * ``trustDomain``— SPIFFE trust domain (``roma.cullis.test``)
#   * ``displayName``— human-readable label (``Roma Mastio``)
#
# The module installs a Python venv at /var/lib/cullis/venv at build
# time (cullis_sdk + cullis_connector + the broker package, all from
# the source tree — same pattern PR #445 added to the Docker image),
# then ships systemd units that run uvicorn directly. No Docker, no
# containers — every Mastio is a real NixOS host with its own systemd
# slice, journalctl history, and on-disk PKI.
{ config, pkgs, lib, ... }:

{
  # Mock LLM + Mock MCP postgres servers, gated behind
  # ``cullis.mastio.enableMockServices`` (default off). Imported
  # unconditionally so callers get the option set even when they
  # leave it disabled — the actual systemd units only land when
  # ``cullis.mockServices.enable`` flips true via the wiring at
  # the bottom of ``config = …``.
  imports = [ ./mock-services.nix ];

  options.cullis.mastio = with lib; {
    enable = mkEnableOption "Cullis Mastio (broker + proxy + nginx)";

    enableBroker = mkOption {
      type = types.bool;
      default = true;
      description = ''
        Whether to start the FastAPI broker (``app/main.py``) in
        addition to the proxy. Default on — the missing-from-nixpkgs
        ``a2a-sdk`` (and its ``culsans`` / ``aiologic`` transitive)
        ship as small derivations in ``lib/python-deps.nix`` next
        to this module. Flip off only when sharpening a test that
        doesn't need the broker.
      '';
    };

    enableMockServices = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Stand up a tiny mock LLM (port 11434, OpenAI-compat) and a
        mock MCP postgres backend (port 11435) on loopback inside
        the VM so the testScript can drive a daniele@user → tool
        use → MCP query flow without an Anthropic API key or a
        real Postgres. Off by default — Tier 1 baseline doesn't
        need it; the demo path flips it on.
      '';
    };

    cullisSrc = mkOption {
      type = types.path;
      description = "Path to the cullis monorepo source tree.";
    };

    orgId = mkOption {
      type = types.str;
      example = "roma";
      description = ''
        Short org identifier. Used as the ``CULLIS_ORG_ID`` env var
        and as the canonical agent_id prefix (``{orgId}::{name}``).
      '';
    };

    trustDomain = mkOption {
      type = types.str;
      example = "roma.cullis.test";
      description = ''
        SPIFFE trust domain. Embedded in every cert this Mastio
        signs and announced to peers via the federation publisher.
      '';
    };

    displayName = mkOption {
      type = types.str;
      default = "";
      description = "Human-readable label shown in the dashboard.";
    };

    brokerPort = mkOption {
      type = types.port;
      default = 8000;
    };

    proxyPort = mkOption {
      type = types.port;
      default = 9100;
    };

    nginxPort = mkOption {
      type = types.port;
      default = 9443;
      description = "TLS port the SDK / Frontdesk talks to.";
    };

    adminSecret = mkOption {
      type = types.str;
      default = "test-admin-secret";
      description = ''
        Admin secret for ``X-Admin-Secret`` headers. Test-only; a
        real deployment threads this through a secret manager.
      '';
    };

    brokerUrl = mkOption {
      type = types.str;
      default = "";
      description = ''
        Override the proxy's ``MCP_PROXY_BROKER_URL``. When empty
        (default), the proxy points at the loopback broker
        (``http://127.0.0.1:<brokerPort>``), which is the Tier 1
        single-VM shape. Tier 2 cities point at the Court VM via
        this knob so the federation publisher pushes their agents
        to the central registry. The proxy uses the same URL for
        local agent auth and federation publish (current shape;
        a future refactor may split them).
      '';
    };

    nginxAllowExternal = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Open the broker port on 0.0.0.0 instead of 127.0.0.1 and
        add it to ``firewall.allowedTCPPorts``. The Tier 2 Court
        VM flips this on so peers can reach
        ``/v1/federation/publish-agent``.
      '';
    };
  };

  config = lib.mkIf config.cullis.mastio.enable (
    let
      cfg = config.cullis.mastio;
      # ``cfg.cullisSrc`` is the host path the caller passed in
      # (something like ``/home/dev/projects/agent-trust``). The
      # systemd units run inside the test VM where that path does
      # not exist. We copy the tree into the Nix store so the path
      # resolves on both sides; the filter strips directories that
      # are dev-only (``.venv``, ``__pycache__``), git/CI noise
      # (``.git``, ``.github``), and runtime state from sibling
      # tooling that may have rooted-down permissions on the dev
      # box (``connector_data``, ``state``) — all of which would
      # bloat the store closure or break the import outright.
      cullisSrcStore = lib.cleanSourceWith {
        name = "cullis-src";
        src = cfg.cullisSrc;
        filter = path: type:
          let baseName = baseNameOf (toString path); in
          !(builtins.elem baseName [
            ".git"
            ".github"
            ".venv"
            "__pycache__"
            "node_modules"
            "connector_data"
            "state"
            "dist"
            "result"
            # Dev-box .env can carry host-specific values (BROKER_PUBLIC_URL
            # pointing at the dev IP) that pydantic-settings picks up over
            # the explicit env we set per VM, breaking DPoP htu validation.
            ".env"
            ".env.local"
          ]);
      };
      # Custom derivations for PyPI packages not yet in nixpkgs.
      # Currently: ``a2a-sdk`` (used by ``app/a2a/agent_card.py``)
      # plus its ``culsans`` + ``aiologic`` transitive deps.
      cullisPyDeps = import ./python-deps.nix { inherit pkgs; };
      # Build the Python environment offline so the VM boots without
      # outbound network: every wheel comes from the Nix store. The
      # actual ``cullis_sdk`` + ``cullis_connector`` source lives in
      # ``cfg.cullisSrc`` and is added via PYTHONPATH at runtime —
      # cleaner than re-rebuilding wheels every test invocation.
      pythonEnv = pkgs.python311.withPackages (ps: with ps; [
        fastapi
        uvicorn
        starlette
        sse-starlette
        sqlalchemy
        aiosqlite
        asyncpg
        httpx
        cryptography
        pyjwt
        pydantic
        pydantic-settings
        python-multipart
        jinja2
        bcrypt
        redis
        alembic
        websockets
        # Proxy ``mcp_proxy/requirements-proxy.txt`` extras the broker
        # also pulls in. ``a2a-sdk`` is the only requirement missing
        # from nixpkgs and lives only in ``app/a2a/agent_card.py`` —
        # it's why ``cullis-broker`` is gated behind ``enableBroker``
        # at module-eval time.
        pyyaml
        authlib
        python-dotenv
        litellm
        anthropic
        openai
        joserfc
        # OpenTelemetry — ``app/telemetry.py`` imports the SDK + the
        # OTLP gRPC exporter + a handful of instrumentations. The
        # broker's lifespan calls ``init_telemetry`` even when
        # OTEL_ENABLED=false (it gates the exporter, not the
        # imports), so all of these need to be in the closure.
        opentelemetry-api
        opentelemetry-sdk
        opentelemetry-exporter-otlp-proto-grpc
        opentelemetry-exporter-prometheus
        opentelemetry-instrumentation-fastapi
        opentelemetry-instrumentation-sqlalchemy
        opentelemetry-instrumentation-redis
        opentelemetry-instrumentation-httpx
        opentelemetry-instrumentation-asgi
      ] ++ [
        # Custom derivations from ``python-deps.nix`` — pulled in
        # only when the broker is enabled; the proxy doesn't import
        # ``a2a`` at all. (Keeping them in the env unconditionally
        # is fine — withPackages closes over the union, ~3 MB.)
        cullisPyDeps.a2a-sdk
      ]);
      stateDir = "/var/lib/cullis";
      certsDir = "${stateDir}/certs";
      pyEnvBin = "${pythonEnv}/bin/python";
    in
    {
      # Don't override ``networking.hostName`` here — the test
      # framework derives the Python symbol exposed in the testScript
      # from the node attribute name (``roma``), and forcing
      # ``hostName`` to anything else (``mastio-roma`` etc.) leaks
      # into the exposed symbol and ``roma.succeed(...)`` in the
      # testScript hits ``NameError``. The nginx vhost listens on
      # ``mastio.${trustDomain}`` regardless — that's the FQDN
      # callers actually hit.
      networking.firewall.allowedTCPPorts =
        [ cfg.nginxPort ]
        ++ lib.optional cfg.nginxAllowExternal cfg.brokerPort;

      # Forward the mock-services toggle. ``cullis.mockServices``
      # is defined in ``mock-services.nix`` (imported above);
      # passing ``pythonEnv`` here lets the mock services reuse
      # the same closure (fastapi + uvicorn + everything else)
      # the broker / proxy already pulled in — no doubling.
      cullis.mockServices = {
        enable = cfg.enableMockServices;
        inherit pythonEnv;
      };

      # Make the Cullis-flavoured Python interpreter (with fastapi /
      # uvicorn / cryptography / cullis_sdk deps) available as
      # ``python3`` system-wide, plus the CLI tools the testScript
      # leans on (openssl for the on-VM PKI fixture, sqlite3 for
      # poking the proxy DB without booting the dashboard).
      environment.systemPackages = [
        pythonEnv
        pkgs.openssl
        pkgs.curl
        pkgs.sqlite
      ];

      # Expose the Cullis source tree on ``PYTHONPATH`` for any
      # interactive ``python3`` the testScript launches (the
      # systemd units already get this via their ``environment``
      # block, but ``machine.succeed("python3 -c ...")`` runs in a
      # fresh login shell that doesn't inherit those).
      environment.sessionVariables.PYTHONPATH = toString cullisSrcStore;

      users.users.cullis = {
        isSystemUser = true;
        group = "cullis";
        home = stateDir;
        createHome = true;
      };
      users.groups.cullis = { };

      systemd.tmpfiles.rules = [
        "d ${stateDir} 0750 cullis cullis -"
        # nginx runs as its own user but needs to read ``server.pem``
        # + ``server.key``, so the cert dir is group-readable. Add
        # the nginx system user to the ``cullis`` group below to
        # complete the wiring.
        "d ${certsDir} 0750 cullis cullis -"
      ];

      # Let nginx read the on-disk PKI under ``${certsDir}``. Mode
      # ``0640`` on the keys + this group membership keeps the
      # surface tight (no world-readable private key) while the
      # ``nginx -t`` syntax check still succeeds.
      users.users.nginx.extraGroups = [ "cullis" ];

      # Generate per-host PKI on first boot. Each Mastio gets its own
      # Org CA — Roma's CA bytes never appear on San Francisco's
      # disk, which is exactly the cross-org isolation we want to
      # demonstrate.
      systemd.services.cullis-pki-bootstrap = {
        description = "Generate Cullis Org CA + nginx server cert (first boot)";
        wantedBy = [ "multi-user.target" ];
        before = [ "cullis-broker.service" "cullis-proxy.service" "nginx.service" ];
        serviceConfig = {
          Type = "oneshot";
          User = "cullis";
          Group = "cullis";
          RemainAfterExit = true;
        };
        script = ''
          set -eu
          if [ -f ${certsDir}/org-ca.pem ]; then
            echo "PKI already provisioned, skipping"
            exit 0
          fi
          ${pkgs.openssl}/bin/openssl ecparam -name prime256v1 -genkey -noout \
            -out ${certsDir}/org-ca.key
          ${pkgs.openssl}/bin/openssl req -x509 -new -key ${certsDir}/org-ca.key \
            -out ${certsDir}/org-ca.pem -days 3650 \
            -subj "/CN=${cfg.orgId} CA/O=${cfg.orgId}"
          ${pkgs.openssl}/bin/openssl ecparam -name prime256v1 -genkey -noout \
            -out ${certsDir}/server.key
          ${pkgs.openssl}/bin/openssl req -new -key ${certsDir}/server.key \
            -out ${certsDir}/server.csr \
            -subj "/CN=mastio.${cfg.trustDomain}/O=${cfg.orgId}"
          ${pkgs.openssl}/bin/openssl x509 -req \
            -in ${certsDir}/server.csr \
            -CA ${certsDir}/org-ca.pem -CAkey ${certsDir}/org-ca.key \
            -CAcreateserial -out ${certsDir}/server.pem -days 825 \
            -extfile <(printf "subjectAltName=DNS:mastio.${cfg.trustDomain},DNS:localhost,IP:127.0.0.1")
          # Keys group-readable (cullis group includes nginx — see
          # ``users.users.nginx.extraGroups`` below). Certs stay
          # world-readable, they're public material.
          chmod 640 ${certsDir}/*.key
          chmod 644 ${certsDir}/*.pem
        '';
      };

      systemd.services.cullis-broker = lib.mkIf cfg.enableBroker {
        description = "Cullis Mastio broker (FastAPI)";
        wantedBy = [ "multi-user.target" ];
        after = [ "cullis-pki-bootstrap.service" "network.target" ];
        requires = [ "cullis-pki-bootstrap.service" ];
        environment = {
          PYTHONPATH = toString cullisSrcStore;
          # The broker reads via pydantic-settings without a prefix —
          # ``ADMIN_SECRET``, not ``CULLIS_ADMIN_SECRET``. Setting
          # both forms keeps any module that wants the prefix happy.
          CULLIS_ORG_ID = cfg.orgId;
          ORG_ID = cfg.orgId;
          CULLIS_TRUST_DOMAIN = cfg.trustDomain;
          TRUST_DOMAIN = cfg.trustDomain;
          CULLIS_ADMIN_SECRET = cfg.adminSecret;
          ADMIN_SECRET = cfg.adminSecret;
          DATABASE_URL = "sqlite+aiosqlite:///${stateDir}/broker.sqlite";
          KMS_BACKEND = "local";
          OTEL_ENABLED = "false";
          # ``app/kms/admin_secret.py`` defaults to ``certs/`` relative
          # to the broker's CWD, which here is the read-only Nix store.
          # Redirect to the writable state dir so first-boot mkdir of
          # ``.admin_bootstrap_token`` succeeds. Lands via #468.
          CULLIS_LOCAL_KMS_DIR = certsDir;
          # Court advertises itself as ``http://court:8000`` so cities
          # signing DPoP proofs with that exact URL pass htu validation.
          # When the broker is loopback-only (cities) the override stops
          # any inherited dev-box ``BROKER_PUBLIC_URL`` from the source
          # tree's ``.env`` (already filtered, but env override is the
          # authoritative source). pydantic-settings: env > .env > defaults.
          # Issue #462 tracks turning this into an allowlist for multi-
          # ingress Court setups.
          BROKER_PUBLIC_URL =
            if cfg.nginxAllowExternal
            then "http://court:${toString cfg.brokerPort}"
            else "http://127.0.0.1:${toString cfg.brokerPort}";
          # Sandbox/demo PDP fall-through (issue #461 / PR #463). Cities
          # are registered without a webhook_url; the dispatcher would
          # otherwise default-deny every cross-org call. ``allow`` lets
          # the test fixture exercise the path with audit rows tagged
          # ``policy_default_allow`` so reviewers can grep for the
          # bypass after the fact. Production refuses this value (see
          # ``app/config.py::validate_config``).
          POLICY_DEFAULT_DECISION = "allow";
        };
        serviceConfig = {
          Type = "simple";
          User = "cullis";
          Group = "cullis";
          WorkingDirectory = "${cullisSrcStore}";
          ExecStart =
            "${pyEnvBin} -m uvicorn app.main:app "
            + "--host ${if cfg.nginxAllowExternal then "0.0.0.0" else "127.0.0.1"} "
            + "--port ${toString cfg.brokerPort}";
          Restart = "on-failure";
          RestartSec = "2s";
        };
      };

      systemd.services.cullis-proxy = {
        description = "Cullis Mastio MCP proxy";
        wantedBy = [ "multi-user.target" ];
        # Order behind the broker only when it's actually enabled —
        # ``cullis-broker.service`` is conditional on ``enableBroker``
        # (``a2a-sdk`` not in nixpkgs yet). The PKI oneshot is the only
        # hard prerequisite the proxy actually needs.
        after = [ "cullis-pki-bootstrap.service" ]
                ++ lib.optional cfg.enableBroker "cullis-broker.service";
        requires = [ "cullis-pki-bootstrap.service" ]
                   ++ lib.optional cfg.enableBroker "cullis-broker.service";
        environment = {
          PYTHONPATH = toString cullisSrcStore;
          MCP_PROXY_ORG_ID = cfg.orgId;
          PROXY_TRUST_DOMAIN = cfg.trustDomain;
          MCP_PROXY_ADMIN_SECRET = cfg.adminSecret;
          MCP_PROXY_DATABASE_URL = "sqlite+aiosqlite:///${stateDir}/proxy.sqlite";
          MCP_PROXY_BROKER_URL =
            if cfg.brokerUrl != ""
            then cfg.brokerUrl
            else "http://127.0.0.1:${toString cfg.brokerPort}";
          # Federation publisher: pushes ``internal_agents`` rows
          # marked ``federated=1`` to the broker we just pointed at
          # (``/v1/federation/publish-agent``) every tick.
          PROXY_FEDERATION_SYNC = "true";
          # Default poll is 30s — leaves the nixosTest sleeping past
          # every CI budget. 2s keeps the test responsive without
          # observing a tick mid-startup.
          MCP_PROXY_FEDERATION_POLL_INTERVAL_S = "2";
          # ``standalone=True`` (default) forcibly clears
          # ``broker_url`` at app startup so the publisher gate
          # ``if broker_url and mastio_loaded`` never fires. Cities
          # that point at an external Court need standalone=false.
          # Court itself stays standalone (it IS the federation
          # hub), inferred from ``cfg.brokerUrl == ""``.
          MCP_PROXY_STANDALONE =
            if cfg.brokerUrl != "" then "false" else "true";
          # DPoP htu validation needs the public URL the SDK speaks to
          # (nginx mTLS endpoint), not the loopback uvicorn binds. Without
          # this set, ``_build_htu`` falls back to ``request.url`` which
          # in our setup is ``http://127.0.0.1:9100`` and never matches
          # the SDK's ``https://mastio.<td>:9443/...`` signed proof.
          # See feedback_proxy_env_public_url_vm.md +
          # feedback_proxy_headers_insufficient.md — auto-detect via
          # ``--proxy-headers`` alone is not enough.
          MCP_PROXY_PROXY_PUBLIC_URL =
            "https://mastio.${cfg.trustDomain}:${toString cfg.nginxPort}";
        } // lib.optionalAttrs (cfg.brokerUrl != "") {
          # ADR-012 — non-standalone proxies default to forwarding
          # ``/v1/auth/token`` to the broker, which fails htu validation
          # in our cross-org topology (Court only sees the forwarded URL,
          # not the SDK's signed mastio.<td>:9443 URL). Cities should
          # issue tokens locally exactly like the standalone case;
          # Court keeps standalone=true and turns this on via the
          # auto-default in ``config.py``.
          MCP_PROXY_LOCAL_AUTH_ENABLED = "true";
        } // lib.optionalAttrs cfg.enableMockServices {
          # Point the AI gateway at the mock LLM. We use the
          # ``portkey`` backend wrapper because it honours
          # ``ai_gateway_url`` directly (the ``litellm_embedded``
          # branch baked-in routes upstream); the mock serves the
          # exact same OpenAI-compat endpoint, so the headers
          # Portkey adds are ignored harmlessly.
          MCP_PROXY_AI_GATEWAY_BACKEND = "portkey";
          MCP_PROXY_AI_GATEWAY_URL = "http://127.0.0.1:11434";
          # Portkey's ``provider_key_missing`` guard rejects empty
          # values, so feed it a sentinel — the mock never reads
          # the bearer.
          MCP_PROXY_ANTHROPIC_API_KEY = "mock-key-not-checked";
        };
        serviceConfig = {
          Type = "simple";
          User = "cullis";
          Group = "cullis";
          WorkingDirectory = "${cullisSrcStore}";
          ExecStart =
            "${pyEnvBin} -m uvicorn mcp_proxy.main:app "
            + "--host 127.0.0.1 --port ${toString cfg.proxyPort}";
          Restart = "on-failure";
          RestartSec = "2s";
        };
      };

      # nginx pre-start runs ``nginx -t`` which reads the on-disk
      # SSL cert; without explicit ordering it can land before
      # ``cullis-pki-bootstrap`` writes ``server.pem`` and fail with
      # ``no "ssl_certificate" is defined``. The ``before =`` hint on
      # the bootstrap unit is only ordering, not a hard dep — make
      # nginx actually require it.
      systemd.services.nginx = {
        after = [ "cullis-pki-bootstrap.service" ];
        requires = [ "cullis-pki-bootstrap.service" ];
      };

      services.nginx = {
        enable = true;
        recommendedTlsSettings = true;
        recommendedProxySettings = true;
        virtualHosts."mastio.${cfg.trustDomain}" = {
          listen = [
            { addr = "0.0.0.0"; port = cfg.nginxPort; ssl = true; }
          ];
          # NixOS only emits ``ssl_certificate`` directives when the
          # vhost has ``addSSL = true`` / ``forceSSL = true``, which
          # both presume an HTTP-side listener on port 80. We're
          # SSL-only on a custom port (9443) — declare the cert
          # paths via ``extraConfig`` directly to keep the listener
          # shape clean. Same applies to the mTLS gate (PR #445
          # production config extends the regex to ``llm|chat``).
          extraConfig = ''
            ssl_certificate         ${certsDir}/server.pem;
            ssl_certificate_key     ${certsDir}/server.key;
            ssl_client_certificate  ${certsDir}/org-ca.pem;
            ssl_verify_client       optional;
          '';
          # Regex locations are evaluated in nginx config order. NixOS
          # sorts ``locations`` alphabetically by attribute name, so a
          # later-alphabetic auth-specific block would be shadowed by
          # the ``^/v1/(.*)$`` catch-all. The ``priority`` attribute
          # forces explicit ordering: lowest priority emits first, so
          # the mTLS-gated paths (egress + auth challenge endpoints)
          # match before the catch-all wipes ``X-SSL-Client-Cert``.
          locations."~ ^/v1/(egress|agents|audit|llm|chat)(/.*)?$" = {
            priority = 100;
            proxyPass = "http://127.0.0.1:${toString cfg.proxyPort}";
            extraConfig = ''
              if ($ssl_client_verify != SUCCESS) { return 401; }
              proxy_set_header X-SSL-Client-Cert   $ssl_client_escaped_cert;
              proxy_set_header X-SSL-Client-Verify $ssl_client_verify;
            '';
          };
          # PR #445 user-principal flow: the SDK's
          # ``login_via_proxy_with_local_key`` posts to
          # ``/v1/auth/login-challenge`` and ``/v1/auth/sign-challenged-assertion``
          # carrying a client cert in the TLS handshake. The proxy
          # backend authenticates the principal off the
          # ``X-SSL-Client-Cert`` header — so unlike the catch-all
          # block (which strips the header to defeat spoofing) these
          # specific paths must forward the verified cert + verify
          # status downstream. This block mirrors the production
          # ``nginx/mastio/mastio.conf`` layout.
          locations."~ ^/v1/auth/(login-challenge|sign-challenged-assertion|sign-assertion)$" = {
            priority = 200;
            proxyPass = "http://127.0.0.1:${toString cfg.proxyPort}";
            extraConfig = ''
              if ($ssl_client_verify != SUCCESS) { return 401; }
              proxy_set_header X-SSL-Client-Cert   $ssl_client_escaped_cert;
              proxy_set_header X-SSL-Client-Verify $ssl_client_verify;
            '';
          };
          locations."~ ^/v1/(.*)$" = {
            priority = 1000;
            proxyPass = "http://127.0.0.1:${toString cfg.proxyPort}";
            extraConfig = ''
              proxy_set_header X-SSL-Client-Cert "";
            '';
          };
          locations."/" = {
            proxyPass = "http://127.0.0.1:${toString cfg.proxyPort}";
          };
        };
      };
    }
  );
}
