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
  options.cullis.mastio = with lib; {
    enable = mkEnableOption "Cullis Mastio (broker + proxy + nginx)";

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
  };

  config = lib.mkIf config.cullis.mastio.enable (
    let
      cfg = config.cullis.mastio;
      # Build the Python environment offline so the VM boots without
      # outbound network: every wheel comes from the Nix store. The
      # actual ``cullis_sdk`` + ``cullis_connector`` source lives in
      # ``cfg.cullisSrc`` and is added via PYTHONPATH at runtime —
      # cleaner than re-rebuilding wheels every test invocation.
      pythonEnv = pkgs.python311.withPackages (ps: with ps; [
        fastapi
        uvicorn
        starlette
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
      ]);
      stateDir = "/var/lib/cullis";
      certsDir = "${stateDir}/certs";
      pyEnvBin = "${pythonEnv}/bin/python";
    in
    {
      networking.hostName = "mastio-${cfg.orgId}";
      networking.firewall.allowedTCPPorts = [ cfg.nginxPort ];

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

      users.users.cullis = {
        isSystemUser = true;
        group = "cullis";
        home = stateDir;
        createHome = true;
      };
      users.groups.cullis = { };

      systemd.tmpfiles.rules = [
        "d ${stateDir} 0750 cullis cullis -"
        "d ${certsDir} 0750 cullis cullis -"
      ];

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
          chmod 600 ${certsDir}/*.key
        '';
      };

      systemd.services.cullis-broker = {
        description = "Cullis Mastio broker (FastAPI)";
        wantedBy = [ "multi-user.target" ];
        after = [ "cullis-pki-bootstrap.service" "network.target" ];
        requires = [ "cullis-pki-bootstrap.service" ];
        environment = {
          PYTHONPATH = toString cfg.cullisSrc;
          CULLIS_ORG_ID = cfg.orgId;
          CULLIS_TRUST_DOMAIN = cfg.trustDomain;
          CULLIS_ADMIN_SECRET = cfg.adminSecret;
          DATABASE_URL = "sqlite+aiosqlite:///${stateDir}/broker.sqlite";
          KMS_BACKEND = "local";
          OTEL_ENABLED = "false";
        };
        serviceConfig = {
          Type = "simple";
          User = "cullis";
          Group = "cullis";
          WorkingDirectory = cfg.cullisSrc;
          ExecStart =
            "${pyEnvBin} -m uvicorn app.main:app "
            + "--host 127.0.0.1 --port ${toString cfg.brokerPort}";
          Restart = "on-failure";
          RestartSec = "2s";
        };
      };

      systemd.services.cullis-proxy = {
        description = "Cullis Mastio MCP proxy";
        wantedBy = [ "multi-user.target" ];
        after = [ "cullis-broker.service" ];
        requires = [ "cullis-broker.service" ];
        environment = {
          PYTHONPATH = toString cfg.cullisSrc;
          MCP_PROXY_ORG_ID = cfg.orgId;
          PROXY_TRUST_DOMAIN = cfg.trustDomain;
          MCP_PROXY_ADMIN_SECRET = cfg.adminSecret;
          MCP_PROXY_DATABASE_URL = "sqlite+aiosqlite:///${stateDir}/proxy.sqlite";
          MCP_PROXY_BROKER_URL = "http://127.0.0.1:${toString cfg.brokerPort}";
        };
        serviceConfig = {
          Type = "simple";
          User = "cullis";
          Group = "cullis";
          WorkingDirectory = cfg.cullisSrc;
          ExecStart =
            "${pyEnvBin} -m uvicorn mcp_proxy.main:app "
            + "--host 127.0.0.1 --port ${toString cfg.proxyPort}";
          Restart = "on-failure";
          RestartSec = "2s";
        };
      };

      services.nginx = {
        enable = true;
        recommendedTlsSettings = true;
        recommendedProxySettings = true;
        virtualHosts."mastio.${cfg.trustDomain}" = {
          listen = [
            { addr = "0.0.0.0"; port = cfg.nginxPort; ssl = true; }
          ];
          sslCertificate = "${certsDir}/server.pem";
          sslCertificateKey = "${certsDir}/server.key";
          # mTLS gate — same regex as ``nginx/mastio/mastio.conf`` in
          # the production config (PR #445 extended this to llm/chat
          # for the typed-principal flow).
          extraConfig = ''
            ssl_client_certificate ${certsDir}/org-ca.pem;
            ssl_verify_client      optional;
          '';
          locations."~ ^/v1/(egress|agents|audit|llm|chat)(/.*)?$" = {
            proxyPass = "http://127.0.0.1:${toString cfg.proxyPort}";
            extraConfig = ''
              if ($ssl_client_verify != SUCCESS) { return 401; }
              proxy_set_header X-SSL-Client-Cert   $ssl_client_escaped_cert;
              proxy_set_header X-SSL-Client-Verify $ssl_client_verify;
            '';
          };
          locations."~ ^/v1/(.*)$" = {
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
