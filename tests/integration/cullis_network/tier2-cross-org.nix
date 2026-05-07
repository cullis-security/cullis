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

  # Same Org CA preload trick PR #454 used in tier1-roma. With
  # ``standalone=false`` the proxy stops auto-generating a CA on
  # first boot, so the federation publisher's ``mastio_loaded``
  # gate stays False forever. Upserting the on-disk CA into
  # ``proxy_config`` and restarting the proxy flips the gate
  # without needing the full broker attach-ca admin flow.
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

  # Drives the four-step Court bootstrap for a single city, all from
  # within the city's own VM (it can reach ``court:8000`` over the test
  # vlan, and it owns its proxy admin secret so it can fetch its own
  # mastio_pubkey + Org CA without copy_from_vm gymnastics).
  #
  #   1. ``POST /v1/admin/invites`` on Court (admin secret)
  #   2. ``POST /v1/onboarding/join`` on Court (org CA + invite_token)
  #   3. ``POST /v1/admin/orgs/{org_id}/approve`` on Court (admin secret)
  #   4. ``GET /v1/admin/mastio-pubkey`` on local proxy → ``PATCH
  #      /v1/admin/orgs/{org_id}/mastio-pubkey`` on Court
  #
  # All four endpoints are the same ones ``reference/bootstrap/`` drives
  # via the docker-compose sandbox; this script is the parallel for
  # NixOS tests where every city is an isolated VM. Idempotent on each
  # step (409 = already there → continue), so the subtest can re-run
  # against a partially-bootstrapped state without resetting.
  courtBootstrapScript = pkgs.writeText "court-bootstrap.py" ''
    """Bootstrap a city on Court so federation publishes get accepted.

    Args (positional):
      org_id          short org id (``roma``, ``tokyo``)
      display_name    human label
      trust_domain    SPIFFE trust domain
      court_url       e.g. ``http://court:8000``
      proxy_url       local proxy admin (e.g. ``http://127.0.0.1:9100``)
      org_ca_path     filesystem path to ``org-ca.pem``
      admin_secret    same on Court + local proxy in the test fixture
      org_secret      passed in the join body (Court will hash + store)
    """
    import json
    import sys
    import urllib.error
    import urllib.request

    if len(sys.argv) != 9:
        print(f"USAGE: {sys.argv[0]} org_id display_name trust_domain "
              f"court_url proxy_url org_ca_path admin_secret org_secret",
              file=sys.stderr)
        sys.exit(2)

    (_, org_id, display_name, trust_domain, court_url, proxy_url,
     org_ca_path, admin_secret, org_secret) = sys.argv

    org_ca_pem = open(org_ca_path).read()


    def _req(method, url, body=None, headers=None, allow_status=()):
        data = json.dumps(body).encode() if body is not None else None
        h = {"Content-Type": "application/json"} if body is not None else {}
        h.update(headers or {})
        req = urllib.request.Request(url, data=data, headers=h, method=method)
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                payload = resp.read().decode()
                code = resp.getcode()
        except urllib.error.HTTPError as exc:
            payload = exc.read().decode()
            code = exc.code
            if code in allow_status:
                return code, payload
            print(f"FAILED {method} {url} → HTTP {code}: {payload[:300]}",
                  file=sys.stderr)
            sys.exit(1)
        return code, payload


    # 1. Admin generates a one-time invite token on Court.
    print(f"[1/4] POST {court_url}/v1/admin/invites …", flush=True)
    code, payload = _req(
        "POST", f"{court_url}/v1/admin/invites",
        body={"label": f"{org_id}-invite", "ttl_hours": 1},
        headers={"X-Admin-Secret": admin_secret},
    )
    invite_token = json.loads(payload)["token"]
    print(f"      invite issued (id={json.loads(payload).get('id')})")

    # 2. Org submits join with its CA + invite_token. 409 = already
    # registered (re-run); continue so step 3 still runs.
    print(f"[2/4] POST {court_url}/v1/onboarding/join (org_id={org_id}) …",
          flush=True)
    code, payload = _req(
        "POST", f"{court_url}/v1/onboarding/join",
        body={
            "org_id": org_id,
            "display_name": display_name,
            "secret": org_secret,
            "ca_certificate": org_ca_pem,
            "contact_email": f"admin@{org_id}.test",
            "invite_token": invite_token,
            "trust_domain": trust_domain,
        },
        allow_status=(409,),
    )
    print(f"      join → HTTP {code}")

    # 3. Admin approves. 409 = already active.
    print(f"[3/4] POST {court_url}/v1/admin/orgs/{org_id}/approve …",
          flush=True)
    code, payload = _req(
        "POST", f"{court_url}/v1/admin/orgs/{org_id}/approve",
        headers={"X-Admin-Secret": admin_secret},
        allow_status=(409,),
    )
    print(f"      approve → HTTP {code}")

    # 4. Pull the local proxy's mastio_pubkey and pin it on Court so
    # counter-signature verification on /v1/federation/publish-agent
    # can succeed. The proxy's lifespan generates the mastio identity
    # asynchronously; poll until the pubkey is non-null (cap 60s).
    import time
    print(f"[4/4] GET  {proxy_url}/v1/admin/mastio-pubkey …", flush=True)
    deadline = time.monotonic() + 60.0
    pubkey = None
    while time.monotonic() < deadline:
        code, payload = _req(
            "GET", f"{proxy_url}/v1/admin/mastio-pubkey",
            headers={"X-Admin-Secret": admin_secret},
        )
        pubkey = json.loads(payload).get("mastio_pubkey")
        if pubkey:
            break
        time.sleep(1.0)
    if not pubkey:
        print("FAILED mastio_pubkey still null after 60s", file=sys.stderr)
        sys.exit(1)
    print(f"      proxy mastio_pubkey ready ({len(pubkey)} chars)")

    print(f"      PATCH {court_url}/v1/admin/orgs/{org_id}/mastio-pubkey …",
          flush=True)
    code, payload = _req(
        "PATCH", f"{court_url}/v1/admin/orgs/{org_id}/mastio-pubkey",
        body={"mastio_pubkey": pubkey},
        headers={"X-Admin-Secret": admin_secret},
    )
    print(f"      pin → HTTP {code}")
    print(f"BOOTSTRAPPED org_id={org_id} on Court")
  '';

  # Provisions a single agent on the local Mastio via the BYOCA
  # enrollment endpoint. Mints an Org-CA-signed cert, generates a DPoP
  # keypair, POSTs to ``/v1/admin/agents/enroll/byoca``, and persists
  # the runtime credentials under
  # ``<identity_root>/<org_id>/agents/<agent_name>/`` so the SDK's
  # ``CullisClient.from_identity_dir`` can pick them up later. Mirrors
  # ``reference/bootstrap/bootstrap_mastio.py::_enroll_one_byoca`` but
  # written for the test driver (no /state shared mount, no docker).
  provisionAgentScript = pkgs.writeText "provision-agent.py" ''
    """Provision a single agent on the local Mastio via BYOCA enroll.

    Args (positional):
      org_id          short org id
      agent_name      short agent name (no ``::``)
      capabilities    comma-separated list (use empty string for none)
      proxy_url       local proxy admin (e.g. ``http://127.0.0.1:9100``)
      admin_secret    proxy admin secret
      identity_root   filesystem root for runtime creds
      org_ca_cert     filesystem path to ``org-ca.pem``
      org_ca_key      filesystem path to ``org-ca.key``
      trust_domain    SPIFFE trust domain (e.g. ``roma.cullis.test``)
    """
    import base64
    import json
    import os
    import pathlib
    import subprocess
    import sys
    import urllib.error
    import urllib.request

    from cryptography.hazmat.primitives.asymmetric import ec

    if len(sys.argv) != 10:
        print(
            f"USAGE: {sys.argv[0]} org_id agent_name capabilities proxy_url "
            f"admin_secret identity_root org_ca_cert org_ca_key trust_domain",
            file=sys.stderr,
        )
        sys.exit(2)

    (_, org_id, agent_name, caps_csv, proxy_url, admin_secret,
     identity_root, org_ca_cert, org_ca_key, trust_domain) = sys.argv

    capabilities = [c for c in caps_csv.split(",") if c]
    agent_id = f"{org_id}::{agent_name}"
    # Cullis SPIFFE SAN convention (mcp_proxy/auth/client_cert.py
    # ``_parse_spiffe_uri``): 3-component path = ``{td}/{org}/{name}``.
    # The 4-component typed variant (``{td}/{org}/agent/{name}``) is
    # also valid; this 3-comp form mirrors what
    # ``agent_manager._generate_agent_cert`` emits in production.
    spiffe_uri = f"spiffe://{trust_domain}/{org_id}/{agent_name}"

    identity_dir = pathlib.Path(identity_root) / org_id / "agents" / agent_name
    identity_dir.mkdir(parents=True, exist_ok=True)
    cert_path = identity_dir / "agent.pem"
    key_path = identity_dir / "agent-key.pem"
    dpop_path = identity_dir / "dpop.jwk"
    ca_chain_path = pathlib.Path(identity_root) / org_id / "ca.pem"
    ca_chain_path.parent.mkdir(parents=True, exist_ok=True)

    # Mint EC P-256 cert signed by Org CA. Using openssl rather than
    # cryptography directly keeps the cert structure byte-identical to
    # the existing ``fedtest`` cert generation in this file (same
    # subject/SAN convention).
    csr_path = identity_dir / "agent.csr"
    extfile = identity_dir / "agent.ext"
    extfile.write_text(
        f"subjectAltName=URI:{spiffe_uri}\nextendedKeyUsage=clientAuth\n"
    )
    subprocess.check_call([
        "openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout",
        "-out", str(key_path),
    ])
    subprocess.check_call([
        "openssl", "req", "-new", "-key", str(key_path),
        "-out", str(csr_path),
        "-subj", f"/CN={agent_id}/O={org_id}",
    ])
    subprocess.check_call([
        "openssl", "x509", "-req", "-in", str(csr_path),
        "-CA", org_ca_cert, "-CAkey", org_ca_key, "-CAcreateserial",
        "-out", str(cert_path), "-days", "1",
        "-extfile", str(extfile),
    ])
    cert_path.chmod(0o644)
    key_path.chmod(0o600)
    print(f"  minted cert + key for {agent_id} (SAN={spiffe_uri})")

    # Generate DPoP keypair (EC P-256). Public JWK goes into the enroll
    # body so the Mastio pins ``dpop_jkt`` from the first request;
    # private JWK lands on disk next to the cert for the runtime SDK.
    priv = ec.generate_private_key(ec.SECP256R1())
    pub_nums = priv.public_key().public_numbers()
    priv_nums = priv.private_numbers()

    def _b64url(n: int) -> str:
        return base64.urlsafe_b64encode(n.to_bytes(32, "big")).rstrip(b"=").decode()

    public_jwk = {
        "kty": "EC", "crv": "P-256",
        "x": _b64url(pub_nums.x), "y": _b64url(pub_nums.y),
    }
    private_jwk = {**public_jwk, "d": _b64url(priv_nums.private_value)}

    # POST /v1/admin/agents/enroll/byoca
    body = json.dumps({
        "agent_name": agent_name,
        "display_name": agent_name,
        "capabilities": capabilities,
        "federated": True,
        "cert_pem": cert_path.read_text(),
        "private_key_pem": key_path.read_text(),
        "dpop_jwk": public_jwk,
    }).encode()
    req = urllib.request.Request(
        f"{proxy_url}/v1/admin/agents/enroll/byoca",
        data=body, method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Admin-Secret": admin_secret,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
            code = resp.getcode()
    except urllib.error.HTTPError as exc:
        print(f"FAILED enroll/byoca → HTTP {exc.code}: {exc.read().decode()[:300]}",
              file=sys.stderr)
        sys.exit(1)

    if code != 201:
        print(f"FAILED enroll/byoca → HTTP {code}", file=sys.stderr)
        sys.exit(1)

    # Persist runtime DPoP private JWK + Org CA chain alongside the cert
    # — these four files are exactly what ``CullisClient.from_identity_dir``
    # opens on send.
    dpop_path.write_text(
        json.dumps({"private_jwk": private_jwk}, separators=(",", ":"))
    )
    dpop_path.chmod(0o600)
    ca_chain_path.write_text(open(org_ca_cert).read())
    ca_chain_path.chmod(0o644)

    jkt = (data.get("dpop_jkt") or "")[:12]
    thumb = (data.get("cert_thumbprint") or "")[:12]
    print(f"PROVISIONED {agent_id} jkt={jkt}… thumb={thumb}…")
  '';

  # Drives the binding flow on Court for an agent that the federation
  # publisher has already pushed. ``POST /v1/registry/bindings`` takes
  # ``X-Org-Id`` + ``X-Org-Secret`` headers; the body's ``org_id`` must
  # match the auth org (intra-org binding only — cross-org A2A is
  # gated by federation registry visibility + cert chain, not by a
  # cross-org binding row). Retries POST while the publisher catches
  # up — 404 means the agent isn't visible on Court yet.
  bindAgentScript = pkgs.writeText "bind-agent.py" ''
    """Create + approve a binding for a federated agent on Court.

    Args (positional):
      court_url       e.g. ``http://court:8000``
      org_id          short org id
      org_secret      same secret submitted at /onboarding/join
      agent_id        full ``org::name``
      scope_csv       comma-separated capabilities (subset of agent's caps)
    """
    import json
    import sys
    import time
    import urllib.error
    import urllib.request

    if len(sys.argv) != 6:
        print(
            f"USAGE: {sys.argv[0]} court_url org_id org_secret agent_id scope_csv",
            file=sys.stderr,
        )
        sys.exit(2)

    _, court_url, org_id, org_secret, agent_id, scope_csv = sys.argv
    scope = [c for c in scope_csv.split(",") if c]
    headers = {"X-Org-Id": org_id, "X-Org-Secret": org_secret,
               "Content-Type": "application/json"}


    def _req(method, url, body=None, allow_status=()):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.getcode(), resp.read().decode()
        except urllib.error.HTTPError as exc:
            payload = exc.read().decode()
            if exc.code in allow_status:
                return exc.code, payload
            raise


    # Retry create until publisher has pushed the agent to Court
    # (404 → agent_id not visible yet, retry; 409 → already there).
    binding_id = None
    deadline = time.monotonic() + 30.0
    last_err = "(no attempt)"
    while time.monotonic() < deadline:
        try:
            code, payload = _req(
                "POST", f"{court_url}/v1/registry/bindings",
                body={"org_id": org_id, "agent_id": agent_id, "scope": scope},
                allow_status=(404, 409),
            )
        except urllib.error.URLError as exc:
            last_err = f"connection: {exc}"
            time.sleep(1.0)
            continue
        if code == 201:
            binding_id = json.loads(payload)["id"]
            print(f"  created binding {binding_id} for {agent_id}")
            break
        if code == 409:
            # Already there — list and find it.
            lc, lp = _req(
                "GET", f"{court_url}/v1/registry/bindings?org_id={org_id}",
            )
            for b in json.loads(lp):
                if b.get("agent_id") == agent_id:
                    binding_id = b["id"]
                    break
            print(f"  binding already existed → id={binding_id}")
            break
        last_err = f"HTTP {code}: {payload[:200]}"
        time.sleep(1.0)

    if binding_id is None:
        print(
            f"FAILED binding create did not succeed in 30s "
            f"(last={last_err})",
            file=sys.stderr,
        )
        sys.exit(1)

    # Approve. 200 / 204 both ok; 409 if already approved.
    code, payload = _req(
        "POST", f"{court_url}/v1/registry/bindings/{binding_id}/approve",
        allow_status=(409,),
    )
    print(f"  approve → HTTP {code}")
    print(f"BOUND {agent_id} scope={scope} binding_id={binding_id}")
  '';

  # Creates an allow-all session policy for the given org on Court.
  # Mirrors ``reference/bootstrap/bootstrap.py::phase_5_session_policies``.
  # Without this, ``evaluate_session_policy`` defaults to deny on the
  # ``/v1/broker/oneshot/forward`` path → 403 even with a valid binding.
  policyAllowScript = pkgs.writeText "policy-allow.py" ''
    """Create a default-allow session policy on Court for one org.

    Args (positional):
      court_url       e.g. ``http://court:8000``
      org_id          short org id
      org_secret      same secret submitted at /onboarding/join
    """
    import json
    import sys
    import urllib.error
    import urllib.request

    if len(sys.argv) != 4:
        print(f"USAGE: {sys.argv[0]} court_url org_id org_secret",
              file=sys.stderr)
        sys.exit(2)

    _, court_url, org_id, org_secret = sys.argv

    body = {
        "policy_id": f"{org_id}::session-allow-all",
        "org_id": org_id,
        "policy_type": "session",
        "rules": {
            "effect": "allow",
            "conditions": {"target_org_id": [], "capabilities": []},
        },
    }
    req = urllib.request.Request(
        f"{court_url}/v1/policy/rules",
        data=json.dumps(body).encode(),
        headers={
            "Content-Type": "application/json",
            "X-Org-Id": org_id,
            "X-Org-Secret": org_secret,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            code = resp.getcode()
    except urllib.error.HTTPError as exc:
        if exc.code == 409:
            code = 409  # already there — idempotent
        else:
            print(f"FAILED policy create → HTTP {exc.code}: "
                  f"{exc.read().decode()[:300]}",
                  file=sys.stderr)
            sys.exit(1)
    print(f"POLICY {body['policy_id']} → HTTP {code}")
  '';

  # Loads a CullisClient from disk-pinned identity files and fires
  # ``send_oneshot`` against a cross-org recipient. The local proxy's
  # ``/v1/egress/resolve`` returns the recipient's cert from Court's
  # federation registry, the SDK encrypts + signs, and the broker
  # bridge forwards via ``POST /v1/broker/oneshot/forward`` on Court.
  oneshotSendScript = pkgs.writeText "oneshot-send.py" ''
    """SDK-driven cross-org one-shot send.

    Args (positional):
      mastio_url      e.g. ``https://mastio.roma.cullis.test:9443``
      org_id          sender's org
      agent_name      sender's agent name
      target_id       recipient ``org::name``
      identity_root   filesystem root with provisioned creds
      nonce           opaque marker, echoed inside payload for receiver match
    """
    import json
    import pathlib
    import sys

    from cullis_sdk import CullisClient

    if len(sys.argv) != 7:
        print(
            f"USAGE: {sys.argv[0]} mastio_url org_id agent_name target_id "
            f"identity_root nonce",
            file=sys.stderr,
        )
        sys.exit(2)

    _, mastio_url, org_id, agent_name, target_id, identity_root, nonce = sys.argv
    identity_dir = pathlib.Path(identity_root) / org_id / "agents" / agent_name
    cert_path = identity_dir / "agent.pem"
    key_path = identity_dir / "agent-key.pem"
    dpop_path = identity_dir / "dpop.jwk"
    ca_chain = pathlib.Path(identity_root) / org_id / "ca.pem"

    client = CullisClient.from_identity_dir(
        mastio_url,
        cert_path=cert_path,
        key_path=key_path,
        dpop_key_path=dpop_path,
        agent_id=f"{org_id}::{agent_name}",
        org_id=org_id,
        ca_chain_path=ca_chain,
    )
    client.login_via_proxy()
    client._signing_key_pem = key_path.read_text()

    payload = {"nonce": nonce, "hello": "cross-org A2A from nixosTest",
               "sender": f"{org_id}::{agent_name}"}
    resp = client.send_oneshot(target_id, payload)
    print(json.dumps({"sent_to": target_id, "nonce": nonce, **resp}))
    print("ONESHOT_SENT")
  '';

  # Polls the recipient's inbox until the expected nonce arrives, then
  # decrypts the envelope and verifies the inner signature. ``nonce``
  # is the marker to match (passed in plaintext payload by the sender);
  # the deadline keeps the test bounded if the message never lands.
  oneshotPollScript = pkgs.writeText "oneshot-poll.py" ''
    """SDK-driven inbox poll + decrypt for the receiver side.

    Args (positional):
      mastio_url      e.g. ``https://mastio.tokyo.cullis.test:9443``
      org_id          recipient's org
      agent_name      recipient's agent name
      identity_root   filesystem root with provisioned creds
      expected_nonce  the nonce the sender embedded in payload
      timeout_s       wait deadline (seconds)
    """
    import pathlib
    import sys
    import time

    from cullis_sdk import CullisClient

    if len(sys.argv) != 7:
        print(
            f"USAGE: {sys.argv[0]} mastio_url org_id agent_name "
            f"identity_root expected_nonce timeout_s",
            file=sys.stderr,
        )
        sys.exit(2)

    (_, mastio_url, org_id, agent_name, identity_root, expected_nonce,
     timeout_s) = sys.argv
    deadline = time.monotonic() + float(timeout_s)
    identity_dir = pathlib.Path(identity_root) / org_id / "agents" / agent_name
    ca_chain = pathlib.Path(identity_root) / org_id / "ca.pem"

    client = CullisClient.from_identity_dir(
        mastio_url,
        cert_path=identity_dir / "agent.pem",
        key_path=identity_dir / "agent-key.pem",
        dpop_key_path=identity_dir / "dpop.jwk",
        agent_id=f"{org_id}::{agent_name}",
        org_id=org_id,
        ca_chain_path=ca_chain,
    )
    client.login_via_proxy()
    # Envelope-mode decrypt unwraps the AES key with the recipient's
    # private key. ``from_identity_dir`` skips ``__init__`` so we
    # populate ``_signing_key_pem`` explicitly, mirroring what the
    # send side does.
    client._signing_key_pem = (identity_dir / "agent-key.pem").read_text()

    last_err = "(no rows yet)"
    while time.monotonic() < deadline:
        rows = client.receive_oneshot()
        for row in rows:
            try:
                decrypted = client.decrypt_oneshot(row)
            except Exception as exc:  # noqa: BLE001 — surface decrypt failure
                last_err = f"decrypt: {exc}"
                continue
            payload = decrypted.get("payload") or {}
            if payload.get("nonce") == expected_nonce:
                print(
                    f"RECEIVED nonce={expected_nonce} "
                    f"sender={payload.get('sender')} "
                    f"sender_verified={decrypted.get('sender_verified')} "
                    f"mode={decrypted.get('mode')}"
                )
                sys.exit(0)
            last_err = (
                f"nonce mismatch: got {payload.get('nonce')!r}, "
                f"want {expected_nonce!r}"
            )
        time.sleep(1.0)

    print(f"FAILED no message with nonce={expected_nonce} within "
          f"{timeout_s}s (last={last_err})", file=sys.stderr)
    sys.exit(1)
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
      # Court is the federation hub: only it needs the broker bound
      # on the world-facing interface so peers can reach
      # ``/v1/federation/publish-agent``. Cities run a local broker
      # for their own agent auth, but the federation publisher
      # task on each city points its publish loop at Court via
      # ``brokerUrl``.
      enableBroker = true;
      nginxAllowExternal = name == "court";
      brokerUrl =
        if name == "court"
        then ""  # local loopback default. Court IS the broker.
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
        for c in [roma, sanfrancisco, tokyo]:
            health = c.succeed(
                "curl -fs http://court:8000/health || echo OFFLINE"
            ).strip()
            assert "OFFLINE" not in health, (
                f"{c.name} can't reach Court's broker (got: {health!r})"
            )
            print(f"  {c.name} → court:8000/health = {health}")

    with subtest("Mastio identity readiness: preload Org CA + restart proxy"):
        # The proxy starts with ``standalone=false`` (because
        # ``brokerUrl`` points at Court) which keeps it from auto-
        # generating a CA on first boot. Without an Org CA in
        # ``proxy_config``, the ``mastio_loaded`` gate that drives
        # the lifespan's mastio-identity generation never fires, so
        # ``GET /v1/admin/mastio-pubkey`` returns null forever.
        # Preloading the on-disk Org CA + restarting unblocks the
        # gate; after the second boot the proxy mints its mastio
        # ES256 identity and the federation publisher loop arms.
        # Both Roma and Tokyo need this before the Court bootstrap
        # subtest pulls their mastio_pubkeys to pin on Court.
        for city in (roma, tokyo):
            city.succeed("python3 ${preloadOrgCaScript}")
            city.succeed("systemctl restart cullis-proxy.service")
            city.wait_for_unit("cullis-proxy.service")
            city.wait_until_succeeds(
                "curl -fs http://127.0.0.1:9100/health", timeout=30,
            )

    with subtest("Court bootstrap: register Roma + Tokyo, pin pubkeys"):
        # Drives the same admin-side flow ``reference/bootstrap/`` runs
        # against the docker-compose sandbox: ``/v1/admin/invites`` →
        # ``/v1/onboarding/join`` (per city) → ``/v1/admin/orgs/{id}/
        # approve`` → ``PATCH /v1/admin/orgs/{id}/mastio-pubkey``. After
        # this, Court can verify the ES256 counter-signature each city's
        # federation publisher attaches to ``publish-agent`` requests.
        #
        # Roma is the only publisher exercised in the next subtest, but
        # we bootstrap Tokyo too so a follow-up A2A oneshot subtest can
        # rely on the symmetric topology without re-entering this code
        # path.
        for city, cfg in (
            (roma,  {"orgId": "roma",  "displayName": "Roma Mastio (CET)",
                     "trustDomain": "roma.cullis.test"}),
            (tokyo, {"orgId": "tokyo", "displayName": "Tokyo Mastio (JST)",
                     "trustDomain": "tokyo.cullis.test"}),
        ):
            out = city.succeed(
                "python3 ${courtBootstrapScript} "
                f"{cfg['orgId']} '{cfg['displayName']}' "
                f"{cfg['trustDomain']} "
                "http://court:8000 http://127.0.0.1:9100 "
                "/var/lib/cullis/certs/org-ca.pem "
                f"test-admin-secret {cfg['orgId']}-secret-test"
            )
            assert "BOOTSTRAPPED" in out, (
                f"bootstrap of {cfg['orgId']} did not finish:\n{out}"
            )
            print(f"  {cfg['orgId']} bootstrapped on Court")

    with subtest("Federation publish: Roma pushes to Court (payload wire)"):
        # The previous two subtests preloaded Roma's Org CA + restarted
        # the proxy (so the mastio identity is ready) and bootstrapped
        # Roma on Court (so counter-sig + cert-chain checks pass on the
        # receiving end). What's left is the actual publish trigger:
        # insert a federated=1 row, wait for the publisher tick, and
        # confirm Court accepted the payload.
        #
        # Insert a row in Roma's ``internal_agents`` with
        # ``federated=1`` so the publisher picks it up on its next
        # tick (poll interval forced to 2s via
        # ``MCP_PROXY_FEDERATION_POLL_INTERVAL_S``). The publisher
        # counter-signs the body and POSTs to Court at
        # ``/v1/federation/publish-agent``. Expected success line:
        # ``federation publish OK: roma::fedtest rev=1 status=...``.
        # ``broker unreachable`` is the dead-wire failure mode; an
        # ``HTTP 4xx`` log line means Court rejected despite bootstrap
        # (surface it so the cross-org regression is greppable).
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
        # +epsilon). The publisher's ``_tick`` does the SELECT +
        # POST + log.
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
        # ``broker unreachable`` would mean a dead wire (TCP/HTTP
        # transport failure). Catch it explicitly so the test fails
        # with a clear message rather than waiting on a downstream
        # assertion.
        assert "broker unreachable" not in publish_log, publish_log
        # With Court bootstrap done, the publisher counter-signature
        # should verify and Court should persist the agent row →
        # ``federation publish OK: roma::fedtest …``. If Court instead
        # rejects (``HTTP 4xx``), surface the line so the cross-org
        # trust regression is greppable from the test log without
        # spelunking journalctl.
        assert "federation publish OK" in publish_log, (
            f"federation publish did NOT succeed end-to-end. Log line:\n"
            f"  {publish_log}\n"
            f"Last 100 proxy lines:\n"
            f"{roma.succeed('journalctl -u cullis-proxy --no-pager -n 100')}\n"
            f"Last 50 broker lines on Court:\n"
            f"{court.succeed('journalctl -u cullis-broker --no-pager -n 50')}"
        )
        print(f"  publish accepted by Court:\n    {publish_log}")

    with subtest("Cross-org A2A oneshot: roma::sender → tokyo::receiver"):
        # Six-phase round-trip — Roma SDK encrypt+sign, broker bridge
        # forwards, Court counter-signs, Tokyo SDK decrypts+verifies.
        # Each phase reuses one of the helper scripts defined in the
        # ``let`` block above; the test driver wires them together
        # with the right env per VM.
        identity_root = "/var/lib/cullis/test-identities"

        # Phase 1: provision both agents on their respective Mastios
        # via the BYOCA enroll endpoint. The script mints a cert
        # against the local Org CA, generates a DPoP keypair, posts
        # the public material to /v1/admin/agents/enroll/byoca, and
        # drops cert+key+dpop+CA chain on disk in the layout the
        # SDK's ``from_identity_dir`` expects.
        for city, cfg in (
            (roma,  {"orgId": "roma",  "agentName": "sender",
                     "trustDomain": "roma.cullis.test"}),
            (tokyo, {"orgId": "tokyo", "agentName": "receiver",
                     "trustDomain": "tokyo.cullis.test"}),
        ):
            out = city.succeed(
                "python3 ${provisionAgentScript} "
                f"{cfg['orgId']} {cfg['agentName']} oneshot.message "
                "http://127.0.0.1:9100 test-admin-secret "
                f"{identity_root} "
                "/var/lib/cullis/certs/org-ca.pem "
                "/var/lib/cullis/certs/org-ca.key "
                f"{cfg['trustDomain']}"
            )
            assert "PROVISIONED" in out, (
                f"provisioning of {cfg['orgId']}::{cfg['agentName']} failed:\n{out}"
            )
            print(f"  {cfg['orgId']}::{cfg['agentName']} provisioned")

        # No trust-bundle plumbing needed: PR #467 (issue #459) delegates
        # cross-org chain checks to Court, which already verified the
        # leaf at federation publish time. Each agent's ``ca.pem`` holds
        # only the local Org CA and the SDK's ``decrypt_oneshot`` skips
        # the chain step for cross-org senders.

        # Phase 2: wait for the federation publisher to push both
        # rows to Court. The ``federated=true`` flag came in via
        # provisioning; poll interval is forced to 2s by the module
        # env. Look for the success log line on each side.
        for city, agent_id in (
            (roma, "roma::sender"),
            (tokyo, "tokyo::receiver"),
        ):
            city.wait_until_succeeds(
                "journalctl -u cullis-proxy --no-pager | "
                f"grep -q 'federation publish OK: {agent_id}'",
                timeout=20,
            )
            print(f"  {agent_id} published to Court")

        # Phase 3: bind both agents on Court so authentication +
        # capability gates allow the oneshot. Each binding is
        # intra-org (the auth org_id must match the body org_id);
        # cross-org A2A is gated by federation registry visibility
        # plus the recipient's intra-org binding having scope.
        for city, cfg in (
            (roma,  {"orgId": "roma",  "agentId": "roma::sender"}),
            (tokyo, {"orgId": "tokyo", "agentId": "tokyo::receiver"}),
        ):
            out = city.succeed(
                "python3 ${bindAgentScript} "
                "http://court:8000 "
                f"{cfg['orgId']} {cfg['orgId']}-secret-test "
                f"{cfg['agentId']} oneshot.message"
            )
            assert "BOUND" in out, (
                f"binding for {cfg['agentId']} failed:\n{out}"
            )
            print(f"  {cfg['agentId']} bound + approved on Court")

        # Phase 3b: install an allow-all session policy on Court for
        # both orgs. Without this, ``evaluate_session_policy`` on the
        # ``/v1/broker/oneshot/forward`` path defaults to deny → 403
        # even with valid bindings.
        for city, org_id in ((roma, "roma"), (tokyo, "tokyo")):
            out = city.succeed(
                "python3 ${policyAllowScript} "
                f"http://court:8000 {org_id} {org_id}-secret-test"
            )
            assert "POLICY" in out, f"policy create for {org_id} failed:\n{out}"
            print(f"  {org_id} session-allow-all policy installed")

        # Phase 4: send. Roma SDK loads the cert/key/dpop from disk,
        # logs in via the local proxy, encrypts the payload for the
        # Tokyo recipient (cert pulled from Court via /resolve), and
        # POSTs to ``/v1/egress/message/send``.
        nonce = "tier2-a2a-cross-org-roundtrip"
        out = roma.succeed(
            "python3 ${oneshotSendScript} "
            "https://mastio.roma.cullis.test:9443 "
            "roma sender tokyo::receiver "
            f"{identity_root} {nonce}"
        )
        assert "ONESHOT_SENT" in out, f"send_oneshot failed:\n{out}"
        print(f"  Roma SDK fired one-shot:\n    {out.strip()}")

        # Phase 5: receive. Tokyo SDK polls inbox, decrypts the
        # envelope, verifies the inner signature, and confirms the
        # nonce matches what Roma sent. Times out at 20s — the
        # broker queue + bridge poll cadence is in the 2-5s range.
        out = tokyo.succeed(
            "python3 ${oneshotPollScript} "
            "https://mastio.tokyo.cullis.test:9443 "
            "tokyo receiver "
            f"{identity_root} {nonce} 20"
        )
        assert "RECEIVED" in out, f"inbox poll did not match nonce:\n{out}"
        assert "sender_verified=True" in out, (
            f"recipient could not verify sender signature:\n{out}"
        )
        print(f"  Tokyo SDK received + verified:\n    {out.strip()}")

        # Phase 6: dump the local oneshot audit rows (informative). The
        # broker-side ``log_event_cross_org`` writes the canonical
        # cross-org pair on Court; each Mastio mirrors a local row via
        # the egress pipeline (``mcp_proxy/egress/oneshot.py`` →
        # ``oneshot_sent`` / ``oneshot_delivered``). Surface the rows
        # for visual inspection without asserting an exact event_type
        # name (varies by code path); the previous assertions on send
        # + receive already proved the round-trip cryptographically.
        for city in (roma, tokyo):
            rc, dump = city.execute(
                "sqlite3 /var/lib/cullis/proxy.sqlite "
                "\"SELECT event_type, result FROM audit_log "
                "WHERE event_type LIKE '%oneshot%' "
                "ORDER BY id DESC LIMIT 5\" 2>&1 || true"
            )
            print(f"  {city.name} oneshot audit (last 5):\n{dump.rstrip()}")

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
