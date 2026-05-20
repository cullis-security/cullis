---
title: "Frontdesk bundle"
description: "Deploy the Cullis Frontdesk bundle — a multi-user chat SPA over a shared-mode Mastio, with per-user identity and audit. Single Docker Compose host."
category: "Install"
order: 30
updated: "2026-05-20"
---

# Frontdesk bundle

**Who this is for**: an org admin who wants every human user in the organization to talk to LLMs through Cullis, with a per-user identity and a per-user audit trail. The Frontdesk bundle is a multi-user chat SPA co-located with a Mastio in shared mode.

If your scenario is headless agents only, deploy [the Mastio bundle](mastio-self-host) instead. If your scenario is a single developer plugging Cursor / Claude Code into Cullis, deploy [the Connector](connector).

## What you get

```
http://localhost:8080
  └─ Cullis Chat SPA          (multi-user, sign-up + sign-in)
       └─ Connector (shared)  (issues per-user identity)
            └─ Mastio          (agent CA, policy, audit chain, AI gateway)
                ├─ /proxy/login   admin dashboard (port :9443)
                └─ external LLM provider (Anthropic / OpenAI / Gemini / Ollama)
```

Every chat message is bound to the signed-in user's identity. The Mastio's audit chain records every LLM call, every tool call, every cross-user event. One bundle, one host, one deploy script.

## Prerequisites

- Docker Engine ≥ 24 with Compose v2
- 2 GB free RAM
- An LLM provider you can reach: API key for Anthropic / OpenAI / Gemini, or a reachable Ollama running on the host

## 1. Deploy

```bash
curl -L https://github.com/cullis-security/cullis/releases/download/frontdesk-bundle-v0.2.10/cullis-frontdesk-bundle.tar.gz | tar xz
cd cullis-frontdesk-bundle
./deploy.sh
```

First boot mints the Org CA, creates the Mastio admin account, provisions the shared-mode Connector, and writes a self-signed TLS leaf for `localhost:8080`. Output ends with the URL + the admin password (saved in `frontdesk.env`).

To pin a public hostname instead of `localhost`, set `CULLIS_FRONTDESK_PUBLIC_URL=https://chat.acme.corp:8443` in `frontdesk.env` before `./deploy.sh`. The TLS SAN auto-derives from the URL host.

## 2. Sign up + chat

Open `http://localhost:8080` (or your public URL). Sign up with email + password. The Frontdesk:

1. Creates a local user account in the Mastio's user store
2. Provisions a per-user identity (cert + DPoP key) under the Connector's shared session store
3. Lands you on the chat view with the configured LLM provider

Every message is signed with your per-user DPoP key. The Mastio's audit chain records the user identity, the prompt, the LLM response, and any tool calls.

## 3. Admin dashboard

Open `https://localhost:9443/proxy/login` (or your public Mastio URL). Sign in with the admin password printed at the end of `./deploy.sh`.

From here:

- **Users** — list of human users, suspend / delete, see their audit
- **AI gateway** — switch provider, rotate API keys, set per-user rate limits
- **Audit** — full hash-chained log across users + agents
- **PKI** — view CA, rotate Org Root or Mastio Intermediate (ADR-033 three-tier hardening)

## 4. Production overrides

For real deploys, expect to configure at least:

- **`CULLIS_FRONTDESK_PUBLIC_URL`** — your real hostname + port (matters for TLS SAN, cookies, CORS)
- **`MASTIO_ADMIN_TOKEN`** — rotate the bootstrap admin password to one from your secret manager
- **`AI_GATEWAY_*`** — switch from Ollama to your real provider, point at your KMS-stored key
- **TLS sidecar** — replace the self-signed leaf with a real cert (Let's Encrypt sidecar example in `packaging/frontdesk-bundle/nginx-tls/`)
- **Reverse-proxy auth** — drop oauth2-proxy in front of `:8080` if you already have an IDP; Frontdesk will trust the upstream user header instead of running its own sign-up

See `packaging/frontdesk-bundle/README.md` for the full env reference + upgrade flow.

## 5. Upgrades

```bash
cd cullis-frontdesk-bundle
./deploy.sh --upgrade
```

`--upgrade` refreshes both the bundle files (compose, nginx config, env template) and the container images. The user store, audit chain, and Mastio CA are preserved across upgrades.

## Troubleshoot

**Sign-up returns 401 immediately**
: The Connector shared-mode auth gate refused the request. Most often the bundle env marker is not set — check `FRONTDESK_BUNDLE=1` in `frontdesk.env`.

**Chat works for one user but not another**
: Per-user identity propagation. Verify in the Mastio audit that the second user has a distinct `cert_thumbprint`. If both users share a thumbprint, the Connector is falling back to the workload identity — open an issue with the audit excerpt.

**TLS sidecar serves the wrong cert**
: The auto-derived SAN reads `CULLIS_FRONTDESK_PUBLIC_URL` at deploy time. If you change the public URL after the first boot, re-run `./deploy.sh --upgrade --mint-tls` to re-mint the cert.

## Next

- [Self-host the Mastio](mastio-self-host) — same Mastio, headless mode (no Frontdesk SPA)
- [Install the Connector](connector) — single-user laptop client, for devs
- [Runbook](../operate/runbook) — incident response for production
