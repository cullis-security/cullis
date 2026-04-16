---
title: "Cullis on Kubernetes — Quickstart"
description: "Deploy the Cullis Court and Mastio on Kubernetes using the official Helm chart."
category: "Deployment"
order: 10
updated: "2026-04-12"
---

# Cullis on Kubernetes — Quickstart

This guide walks you through deploying the Cullis broker and MCP proxy
on a Kubernetes cluster using the Helm charts published at
`deploy/helm/cullis/` and `deploy/helm/cullis-proxy/`.

Tested against: `kind`, `k3d`, managed k8s (EKS / GKE / AKS — pending
customer validation).

---

## Scope and non-goals

**In scope**
- Deploying broker + proxy via `helm install`
- Wiring a customer-provided PKI (BYOCA) into the broker
- Exposing broker + proxy via `ingress-nginx`
- Reaching `/healthz` → 200 and `/readyz` → ready on both

**Out of scope** (documented elsewhere)
- End-to-end message flow assertions (see `demo_network/smoke.sh` —
  authoritative behaviour gate, runs on docker-compose)
- Production hardening (TLS at the Ingress, Vault auto-unseal, secret
  rotation) — see `docs/operations-runbook.md`
- Setting up an external Postgres, Redis, Vault — `values.yaml`
  `*.internal: true` brings those up inline for dev; flip to `false`
  and point env vars at your managed services for production

---

## Prerequisites

- Kubernetes cluster v1.28+ with `kubectl` context configured
- Helm v3.14+
- `openssl` (for generating the BYOCA demo CA; in production your
  security team provides these PEMs)
- An Ingress controller — `ingress-nginx` recommended; the chart
  annotations are written for it

---

## Step 1 — Install `ingress-nginx`

If your cluster already has one, skip this. Otherwise:

```bash
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
helm repo update
helm install ingress-nginx ingress-nginx/ingress-nginx \
  --namespace ingress-nginx --create-namespace \
  --set controller.service.type=LoadBalancer \
  --wait
```

---

## Step 2 — Provide a broker CA

The broker signs agent certificates with a root CA it reads from
`/app/certs/broker-ca.pem` + `/app/certs/broker-ca-key.pem`. Pick one
of the two paths below.

### Option A — Auto-bootstrap (evaluation / dev clusters)

`values-dev.yaml` enables this by default. The chart renders a
post-install Job that generates a self-signed CA, writes it into a
Secret the broker Deployment mounts, and pushes the PEMs into the
in-cluster Vault so `KMS_BACKEND=vault` resolves on first boot — no
manual `kubectl exec` required.

Nothing to do in this step except create the namespace:

```bash
kubectl create namespace cullis
```

### Option B — Bring Your Own CA (production-preferred)

In production your security team provides the PEMs (or you integrate
with an internal PKI). For a one-off ephemeral pair:

```bash
mkdir -p /tmp/cullis-pki && cd /tmp/cullis-pki
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 \
  -subj "/CN=Your Org Cullis CA/O=Your Org" -out ca.crt

kubectl create namespace cullis
kubectl -n cullis create secret generic broker-pki \
  --from-file=broker-ca.pem=ca.crt \
  --from-file=broker-ca-key.pem=ca.key
```

The keys MUST be named `broker-ca.pem` + `broker-ca-key.pem` — the
broker's `Settings()` expects those exact filenames. At install time,
add `--set broker.pki.bootstrap.enabled=false --set
broker.pki.existingSecret=broker-pki` to disable the auto-bootstrap
and use your Secret instead.

---

## Step 3 — Install the broker chart

Dev-ergonomic deployment (Postgres / Redis / Vault spun up inline,
Vault in dev mode, auto-bootstrapped CA — suitable for evaluation and
testing only):

```bash
helm install cullis deploy/helm/cullis/ \
  --namespace cullis \
  --values deploy/helm/cullis/values-dev.yaml \
  --set ingress.host=broker.your-org.com \
  --wait --timeout 5m
```

Replace `broker.your-org.com` with a hostname resolvable to your
cluster's Ingress IP. For local k3d / kind runs, `broker.127.0.0.1.nip.io`
works without editing `/etc/hosts`.

For Option B (BYOCA), extend the command:

```bash
helm install cullis deploy/helm/cullis/ \
  --namespace cullis \
  --values deploy/helm/cullis/values-dev.yaml \
  --set broker.pki.bootstrap.enabled=false \
  --set broker.pki.existingSecret=broker-pki \
  --set ingress.host=broker.your-org.com \
  --wait --timeout 5m
```

### Verify

```bash
kubectl -n cullis get pods
# cullis-broker-xxx      1/1 Running
# cullis-postgres-0      1/1 Running
# cullis-redis-0         1/1 Running
# cullis-vault-0         1/1 Running

# From your laptop (or cluster-internal):
curl -H "Host: broker.your-org.com" http://<INGRESS-IP>/healthz
# → {"status":"ok"}

curl -H "Host: broker.your-org.com" http://<INGRESS-IP>/readyz
# → {"status":"ready","checks":{"database":"ok","redis":"ok","kms":"ok"}}
```

---

## Step 4 — Install the proxy chart

The proxy is stateless (from the broker's perspective) and uses its own
small SQLite DB. It needs the broker's public base URL and JWKS URL
to resolve inside the cluster:

```bash
helm install cullis-proxy deploy/helm/cullis-proxy/ \
  --namespace cullis \
  --values deploy/helm/cullis-proxy/values-dev.yaml \
  --set ingress.host=proxy.your-org.com \
  --wait --timeout 5m
```

### Verify

```bash
curl -H "Host: proxy.your-org.com" http://<INGRESS-IP>/healthz
# → {"status":"ok"}

curl -H "Host: proxy.your-org.com" http://<INGRESS-IP>/readyz
# → {"status":"ready","checks":{"database":"ok","jwks_cache":"ok"}}
```

---

## Step 5 — Agent registration and message flow

The behavioural end-to-end flow (agent login, DPoP-bound session, E2E
message, policy evaluation) is identical to the docker-compose demo.
For a real trial, follow the `enterprise-kit/` templates — the
integration points are the same on k8s as on docker:

- `broker.your-org.com` replaces the docker service name in SDK config
- Agent certificates are signed by your Org CA (generated separately)
- `/v1/auth/token` is the entry point

See `enterprise-kit/BYOCA.md` and `enterprise-kit/quickstart.sh` for
the full onboarding flow.

---

## Switching to production values

Once the dev stack proves viable, replace the inline StatefulSets with
managed services:

```yaml
# values-prod.yaml (sketch — adapt to your environment)

broker:
  environment: production
  logFormat: json
  replicaCount: 3
  pki:
    existingSecret: broker-pki          # from your secret manager
  # VAULT_ALLOW_HTTP is NOT set — production requires Vault HTTPS

postgres:
  internal: false                        # point env at RDS / Cloud SQL / etc.

redis:
  internal: false                        # point env at ElastiCache / Memorystore

vault:
  internal: false                        # point VAULT_ADDR at external Vault

ingress:
  tls:
    enabled: true
    certManagerIssuer: letsencrypt-prod  # or your internal issuer

networkPolicy:
  enabled: true
```

Full `values.yaml` options are documented inline in the chart.

---

## Troubleshooting

**`/readyz` stuck at 503 with `kms: error: Vault address must use https://`**
→ You're on `values-dev.yaml` (Vault dev HTTP). Confirm `VAULT_ALLOW_HTTP=true`
   is set via `broker.extraEnv`. As of chart version post-#7, values-dev.yaml
   sets this automatically.

**`/readyz` stuck at 503 with `kms: error: Vault secret ... missing 'ca_cert_pem'`**
→ The PKI bootstrap Job failed or did not run. Check its logs:
   `kubectl -n cullis get jobs -l app.kubernetes.io/component=broker-pki-bootstrap`
   `kubectl -n cullis logs job/cullis-broker-pki-bootstrap`
   Common causes: Vault StatefulSet still coming up (the Job retries
   for ~2 minutes), or `broker.pki.bootstrap.pushToVault=false` when
   `vault.kmsBackend=vault`.

**Broker pod `CrashLoopBackOff` with no `certs/broker-ca.pem`**
→ `broker.pki.existingSecret` is empty or the Secret doesn't have
   keys named `broker-ca.pem` + `broker-ca-key.pem`. Verify with
   `kubectl -n cullis get secret broker-pki -o yaml`.

**`/healthz` returns 200 but `/readyz` 503 with `jwks_cache: error`**
→ The proxy cannot reach the broker's JWKS endpoint. Check
   `proxy.brokerJwksUrl` in values-dev.yaml resolves correctly and
   the in-cluster DNS / NetworkPolicy allows egress to the broker
   Service.

**For anything else**, dump pod logs:

```bash
kubectl -n cullis logs deploy/cullis-broker --tail=200
kubectl -n cullis logs deploy/cullis-proxy --tail=200
kubectl -n cullis get events --sort-by='.lastTimestamp' | tail -30
```
