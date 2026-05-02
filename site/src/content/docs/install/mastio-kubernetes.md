---
title: "Mastio on Kubernetes"
description: "Deploy the Cullis Mastio (and optionally a Court) on a Kubernetes cluster with the official Helm charts — ingress, BYOCA, dev vs. prod values."
category: "Install"
order: 30
updated: "2026-04-23"
---

# Mastio on Kubernetes

**Who this is for**: an operator deploying Cullis on a managed or self-hosted Kubernetes cluster. For a single-host deploy, see [Self-host the Mastio](mastio-self-host) instead.

Tested against: `kind`, `k3d`, and managed Kubernetes (EKS / GKE / AKS — pending customer validation at scale).

## Prerequisites

- Kubernetes ≥ v1.28 with `kubectl` context configured
- Helm ≥ v3.14
- An Ingress controller — `ingress-nginx` recommended; the chart annotations are written for it
- `openssl` on the host (for BYOCA demo material; in production your security team provides the PEMs)

## Scope

**In scope**

- Deploying Court + Mastio via `helm install`
- Wiring a customer-provided PKI (BYOCA) into the Court
- Exposing both behind `ingress-nginx`
- `/healthz` → 200 and `/readyz` → ready on each

**Out of scope** (covered elsewhere)

- End-to-end message flow assertions — see `sandbox/smoke.sh`, the authoritative behaviour gate
- Production hardening (TLS at the Ingress, Vault auto-unseal, secret rotation) — see [Runbook](../operate/runbook)
- External Postgres / Redis / Vault — flip `*.internal` in `values.yaml` to `false` and point env vars at your managed services

## 1. Install `ingress-nginx`

Skip if your cluster already has one. Otherwise:

```bash
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
helm repo update
helm install ingress-nginx ingress-nginx/ingress-nginx \
    --namespace ingress-nginx --create-namespace \
    --set controller.service.type=LoadBalancer \
    --wait
```

## 2. Provide a Court CA

The Court signs agent certificates with a root CA it reads from `/app/certs/broker-ca.pem` + `/app/certs/broker-ca-key.pem`. Pick one of the two paths below.

### A. Auto-bootstrap (evaluation / dev clusters)

`values-dev.yaml` enables this by default. The chart renders a post-install Job that generates a self-signed CA, writes it into a Secret the Court Deployment mounts, and pushes the PEMs into the in-cluster Vault so `KMS_BACKEND=vault` resolves on first boot — no manual `kubectl exec` required.

```bash
kubectl create namespace cullis
```

### B. Bring Your Own CA (production-preferred)

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

The files **must** be named `broker-ca.pem` + `broker-ca-key.pem` — the Court's `Settings()` expects those exact filenames. At install time, pass `--set broker.pki.bootstrap.enabled=false --set broker.pki.existingSecret=broker-pki` to disable auto-bootstrap and mount your Secret instead.

## 3. Install the Court chart

Dev-ergonomic deployment (Postgres / Redis / Vault spun up inline, Vault in dev mode, auto-bootstrapped CA — evaluation only):

```bash
helm install cullis deploy/helm/cullis/ \
    --namespace cullis \
    --values deploy/helm/cullis/values-dev.yaml \
    --set ingress.host=broker.your-org.com \
    --wait --timeout 5m
```

Replace `broker.your-org.com` with a hostname resolvable to your cluster's Ingress IP. For local k3d / kind runs, `broker.127.0.0.1.nip.io` works without editing `/etc/hosts`.

For Option B (BYOCA), extend:

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

curl -H "Host: broker.your-org.com" http://<INGRESS-IP>/healthz
# {"status":"ok"}

curl -H "Host: broker.your-org.com" http://<INGRESS-IP>/readyz
# {"status":"ready","checks":{"database":"ok","redis":"ok","kms":"ok"}}
```

## 4. Install the Mastio chart

The Mastio is stateless from the Court's perspective and uses its own small SQLite database. Point it at the Court's public base URL + JWKS URL:

```bash
helm install cullis-mastio deploy/helm/cullis-mastio/ \
    --namespace cullis \
    --values deploy/helm/cullis-mastio/values-dev.yaml \
    --set ingress.host=proxy.your-org.com \
    --wait --timeout 5m
```

### Verify

```bash
curl -H "Host: proxy.your-org.com" http://<INGRESS-IP>/healthz
# {"status":"ok"}

curl -H "Host: proxy.your-org.com" http://<INGRESS-IP>/readyz
# {"status":"ready","checks":{"database":"ok","jwks_cache":"ok"}}
```

## 5. Switching to production values

Once the dev stack proves viable, replace the inline StatefulSets with managed services:

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
  internal: false                        # ElastiCache / Memorystore

vault:
  internal: false                        # external Vault

ingress:
  tls:
    enabled: true
    certManagerIssuer: letsencrypt-prod   # or your internal issuer

networkPolicy:
  enabled: true
```

Full `values.yaml` options are documented inline in the chart.

## Troubleshoot

**`/readyz` stuck at 503 with `kms: error: Vault address must use https://`**
: You're on `values-dev.yaml` (Vault dev HTTP). Confirm `VAULT_ALLOW_HTTP=true` is set via `broker.extraEnv`. From chart version post-#7 `values-dev.yaml` sets this automatically.

**`/readyz` stuck at 503 with `kms: error: Vault secret ... missing 'ca_cert_pem'`**
: The PKI bootstrap Job failed or didn't run. Check its logs:
  ```bash
  kubectl -n cullis get jobs -l app.kubernetes.io/component=broker-pki-bootstrap
  kubectl -n cullis logs job/cullis-broker-pki-bootstrap
  ```
  Common causes: Vault StatefulSet still coming up (the Job retries for ~2 min), or `broker.pki.bootstrap.pushToVault=false` when `vault.kmsBackend=vault`.

**Court pod `CrashLoopBackOff` with no `certs/broker-ca.pem`**
: `broker.pki.existingSecret` is empty or the Secret doesn't carry `broker-ca.pem` + `broker-ca-key.pem`. Inspect with `kubectl -n cullis get secret broker-pki -o yaml`.

**`/healthz` returns 200 but `/readyz` 503 with `jwks_cache: error`**
: The Mastio can't reach the Court's JWKS endpoint. Check `proxy.brokerJwksUrl` in `values-dev.yaml` resolves, and the in-cluster DNS / NetworkPolicy allows egress to the Court Service.

**Everything else**
: Dump pod logs:
  ```bash
  kubectl -n cullis logs deploy/cullis-broker --tail=200
  kubectl -n cullis logs deploy/cullis-proxy --tail=200
  kubectl -n cullis get events --sort-by='.lastTimestamp' | tail -30
  ```

## Next

- [Enroll agents via BYOCA](../enroll/byoca) — on a k8s cluster, BYOCA is usually the right enrollment method for agent workloads
- [Enroll agents via SPIRE](../enroll/spire) — if SPIRE is already part of your workload identity fabric
- [Runbook](../operate/runbook) — production incident response
- [Self-host the Mastio](mastio-self-host) — the single-host alternative
