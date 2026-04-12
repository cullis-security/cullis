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

## Step 2 — Bring Your Own CA (BYOCA)

The broker needs a CA certificate + private key. In production your
security team hands these to you (or you integrate with an internal PKI).
For a first deployment on a fresh cluster, generate an ephemeral pair:

```bash
mkdir -p /tmp/cullis-pki && cd /tmp/cullis-pki
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 \
  -subj "/CN=Your Org Cullis CA/O=Your Org" -out ca.crt
```

Create the namespace and the Secret that the chart will mount:

```bash
kubectl create namespace cullis

kubectl -n cullis create secret generic broker-pki \
  --from-file=broker-ca.pem=ca.crt \
  --from-file=broker-ca-key.pem=ca.key
```

The Secret MUST be named `broker-pki` (or whatever you reference in
`values.yaml → broker.pki.existingSecret`), and the keys MUST be
`broker-ca.pem` and `broker-ca-key.pem` — the broker's
`Settings()` expects those filenames.

---

## Step 3 — Install the broker chart

Dev-ergonomic deployment (Postgres / Redis / Vault spun up inline, Vault
in dev mode — suitable for evaluation and testing only):

```bash
helm install cullis deploy/helm/cullis/ \
  --namespace cullis \
  --values deploy/helm/cullis/values-dev.yaml \
  --set broker.pki.existingSecret=broker-pki \
  --set ingress.host=broker.your-org.com \
  --wait --timeout 5m
```

Replace `broker.your-org.com` with a hostname resolvable to your
cluster's Ingress IP. For local k3d / kind runs, `broker.127.0.0.1.nip.io`
works without editing `/etc/hosts`.

### Bootstrap Vault secret

The chart provisions an inline Vault StatefulSet but does not yet
populate it with the broker's CA. Until the PKI bootstrap Job lands
(tracked in a follow-up), run once after install:

```bash
kubectl -n cullis exec cullis-vault-0 -- sh -c '
  export VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=dev-root-token
  vault kv put secret/broker \
    private_key_pem="'"$(cat /tmp/cullis-pki/ca.key)"'" \
    ca_cert_pem="'"$(cat /tmp/cullis-pki/ca.crt)"'"
'

kubectl -n cullis rollout restart deployment/cullis-broker
kubectl -n cullis rollout status  deployment/cullis-broker --timeout=3m
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
→ You skipped Step 3's "Bootstrap Vault secret" subsection. Run those
   `kubectl exec vault-0 vault kv put ...` commands.

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
