# Cullis Helm Chart

Helm chart for [Cullis](https://cullis.io), the federated trust broker for
inter-organizational AI agents. The chart targets managed Kubernetes
(EKS, GKE, AKS) and assumes external Postgres, Redis and Vault by default.
In-cluster fallbacks exist for `kind` / `minikube` development.

> ⚠️ **Status: work in progress, not yet production-validated.**
> The chart is `helm lint`-clean and captures the intended deployment
> topology, but has not been exercised end to end against a managed
> Kubernetes cluster yet. Treat it as a starting point you can fork and
> harden for your environment, not a turnkey install. The end-to-end path
> currently covered by automated tests is the
> [`sandbox/`](../../../sandbox/) demo, not this chart.

## Quick start

Production install (external dependencies):

```bash
helm install cullis ./deploy/helm/cullis \
  --namespace cullis --create-namespace \
  --set ingress.host=cullis.example.com \
  --set postgres.externalUrl="postgresql+asyncpg://cullis:secret@db.example.com:5432/cullis" \
  --set redis.externalUrl="rediss://:secret@redis.example.com:6379/0" \
  --set vault.externalAddr="https://vault.example.com:8200" \
  --set secrets.adminSecret="$(openssl rand -hex 32)" \
  --set secrets.vaultToken="$(cat ~/.vault-token)"
```

Or with a values file:

```bash
helm install cullis ./deploy/helm/cullis -f values-prod.yaml
```

Dev install on `kind` / `minikube`:

```bash
helm install cullis ./deploy/helm/cullis \
  --namespace cullis --create-namespace \
  -f deploy/helm/cullis/values-dev.yaml
```

## What the chart deploys

| Component         | Resource                   | Notes                                          |
|-------------------|----------------------------|------------------------------------------------|
| Broker            | Deployment, Service        | 2 replicas default, HPA-managed when enabled   |
| Broker (HA)       | HPA, PodDisruptionBudget   | CPU 70%, minAvailable 1                        |
| Broker (security) | NetworkPolicy              | Ingress only from nginx-ingress, restricted egress |
| Broker (config)   | ConfigMap, Secret          | Secret can be replaced by SealedSecret/ExternalSecret |
| Broker (auth)     | ServiceAccount             | Annotate for IRSA / Workload Identity          |
| Ingress           | Ingress (nginx + cert-manager) | Websocket annotations, TLS via ClusterIssuer |
| Monitoring        | PrometheusRule, ServiceMonitor | Prometheus Operator CRDs                   |
| Postgres (dev)    | StatefulSet, Service       | Only when `postgres.internal=true`             |
| Redis (dev)       | StatefulSet, Service       | Only when `redis.internal=true`                |
| Vault (dev)       | StatefulSet, Service       | Only when `vault.internal=true`                |
| Jaeger (dev)      | Deployment, Service        | Only when `jaeger.enabled=true`                |

## External dependencies

The chart defaults to **external** Postgres, Redis and Vault. This is the
right choice for production: managed services give you HA, backups and
patching for free, and they outlive any single Kubernetes cluster.

### Postgres (RDS / CloudSQL / Crunchy)

Set `postgres.externalUrl` to a SQLAlchemy async URL pointing at your
managed instance, for example:

```yaml
postgres:
  internal: false
  externalUrl: "postgresql+asyncpg://cullis:secret@cullis.cluster-xxxx.eu-west-1.rds.amazonaws.com:5432/cullis"
```

For production prefer to put the URL in a `Secret` (named via
`postgres.existingSecret` or composed via `secrets.extra`) and reference
it from `broker.extraEnvFrom` so passwords never end up in `values.yaml`.

### Redis (ElastiCache / Memorystore)

```yaml
redis:
  internal: false
  externalUrl: "rediss://:supersecret@cullis-redis.xxx.cache.amazonaws.com:6379/0"
```

The DPoP JTI store, sliding-window rate limiter and WebSocket pub/sub all
need Redis. Without it the broker degrades to in-memory mode and HA across
replicas breaks (per-pod state).

### Vault (external HashiCorp Vault)

```yaml
vault:
  internal: false
  externalAddr: "https://vault.corp.example.com:8200"
  kmsBackend: vault
  secretPath: "secret/data/cullis-broker"
```

For the Vault token, prefer Kubernetes auth (projected ServiceAccount
token) bound to a Vault role rather than a static token. When you must use
a static token, supply it via the broker Secret:

```yaml
secrets:
  vaultToken: "hvs.xxxx"
```

…or via an `ExternalSecret` (see below).

## Dev install (kind / minikube)

`values-dev.yaml` flips every dependency to in-cluster, disables the
NetworkPolicy and HPA, and bumps Jaeger on:

```bash
kind create cluster --name cullis
helm install cullis ./deploy/helm/cullis \
  -n cullis --create-namespace \
  -f deploy/helm/cullis/values-dev.yaml
```

Then add a hosts entry pointing the chosen `ingress.host` at your kind
LB or use `kubectl port-forward svc/cullis-broker 8000:8000` and open
`http://127.0.0.1:8000/dashboard/login`.

## Upgrade

The broker uses a 5-second `preStop sleep` followed by a uvicorn graceful
shutdown (item 4 of the production plan). When you `helm upgrade` Helm
performs a rolling update; the chart configures `maxUnavailable: 0` so
there is always at least one ready replica behind the Ingress, and the
`PodDisruptionBudget` (`minAvailable: 1`) protects against simultaneous
voluntary evictions during a node drain.

```bash
helm upgrade cullis ./deploy/helm/cullis -f values-prod.yaml
```

If you change the broker image tag the rollout drains old pods one at a
time, sending close code 1012 ("service restart") on every WebSocket so
that the Cullis SDK reconnects with backoff instead of erroring.

## Secrets via SealedSecret or ExternalSecret

Set `secrets.create=false` and create the Secret yourself:

### SealedSecret

```yaml
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: cullis-broker
  namespace: cullis
spec:
  encryptedData:
    ADMIN_SECRET: AgB...
    DATABASE_URL: AgB...
    REDIS_URL: AgB...
    VAULT_TOKEN: AgB...
```

Then install with:

```bash
helm install cullis ./deploy/helm/cullis \
  -f values-prod.yaml \
  --set secrets.create=false \
  --set secrets.existingSecret=cullis-broker
```

### ExternalSecret (External Secrets Operator)

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: cullis-broker
  namespace: cullis
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secretsmanager
    kind: ClusterSecretStore
  target:
    name: cullis-broker
    creationPolicy: Owner
  data:
    - secretKey: ADMIN_SECRET
      remoteRef:
        key: cullis/broker/admin_secret
    - secretKey: DATABASE_URL
      remoteRef:
        key: cullis/broker/database_url
    - secretKey: REDIS_URL
      remoteRef:
        key: cullis/broker/redis_url
    - secretKey: VAULT_TOKEN
      remoteRef:
        key: cullis/broker/vault_token
```

## Values reference

| Key | Default | Description |
|-----|---------|-------------|
| `nameOverride` | `""` | Override chart name (per release). |
| `fullnameOverride` | `""` | Override fully qualified name. |
| `imagePullSecrets` | `[]` | Image pull secrets applied to every pod. |
| `broker.image.repository` | `ghcr.io/cullis-security/cullis` | Broker image repo. |
| `broker.image.tag` | `""` | Image tag (defaults to chart `appVersion`). |
| `broker.image.pullPolicy` | `IfNotPresent` | Image pull policy. |
| `broker.replicaCount` | `2` | Static replica count when HPA disabled. |
| `broker.environment` | `production` | Sets `ENVIRONMENT` env var. |
| `broker.logFormat` | `json` | Sets `LOG_FORMAT`. Use `json` for SIEM ingestion. |
| `broker.containerPort` | `8000` | Container port (matches Dockerfile). |
| `broker.resources` | `200m/256Mi → 1000m/1Gi` | CPU/memory requests + limits. |
| `broker.terminationGracePeriodSeconds` | `40` | Aligned with item 4 graceful shutdown budget. |
| `broker.prometheusEnabled` | `true` | Toggle `/metrics` exporter. |
| `broker.extraEnv` | `[]` | Extra env vars (OIDC, KMS, custom config). |
| `broker.extraEnvFrom` | `[]` | Extra envFrom sources (e.g. ExternalSecret-backed Secret). |
| `broker.extraVolumes` | `[]` | Extra pod volumes. |
| `broker.extraVolumeMounts` | `[]` | Extra container mounts. |
| `broker.podAnnotations` | `{}` | Extra pod annotations. |
| `broker.podLabels` | `{}` | Extra pod labels. |
| `broker.podSecurityContext` | non-root, fsGroup 1000, seccomp RuntimeDefault | Pod-level securityContext. |
| `broker.securityContext` | drop ALL caps, no privilege escalation | Container-level securityContext. |
| `broker.nodeSelector` | `{}` | Node selector. |
| `broker.tolerations` | `[]` | Tolerations. |
| `broker.affinity` | preferred pod anti-affinity by hostname | Affinity rules. |
| `broker.livenessProbe` | `/healthz` | Liveness probe spec. |
| `broker.readinessProbe` | `/readyz` | Readiness probe spec — flips to 503 during drain. |
| `broker.startupProbe` | `/healthz` | Optional startup probe (handles first migration). |
| `broker.preStopSleepSeconds` | `5` | Sleep before SIGTERM so Service endpoints catch up. |
| `broker.service.type` | `ClusterIP` | Broker Service type. |
| `broker.service.port` | `8000` | Broker Service port. |
| `broker.service.annotations` | `{}` | Extra annotations on the broker Service. |
| `broker.serviceAccount.create` | `true` | Create a dedicated ServiceAccount. |
| `broker.serviceAccount.name` | `""` | Override the SA name. |
| `broker.serviceAccount.annotations` | `{}` | SA annotations (IRSA / Workload Identity). |
| `secrets.create` | `true` | Render the broker Secret from chart values. |
| `secrets.existingSecret` | `""` | Use a user-managed Secret instead. |
| `secrets.adminSecret` | `""` | Admin console HMAC + initial admin password. **REQUIRED** for production. |
| `secrets.dashboardSigningKey` | `""` | Dashboard cookie signing key (auto when empty). |
| `secrets.oidcClientSecret` | `""` | OIDC client secret. |
| `secrets.vaultToken` | `""` | Vault token (when not using K8s auth). |
| `secrets.anthropicApiKey` | `""` | Anthropic API key for the LLM judge (optional). |
| `secrets.extra` | `{}` | Free-form extra secret entries. |
| `postgres.internal` | `false` | Deploy in-cluster Postgres (dev only). |
| `postgres.externalUrl` | `""` | External Postgres URL (REQUIRED when `internal=false`). |
| `postgres.existingSecret` | `""` | Existing Secret with `database-url` key. |
| `postgres.image` | `postgres:16-alpine` | In-cluster Postgres image. |
| `postgres.storageSize` | `20Gi` | PVC size for in-cluster Postgres. |
| `postgres.storageClassName` | `""` | StorageClass override. |
| `postgres.username` / `password` / `database` / `port` | `cullis / cullis-dev-password / cullis / 5432` | In-cluster Postgres credentials. |
| `postgres.resources` | `200m/256Mi → 1000m/1Gi` | In-cluster Postgres resources. |
| `redis.internal` | `false` | Deploy in-cluster Redis (dev only). |
| `redis.externalUrl` | `""` | External Redis URL (REQUIRED when `internal=false`). |
| `redis.existingSecret` | `""` | Existing Secret with `redis-url` key. |
| `redis.image` | `redis:7-alpine` | In-cluster Redis image. |
| `redis.storageSize` | `5Gi` | PVC size. |
| `redis.storageClassName` | `""` | StorageClass override. |
| `redis.port` | `6379` | Redis port. |
| `redis.resources` | `100m/128Mi → 500m/512Mi` | Redis resources. |
| `vault.internal` | `false` | Deploy in-cluster Vault dev mode (dev only). |
| `vault.externalAddr` | `""` | External Vault address (REQUIRED when `internal=false`). |
| `vault.externalTokenSecretName` | `""` | Existing Secret with the Vault token. |
| `vault.kmsBackend` | `vault` | KMS backend (`vault` or `local`). |
| `vault.secretPath` | `secret/data/broker` | Vault KV v2 secret path. |
| `vault.image` | `hashicorp/vault:1.17` | In-cluster Vault image. |
| `vault.port` | `8200` | Vault port. |
| `vault.storageSize` | `2Gi` | PVC size. |
| `vault.devRootToken` | `dev-root-token` | Dev root token (in-cluster only). |
| `jaeger.enabled` | `false` | Deploy Jaeger all-in-one for OTLP traces. |
| `jaeger.image` | `jaegertracing/all-in-one:1.57` | Jaeger image. |
| `jaeger.otlpGrpcPort` | `4317` | OTLP gRPC port. |
| `jaeger.uiPort` | `16686` | Jaeger UI port. |
| `ingress.enabled` | `true` | Render an Ingress in front of the broker Service. |
| `ingress.className` | `nginx` | IngressClass name. |
| `ingress.host` | `cullis.example.com` | Public hostname. **REQUIRED** for production. |
| `ingress.path` | `/` | Path prefix. |
| `ingress.pathType` | `Prefix` | Path type. |
| `ingress.annotations` | `{}` | Extra annotations merged with the websocket/TLS defaults. |
| `ingress.tls.enabled` | `true` | Terminate TLS at the Ingress. |
| `ingress.tls.certManagerIssuer` | `letsencrypt-prod` | cert-manager issuer name. |
| `ingress.tls.certManagerIssuerKind` | `ClusterIssuer` | Issuer kind (`ClusterIssuer` or `Issuer`). |
| `ingress.tls.secretName` | `""` | Override the TLS secret name. |
| `monitoring.prometheusRule.enabled` | `true` | Render the PrometheusRule CRD. |
| `monitoring.prometheusRule.labels` | `{}` | Extra labels (Prometheus Operator selector). |
| `monitoring.prometheusRule.annotations` | `{}` | Extra annotations. |
| `monitoring.serviceMonitor.enabled` | `true` | Render the ServiceMonitor CRD. |
| `monitoring.serviceMonitor.interval` | `30s` | Scrape interval. |
| `monitoring.serviceMonitor.scrapeTimeout` | `10s` | Scrape timeout. |
| `monitoring.serviceMonitor.labels` | `{}` | Extra labels (Prometheus Operator selector). |
| `monitoring.serviceMonitor.targetLabels` | `[]` | Target labels propagation. |
| `monitoring.serviceMonitor.metricRelabelings` | `[]` | Metric relabel configs. |
| `monitoring.serviceMonitor.relabelings` | `[]` | Relabel configs. |
| `networkPolicy.enabled` | `true` | Render the broker NetworkPolicy. |
| `networkPolicy.ingressNamespace` | `ingress-nginx` | Namespace where the ingress controller runs. |
| `networkPolicy.extraEgress` | `[]` | Extra egress rules (e.g. to PDP webhook). |
| `autoscaling.enabled` | `true` | Enable HPA. |
| `autoscaling.minReplicas` | `2` | HPA min replicas. |
| `autoscaling.maxReplicas` | `10` | HPA max replicas. |
| `autoscaling.targetCPUUtilizationPercentage` | `70` | HPA CPU target. |
| `autoscaling.targetMemoryUtilizationPercentage` | `0` | HPA memory target (0 disables). |
| `podDisruptionBudget.enabled` | `true` | Render PodDisruptionBudget. |
| `podDisruptionBudget.minAvailable` | `1` | PDB minimum available pods. |
| `podDisruptionBudget.maxUnavailable` | `""` | PDB max unavailable (overrides minAvailable when set). |

## Critical values to set before installing

1. `secrets.adminSecret` — admin console + dashboard cookie HMAC. Generate
   with `openssl rand -hex 32`. Empty value will be auto-generated by Helm
   on each upgrade unless pinned.
2. `ingress.host` — public DNS name reachable by the agents.
3. `ingress.tls.certManagerIssuer` — name of the cert-manager
   `ClusterIssuer` (e.g. `letsencrypt-prod`) or set `ingress.tls.secretName`
   to a pre-provisioned TLS secret.
4. `postgres.externalUrl` (or `postgres.internal=true` for dev only).
5. `redis.externalUrl` (or `redis.internal=true` for dev only).
6. `vault.externalAddr` and `secrets.vaultToken` (or use Kubernetes auth).
7. `broker.image.tag` — pin to a specific release tag, do not rely on the
   chart `appVersion` in production.

## Dashboards

The chart renders the Prometheus Operator CRDs (`ServiceMonitor` +
`PrometheusRule`), but does not bundle a Grafana dashboard. A drop-in
dashboard for the Session Reliability Layer (M1 + M2 + M3 — offline
queue, WebSocket heartbeat, session resume, sweeper) lives at
[`enterprise-kit/monitoring/cullis-session-reliability.json`](../../../enterprise-kit/monitoring/cullis-session-reliability.json).
Import it via **Grafana → Dashboards → New → Import** and point the
`$datasource` variable at the Prometheus instance scraping this chart.

## Validation

```bash
helm lint deploy/helm/cullis
helm template deploy/helm/cullis > /dev/null
helm template deploy/helm/cullis -f deploy/helm/cullis/values-dev.yaml > /dev/null
```

For Prometheus Operator CRDs (`PrometheusRule`, `ServiceMonitor`) the
`helm template` rendering does not require the CRDs to be installed; the
CRDs only need to exist in the target cluster at install time. If your
cluster does not run Prometheus Operator set
`monitoring.prometheusRule.enabled=false` and
`monitoring.serviceMonitor.enabled=false`.
