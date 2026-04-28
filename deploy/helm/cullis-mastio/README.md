# Cullis MCP Proxy Helm Chart

Helm chart for the Cullis **MCP Proxy** — the org-level gateway that sits
between internal AI agents and the [Cullis](https://cullis.io) trust
broker. The chart is a structural mirror of the broker chart
(`deploy/helm/cullis/`): same label scheme, same security posture, same
ingress story.

> Status: work in progress, not yet production-validated. `helm lint` and
> `helm template` pass; end-to-end install on a managed cluster has not
> been exercised. Fork and harden for your environment.

## Quick start

Production install:

```bash
helm install cullis-mastio ./deploy/helm/cullis-mastio \
  --namespace cullis-mastio --create-namespace \
  --set ingress.host=proxy.myorg.example.com \
  --set proxy.brokerUrl=https://broker.cullis.example.com \
  --set proxy.brokerJwksUrl=https://broker.cullis.example.com/.well-known/jwks.json \
  --set proxy.proxyPublicUrl=https://proxy.myorg.example.com \
  --set proxy.pdpUrl=https://proxy.myorg.example.com/pdp/policy \
  --set secrets.adminSecret="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')" \
  --set secrets.dashboardSigningKey="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
```

Dev install on `kind` / `minikube`:

```bash
helm install cullis-mastio ./deploy/helm/cullis-mastio \
  --namespace cullis-mastio --create-namespace \
  -f deploy/helm/cullis-mastio/values-dev.yaml
```

## What the chart deploys

| Component        | Resource                 | Notes                                        |
|------------------|--------------------------|----------------------------------------------|
| Proxy            | Deployment, Service      | Single replica by default (SQLite-backed)    |
| Proxy (HA)       | HPA, PodDisruptionBudget | Opt-in, requires RWX storage for >1 replicas |
| Proxy (security) | NetworkPolicy            | Ingress from nginx + broker ns; egress locked down |
| Proxy (config)   | ConfigMap, Secret        | Secret can be replaced by SealedSecret / ExternalSecret |
| Proxy (auth)     | ServiceAccount           | Annotate for IRSA / Workload Identity        |
| Data             | PersistentVolumeClaim    | SQLite DB + audit log on /data               |
| Ingress          | Ingress (nginx + cert-manager) | Websocket annotations, TLS via ClusterIssuer |
| Monitoring       | ServiceMonitor (opt-in)  | Prometheus Operator CRD                      |
| Postgres (stub)  | StatefulSet, Service     | Only when `postgres.internal=true`; forward-compatible stub, proxy code does not use Postgres today |

## Persistence

The proxy persists two things on `/data`:

1. A SQLite database (`mcp_proxy.db`) with registered internal agents,
   audit log and dashboard configuration.
2. An append-only audit log (same DB file; rows never deleted).

The chart defaults to a 5 Gi PVC with `ReadWriteOnce`. Single-replica
deployments work on any StorageClass. To run multiple replicas the
volume must be `ReadWriteMany` — pick EFS (AWS), Filestore (GCP), Azure
Files or Longhorn RWX.

```yaml
proxy:
  replicaCount: 2
persistence:
  accessModes:
    - ReadWriteMany
  storageClassName: efs-sc
```

## Broker uplink

Three values must point at the broker:

| Key                        | Purpose                                              |
|----------------------------|------------------------------------------------------|
| `proxy.brokerUrl`          | Base URL for admin + egress calls to the broker       |
| `proxy.brokerJwksUrl`      | JWKS endpoint for validating broker-signed JWTs       |
| `proxy.pdpUrl`             | URL the broker calls to reach this proxy's PDP       |

When the broker TLS cert is signed by a non-public CA (corporate root,
Let's Encrypt staging, etc) mount the CA bundle and point the proxy at
it:

```yaml
proxy:
  brokerCaBundle: /certs/corporate-ca.pem
  extraVolumes:
    - name: broker-ca
      configMap:
        name: broker-ca-bundle
        items:
          - key: ca.pem
            path: corporate-ca.pem
  extraVolumeMounts:
    - name: broker-ca
      mountPath: /certs
      readOnly: true
```

## Vault backend (optional)

When `vault.enabled=true` the proxy reads tool secrets from Vault KV v2
instead of environment variables:

```yaml
vault:
  enabled: true
  addr: https://vault.corp.example.com:8200
  secretPrefix: secret/data/mcp-proxy/tools

secrets:
  vaultToken: "hvs.xxxx"   # or use Kubernetes auth via the SA below

proxy:
  serviceAccount:
    annotations:
      vault.hashicorp.com/role: cullis-mastio
```

For production prefer the Vault Agent Injector (sidecar) or External
Secrets Operator over a static token in Helm values — see the commented
examples in `values.yaml`.

## Secrets via SealedSecret or ExternalSecret

Set `secrets.create=false` and create the Secret yourself:

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: cullis-mastio-env
  namespace: cullis-mastio
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secretsmanager
    kind: ClusterSecretStore
  target:
    name: cullis-mastio-env
    creationPolicy: Owner
  data:
    - secretKey: MCP_PROXY_ADMIN_SECRET
      remoteRef:
        key: cullis-mastio/admin_secret
    - secretKey: MCP_PROXY_DASHBOARD_SIGNING_KEY
      remoteRef:
        key: cullis-mastio/dashboard_signing_key
```

Then install with:

```bash
helm install cullis-mastio ./deploy/helm/cullis-mastio \
  --set secrets.create=false \
  --set secrets.existingSecret=cullis-mastio-env
```

## Security posture

* `podSecurityContext`: `runAsNonRoot: true`, `runAsUser: 1000`,
  `fsGroup: 1000`, `seccompProfile: RuntimeDefault`.
* `securityContext`: `allowPrivilegeEscalation: false`, `capabilities:
  drop: [ALL]`.
* `automountServiceAccountToken: false` on the ServiceAccount.
* NetworkPolicy restricts ingress to the nginx ingress controller
  namespace (+ optionally the broker namespace for the PDP webhook) and
  egress to DNS, HTTPS and, when enabled, Vault.
* Ingress annotates websocket support and backend protocol for the
  nginx ingress controller.

`readOnlyRootFilesystem` is left false because the proxy writes SQLite
temp files next to the DB. Flip it to true by adding a dedicated
`emptyDir` mount on `/tmp` if your security baseline requires it.

## Validation

```bash
helm lint deploy/helm/cullis-mastio
helm template deploy/helm/cullis-mastio > /dev/null
helm template deploy/helm/cullis-mastio -f deploy/helm/cullis-mastio/values-dev.yaml > /dev/null
```

The `ServiceMonitor` is only rendered when
`monitoring.serviceMonitor.enabled=true`. The Prometheus Operator CRDs do
not need to be installed at `helm template` time; they must exist in the
cluster at `helm install` time.

## Upgrade

```bash
helm upgrade cullis-mastio ./deploy/helm/cullis-mastio -f values-prod.yaml
```

The Deployment uses `maxSurge: 1, maxUnavailable: 0` and a 5 s
`preStop sleep` so there is always a Ready pod behind the Service during
a rolling update. A `PodDisruptionBudget` (opt-in) protects against
simultaneous voluntary evictions during a node drain.
