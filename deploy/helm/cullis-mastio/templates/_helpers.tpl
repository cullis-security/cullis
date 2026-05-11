{{/*
Expand the name of the chart.
*/}}
{{- define "cullis-mastio.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
Truncated at 63 chars because some Kubernetes name fields are limited.
*/}}
{{- define "cullis-mastio.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Chart label value (chart name + version, dots replaced by underscores).
*/}}
{{- define "cullis-mastio.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Standard Helm 3 labels applied to every object rendered by the chart.
*/}}
{{- define "cullis-mastio.labels" -}}
helm.sh/chart: {{ include "cullis-mastio.chart" . }}
{{ include "cullis-mastio.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: cullis
{{- end -}}

{{/*
Selector labels — stable subset used in matchLabels of workloads.
*/}}
{{- define "cullis-mastio.selectorLabels" -}}
app.kubernetes.io/name: {{ include "cullis-mastio.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Proxy-specific labels (adds the component tag).
*/}}
{{- define "cullis-mastio.proxy.labels" -}}
{{ include "cullis-mastio.labels" . }}
app.kubernetes.io/component: proxy
{{- end -}}

{{- define "cullis-mastio.proxy.selectorLabels" -}}
{{ include "cullis-mastio.selectorLabels" . }}
app.kubernetes.io/component: proxy
{{- end -}}

{{/*
Proxy ServiceAccount name.
*/}}
{{- define "cullis-mastio.serviceAccountName" -}}
{{- if .Values.proxy.serviceAccount.create -}}
{{- default (include "cullis-mastio.fullname" .) .Values.proxy.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.proxy.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Workload resource names.
*/}}
{{- define "cullis-mastio.proxy.fullname" -}}
{{- include "cullis-mastio.fullname" . -}}
{{- end -}}

{{/*
Name of the proxy Secret (user-managed or chart-managed).
*/}}
{{- define "cullis-mastio.secretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{- .Values.secrets.existingSecret -}}
{{- else -}}
{{- printf "%s-env" (include "cullis-mastio.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/*
Name of the proxy ConfigMap.
*/}}
{{- define "cullis-mastio.configMapName" -}}
{{- printf "%s-env" (include "cullis-mastio.fullname" .) -}}
{{- end -}}

{{/*
Name of the PVC that backs /data.
*/}}
{{- define "cullis-mastio.pvcName" -}}
{{- if .Values.persistence.existingClaim -}}
{{- .Values.persistence.existingClaim -}}
{{- else -}}
{{- printf "%s-data" (include "cullis-mastio.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/*
Proxy image reference.
*/}}
{{- define "cullis-mastio.image" -}}
{{- $tag := .Values.proxy.image.tag | default .Chart.AppVersion -}}
{{- printf "%s:%s" .Values.proxy.image.repository $tag -}}
{{- end -}}

{{/*
Name of the TLS secret referenced by the Ingress.
*/}}
{{- define "cullis-mastio.ingress.tlsSecretName" -}}
{{- if .Values.ingress.tls.secretName -}}
{{- .Values.ingress.tls.secretName -}}
{{- else -}}
{{- printf "%s-tls" (include "cullis-mastio.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/*
Postgres-specific labels.
*/}}
{{- define "cullis-mastio.postgres.labels" -}}
{{ include "cullis-mastio.labels" . }}
app.kubernetes.io/component: postgres
{{- end -}}

{{- define "cullis-mastio.postgres.selectorLabels" -}}
{{ include "cullis-mastio.selectorLabels" . }}
app.kubernetes.io/component: postgres
{{- end -}}

{{- define "cullis-mastio.postgres.fullname" -}}
{{- printf "%s-postgres" (include "cullis-mastio.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Resolve the proxy database URL. Precedence (high → low):
  1. postgres.externalUrl  → user-managed Postgres (preferred for prod)
  2. postgres.internal     → in-cluster Postgres StatefulSet
  3. SQLite on the PVC     → default, single-replica only

Phase 1.4 (ADR-001): when Postgres is in use the proxy reads PROXY_DB_URL
from the ConfigMap; SQLite path keeps emitting MCP_PROXY_DATABASE_URL for
backwards compatibility with deployments still on the legacy env name.
*/}}
{{- define "cullis-mastio.databaseUrl" -}}
{{- if .Values.postgres.externalUrl -}}
{{- .Values.postgres.externalUrl -}}
{{- else if .Values.postgres.internal -}}
{{- printf "postgresql+asyncpg://%s:%s@%s:%d/%s"
    .Values.postgres.username
    (include "cullis-mastio.postgresPassword" .)
    (include "cullis-mastio.postgres.fullname" .)
    (int .Values.postgres.port)
    .Values.postgres.database -}}
{{- else -}}
{{- printf "sqlite+aiosqlite:///%s/mcp_proxy.db" .Values.persistence.mountPath -}}
{{- end -}}
{{- end -}}

{{/*
Wave B F3 (audit 2026-05-11) — internal-Postgres credential resolver.

Pre-fix the chart shipped a deterministic literal default
(``cullis-mastio-dev-password``) — every fresh install had the same
world-known DB password.

Post-fix the default is the explicit sentinel
``INSECURE-DEV-DEFAULT-please-override-via-set-postgres-password``.
This helper passes the configured value through verbatim BUT calls
``fail`` when production environment is targeted with the sentinel
still in place — caught at template render time, not at "DB
unreachable" debugging time later.

An earlier draft used ``lookup`` + ``randAlphaNum`` to auto-generate
and persist a random per-release password. That pattern broke on
cold install: Helm renders multiple templates that each call this
helper, and ``lookup`` returning nil on first render yields a
different ``randAlphaNum`` per call site → StatefulSet POSTGRES_PASSWORD
diverged from the ConfigMap DATABASE_URL. Reverted to the
explicit-override pattern.
*/}}
{{- define "cullis-mastio.postgresPassword" -}}
{{- $sentinel := "INSECURE-DEV-DEFAULT-please-override-via-set-postgres-password" -}}
{{- if and (eq .Values.postgres.password $sentinel) (eq (default "" .Values.proxy.environment) "production") -}}
{{- fail "postgres.password is the INSECURE default. Set --set postgres.password=<strong-random> before installing in production (proxy.environment=production)." -}}
{{- end -}}
{{- .Values.postgres.password -}}
{{- end -}}

{{/*
True when the chart is configured to run on Postgres (either external or
in-cluster). Used to skip the SQLite PVC and to gate Postgres-specific
secret keys.
*/}}
{{- define "cullis-mastio.usesPostgres" -}}
{{- if or .Values.postgres.externalUrl .Values.postgres.internal -}}
true
{{- end -}}
{{- end -}}
