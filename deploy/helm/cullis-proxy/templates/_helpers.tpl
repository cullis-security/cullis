{{/*
Expand the name of the chart.
*/}}
{{- define "cullis-proxy.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
Truncated at 63 chars because some Kubernetes name fields are limited.
*/}}
{{- define "cullis-proxy.fullname" -}}
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
{{- define "cullis-proxy.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Standard Helm 3 labels applied to every object rendered by the chart.
*/}}
{{- define "cullis-proxy.labels" -}}
helm.sh/chart: {{ include "cullis-proxy.chart" . }}
{{ include "cullis-proxy.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: cullis
{{- end -}}

{{/*
Selector labels — stable subset used in matchLabels of workloads.
*/}}
{{- define "cullis-proxy.selectorLabels" -}}
app.kubernetes.io/name: {{ include "cullis-proxy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Proxy-specific labels (adds the component tag).
*/}}
{{- define "cullis-proxy.proxy.labels" -}}
{{ include "cullis-proxy.labels" . }}
app.kubernetes.io/component: proxy
{{- end -}}

{{- define "cullis-proxy.proxy.selectorLabels" -}}
{{ include "cullis-proxy.selectorLabels" . }}
app.kubernetes.io/component: proxy
{{- end -}}

{{/*
Proxy ServiceAccount name.
*/}}
{{- define "cullis-proxy.serviceAccountName" -}}
{{- if .Values.proxy.serviceAccount.create -}}
{{- default (include "cullis-proxy.fullname" .) .Values.proxy.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.proxy.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Workload resource names.
*/}}
{{- define "cullis-proxy.proxy.fullname" -}}
{{- include "cullis-proxy.fullname" . -}}
{{- end -}}

{{/*
Name of the proxy Secret (user-managed or chart-managed).
*/}}
{{- define "cullis-proxy.secretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{- .Values.secrets.existingSecret -}}
{{- else -}}
{{- printf "%s-env" (include "cullis-proxy.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/*
Name of the proxy ConfigMap.
*/}}
{{- define "cullis-proxy.configMapName" -}}
{{- printf "%s-env" (include "cullis-proxy.fullname" .) -}}
{{- end -}}

{{/*
Name of the PVC that backs /data.
*/}}
{{- define "cullis-proxy.pvcName" -}}
{{- if .Values.persistence.existingClaim -}}
{{- .Values.persistence.existingClaim -}}
{{- else -}}
{{- printf "%s-data" (include "cullis-proxy.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/*
Proxy image reference.
*/}}
{{- define "cullis-proxy.image" -}}
{{- $tag := .Values.proxy.image.tag | default .Chart.AppVersion -}}
{{- printf "%s:%s" .Values.proxy.image.repository $tag -}}
{{- end -}}

{{/*
Name of the TLS secret referenced by the Ingress.
*/}}
{{- define "cullis-proxy.ingress.tlsSecretName" -}}
{{- if .Values.ingress.tls.secretName -}}
{{- .Values.ingress.tls.secretName -}}
{{- else -}}
{{- printf "%s-tls" (include "cullis-proxy.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/*
Postgres-specific labels.
*/}}
{{- define "cullis-proxy.postgres.labels" -}}
{{ include "cullis-proxy.labels" . }}
app.kubernetes.io/component: postgres
{{- end -}}

{{- define "cullis-proxy.postgres.selectorLabels" -}}
{{ include "cullis-proxy.selectorLabels" . }}
app.kubernetes.io/component: postgres
{{- end -}}

{{- define "cullis-proxy.postgres.fullname" -}}
{{- printf "%s-postgres" (include "cullis-proxy.fullname" .) | trunc 63 | trimSuffix "-" -}}
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
{{- define "cullis-proxy.databaseUrl" -}}
{{- if .Values.postgres.externalUrl -}}
{{- .Values.postgres.externalUrl -}}
{{- else if .Values.postgres.internal -}}
{{- printf "postgresql+asyncpg://%s:%s@%s:%d/%s"
    .Values.postgres.username
    .Values.postgres.password
    (include "cullis-proxy.postgres.fullname" .)
    (int .Values.postgres.port)
    .Values.postgres.database -}}
{{- else -}}
{{- printf "sqlite+aiosqlite:///%s/mcp_proxy.db" .Values.persistence.mountPath -}}
{{- end -}}
{{- end -}}

{{/*
True when the chart is configured to run on Postgres (either external or
in-cluster). Used to skip the SQLite PVC and to gate Postgres-specific
secret keys.
*/}}
{{- define "cullis-proxy.usesPostgres" -}}
{{- if or .Values.postgres.externalUrl .Values.postgres.internal -}}
true
{{- end -}}
{{- end -}}
