{{/*
Expand the name of the chart.
*/}}
{{- define "cullis.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
Truncated at 63 chars because some Kubernetes name fields are limited.
*/}}
{{- define "cullis.fullname" -}}
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
{{- define "cullis.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Standard Helm 3 labels applied to every object rendered by the chart.
*/}}
{{- define "cullis.labels" -}}
helm.sh/chart: {{ include "cullis.chart" . }}
{{ include "cullis.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: cullis
{{- end -}}

{{/*
Selector labels — stable subset used in matchLabels of workloads.
*/}}
{{- define "cullis.selectorLabels" -}}
app.kubernetes.io/name: {{ include "cullis.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Broker-specific labels (adds the component tag).
*/}}
{{- define "cullis.broker.labels" -}}
{{ include "cullis.labels" . }}
app.kubernetes.io/component: broker
{{- end -}}

{{- define "cullis.broker.selectorLabels" -}}
{{ include "cullis.selectorLabels" . }}
app.kubernetes.io/component: broker
{{- end -}}

{{/*
Postgres-specific labels.
*/}}
{{- define "cullis.postgres.labels" -}}
{{ include "cullis.labels" . }}
app.kubernetes.io/component: postgres
{{- end -}}

{{- define "cullis.postgres.selectorLabels" -}}
{{ include "cullis.selectorLabels" . }}
app.kubernetes.io/component: postgres
{{- end -}}

{{/*
Redis-specific labels.
*/}}
{{- define "cullis.redis.labels" -}}
{{ include "cullis.labels" . }}
app.kubernetes.io/component: redis
{{- end -}}

{{- define "cullis.redis.selectorLabels" -}}
{{ include "cullis.selectorLabels" . }}
app.kubernetes.io/component: redis
{{- end -}}

{{/*
Vault-specific labels.
*/}}
{{- define "cullis.vault.labels" -}}
{{ include "cullis.labels" . }}
app.kubernetes.io/component: vault
{{- end -}}

{{- define "cullis.vault.selectorLabels" -}}
{{ include "cullis.selectorLabels" . }}
app.kubernetes.io/component: vault
{{- end -}}

{{/*
Jaeger-specific labels.
*/}}
{{- define "cullis.jaeger.labels" -}}
{{ include "cullis.labels" . }}
app.kubernetes.io/component: jaeger
{{- end -}}

{{- define "cullis.jaeger.selectorLabels" -}}
{{ include "cullis.selectorLabels" . }}
app.kubernetes.io/component: jaeger
{{- end -}}

{{/*
Broker ServiceAccount name.
*/}}
{{- define "cullis.broker.serviceAccountName" -}}
{{- if .Values.broker.serviceAccount.create -}}
{{- default (printf "%s-broker" (include "cullis.fullname" .)) .Values.broker.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.broker.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Workload resource names.
*/}}
{{- define "cullis.broker.fullname" -}}
{{- printf "%s-broker" (include "cullis.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "cullis.postgres.fullname" -}}
{{- printf "%s-postgres" (include "cullis.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "cullis.redis.fullname" -}}
{{- printf "%s-redis" (include "cullis.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "cullis.vault.fullname" -}}
{{- printf "%s-vault" (include "cullis.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "cullis.jaeger.fullname" -}}
{{- printf "%s-jaeger" (include "cullis.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Name of the broker Secret (user-managed or chart-managed).
*/}}
{{- define "cullis.broker.secretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{- .Values.secrets.existingSecret -}}
{{- else -}}
{{- printf "%s-broker" (include "cullis.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/*
Name of the broker ConfigMap.
*/}}
{{- define "cullis.broker.configMapName" -}}
{{- printf "%s-broker-env" (include "cullis.fullname" .) -}}
{{- end -}}

{{/*
Broker image reference.
*/}}
{{- define "cullis.broker.image" -}}
{{- $tag := .Values.broker.image.tag | default .Chart.AppVersion -}}
{{- printf "%s:%s" .Values.broker.image.repository $tag -}}
{{- end -}}

{{/*
Resolved DATABASE_URL source. When postgres.internal is true, build a URL
from the in-cluster StatefulSet Service. Otherwise return externalUrl or
reference the existing Secret.
*/}}
{{- define "cullis.databaseUrl" -}}
{{- if .Values.postgres.internal -}}
{{- $svc := include "cullis.postgres.fullname" . -}}
{{- printf "postgresql+asyncpg://%s:%s@%s:%v/%s" .Values.postgres.username .Values.postgres.password $svc .Values.postgres.port .Values.postgres.database -}}
{{- else -}}
{{- .Values.postgres.externalUrl -}}
{{- end -}}
{{- end -}}

{{/*
Resolved REDIS_URL for the in-cluster fallback.
*/}}
{{- define "cullis.redisUrl" -}}
{{- if .Values.redis.internal -}}
{{- $svc := include "cullis.redis.fullname" . -}}
{{- printf "redis://%s:%v/0" $svc .Values.redis.port -}}
{{- else -}}
{{- .Values.redis.externalUrl -}}
{{- end -}}
{{- end -}}

{{/*
Resolved VAULT_ADDR for the in-cluster fallback.
*/}}
{{- define "cullis.vaultAddr" -}}
{{- if .Values.vault.internal -}}
{{- $svc := include "cullis.vault.fullname" . -}}
{{- printf "http://%s:%v" $svc .Values.vault.port -}}
{{- else -}}
{{- .Values.vault.externalAddr -}}
{{- end -}}
{{- end -}}

{{/*
Name of the Secret holding the broker CA (broker-ca.pem + broker-ca-key.pem).
Resolution order:
  1. broker.pki.existingSecret (explicit BYOCA)
  2. broker.pki.bootstrap.secretName (explicit bootstrap override)
  3. bootstrap default: <release>-broker-pki (when bootstrap enabled)
Returns empty string when no PKI source is configured — caller must
guard with `if`.
*/}}
{{- define "cullis.broker.pkiSecretName" -}}
{{- if .Values.broker.pki.existingSecret -}}
{{- .Values.broker.pki.existingSecret -}}
{{- else if .Values.broker.pki.bootstrap.enabled -}}
{{- if .Values.broker.pki.bootstrap.secretName -}}
{{- .Values.broker.pki.bootstrap.secretName -}}
{{- else -}}
{{- printf "%s-broker-pki" (include "cullis.fullname" .) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Name of the ServiceAccount used by the PKI bootstrap Job (needs
create/get Secrets RBAC in the release namespace).
*/}}
{{- define "cullis.broker.pkiBootstrap.serviceAccountName" -}}
{{- printf "%s-broker-pki-bootstrap" (include "cullis.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Broker PKI bootstrap image — defaults to the broker image (which ships
cryptography + httpx).
*/}}
{{- define "cullis.broker.pkiBootstrap.image" -}}
{{- $repo := .Values.broker.pki.bootstrap.image.repository | default .Values.broker.image.repository -}}
{{- $tag  := .Values.broker.pki.bootstrap.image.tag | default (.Values.broker.image.tag | default .Chart.AppVersion) -}}
{{- printf "%s:%s" $repo $tag -}}
{{- end -}}

{{/*
Name of the TLS secret referenced by the Ingress.
*/}}
{{- define "cullis.ingress.tlsSecretName" -}}
{{- if .Values.ingress.tls.secretName -}}
{{- .Values.ingress.tls.secretName -}}
{{- else -}}
{{- printf "%s-tls" (include "cullis.fullname" .) -}}
{{- end -}}
{{- end -}}
