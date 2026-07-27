{{- define "wallet.name" -}}{{ .Chart.Name }}{{- end -}}
{{- define "wallet.fullname" -}}{{ printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" }}{{- end -}}
{{- define "wallet.labels" -}}
app.kubernetes.io/name: {{ include "wallet.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}
{{- define "wallet.selectorLabels" -}}
app.kubernetes.io/name: {{ include "wallet.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
