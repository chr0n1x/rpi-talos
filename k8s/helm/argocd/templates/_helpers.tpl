{{- define "argocd-watch.scriptChecksum" -}}
{{- .Files.Get "scripts/argocd_watch.py" | sha256sum -}}
{{- end -}}
