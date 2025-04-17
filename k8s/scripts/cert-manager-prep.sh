kubectl create ns cert-manager || :

kubectl annotate --overwrite=true ns cert-manager meta.helm.sh/release-name=cert-manager || :
kubectl annotate --overwrite=true ns cert-manager meta.helm.sh/release-namespace=cert-manager || :
kubectl label ns cert-manager app.kubernetes.io/managed-by=Helm || :

kubectl label ns cert-manager "pod-security.kubernetes.io/audit=privileged" || :
kubectl label ns cert-manager "pod-security.kubernetes.io/enforce=privileged" || :
kubectl label ns cert-manager "pod-security.kubernetes.io/warn=privileged" || :
