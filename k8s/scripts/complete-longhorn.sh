kubectl label namespace longhorn-system pod-security.kubernetes.io/enforce=privileged
kubectl label StorageClass longhorn storageclass.kubernetes.io/is-default-class=true

