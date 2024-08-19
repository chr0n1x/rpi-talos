kubectl -n argocd wait --for=condition=Available deployments argocd-server

kubectl -n argocd patch -p '{"data": { "kustomize.buildOptions": "--enable-helm" } }' --type=merge configmap argocd-cm
