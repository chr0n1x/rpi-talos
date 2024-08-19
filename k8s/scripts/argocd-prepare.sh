# HACK: I hate this ecosystem


rm helm/argocd/Chart.lock || :

kubectl apply -k https://github.com/argoproj/argo-cd/manifests/crds?ref=stable

kubectl annotate --overwrite=true -n argocd crd applications.argoproj.io meta.helm.sh/release-name=argocd
kubectl annotate --overwrite=true -n argocd crd applications.argoproj.io meta.helm.sh/release-namespace=argocd
kubectl label -n argocd crd applications.argoproj.io app.kubernetes.io/managed-by=Helm

kubectl annotate --overwrite=true -n argocd crd applicationsets.argoproj.io meta.helm.sh/release-name=argocd
kubectl annotate --overwrite=true -n argocd crd applicationsets.argoproj.io meta.helm.sh/release-namespace=argocd
kubectl label -n argocd crd applicationsets.argoproj.io app.kubernetes.io/managed-by=Helm

kubectl annotate --overwrite=true -n argocd crd appprojects.argoproj.io meta.helm.sh/release-name=argocd
kubectl annotate --overwrite=true -n argocd crd appprojects.argoproj.io meta.helm.sh/release-namespace=argocd
kubectl label -n argocd crd appprojects.argoproj.io app.kubernetes.io/managed-by=Helm

# HACK: cannot track down the damn nginx validation webhook error
kubectl -n argocd delete ingress --all
