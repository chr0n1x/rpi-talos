# HACK: I hate this ecosystem


rm helm/argocd/Chart.lock || :

kubectl apply -k https://github.com/argoproj/argo-cd/manifests/crds?ref=stable

kubectl annotate --overwrite=true -n argocd crd applications.argoproj.io meta.helm.sh/release-name=argocd
kubectl annotate --overwrite=true -n argocd crd applications.argoproj.io meta.helm.sh/release-namespace=argocd
kubectl annotate --overwrite=true -n argocd crd applicationsets.argoproj.io meta.helm.sh/release-name=argocd
kubectl annotate --overwrite=true -n argocd crd applicationsets.argoproj.io meta.helm.sh/release-namespace=argocd
kubectl annotate --overwrite=true -n argocd crd appprojects.argoproj.io meta.helm.sh/release-name=argocd
kubectl annotate --overwrite=true -n argocd crd appprojects.argoproj.io meta.helm.sh/release-namespace=argocd
