kubectl create ns ingress-nginx || :

kubectl annotate --overwrite=true ns ingress-nginx meta.helm.sh/release-name=ingress-nginx
kubectl annotate --overwrite=true ns ingress-nginx meta.helm.sh/release-namespace=ingress-nginx
kubectl label ns ingress-nginx app.kubernetes.io/managed-by=Helm
