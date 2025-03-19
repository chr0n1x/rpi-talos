kubectl -n ingress-nginx wait --for=condition=available deployment ingress-nginx-controller

kubectl -n ingress-nginx wait job --all --for condition=Complete

kubectl expose deployment ingress-nginx-controller --type=LoadBalancer --name=ingress-nginx-controller || :
