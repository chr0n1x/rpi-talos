kubectl -n ingress-nginx wait --for=condition=available deployment ingress-nginx-controller

kubectl -n ingress-nginx wait job --all --for condition=Complete
