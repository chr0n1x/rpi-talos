kubectl -n argocd wait --for=condition=Ready deployments argocd-server

kubectl -n argocd patch -p '{"data": { "kustomize.buildOptions": "--enable-helm" } }' --type=merge configmap argocd-cm

# HACK: cannot track down the damn nginx validation webhook error
cat <<EOF | kubectl apply -f -
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    nginx.ingress.kubernetes.io/backend-protocol: "HTTP"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "false"
    nginx.ingress.kubernetes.io/ssl-passthrough: "true"

    nginx.ingress.kubernetes.io/auth-url: https://oauth2-proxy.home.k8s:30443/oauth2/auth
    # don't feel too good about this; ideally should be \$server_port, but
    # using a NodePort instead of an actual LB doesn't seem to allow this (TBD)
    nginx.ingress.kubernetes.io/auth-signin: "https://oauth2-proxy.home.k8s:30443/oauth2/start?rd=\$scheme://\$host:30443\$request_uri"
    nginx.ingress.kubernetes.io/auth-response-headers: X-Auth-Request-User,X-Auth-Request-Email,X-Forwarded-Groups
  name: argo-cd-argocd-server
  namespace: argocd
spec:
  ingressClassName: nginx
  rules:
    - host: argocd.home.k8s
      http:
        paths:
        - path: /
          pathType: Prefix
          backend:
            service:
              name: argocd-server
              port:
                name: http
EOF
