kubectl -n longhorn-system patch -p '{"value": "true"}' --type=merge lhs deleting-confirmation-flag

helm uninstall longhorn -n longhorn-system
