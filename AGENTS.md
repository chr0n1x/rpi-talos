# AGENTS.md

Instructions for AI agents working in this repo.

**This is effectively a production cluster.** Every change - a one-line value tweak, a
chart bump, a namespace label - goes to live infrastructure running ~30
services that the user depends on daily. Treat all operations with
production-level care: verify before changing, prefer the smallest possible
diff, and never batch unrelated changes.

## What this is

A Raspberry Pi Kubernetes cluster (Talos Linux) running ~30 services
managed via GitOps. 3 RPi5 control-plane nodes, 6 workers (RPi5, RPi4,
zimaboard, one with NVIDIA GPU). Longhorn block storage. Everything exposed
via Traefik + cert-manager on DuckDNS, LAN-only (Twingate for remote).

RPi5 TalosOS image provided via this community project:
https://github.com/talos-rpi5/talos-builder

## GitOps flow

Two tiers:

1. **helmfile** (`make sync` / `make apply`) seeds the platform: ArgoCD,
   cert-manager, Longhorn, SMB CSI, distribution, chart-museum. **Do not
   run helmfile unless explicitly asked** - it redeploys platform charts
   and can overwrite manual changes.
2. **ArgoCD** takes over from git alone. `k8s/helm/cluster-apps/templates/`
   contains one Application CRD per service (~34 apps). Each points to
   `k8s/argocd-deploy/<app>/values.yaml`.

All apps have `selfHeal: true`. **Direct `kubectl apply`/`edit` on managed
resources gets reverted.** Changes go through the repo: edit values, commit,
push, ArgoCD syncs.

## Change protocol

Use the **`k8s-change`** command (`.claude/commands/k8s-change.md`) for any
change to cluster workloads. It enforces: locate -> propose -> stop for
approval -> lint -> hand off -> verify -> report. Never apply to the cluster
directly. Never commit or push without explicit user approval.

## Repo layout

```
k8s/
  helmfile.yaml              # platform bootstrap charts
  helm/
    cluster-apps/            # ~34 Application CRDs (one per service)
    argocd/                  # ArgoCD install chart
    cert-manager/            # cert-manager
    longhorn/                # Longhorn storage
    smb-csi/                 # SMB CSI driver
    distribution/            # container registry proxy
    chart-museum/            # Helm chart repo
    traefik-ingress/         # shared sub-chart: Traefik ingress routes
    vault-auth/              # shared sub-chart: Vault auth wiring
    keda-global-cron/        # shared sub-chart: KEDA cron triggers
  argocd-deploy/
    values.yaml              # shared values (repo.url, argocd.namespace, etc.)
    <app>/                   # per-app wrapper chart (Chart.yaml + values.yaml)
    argocd/                  # ArgoCD self-management app
talos/                       # Talos operations workspace - do NOT commit changes here
docs/                        # initial setup notes, diagrams
etc/                         # misc config
nut/                         # UPS config
```

## Gotchas

### Wrapper chart values must be nested under the dependency name

`k8s/argocd-deploy/<app>/` is a wrapper chart. The top-level key in
`values.yaml` must match the **dependency name in `Chart.yaml`**, not the
service name. Using the service name as the key means the child chart sees
none of it and runs with defaults. This has been the root cause of broken
installs for both descheduler and trivy-operator. Chart version and
`appVersion` are independent - check `appVersion` in the chart's `Chart.yaml`
and use `helm show values` to see supported values before writing overrides.

### StatefulSet volumeClaimTemplates are immutable

Changing a PVC size in wrapper values does not patch an existing StatefulSet.
ArgoCD cannot update `volumeClaimTemplates`. You must delete the StatefulSet
and its PVC, then let ArgoCD recreate them with the new size.

### `prune: true` is inconsistent across apps

17 of ~34 Application CRDs in `k8s/helm/cluster-apps/templates/` are
missing `prune: true` (or have it set to `false`). If you remove a
resource from wrapper values, check the app's Application manifest first -
without `prune`, the resource will persist in the cluster after sync.
Apps explicitly set to `prune: false`: cert-manager, pinchflat, smb-csi.

### DHI images (dhi.io)

Docker Hardened Images are minimal and have several quirks:

**imagePullSecret** - `dhi.io/*` images require authentication. The
`dockerconfigjson` `auth` field must be `base64("<docker-hub-username>:<PAT>")`
where the username is the **Docker Hub username**, NOT `dhi.io` or the
registry hostname. Using `dhi.io` as the username causes 401 on the token
endpoint even with a valid PAT.
Reference: https://docs.docker.com/dhi/how-to/use#create-an-image-pull-secret

**VSO quirks** (vault-secrets-operator) for building dockerconfigjson secrets:
- VSO strips leading dots from Vault key names, so a Vault key
  `.dockerconfigjson` becomes `dockerconfigjson` in the k8s secret.
  Use a `SecretTransformation` with a template + `keyOverride` to rename
  it back.
- The Vault value must be the **decoded JSON string**, not the
  base64-encoded version. K8s base64-encodes secret data automatically;
  storing a pre-encoded value results in double-encoding.
- `transformationRefs` is nested under `destination.transformation`, not
  directly under `destination`. CRD path:
  `spec.destination.transformation.transformationRefs`. Putting it at the
  wrong level is silently ignored - no error.
- `destination.type: kubernetes.io/dockerconfigjson` works; extra keys in
  the secret are harmless - kubelet only reads `.dockerconfigjson`.

**Runtime quirks**:
- Runs as UID/GID 65532 (nobody). PVC mounts are root-owned by default,
  causing `PermissionError` on writes. Set `fsGroup: 65532` in the pod
  securityContext.
- No system CA bundle. `urllib`/`requests` TLS calls to the K8s API fail
  with `CERTIFICATE_VERIFY_FAILED`. Create an SSL context explicitly:
  `ssl.create_default_context(cafile="/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")`.
- No `sh` or `bash`. Only the runtime (e.g. `python3`) is available.
  Avoid `command: [sh, -c, ...]` patterns.

### Use mirror.gcr.io for runtime images

Images pulled at runtime should reference `mirror.gcr.io`, not
`registry-1.docker.io`. This is already configured in most app values.

## Conventions

- Commits: follow the user's commit-push skill/command if available.
  Otherwise: `type: description`, short messages.
- Never force push, skip hooks, or commit secrets.
- `make sync` / `make apply` for platform bootstrap. `make` with no args
  runs tool validation.
- If a wrapper chart's `Chart.lock` is stale after a chart bump, run
  `make push-cm-charts CHART_DIR=k8s/argocd-deploy CHART_MUSEUM_NAME=my.chartmuseum`
  to update dependencies and push to the in-cluster chart-museum
  (`chart-museum.rannet.duckdns.org`). Do not run `helm dep update` directly
  - it updates `Chart.lock` in place without pushing the new chart.

## ArgoCD sync (manual)

The `argocd` CLI is at `/usr/local/bin/argocd`. Server has
`server.insecure: true` (plain HTTP on port 80).

```bash
argocd app sync <app> --port-forward --port-forward-namespace argocd \
  --auth-token <TOKEN> --plaintext
```

The CLI needs an **Argo CD API token**, not a Kubernetes ServiceAccount
token (SA tokens are rejected as "invalid session"). The token is the
`k8s_automation_user` apiKey in Vault. The admin account is disabled. If no
token is available, the user must sync via the UI.
