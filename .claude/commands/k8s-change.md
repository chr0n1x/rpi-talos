---
name: k8s-change
description: Propose, lint, and hand off a change to this cluster's k8s workloads via the repo
user-invocable: true
argument-hint: description of the change (e.g. "protect traefik from descheduler")
allowed-tools: Bash(kubectl*), Bash(helm template*), Bash(helm show*), Bash(jq*), Bash(grep*), Bash(cat*), Bash(ls*), Bash(mkdir*), Bash(diff*), Read, Glob, Grep, Write, Edit
---

# k8s Change Protocol

This cluster is production and is GitOps-driven. ArgoCD has `selfHeal: true` on
all applications in `k8s/helm/cluster-apps/templates/`, so **direct `kubectl edit`
/ `kubectl apply` on managed resources will be reverted**. Changes go through the
repo. **You never apply anything to the cluster.** You locate, propose, lint,
and hand off. The user commits and syncs (or runs manual commands).

## Ground Rules

1. **Never** `kubectl apply` or `kubectl edit` a resource owned by an ArgoCD
   Application. Find the app's source in the repo instead:
   - `k8s/argocd-deploy/<app>/` - per-app Helm value overrides (synced by ArgoCD)
   - `k8s/argocd-deploy/values.yaml` - shared values
   - `k8s/helm/<chart>/` - chart sources rendered by helmfile for bootstrapping
2. **Never** commit or push. Prepare the diff and present it. The user commits.
3. **Never** force-push, delete releases/namespaces, or modify
   `argocd-deploy/distribution`.
4. **Never apply changes to the cluster.** No `kubectl apply`, no `kubectl
   edit`, no `helm upgrade`, no `helm install`. You prepare the diff; the
   user commits and lets ArgoCD sync, or runs manual commands themselves.
   If a change requires an imperative out-of-band action, list the exact
   commands and wait for the user to run them.

## Phase 1: Locate

Identify what needs to change and where it lives in the repo.

- `kubectl get all -A -o wide` to see current state
- `kubectl get app -n argocd -o name` to list ArgoCD applications
- For the target app, find its `Application` manifest in
  `k8s/helm/cluster-apps/templates/` and note the `path:` (the
  `k8s/argocd-deploy/<app>` dir)
- Read `k8s/argocd-deploy/<app>/values.yaml` and `Chart.yaml` to see what
  overrides exist today. **Check the dependency name in `Chart.yaml`** - the
  top-level key in `values.yaml` must match it, not the service name.
  Also note `appVersion` (the binary version) which is independent of the
  chart version.
- If the needed knob is not in the wrapper values, check the upstream chart:
  `helm show values <chart> --version <ver>` to see all supported values
- Check the Application manifest in `k8s/helm/cluster-apps/templates/` for
  `prune: true`. If missing or `false`, removals from wrapper values will
  NOT delete the resource from the cluster - flag this in Phase 2.

## Phase 2: Propose

State the plan before touching anything:

- Which repo file(s) change and why
- The exact diff (show it as a proposed patch, do not write it to disk yet)
- What the change does and does not affect
- Whether it triggers a rollout (Deployment pod template changes do; values
  that only affect ConfigMaps may not)
- Rollout risk: single-replica services have a brief outage window during
  rollout. Flag this and suggest a quiet time if relevant.
- **StatefulSet PVC changes:** if the change touches `storageSize`,
  `volumeClaimTemplates`, or any field under a StatefulSet's volume
  template, flag that the existing StatefulSet + PVC must be deleted first
  (they are immutable). List the delete commands as imperative out-of-band
  actions in Phase 4.
- **Prune check:** if the Application manifest lacks `prune: true`, note
  that removed resources will be orphaned in the cluster, not deleted.

**Stop and wait for approval before Phase 3.**

## Phase 3: Lint

Before presenting the final diff, validate it.

- **Wrapper nesting check:** verify the top-level key(s) in
  `k8s/argocd-deploy/<app>/values.yaml` match the dependency name(s) in
  `Chart.yaml`. A mismatch means the child chart sees no overrides and runs
  with defaults. This is the most common wrapper chart bug.
- **`file://` dependencies:** many wrapper charts pull in shared sub-charts
  from `k8s/helm/` via `file://` paths (traefik-ingress, vault-auth,
  keda-global-cron). When linting with `helm template`, run it from
  the repo root so relative `file://` paths resolve. If a dependency fails
  to resolve, the rendered output will be missing resources from those
  sub-charts - check the helm template output for errors before trusting
  the diff.
- YAML syntax: `helm template` the affected release with the new values.
  Use `--dependency-update` to fetch remote deps locally (safe, does not
  modify the cluster). Do not commit the resulting `Chart.lock` changes
  unless the user approves:
  ```bash
  helm template <release> <chart-path> -f <values-file> --namespace <ns> \
    --dependency-update > /tmp/rendered.yaml
  ```
  Compare against current live state:
  ```bash
  kubectl get <kind> <name> -n <ns> -o yaml > /tmp/live.yaml
  ```
  Diff the two. Resources in rendered but not live are new creates. Resources
  in live but not rendered will be pruned (if `prune: true`) or orphaned
  (if not). Flag orphans explicitly.
- **Schema-aware validation** for embedded configs (Helm does not lint
  DeschedulerPolicy, Prometheus configs, etc.). For descheduler policy changes,
  run the descheduler image locally with `--to-dry-run=true` against the
  rendered policy, or fetch the JSON schema from the descheduler v<version>
  tag and validate with `jq`/`python -c "import jsonschema"`.
- Helm repo hygiene: if `Chart.lock` is stale, note it in the report. Do
  not commit `Chart.lock` changes without explicit user approval (use
  `make push-cm-charts` instead, which updates and pushes in one step).

## Phase 4: Hand Off

Do **not** apply anything to the cluster. Write the approved changes to the
repo files, then stop.

- Write the changes to the repo file(s) identified in Phase 1 (this is a
  repo edit, not a cluster apply - it is allowed and expected)
- Show the final `git diff` so the user can review exactly what was written
- List any imperative out-of-band commands that would be needed, as a list -
  do not run them
- Tell the user to review and commit. The push triggers an ArgoCD sync
  automatically (the apps use `targetRevision: HEAD` with automated
  `selfHeal`).
- If you are able to trigger a sync on behalf of the user, **offer** to do
  it. Do not do it unasked. The user must push first - syncing before the
  push is a no-op at best and a rollback at worst.
- How to trigger a sync from this machine:
  - The `argocd` CLI is installed at `/usr/local/bin/argocd`. The server
    has `server.insecure: true` (plain HTTP on port 80).
  - Use `argocd app sync <app> --port-forward --port-forward-namespace
    argocd --auth-token <TOKEN> --plaintext` where `<TOKEN>` is an Argo CD
    API token for an account with write access (e.g. the
    `k8s_automation_user` apiKey, whose raw value is in the
    `accounts.k8s_automation_user.tokens` key of Vault - the secret in the
    cluster only holds the token ID, not the value).
  - **Known limitation:** Kubernetes ServiceAccount tokens
    (`kubectl create token argocd-server -n argocd`) do NOT work as
    `--auth-token`. Argo CD treats them as opaque strings, not JWTs, and
    rejects them with "invalid session: failed to verify the token". The
    admin account is also disabled. So if no Argo CD API token is
    available, you cannot trigger a sync from the CLI - tell the user to
    sync via the UI or provide a token.
- Ask whether they want to proceed. Wait.

## Phase 5: Verify

Only after the user confirms they have committed and pushed (and ArgoCD has
synced, or you triggered the sync). Verify by inspecting the live state of
the resources that were expected to change:

- `kubectl get app <app> -n argocd` - confirm `Synced` status (check both
  `sync.status` and `health.status` in the output)
- Check the specific objects that should have changed, in their namespace:
  - ConfigMaps: `kubectl get cm <name> -n <ns> -o yaml` - confirm the new
    content is present
  - Deployments/Pods: confirm the new labels/annotations/args are on the
    live pods (not just the deployment spec - the pod template change must
    have rolled)
  - CronJob-managed controllers (e.g. descheduler): wait for the next
    scheduled run, then `kubectl logs -n <ns> job/<job-name>` and confirm no
    config errors
- Verify the actual effect, not just "no errors": e.g. for an annotation
  change, confirm the annotation is present on the live pods; for a policy
  change, run a dry-run job and grep for the expected exclusion/behavior
- Report what was verified and what could not be verified (e.g. "protection
  only observable under real eviction pressure")

## Phase 6: Report

Summarize:

- What changed (files, repo diff)
- What was verified
- What remains unverified and how to observe it later
- Any follow-up (e.g. "add prune to this app", "commit this")
