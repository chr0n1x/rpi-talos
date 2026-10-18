# komga

Komga media server + gutendexer (Gutenberg EPUB importer).

## What's here

A Helm wrapper chart for the komga namespace. Two app-template subcharts:

1. **komga** - the komga media server (ghcr.io/gotson/komga), deployed via
   app-template with two SMB PVCs (config 8Gi, data 8Gi), OIDC auth from
   Vault, and a Traefik ingress on `komga.rannet.duckdns.org`.

2. **gutendexer** - a `dhi.io/python:3.14` stdlib-only HTTP server that
   downloads public-domain English EPUBs from gutendex.com into the komga
   data PVC. Also app-template (its `persistence` block supports configMap,
   secret, and existingClaim PVC mounts). Traefik ingress on
   `gutendex.rannet.duckdns.org`.

## gutendexer

**Files**:
- `scripts/gutenberg_server.py` - the server (~600 lines, stdlib only)
- `scripts/test_gutenberg_server.py` - 57 unit tests
  (`python3 test_gutenberg_server.py`)
- `templates/gutendexer-cm.yaml` - ConfigMap `gutendexer-script`: the
  Python script + `gutenberg.json` seed (from `.Values.gutendexer.config`).
  Hand-rolled because app-template's `configMaps.data` evaluates values as
  templates with the subchart context, so `.Files.Get "scripts/..."` can't
  reach the wrapper chart's files.
- `templates/gutendexer-secrets.yaml` - both VSO secrets: dhi.io
  dockerconfigjson (`dhi-io-image-pull`, from `cert-manager/docker`) and
  the CA bundle (`gutendexer-ca`, from Vault `komga/gutendex`)

Everything else (Deployment, Service, volumes, mounts, probes) lives in the
`gutendexer:` block of `values.yaml` as app-template values.

**How it works**:
- Internal scheduler fires at `schedule_hour` (default 02:00) daily
- Manual trigger via `POST /run` or the HTML button
- Fetches candidates from gutendex.com by topic, deduplicates, sorts by ID
- Downloads EPUBs to `/data/Gutenberg/<Author>/<Title>.epub`
- Politeness: `max_per_run` (10), `sleep_between` (1800s), stop-on-error,
  resume via `last_id`
- No children's books (topic filtering handles this)

**Endpoints** (on `gutendex.rannet.duckdns.org`):
- `GET /` - HTML status page (run history, "Start run now" button)
- `GET /status` - JSON status
- `GET/POST /config` - read/edit config (persists to state PVC)
- `POST /run` - trigger a download run (409 if busy)
- `GET /healthz` - liveness/readiness

**Config flow**:
- ConfigMap `/cfg/gutenberg.json` is the read-only seed (rendered from
  `values.yaml` `gutendexer.config`)
- On first boot, script copies it to `/state/gutenberg.json` (writable, SMB
  PVC)
- All subsequent reads/writes go to the state PVC copy
- UI edits (`POST /config`) persist to the state PVC, not the ConfigMap
- ArgoCD sync reverts the ConfigMap to `values.yaml` but does NOT touch the
  state PVC, so UI edits survive syncs
- The `values.yaml` config is only the initial seed. Once the state PVC
  exists, it is inert. To change the seed for a fresh PVC, edit
  `values.yaml` `gutendexer.config` and redeploy.

**State**:
- `/state/gutenberg.json` - writable config copy
- `/state/gutenberg_state.json` - `last_id`, run history (capped at 5),
  `last_scheduled_run_date`

**DHI TLS**:
- DHI images have no system CA bundle. `ssl.create_default_context()` fails
  with `CERTIFICATE_VERIFY_FAILED`.
- Fix: CA bundle in Vault at `komga/gutendex` (field `bundle.pem`), pulled
  into cluster as Opaque secret `gutendexer-ca` via VSO, mounted at
  `/ca/ca-bundle.pem`, passed via `CA_FILE` env var.
- The script's `_ssl_ctx()` uses `cafile=CA_FILE` if the file exists, else
  falls back to default.
- The CA bundle contains public root CAs (GTS Root R4, GlobalSign, USERTrust,
  Network Solutions). No identifying info.

**Image pull**:
- `dhi.io/python:3.14` requires auth. VSO plain copy from
  `cert-manager/docker` (which has `.dockerconfigjson` directly, no
  SecretTransformation needed) creates `dhi-io-image-pull`.

## app-template notes (gotchas hit while wiring gutendexer)

- **`global.fullnameOverride` inside the alias block**: app-template's
  `common.yaml` auto-sets `global.nameOverride` to the release name when
  unset, and it beats the subchart-level `nameOverride`. Without
  `gutendexer.global.fullnameOverride: gutendexer` every resource rendered
  as `komga` (the wrapper release name) and collided with the komga
  subchart's resources.
- **`fullnameOverride` strips the PVC identifier suffix.** With
  `global.fullnameOverride: gutendexer` set, an app-template-provisioned
  PVC for identifier `state` would just be named `gutendexer`, not
  `gutendexer-state`. Fixed with `persistence.state.forceRename:
  gutendexer-state` (per-item name override; also available on services,
  configMaps, etc.).
- **Cross-subchart PVC sharing** goes through `existingClaim`:
  `persistence.data.existingClaim: komga-data` mounts the PVC that the
  komga subchart provisions. No duplicate PVC is created.
- **Container `ports` is an array** (`- name: http` / `containerPort`),
  not a map. **Probe timing fields nest under `spec:`**
  (`probes.liveness.spec.initialDelaySeconds`), not inline.
- **`persistence.<id>.type`** supports `configMap`/`secret` with `name:`
  (explicit object name, bypassing the app-template-managed
  `configMaps:`/`secrets:` blocks), `items:`, and `defaultMode:`.
- **`serviceAccount.name: komga`** on the controller reuses komga's
  ServiceAccount (the VSO auth role is scoped to the SA, not the workload).

## Gotchas

- **Wrapper chart values must be nested under the dependency name.**
  The `komga:` block feeds the app-template dependency aliased `komga`;
  the `gutendexer:` block feeds the one aliased `gutendexer`.

- **State PVC is SMB, not Longhorn.** 5Mi, ReadWriteOnce, `smb` storage
  class. The SMB CSI driver provisions a subdirectory per PVC
  (`ns-<ns>--<pvc-name>`), so it's isolated from komga-data. Content is
  two small JSON files, so 5Mi is plenty of headroom and a tight blast
  radius if the script ever starts writing garbage.

- **Data PVC is shared with komga.** gutendexer mounts `komga-data`
  (8Gi SMB) read-write at `/data`. Downloads go to `/data/Gutenberg/`.
  Komga sees them as a regular collection.

- **Config is not a secret.** It's a ConfigMap, not Vault. Topics,
  max_per_run, sleep_between, schedule_hour, etc. are all visible in the
  rendered manifest.

- **PRD is partially outdated.** `docs/gutenberg-importer-prd.md` describes
  a CronJob with Vault config. The actual implementation is a Deployment
  (app-template) with ConfigMap + state PVC. The PRD is the original design
  doc.

## Lint

```bash
helm dependency build k8s/argocd-deploy/komga
helm template komga k8s/argocd-deploy/komga
python3 k8s/argocd-deploy/komga/scripts/test_gutenberg_server.py
```
