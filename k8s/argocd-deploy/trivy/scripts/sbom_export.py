#!/usr/bin/env python3
"""
Cluster SBOM plan exporter.

Lists pods cluster-wide, resolves each pod to the workload that owns it,
and records the image plan and the workload inventory on the shared PVC.

Uses only the Python standard library (urllib, json, os, re, sys, time).
"""

import json
import os
import re
import ssl
import sys
import time
import urllib.request
import urllib.error

API = os.environ.get("KUBERNETES_SERVICE_HOST", "")
API_PORT = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
CA_CERT = os.environ.get("KUBERNETES_CA_CERT", "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
SBOM_DIR = os.environ.get("SBOM_DIR", "/data")
# Test entry point: treat this JSON pod list as the cluster's pods.
PODS_FILE = os.environ.get("SBOM_PODS_FILE", "")
# Test entry point: JSON object mapping the plural keys in WORKLOAD_APIS to
# workload item lists instead of querying the API for them.
TRACKING_FILE = os.environ.get("SBOM_TRACKING_FILE", "")

STATE_DIR = os.path.join(SBOM_DIR, "state")
SBOM_SUBDIR = "sboms"
PLAN_PATH = os.path.join(STATE_DIR, "plan.tsv")
MANIFEST_PATH = os.path.join(STATE_DIR, "manifest.json")
KEEP_PER_REF = 2

DIRECT_OWNER_KINDS = ("DaemonSet", "StatefulSet", "Job", "CronJob")
UNSAFE = re.compile(r"[^A-Za-z0-9._-]")

# Workload resources whose ArgoCD tracking annotations name the application,
# as (plural key for the test file, owner kind, API path).
WORKLOAD_APIS = (
    ("deployments", "Deployment", "/apis/apps/v1/deployments"),
    ("statefulsets", "StatefulSet", "/apis/apps/v1/statefulsets"),
    ("daemonsets", "DaemonSet", "/apis/apps/v1/daemonsets"),
    ("jobs", "Job", "/apis/batch/v1/jobs"),
    ("cronjobs", "CronJob", "/apis/batch/v1/cronjobs"),
)


def k8s_token():
    with open("/var/run/secrets/kubernetes.io/serviceaccount/token") as f:
        return f.read().strip()


def k8s_ssl_context():
    ctx = ssl.create_default_context(cafile=CA_CERT)
    return ctx


def k8s_api(path):
    url = f"https://{API}:{API_PORT}{path}"
    req = urllib.request.Request(url)
    req.add_header("Authorization", f"Bearer {k8s_token()}")
    req.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=60, context=k8s_ssl_context()) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"HTTP {e.code} on {path}: {body[:500]}", file=sys.stderr)
        raise


def list_pods():
    if PODS_FILE:
        with open(PODS_FILE) as f:
            data = json.load(f)
    else:
        data = k8s_api("/api/v1/pods")
    return data.get("items", [])


def owner_of(pod):
    """Return (kind, name) for the pod's owner chain, the pod itself when standalone.

    A ReplicaSet name is "<deployment-name>-<pod-template-hash>", so the
    deployment is its prefix before the last dash.

    {"namespace": "apps", "kind": "Deployment", "name": "example"}
    """
    refs = pod["metadata"].get("ownerReferences") or []
    controllers = [r for r in refs if r.get("controller")] or refs
    for ref in controllers:
        kind = ref.get("kind", "")
        name = ref.get("name", "")
        if kind == "ReplicaSet" and name:
            return "Deployment", name.rsplit("-", 1)[0]
        if kind in DIRECT_OWNER_KINDS and name:
            return kind, name
    return "Pod", pod["metadata"]["name"]


def image_pin(status):
    """Return (ref, digest) from a containerStatus, or None when it has no digest.

    imageID is "<repository>@sha256:<hex>", and the SBOM file name uses only
    the hex prefix, which is unique enough.
    """
    image_id = status.get("imageID") or ""
    ref, sep, digest = image_id.rpartition("@")
    if not (sep and ref and digest.startswith("sha256:")):
        return None
    return ref, digest


def image_tag(spec_image):
    """Tag from the pod spec image string, for display only; None when the
    spec pins by digest or carries no tag.

    "docker.io/longhornio/longhorn-instance-manager:v1.11.3" -> "v1.11.3"
    "quay.io/prometheus/node-exporter" -> None
    """
    if not spec_image or "@" in spec_image:
        return None
    tail = spec_image.rsplit("/", 1)[-1]
    if ":" in tail:
        return tail.split(":", 1)[1]
    return None


def sbom_file_name(ref, digest):
    """Path of the SBOM for one pinned image, relative to SBOM_DIR."""
    return f"{SBOM_SUBDIR}/{UNSAFE.sub('-', ref)}-{digest.split(':', 1)[1][:12]}.json"


TRACKING_ANN = "argocd.argoproj.io/tracking-id"


def tracking_apps():
    """Return {(namespace, kind, name): application} from tracking annotations.

    "argo-cd:apps/Deployment:argocd/argocd-watch" -> "argo-cd" is the
    annotation, the application being the text before the first colon. Jobs
    spawned by a CronJob are created by the cluster and carry no annotation,
    so they inherit the owning CronJob's application.
    """
    data = {}
    if TRACKING_FILE:
        with open(TRACKING_FILE) as f:
            data = json.load(f)
    apps = {}
    items_by_kind = {}
    for plural, kind, path in WORKLOAD_APIS:
        if TRACKING_FILE:
            items = data.get(plural, [])
        elif PODS_FILE:
            items = []
        else:
            try:
                items = k8s_api(path).get("items", [])
            except Exception as e:
                print(f"tracking: {plural} list failed: {e}", file=sys.stderr)
                items = []
        items_by_kind[kind] = items
        for item in items:
            meta = item["metadata"]
            ann = (meta.get("annotations") or {}).get(TRACKING_ANN, "")
            if ":" in ann:
                apps[(meta["namespace"], kind, meta["name"])] = ann.split(":", 1)[0]
    for item in items_by_kind.get("Job", []):
        meta = item["metadata"]
        key = (meta["namespace"], "Job", meta["name"])
        if key in apps:
            continue
        for ref in meta.get("ownerReferences") or []:
            if ref.get("kind") == "CronJob":
                owner = apps.get((meta["namespace"], "CronJob", ref["name"]))
                if owner:
                    apps[key] = owner
    return apps


def collect(pods, tracking):
    """Return (workloads, plan, apps) where plan maps (ref, digest) to SBOM path
    and apps maps a workload key to its ArgoCD application name.

    The tracking annotation wins; the pod's Helm instance label is a fallback
    for workloads the tracking map lacks (bare pods, RBAC not yet granted).
    """
    workloads = {}
    plan = {}
    apps = {}
    for pod in pods:
        ns = pod["metadata"]["namespace"]
        kind, name = owner_of(pod)
        key = (ns, kind, name)
        seen = workloads.setdefault(key, set())
        if not apps.get(key):
            apps[key] = tracking.get(key) or (pod["metadata"].get("labels") or {}).get("app.kubernetes.io/instance", "")
        for status in pod.get("status", {}).get("containerStatuses", []) or []:
            pin = image_pin(status)
            if not pin:
                continue
            ref, digest = pin
            out = sbom_file_name(ref, digest)
            plan[(ref, digest)] = out
            seen.add((status.get("name", ""), ref, digest, image_tag(status.get("image", ""))))
    return workloads, plan, apps


def manifest_doc(workloads, apps):
    doc = {"generatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "workloads": []}
    for (ns, kind, name) in sorted(workloads):
        containers = sorted(workloads[(ns, kind, name)])
        doc["workloads"].append({
            "namespace": ns,
            "kind": kind,
            "name": name,
            "app": apps.get((ns, kind, name), ""),
            "containers": [
                {"container": c, "ref": ref, "digest": digest, "tag": tag, "file": sbom_file_name(ref, digest)}
                for c, ref, digest, tag in containers
            ],
        })
    return doc


def write_text(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(text)
    os.rename(tmp, path)


def rotate(current):
    """Drop all but the KEEP_PER_REF newest SBOMs of an image ref; never the live plan."""
    root = os.path.join(SBOM_DIR, SBOM_SUBDIR)
    if not os.path.isdir(root):
        return
    groups = {}
    for entry in os.listdir(root):
        if not entry.endswith(".json"):
            continue
        prefix = entry[: -len(".json")].rsplit("-", 1)[0]
        groups.setdefault(prefix, []).append(os.path.join(root, entry))
    for files in groups.values():
        files.sort(key=lambda p: (os.path.getmtime(p), p), reverse=True)
        for path in files[KEEP_PER_REF:]:
            if os.path.relpath(path, SBOM_DIR) in current:
                continue
            try:
                os.remove(path)
                print(f"rotated out {path}")
            except OSError as e:
                print(f"rotate failed for {path}: {e}", file=sys.stderr)


def main():
    try:
        os.makedirs(os.path.join(SBOM_DIR, SBOM_SUBDIR), exist_ok=True)
        print("Listing pods...")
        pods = list_pods()
        print(f"Found {len(pods)} pods")
        # An empty live pod list means the API call went wrong, not that the
        # cluster is empty, so the previous plan and manifest stay on disk.
        if not pods and not PODS_FILE:
            raise RuntimeError("API listed no pods; refusing to write an empty plan")

        workloads, plan, apps = collect(pods, tracking_apps())
        plan_lines = [f"{out}\t{ref}\t{ref}@{digest}\n" for (ref, digest), out in sorted(plan.items())]
        write_text(PLAN_PATH, "".join(plan_lines))
        write_text(MANIFEST_PATH, json.dumps(manifest_doc(workloads, apps), indent=2) + "\n")
        rotate(set(plan.values()))
        print(f"{len(plan)} unique image(s), {len(workloads)} workload(s) -> {STATE_DIR}")
    except Exception as e:
        print(f"Error: {type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
