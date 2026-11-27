#!/usr/bin/env python3
"""
SBOM browser.

Serves state/manifest.json and the CycloneDX files under sboms/ written by
the exporter, plus the dashboard page from page.html and its script from
page.js, all mounted beside this script by the sbom-scripts ConfigMap.
/api/index exposes every SBOM's component names and versions so the page can
search packages without downloading each SBOM. /api/state also carries a
per-image vulnerability summary built from the trivy-reporter state file.
The two API responses are cached for SBOM_CACHE_TTL seconds; ?fresh=1
rebuilds them. Nothing loads from outside the cluster; the cluster is
LAN-only.

Uses only the Python standard library (json, os, http.server, urllib.parse).
"""

import json
import os
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SBOM_DIR = os.path.realpath(os.environ.get("SBOM_DIR", "/data"))
PORT = int(os.environ.get("SBOM_PORT", "8080"))
SBOM_ROOT = os.path.realpath(os.path.join(SBOM_DIR, "sboms"))
MANIFEST_PATH = os.path.join(SBOM_DIR, "state", "manifest.json")
PAGE_PATH = os.environ.get("SBOM_PAGE", "/scripts/page.html")
PAGE_JS_PATH = os.environ.get("SBOM_PAGE_JS", "/scripts/page.js")
# ArgoCD base URL for the page's application deep links; empty disables them.
ARGO_BASE = os.environ.get("ARGOCD_URL", "").rstrip("/")
# The trivy-reporter CronJob's state file (VulnerabilityReport snapshot),
# mounted from the shared reporter-state volume.
TRIVY_STATE_PATH = os.environ.get("TRIVY_STATE", "/reporter/state.json")

_components = {}
_assets = {}

# How long a built /api/state or /api/index response stays valid; the page's
# reload button sends ?fresh=1 to rebuild immediately. The exporters rewrite
# the data daily, so a stale window costs little and the 60s page polls then
# cost a dict copy.
CACHE_TTL = float(os.environ.get("SBOM_CACHE_TTL", "300"))
_cache = {}


def cached(key, build, fresh):
    now = time.monotonic()
    ent = _cache.get(key)
    if not fresh and ent and now - ent["at"] < CACHE_TTL:
        return ent["doc"]
    doc = build()
    _cache[key] = {"at": now, "doc": doc}
    return doc


def asset_body(path):
    """File bytes, re-read when the mounted file changes.

    A ConfigMap edit lands in the mount without a pod restart, so the UI can
    be iterated on by editing the ConfigMap alone.
    """
    st = os.stat(path)
    key = (st.st_mtime_ns, st.st_size)
    ent = _assets.setdefault(path, {})
    if ent.get("key") != key:
        with open(path, "rb") as f:
            ent["body"] = f.read()
        ent["key"] = key
    return ent["body"]


def components(path, st):
    """(component count, lowercase "name version" strings), cached per mtime/size.

    The name strings feed /api/index; one parses the whole file, the other
    takes the first element, so /api/state and /api/index share a cache.
    """
    cached = _components.get(path)
    if cached and cached[0] == st.st_mtime_ns and cached[1] == st.st_size:
        return cached[2]
    try:
        with open(path, "rb") as f:
            bom = json.load(f)
        comps = bom.get("components") or []
        names = []
        for comp in comps:
            name = comp.get("name")
            if name:
                entry = (name + " " + (comp.get("version") or "")).strip().lower()
                names.append(entry)
        result = (len(comps), names)
    except (OSError, ValueError):
        result = (0, [])
    _components[path] = (st.st_mtime_ns, st.st_size, result)
    return result


def component_count(path, st):
    return components(path, st)[0]


def load_manifest():
    try:
        with open(MANIFEST_PATH, "rb") as f:
            doc = json.load(f)
    except (OSError, ValueError):
        return {"generatedAt": None, "workloads": []}
    if not isinstance(doc, dict):
        return {"generatedAt": None, "workloads": []}
    if not isinstance(doc.get("workloads"), list):
        doc["workloads"] = []
    return doc


def sbom_path(rel):
    """Absolute path for a manifest-relative SBOM, or None if not served.

    Only regular files inside SBOM_DIR/sboms are served: absolute paths,
    traversal and symlinks that leave the tree are rejected.
    """
    if not rel or rel.startswith(("/", "\\")) or "\x00" in rel:
        return None
    candidate = os.path.realpath(os.path.join(SBOM_DIR, rel))
    if candidate == SBOM_ROOT or os.path.commonpath([SBOM_ROOT, candidate]) != SBOM_ROOT:
        return None
    if not os.path.isfile(candidate):
        return None
    return candidate


def sbom_meta(rel):
    """Dashboard-facing metadata for one SBOM file, or None when it is gone."""
    path = sbom_path(rel)
    if path is None:
        return None
    try:
        st = os.stat(path)
    except OSError:
        return None
    return {
        "file": rel,
        "mtime": int(st.st_mtime),
        "size": st.st_size,
        "components": component_count(path, st),
    }


def vuln_list():
    """Per-image severity summary for the page's warning badges.

    Reads the reporter's state file; images without critical or high
    findings are skipped (the reporter's own alarm level), duplicates of one
    repo:tag keep the worst counts. Shape:

    [{"repo": "quay.io/velero/velero", "tag": "v2.32.0", "crit": 0,
      "high": 4, "med": 11, "cves": [{"id": "CVE-...", "pkg": "musl",
      "score": 9.8, "severity": "CRITICAL"}]}]

    cves merge the snapshot's top3 and severe lists, deduped by id and
    capped at the ten highest scores.
    """
    try:
        with open(TRIVY_STATE_PATH, "rb") as f:
            doc = json.load(f)
    except (OSError, ValueError):
        return []
    reports = doc.get("reports")
    if not isinstance(reports, dict):
        return []
    best = {}
    for rep in reports.values():
        counts = rep.get("counts") or {}
        crit = counts.get("CRITICAL", 0)
        high = counts.get("HIGH", 0)
        if not (crit or high):
            continue
        key = (rep.get("repo") or "", rep.get("tag") or "")
        cves = {}
        for v in (rep.get("top3") or []) + (rep.get("severe") or []):
            vid = v.get("id")
            if vid and vid not in cves:
                cves[vid] = {
                    "id": vid,
                    "pkg": v.get("pkg", "?"),
                    "score": v.get("score", 0),
                    "severity": v.get("severity", "?"),
                }
        entry = {
            "repo": key[0],
            "tag": key[1],
            "crit": crit,
            "high": high,
            "med": counts.get("MEDIUM", 0),
            "cves": sorted(cves.values(), key=lambda v: -v["score"])[:10],
        }
        cur = best.get(key)
        if cur is None or crit + high > cur["crit"] + cur["high"]:
            best[key] = entry
    return list(best.values())


def state_doc():
    doc = load_manifest()
    sboms = []
    for workload in doc["workloads"]:
        for container in workload.get("containers") or []:
            rel = container.get("file") or ""
            if any(rel == s["file"] for s in sboms):
                continue
            meta = sbom_meta(rel)
            if meta:
                sboms.append(meta)
    doc["sboms"] = sboms
    doc["argoBase"] = ARGO_BASE
    doc["vulns"] = vuln_list()
    return doc


def index_doc():
    doc = load_manifest()
    files = {}
    for workload in doc["workloads"]:
        for container in workload.get("containers") or []:
            rel = container.get("file") or ""
            if rel in files:
                continue
            path = sbom_path(rel)
            if path is None:
                continue
            try:
                st = os.stat(path)
            except OSError:
                continue
            files[rel] = components(path, st)[1]
    return {"generatedAt": doc.get("generatedAt"), "files": files}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    _sent = False

    def log_message(self, fmt, *args):
        print(f"{self.address_string()} {fmt % args}")

    def _send(self, status, body, content_type, head_only=False):
        self._sent = True
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if not head_only:
            self.wfile.write(body)

    def _json(self, status, obj, head_only=False):
        self._send(status, json.dumps(obj).encode(), "application/json", head_only)

    def do_GET(self):
        self._route(False)

    def do_HEAD(self):
        self._route(True)

    def _route(self, head_only):
        request = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(request.query)
        fresh = (query.get("fresh") or [""])[0] == "1"
        self._sent = False
        try:
            if request.path == "/":
                self._send(200, asset_body(PAGE_PATH), "text/html; charset=utf-8", head_only)
            elif request.path == "/page.js":
                self._send(200, asset_body(PAGE_JS_PATH), "text/javascript; charset=utf-8", head_only)
            elif request.path == "/api/state":
                self._json(200, cached("state", state_doc, fresh), head_only)
            elif request.path == "/api/index":
                self._json(200, cached("index", index_doc, fresh), head_only)
            elif request.path == "/api/sbom":
                self._sbom(query, head_only)
            else:
                self._send(404, b"not found\n", "text/plain; charset=utf-8", head_only)
        except Exception as e:
            print(f"{request.path}: {type(e).__name__}: {e}")
            # Once a status line is on the wire the request's response is spent;
            # a second one would corrupt the keep-alive stream.
            if not self._sent:
                try:
                    self._send(500, f"error: {type(e).__name__}\n".encode(), "text/plain; charset=utf-8", head_only)
                except OSError:
                    pass

    def _sbom(self, query, head_only=False):
        rel = (query.get("file") or [""])[0]
        path = sbom_path(rel)
        if path is None:
            self._send(400, b"unknown sbom file\n", "text/plain; charset=utf-8", head_only)
            return
        with open(path, "rb") as f:
            self._send(200, f.read(), "application/json", head_only)


def main():
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"serving {SBOM_DIR} on 0.0.0.0:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
