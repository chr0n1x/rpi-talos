#!/usr/bin/env python3
"""
SBOM browser.

Serves state/manifest.json and the CycloneDX files under sboms/ written by
the exporter, plus the dashboard page from page.html mounted beside this
script by the sbom-scripts ConfigMap. The page's assets are inline in that
file because the cluster is LAN-only.

Uses only the Python standard library (json, os, http.server, urllib.parse).
"""

import json
import os
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SBOM_DIR = os.path.realpath(os.environ.get("SBOM_DIR", "/data"))
PORT = int(os.environ.get("SBOM_PORT", "8080"))
SBOM_ROOT = os.path.realpath(os.path.join(SBOM_DIR, "sboms"))
MANIFEST_PATH = os.path.join(SBOM_DIR, "state", "manifest.json")
PAGE_PATH = os.environ.get("SBOM_PAGE", "/scripts/page.html")

_counts = {}
_page = {}


def page_body():
    """Dashboard HTML as bytes, re-read when the mounted page file changes.

    A ConfigMap edit lands in the mount without a pod restart, so the UI can
    be iterated on by editing the ConfigMap alone.
    """
    st = os.stat(PAGE_PATH)
    key = (st.st_mtime_ns, st.st_size)
    if _page.get("key") != key:
        with open(PAGE_PATH, "rb") as f:
            _page["body"] = f.read()
        _page["key"] = key
    return _page["body"]


def component_count(path, st):
    """Number of CycloneDX components, cached against the file's mtime and size."""
    cached = _counts.get(path)
    if cached and cached[0] == st.st_mtime_ns and cached[1] == st.st_size:
        return cached[2]
    try:
        with open(path, "rb") as f:
            bom = json.load(f)
        count = len(bom.get("components") or [])
    except (OSError, ValueError):
        count = 0
    _counts[path] = (st.st_mtime_ns, st.st_size, count)
    return count


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
    return doc


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
        self._sent = False
        try:
            if request.path == "/":
                self._send(200, page_body(), "text/html; charset=utf-8", head_only)
            elif request.path == "/api/state":
                self._json(200, state_doc(), head_only)
            elif request.path == "/api/sbom":
                self._sbom(request, head_only)
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

    def _sbom(self, request, head_only=False):
        query = urllib.parse.parse_qs(request.query)
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
