#!/usr/bin/env python3
"""
Trivy vulnerability report sender.

Reads VulnerabilityReport CRs cluster-wide via the Kubernetes API,
compares against previous state on a PVC, and sends a Telegram
summary when something changed.

Uses only the Python standard library (urllib, json, os, sys).
"""

import base64
import html
import json
import os
import sys
import urllib.request
import urllib.error

API = os.environ.get("KUBERNETES_SERVICE_HOST", "")
API_PORT = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
STATE_FILE = os.environ.get("STATE_FILE", "/state/state.json")
SEVERITY_THRESHOLD = float(os.environ.get("SEVERITY_THRESHOLD", "7"))
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
DOCKER_PAT = os.environ.get("DOCKER_PAT", "")

TRIVY_GROUP = "aquasecurity.github.io"
TRIVY_VERSION = "v1alpha1"
VULN_REPORTS_PLURAL = "vulnerabilityreports"


def setup_docker_auth():
    if not DOCKER_PAT:
        print("WARNING: DOCKER_PAT not set, skipping docker auth", file=sys.stderr)
        return
    config = {
        "auths": {
            "dhi.io": {
                "auth": base64.b64encode(f"{DOCKER_PAT}:".encode()).decode()
            }
        }
    }
    os.makedirs("/var/run/docker", exist_ok=True)
    with open("/var/run/docker/config.json", "w") as f:
        json.dump(config, f)


def k8s_token():
    with open("/var/run/secrets/kubernetes.io/serviceaccount/token") as f:
        return f.read().strip()


def k8s_api(path):
    url = f"https://{API}:{API_PORT}{path}"
    req = urllib.request.Request(url)
    req.add_header("Authorization", f"Bearer {k8s_token()}")
    req.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"HTTP {e.code} on {path}: {body[:500]}", file=sys.stderr)
        raise


def list_vuln_reports():
    path = f"/apis/{TRIVY_GROUP}/{TRIVY_VERSION}/{VULN_REPORTS_PLURAL}"
    data = k8s_api(path)
    return data.get("items", [])


def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_state(state):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f)
    os.rename(tmp, STATE_FILE)


def report_key(item):
    ns = item["metadata"]["namespace"]
    name = item["metadata"]["name"]
    return f"{ns}/{name}"


def extract_report(item):
    r = item.get("report", {})
    summary = r.get("summary", {})
    vulns = r.get("vulnerabilities", [])
    artifact = r.get("artifact", {})

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for v in vulns:
        sev = v.get("severity", "UNKNOWN")
        if sev in counts:
            counts[sev] += 1

    high_vulns = sorted(
        [v for v in vulns if v.get("severity", "") in ("CRITICAL", "HIGH")],
        key=lambda v: v.get("score", 0),
        reverse=True,
    )
    top3 = [
        {
            "id": v.get("vulnerabilityID", "?"),
            "pkg": v.get("resource", "?"),
            "score": v.get("score", 0),
            "severity": v.get("severity", "?"),
        }
        for v in high_vulns[:3]
    ]

    severe = [
        {
            "id": v.get("vulnerabilityID", "?"),
            "pkg": v.get("resource", "?"),
            "score": v.get("score", 0),
            "severity": v.get("severity", "?"),
            "fixed": v.get("fixedVersion", "N/A"),
        }
        for v in vulns
        if v.get("score", 0) >= SEVERITY_THRESHOLD
    ]

    return {
        "namespace": item["metadata"]["namespace"],
        "name": item["metadata"]["name"],
        "repo": artifact.get("repository", "unknown"),
        "tag": artifact.get("tag", "unknown"),
        "counts": counts,
        "top3": top3,
        "severe": severe,
    }


def diff_reports(current, previous):
    if not previous:
        ns_summary = {}
        for key, rep in current.items():
            ns = rep["namespace"]
            if ns not in ns_summary:
                ns_summary[ns] = {"crit": 0, "high": 0, "severe": []}
            ns_summary[ns]["crit"] += rep["counts"]["CRITICAL"]
            ns_summary[ns]["high"] += rep["counts"]["HIGH"]
            ns_summary[ns]["severe"].extend(rep["severe"])
        ns_summary = {k: v for k, v in ns_summary.items() if v["crit"] or v["high"]}
        return {
            "type": "first-run",
            "namespaces": ns_summary,
            "total_workloads": len(current),
        }

    changes = []
    current_keys = set(current.keys())
    previous_keys = set(previous.keys())

    for key in current_keys - previous_keys:
        rep = current[key]
        if rep["counts"]["CRITICAL"] or rep["counts"]["HIGH"]:
            changes.append({"type": "new", "key": key, "report": rep})

    for key in previous_keys - current_keys:
        changes.append({"type": "removed", "key": key})

    for key in current_keys & previous_keys:
        cur = current[key]
        prev = previous[key]

        crit_inc = cur["counts"]["CRITICAL"] > prev["counts"]["CRITICAL"]
        high_inc = cur["counts"]["HIGH"] > prev["counts"]["HIGH"]

        prev_severe_ids = {v["id"] for v in prev.get("severe", [])}
        new_severe = [v for v in cur["severe"] if v["id"] not in prev_severe_ids]

        if crit_inc or high_inc or new_severe:
            changes.append({
                "type": "increased",
                "key": key,
                "report": cur,
                "prev_counts": prev["counts"],
                "new_severe": new_severe,
            })

    ns_changes = {}
    for ch in changes:
        if ch["type"] not in ("new", "increased"):
            continue
        rep = ch["report"]
        ns = rep["namespace"]
        if ns not in ns_changes:
            ns_changes[ns] = {"workloads": [], "severe": []}
        ns_changes[ns]["workloads"].append({
            "name": rep["name"],
            "repo": f"{rep['repo']}:{rep['tag']}",
            "crit": rep["counts"]["CRITICAL"],
            "high": rep["counts"]["HIGH"],
            "prev_crit": ch.get("prev_counts", {}).get("CRITICAL", 0) if ch["type"] == "increased" else None,
            "prev_high": ch.get("prev_counts", {}).get("HIGH", 0) if ch["type"] == "increased" else None,
            "top3": rep["top3"],
        })
        if ch["type"] == "increased":
            ns_changes[ns]["severe"].extend(ch.get("new_severe", []))
        elif ch["type"] == "new":
            ns_changes[ns]["severe"].extend(rep["severe"])

    return {
        "type": "changes",
        "namespaces": ns_changes,
        "total_changed": len([c for c in changes if c["type"] in ("new", "increased")]),
    }


def format_telegram_message(result):
    lines = []

    if result["type"] == "first-run":
        lines.append("<b>Trivy scan - initial report</b>")
        lines.append(f"Total workloads scanned: {result['total_workloads']}")
        lines.append("")
        if not result["namespaces"]:
            lines.append("No critical or high severity vulnerabilities found.")
            return "\n".join(lines)

        for ns in sorted(result["namespaces"]):
            info = result["namespaces"][ns]
            lines.append(f"<b>{html.escape(ns)}</b>  [{info['crit']} crit / {info['high']} high]")
            seen = set()
            shown = 0
            for v in sorted(info["severe"], key=lambda x: x["score"], reverse=True):
                if v["id"] in seen or shown >= 5:
                    continue
                seen.add(v["id"])
                lines.append(f"  {html.escape(v['id'])}  {html.escape(v['pkg'])}  score={v['score']}  fixed={html.escape(str(v.get('fixed', 'N/A')))}")
                shown += 1
            lines.append("")
        return "\n".join(lines)

    elif result["type"] == "changes":
        if not result["namespaces"]:
            return None

        lines.append(f"<b>Trivy scan - {result['total_changed']} workload(s) changed</b>")
        lines.append("")

        for ns in sorted(result["namespaces"]):
            info = result["namespaces"][ns]
            lines.append(f"<b>{html.escape(ns)}</b>")
            for w in info["workloads"]:
                crit_part = f"{w['crit']} crit"
                high_part = f"{w['high']} high"
                if w.get("prev_crit") is not None:
                    if w["prev_crit"] != w["crit"]:
                        crit_part = f"{w['crit']} crit (was {w['prev_crit']})"
                    if w["prev_high"] != w["high"]:
                        high_part = f"{w['high']} high (was {w['prev_high']})"
                lines.append(f"  {html.escape(w['repo'])}: {crit_part} / {high_part}")
                for v in w["top3"]:
                    lines.append(f"    {html.escape(v['id'])}  {html.escape(v['pkg'])}  {v['score']}")
            if info["severe"]:
                lines.append("  <b>New high-severity CVEs:</b>")
                seen = set()
                for v in sorted(info["severe"], key=lambda x: x["score"], reverse=True):
                    if v["id"] in seen:
                        continue
                    seen.add(v["id"])
                    lines.append(f"    {html.escape(v['id'])}  {html.escape(v['pkg'])}  score={v['score']}  fixed={html.escape(str(v.get('fixed', 'N/A')))}")
            lines.append("")

        return "\n".join(lines)

    return None


def strip_html(s):
    """Strip HTML tags from a string (fallback when parse errors occur)."""
    start = -1
    out = []
    for ch in s:
        if ch == '<' and start == -1:
            start = 0
        elif ch == '>' and start >= 0:
            start = -1
        elif start == -1:
            out.append(ch)
    return ''.join(out)


def send_telegram(token, chat_id, text, max_retries=3):
    url = f"https://api.telegram.org/bot{token}/sendMessage"

    for attempt in range(max_retries + 1):
        payload = {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }
        body = json.dumps(payload).encode()
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                result = json.loads(resp.read())
                if not result.get("ok"):
                    desc = result.get("description", "")
                    print(f"Telegram error: {desc}", file=sys.stderr)
                    if "can't parse entities" in desc and attempt < max_retries:
                        print("Parse error - stripping HTML and retrying...", file=sys.stderr)
                        text = strip_html(text)
                        continue
                    return result
                return result
        except urllib.error.HTTPError as e:
            err_body = e.read().decode()
            print(f"Telegram HTTP {e.code}: {err_body[:300]}", file=sys.stderr)
            if "can't parse entities" in err_body and attempt < max_retries:
                print("Parse error - stripping HTML and retrying...", file=sys.stderr)
                text = strip_html(text)
                continue
            raise


def main():
    setup_docker_auth()

    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID must be set", file=sys.stderr)
        sys.exit(1)

    try:
        print("Listing VulnerabilityReport CRs...")
        items = list_vuln_reports()
        print(f"Found {len(items)} reports")

        current = {}
        for item in items:
            key = report_key(item)
            current[key] = extract_report(item)

        previous = load_state()

        result = diff_reports(current, previous)
        print(f"Diff type: {result['type']}, changed: {result.get('total_changed', 'N/A')}")

        msg = format_telegram_message(result)
        if msg:
            print(f"Sending Telegram message ({len(msg)} chars)...")
            send_telegram(TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, msg)
            print("Message sent.")
        else:
            print("No changes to report. Skipping Telegram message.")

        save_state(current)
        print("State saved.")
    except Exception as e:
        print(f"Error: {type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
