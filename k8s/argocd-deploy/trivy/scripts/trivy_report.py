#!/usr/bin/env python3
"""
Trivy vulnerability report sender.

Reads VulnerabilityReport CRs cluster-wide via the Kubernetes API,
compares against previous state on a PVC, and sends a Telegram
summary when something changed.

Uses only the Python standard library (urllib, json, os, sys).
"""

import html
import json
import os
import ssl
import sys
import urllib.request
import urllib.error

API = os.environ.get("KUBERNETES_SERVICE_HOST", "")
API_PORT = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
CA_CERT = os.environ.get("KUBERNETES_CA_CERT", "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
STATE_FILE = os.environ.get("STATE_FILE", "/state/state.json")
SEVERITY_THRESHOLD = float(os.environ.get("SEVERITY_THRESHOLD", "7"))
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")

TRIVY_GROUP = "aquasecurity.github.io"
TRIVY_VERSION = "v1alpha1"
VULN_REPORTS_PLURAL = "vulnerabilityreports"


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
        with urllib.request.urlopen(req, timeout=30, context=k8s_ssl_context()) as resp:
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
            data = json.load(f)
        # Backward compat: old format is a flat {key: report} dict
        if "reports" in data:
            return data["reports"], data.get("telegram_message_id")
        return data, None
    except (FileNotFoundError, json.JSONDecodeError):
        return {}, None


def save_state(state, telegram_message_id=None):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    data = {"reports": state, "telegram_message_id": telegram_message_id}
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f)
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

    workloads = {}
    for ch in changes:
        if ch["type"] not in ("new", "increased"):
            continue
        rep = ch["report"]
        image_slug = rep["repo"].rsplit("/", 1)[-1]
        image_key = f"{rep['namespace']}/{image_slug}:{rep['tag']}"
        top3 = rep["top3"]
        if top3:
            worst = top3[0]
            entry = {
                "id": worst["id"],
                "workload": image_key,
                "score": worst["score"],
                "pkg": worst["pkg"],
            }
        else:
            entry = None
        # Dedupe by image: keep highest score if same image changed in multiple workloads
        if image_key in workloads:
            existing = workloads[image_key]
            if entry and existing["top_cve"] and entry["score"] > existing["top_cve"]["score"]:
                existing["top_cve"] = entry
            continue
        workloads[image_key] = {
            "repo": f"{rep['repo']}:{rep['tag']}",
            "crit": rep["counts"]["CRITICAL"],
            "high": rep["counts"]["HIGH"],
            "type": ch["type"],
            "prev_crit": ch.get("prev_counts", {}).get("CRITICAL", 0) if ch["type"] == "increased" else None,
            "prev_high": ch.get("prev_counts", {}).get("HIGH", 0) if ch["type"] == "increased" else None,
            "top_cve": entry,
        }

    return {
        "type": "changes",
        "workloads": workloads,
        "total_changed": len(workloads),
    }


TELEGRAM_MAX_LEN = 4000


def _cap_message(text, header):
    if len(text) <= TELEGRAM_MAX_LEN:
        return text
    cutoff = TELEGRAM_MAX_LEN - len(header) - 50
    return text[:cutoff].rsplit("\n", 1)[0] + "\n\n..." + header


def _make_table(headers, rows):
    """Build a fixed-width text table. Returns list of lines."""
    cols = len(headers)
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if i < cols:
                widths[i] = max(widths[i], len(cell))
    def fmt_row(cells):
        parts = []
        for i, cell in enumerate(cells):
            if i < cols:
                parts.append(cell.ljust(widths[i]))
        return "  ".join(parts).rstrip()
    lines = [fmt_row(headers)]
    lines.append("  ".join("-" * w for w in widths))
    for row in rows:
        lines.append(fmt_row(row))
    return lines


def _top_severe_cves(current, limit=5):
    """Top N images by highest-severity CVE, one entry per unique image."""
    if not current:
        return []
    best = {}
    for key, rep in current.items():
        if not rep["severe"]:
            continue
        worst = max(rep["severe"], key=lambda v: v["score"])
        image_slug = rep["repo"].rsplit("/", 1)[-1]
        image_key = f"{rep['namespace']}/{image_slug}:{rep['tag']}"
        # Keep the highest score if the same image appears in multiple workloads
        if image_key in best and best[image_key]["score"] >= worst["score"]:
            continue
        best[image_key] = {
            "id": worst["id"],
            "workload": image_key,
            "score": worst["score"],
            "pkg": worst["pkg"],
        }
    return sorted(best.values(), key=lambda x: x["score"], reverse=True)[:limit]


def _format_cve_bullets(lines, cves):
    """Append CVE bullets in the shared format: workload | CVE link | score | pkg."""
    if not cves:
        return
    for s in cves:
        cve_link = f'<a href="https://nvd.nist.gov/vuln/detail/{html.escape(s["id"])}">{html.escape(s["id"])}</a>'
        lines.append(f"  \u2022 {html.escape(s['workload'])}  {cve_link}  {s['score']}  {html.escape(s['pkg'])}")


def format_telegram_message(result, current=None):
    lines = []

    if result["type"] == "first-run":
        total_crit = sum(i["crit"] for i in result["namespaces"].values())
        total_high = sum(i["high"] for i in result["namespaces"].values())
        lines.append("<b>\U0001F6A8 RanNet K8s Security Report \U0001FAE0</b>")
        lines.append(f"<i>initial report</i>")
        lines.append(f"{result['total_workloads']} workloads scanned | {total_crit} crit | {total_high} high")
        lines.append("")
        if not result["namespaces"]:
            lines.append("No critical or high severity vulnerabilities found.")
            return "\n".join(lines)

        top5 = _top_severe_cves(current)
        if top5:
            lines.append("")
            lines.append(f"<b>Top 5 offenders (score >= {SEVERITY_THRESHOLD}):</b>")
            _format_cve_bullets(lines, top5)
        return _cap_message("\n".join(lines), "(truncated)")

    elif result["type"] == "changes":
        # Persistent CVE list decides whether to send at all on a no-change run
        all_severe = _top_severe_cves(current)

        no_changes = not result["workloads"]
        if no_changes and not all_severe:
            return None

        if no_changes:
            lines.append("<b>\U0001F6A8 RanNet K8s Security Report \U0001FAE0</b>")
            lines.append("<i>no changes</i>")
        else:
            lines.append(f"<b>\U0001F6A8 RanNet K8s Security Report \U0001FAE0</b>")
            lines.append(f"<i>{result['total_changed']} workload(s) changed</i>")
        lines.append("")

        if not no_changes:
            changed = result["workloads"]
            change_cves = [w["top_cve"] for w in changed.values() if w["top_cve"]]
            if change_cves:
                lines.append("")
                lines.append(f"<b>Changed workloads ({len(change_cves)}):</b>")
                _format_cve_bullets(lines, change_cves)

        if all_severe:
            lines.append("")
            lines.append(f"<b>Top 5 offenders (score >= {SEVERITY_THRESHOLD}):</b>")
            _format_cve_bullets(lines, all_severe)

        return _cap_message("\n".join(lines), "(truncated - too many entries)")

    return None


# Telegram Bot API quirks:
# - No editMessageText for private chats (DMs). To "replace" a message,
#   use deleteMessage + sendMessage. We store the message_id in the state
#   file and delete the previous message before sending a new one.
# - HTML <a href> links do NOT render inside <pre> blocks. The CVE list
#   uses plain text with links (no <pre>) so they are clickable.

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


def delete_telegram(token, chat_id, message_id):
    url = f"https://api.telegram.org/bot{token}/deleteMessage"
    payload = {"chat_id": chat_id, "message_id": message_id}
    body = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=15, context=ssl.create_default_context()) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        err_body = e.read().decode()
        print(f"deleteMessage HTTP {e.code}: {err_body[:300]}", file=sys.stderr)
        return {"ok": False, "description": err_body[:300]}


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
            with urllib.request.urlopen(req, timeout=15, context=ssl.create_default_context()) as resp:
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

        previous, old_msg_id = load_state()

        result = diff_reports(current, previous)
        print(f"Diff type: {result['type']}, changed: {result.get('total_changed', 'N/A')}")

        msg = format_telegram_message(result, current=current)
        new_msg_id = old_msg_id
        if msg:
            if old_msg_id:
                print(f"Deleting old Telegram message {old_msg_id}...")
                del_result = delete_telegram(TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, old_msg_id)
                if not del_result.get("ok"):
                    print(f"Warning: failed to delete old message: {del_result.get('description', 'unknown')}", file=sys.stderr)
            print("--- Telegram message ---")
            print(strip_html(msg))
            print("--- End message ---")
            print(f"Sending Telegram message ({len(msg)} chars)...")
            send_result = send_telegram(TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, msg)
            if send_result and send_result.get("ok"):
                new_msg_id = send_result.get("result", {}).get("message_id")
                print(f"Message sent (id={new_msg_id}).")
            else:
                print(f"Telegram send failed: {send_result}", file=sys.stderr)
        else:
            print("No changes to report. Skipping Telegram message.")

        save_state(current, new_msg_id)
        print("State saved.")
    except Exception as e:
        print(f"Error: {type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
