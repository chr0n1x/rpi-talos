#!/usr/bin/env python3
"""
ArgoCD application status watcher.

Long-running poller that fetches all ArgoCD applications via the REST API,
tracks per-app (sync.status, health.status), and sends a Telegram message
when an app's status has been stable for a settle window.

Flap protection: a status change is only reported after it has persisted
for `settle_polls` consecutive polls. A transient OutOfSync that resolves
within the settle window is silently absorbed.

The first poll records the baseline silently. Uses only the Python
standard library (urllib, json, os, sys, ssl, time).
"""

import html
import json
import os
import ssl
import sys
import time
import urllib.request
import urllib.error

ARGOCD_API_URL = os.environ.get("ARGOCD_API_URL", "http://argocd-server:80")
ARGOCD_API_TOKEN = os.environ.get("ARGOCD_API_TOKEN", "")
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
ARGOCD_UI_URL = os.environ.get("ARGOCD_UI_URL", "https://argocd.rannet.duckdns.org")
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "60"))
SETTLE_POLLS = int(os.environ.get("SETTLE_POLLS", "3"))
TELEGRAM_MAX_LEN = 4000


def argocd_ssl_context():
    if ARGOCD_API_URL.startswith("https://"):
        return ssl.create_default_context()
    return None


def fetch_applications():
    """Fetch all applications from ArgoCD REST API. Returns list of dicts."""
    url = f"{ARGOCD_API_URL}/api/v1/applications"
    req = urllib.request.Request(url)
    req.add_header("Authorization", f"Bearer {ARGOCD_API_TOKEN}")
    req.add_header("Accept", "application/json")
    ctx = argocd_ssl_context()
    kwargs = {"timeout": 30}
    if ctx:
        kwargs["context"] = ctx
    with urllib.request.urlopen(req, **kwargs) as resp:
        return json.loads(resp.read())


def app_status(app):
    """Extract (sync_status, health_status) for an application."""
    sync = app.get("status", {}).get("sync", {}).get("status", "Unknown")
    health = app.get("status", {}).get("health", {}).get("status", "Unknown")
    return (sync, health)


def format_transition(app_name, old, new, app, settle_seconds):
    """Format a single confirmed app transition as a list of lines."""
    ns = app.get("metadata", {}).get("namespace", "argocd")
    lines = [f"\u2022 {html.escape(app_name)}"]
    old_sync, old_health = old
    new_sync, new_health = new
    if old_sync != new_sync:
        lines.append(f"  Sync: {html.escape(old_sync)} \u2192 {html.escape(new_sync)}")
    if old_health != new_health:
        lines.append(f"  Health: {html.escape(old_health)} \u2192 {html.escape(new_health)}")
    lines.append(f"  stable for ~{settle_seconds // 60}m")
    lines.append(f"  <a href=\"{html.escape(ARGOCD_UI_URL)}/applications/{html.escape(ns)}/{html.escape(app_name)}\">open</a>")
    return lines


def build_message(transitions, settle_seconds):
    """Build a Telegram HTML message from a list of (name, old, new, app) tuples."""
    lines = []
    lines.append("<b>\U0001F514 ArgoCD: {} app(s) changed</b>".format(len(transitions)))
    lines.append("")
    for app_name, old, new, app in transitions:
        lines.extend(format_transition(app_name, old, new, app, settle_seconds))
        lines.append("")
    text = "\n".join(lines)
    if len(text) > TELEGRAM_MAX_LEN:
        cutoff = TELEGRAM_MAX_LEN - 50
        text = text[:cutoff].rsplit("\n", 1)[0] + "\n\n...(truncated)"
    return text


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
                    return result
                return result
        except urllib.error.HTTPError as e:
            err_body = e.read().decode()
            print(f"Telegram HTTP {e.code}: {err_body[:300]}", file=sys.stderr)
            if attempt == max_retries:
                raise
            time.sleep(5)


def strip_html(s):
    start = -1
    out = []
    for ch in s:
        if ch == "<" and start == -1:
            start = 0
        elif ch == ">" and start >= 0:
            start = -1
        elif start == -1:
            out.append(ch)
    return "".join(out)


def main():
    if not ARGOCD_API_TOKEN:
        print("ARGOCD_API_TOKEN must be set", file=sys.stderr)
        sys.exit(1)
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID must be set", file=sys.stderr)
        sys.exit(1)

    settle_seconds = SETTLE_POLLS * POLL_INTERVAL
    print(f"ArgoCD watcher starting (poll={POLL_INTERVAL}s, settle={SETTLE_POLLS} polls / ~{settle_seconds // 60}m, API={ARGOCD_API_URL})")

    # Per-app tracking:
    #   baseline[name] = (sync, health)  -- the last CONFIRMED status
    #   candidate[name] = (sync, health) -- the status we're currently observing
    #   candidate_count[name] = int      -- consecutive polls at candidate status
    baseline = {}
    candidate = {}
    candidate_count = {}
    started = False

    while True:
        try:
            apps = fetch_applications()
        except Exception as e:
            print(f"Failed to fetch applications: {type(e).__name__}: {e}", file=sys.stderr)
            time.sleep(POLL_INTERVAL)
            continue

        current_names = set()
        current = {}
        for app in apps:
            name = app.get("metadata", {}).get("name", "")
            if not name:
                continue
            current_names.add(name)
            current[name] = (app_status(app), app)

        if not started:
            for name in current_names:
                status = current[name][0]
                baseline[name] = status
                candidate[name] = status
                candidate_count[name] = 1
            started = True
            print(f"Baseline recorded: {len(baseline)} apps (settle window: {SETTLE_POLLS} polls)")
            for name, (s, h) in sorted((n, current[n][0]) for n in current_names):
                print(f"  {name}: sync={s} health={h}")
            time.sleep(POLL_INTERVAL)
            continue

        transitions = []

        for name, (status, app) in current.items():
            old = baseline.get(name)
            if old is None:
                # Brand-new app: record silently, start settle counting
                baseline[name] = status
                candidate[name] = status
                candidate_count[name] = 1
                print(f"New app {name}: sync={status[0]} health={status[1]} (baseline set, no message)")
                continue

            if status == old:
                # Back to confirmed status: reset candidate tracking
                candidate[name] = status
                candidate_count[name] = 1
                continue

            # Status differs from confirmed baseline
            if candidate.get(name) == status:
                candidate_count[name] = candidate_count.get(name, 0) + 1
            else:
                candidate[name] = status
                candidate_count[name] = 1

            if candidate_count[name] >= SETTLE_POLLS:
                # Settled: confirm the transition
                transitions.append((name, old, status, app))
                baseline[name] = status
                candidate[name] = status
                candidate_count[name] = 1
                print(f"CONFIRMED {name}: {old} -> {status} (stable for {SETTLE_POLLS} polls)")
            else:
                print(f"Observed {name}: {old} -> {status} ({candidate_count[name]}/{SETTLE_POLLS} polls, not yet confirmed)")

        # Apps removed: confirm immediately (removal is not flappy)
        for name in list(baseline.keys()):
            if name not in current_names:
                transitions.append((name, baseline[name], ("Removed", "Removed"), {}))
                print(f"CONFIRMED {name}: removed")
                del baseline[name]
                candidate.pop(name, None)
                candidate_count.pop(name, None)

        if transitions:
            msg = build_message(transitions, settle_seconds)
            print(f"Detected {len(transitions)} confirmed transition(s):")
            for name, old, new, _ in transitions:
                print(f"  {name}: {old} -> {new}")
            print("--- Telegram message ---")
            print(strip_html(msg))
            print("--- End message ---")
            try:
                send_telegram(TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, msg)
                print("Telegram message sent.")
            except Exception as e:
                print(f"Telegram send failed: {e}", file=sys.stderr)

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
