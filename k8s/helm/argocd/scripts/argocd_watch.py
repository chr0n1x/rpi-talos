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

ARGOCD_API_URL = os.environ.get("ARGOCD_API_URL", "http://argo-cd-argocd-server:80")
ARGOCD_API_TOKEN = os.environ.get("ARGOCD_API_TOKEN", "")
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
ARGOCD_UI_URL = os.environ.get("ARGOCD_UI_URL", "https://argocd.rannet.duckdns.org")
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "60"))
SETTLE_POLLS = int(os.environ.get("SETTLE_POLLS", "3"))
HEALTHY_CLEAR_SECONDS = int(os.environ.get("HEALTHY_CLEAR_SECONDS", "900"))
REBAD_REFRESH_SECONDS = int(os.environ.get("REBAD_REFRESH_SECONDS", "300"))
TELEGRAM_MAX_LEN = 4000


def is_good(status):
    """An app is 'good' when Synced and Healthy."""
    return status == ("Synced", "Healthy")


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
        data = json.loads(resp.read())
    # ArgoCD REST API returns {"metadata": ..., "items": [...]}
    if isinstance(data, dict):
        return data.get("items", [])
    return data


def app_status(app):
    """Extract (sync_status, health_status) for an application."""
    sync = app.get("status", {}).get("sync", {}).get("status", "Unknown")
    health = app.get("status", {}).get("health", {}).get("status", "Unknown")
    return (sync, health)


def build_app_message(app_name, old, new, app, settle_seconds, kind="alert", elapsed_seconds=None):
    """Build a Telegram HTML message for a single app transition."""
    emoji = "\U0001F7E2" if kind == "recovery" else "\U0001F534"
    name = html.escape(app_name)
    if kind == "refresh":
        mins = elapsed_seconds // 60 if elapsed_seconds is not None else 0
        text = f"{emoji} <b>{name}</b>\nstill {html.escape(new[1])} ~{mins}m"
    elif kind == "recovery":
        text = f"{emoji} <b>{name}</b> recovered"
    else:
        text = f"{emoji} <b>{name}</b> went {html.escape(new[1])}"
    if len(text) > TELEGRAM_MAX_LEN:
        cutoff = TELEGRAM_MAX_LEN - 50
        text = text[:cutoff].rsplit("\n", 1)[0] + "\n\n...(truncated)"
    return text


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


def execute_actions(state, actions, settle_seconds, send_fn, delete_fn):
    """Execute a list of actions from process_poll. Mutates state.

    send_fn(text) -> dict with 'ok' and 'result.message_id'
    delete_fn(message_id) -> dict with 'ok'
    """
    for action in actions:
        kind = action[0]
        name = action[1]
        if kind == "send":
            elapsed = action[6] if len(action) > 6 else None
            _, name, old, new, app, send_kind = action[:6]
            msg = build_app_message(name, old, new, app, settle_seconds, send_kind, elapsed)
            print(f"{send_kind} for {name}: {old} -> {new}")
            print("--- Telegram message ---")
            print(strip_html(msg))
            print("--- End message ---")
            if name in state["message_ids"]:
                print(f"Deleting old Telegram message for {name} (id={state['message_ids'][name]})...")
                del_result = delete_fn(state["message_ids"][name])
                if not del_result.get("ok"):
                    print(f"Warning: failed to delete old message for {name}: {del_result.get('description', 'unknown')}", file=sys.stderr)
            send_result = send_fn(msg)
            if send_result and send_result.get("ok"):
                state["message_ids"][name] = send_result.get("result", {}).get("message_id")
                print(f"Telegram message sent for {name} (id={state['message_ids'][name]}).")
            else:
                print(f"Telegram send failed for {name}: {send_result}", file=sys.stderr)
        elif kind == "delete":
            reason = action[5]
            if name not in state["message_ids"]:
                continue
            print(f"Deleting Telegram message for {name} (id={state['message_ids'][name]}): {reason}")
            del_result = delete_fn(state["message_ids"][name])
            if not del_result.get("ok"):
                print(f"Warning: failed to delete message for {name}: {del_result.get('description', 'unknown')}", file=sys.stderr)
            state["message_ids"].pop(name, None)


def new_state():
    """Create a fresh watcher state dict. See keys in process_poll."""
    return {
        "baseline": {},
        "candidate": {},
        "candidate_count": {},
        "message_ids": {},
        "healthy_since": {},
        "last_bad_msg_at": {},
        "bad_since": {},
        "started": False,
    }


def process_poll(state, apps, now, settle_polls, healthy_clear_seconds, rebad_refresh_seconds):
    """Run one poll of the state machine. Mutates state, returns a list of actions.

    Each action is a tuple: ("send", name, old, new, app) or ("delete", name, reason).
    The caller is responsible for actually calling Telegram.
    """
    actions = []

    current = {}
    for app in apps:
        name = app.get("metadata", {}).get("name", "")
        if not name:
            continue
        current[name] = (app_status(app), app)

    baseline = state["baseline"]
    candidate = state["candidate"]
    candidate_count = state["candidate_count"]
    message_ids = state["message_ids"]
    healthy_since = state["healthy_since"]
    last_bad_msg_at = state["last_bad_msg_at"]
    bad_since = state["bad_since"]

    if not state["started"]:
        for name in current:
            status = current[name][0]
            baseline[name] = status
            candidate[name] = status
            candidate_count[name] = 1
            healthy_since[name] = now if is_good(status) else None
        state["started"] = True
        return actions

    transitions = []

    for name, (status, app) in current.items():
        old = baseline.get(name)
        if old is None:
            baseline[name] = status
            candidate[name] = status
            candidate_count[name] = 1
            continue

        if status == old:
            candidate[name] = status
            candidate_count[name] = 1
            continue

        if candidate.get(name) == status:
            candidate_count[name] = candidate_count.get(name, 0) + 1
        else:
            candidate[name] = status
            candidate_count[name] = 1

        if candidate_count[name] >= settle_polls:
            transitions.append((name, old, status, app))
            baseline[name] = status
            candidate[name] = status
            candidate_count[name] = 1
        # else: not yet settled, keep counting

    for name in list(baseline.keys()):
        if name not in current:
            transitions.append((name, baseline[name], ("Removed", "Removed"), {}))
            del baseline[name]
            candidate.pop(name, None)
            candidate_count.pop(name, None)
            healthy_since.pop(name, None)
            last_bad_msg_at.pop(name, None)
            bad_since.pop(name, None)
            message_ids.pop(name, None)

    for name, old, new, app in transitions:
        if is_good(new):
            actions.append(("send", name, old, new, app, "recovery"))
            healthy_since[name] = now
            last_bad_msg_at.pop(name, None)
            bad_since.pop(name, None)
        else:
            actions.append(("send", name, old, new, app, "alert"))
            healthy_since[name] = None
            last_bad_msg_at[name] = now
            bad_since[name] = now

    settled_names = {t[0] for t in transitions}
    for name, (status, app) in current.items():
        if name not in baseline or name in settled_names:
            continue
        if is_good(status):
            continue
        if name in last_bad_msg_at and (now - last_bad_msg_at[name]) >= rebad_refresh_seconds:
            elapsed = now - bad_since[name] if bad_since.get(name) else 0
            actions.append(("send", name, status, status, app, "refresh", elapsed))
            last_bad_msg_at[name] = now

    for name in list(message_ids.keys()):
        if name not in current:
            continue
        status = current[name][0]
        if is_good(status) and healthy_since.get(name) and (now - healthy_since[name]) >= healthy_clear_seconds:
            actions.append(("delete", name, None, None, None, f"healthy for {int((now - healthy_since[name]) // 60)}m"))
            healthy_since[name] = None

    return actions


def main():
    if not ARGOCD_API_TOKEN:
        print("ARGOCD_API_TOKEN must be set", file=sys.stderr)
        sys.exit(1)
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID must be set", file=sys.stderr)
        sys.exit(1)

    settle_seconds = SETTLE_POLLS * POLL_INTERVAL
    print(f"ArgoCD watcher starting (poll={POLL_INTERVAL}s, settle={SETTLE_POLLS} polls / ~{settle_seconds // 60}m, API={ARGOCD_API_URL})")

    state = new_state()

    def _send(text):
        return send_telegram(TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, text)

    def _delete(message_id):
        return delete_telegram(TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, message_id)

    while True:
        try:
            apps = fetch_applications()
        except Exception as e:
            print(f"Failed to fetch applications: {type(e).__name__}: {e}", file=sys.stderr)
            time.sleep(POLL_INTERVAL)
            continue

        now = time.time()
        was_started = state["started"]
        actions = process_poll(state, apps, now, SETTLE_POLLS, HEALTHY_CLEAR_SECONDS, REBAD_REFRESH_SECONDS)

        if not was_started and state["started"]:
            print(f"Baseline recorded: {len(state['baseline'])} apps (settle window: {SETTLE_POLLS} polls)")
            for name, (s, h) in sorted((n, state['baseline'][n]) for n in state['baseline']):
                print(f"  {name}: sync={s} health={h}")
            time.sleep(POLL_INTERVAL)
            continue

        try:
            execute_actions(state, actions, settle_seconds, _send, _delete)
        except Exception as e:
            print(f"Action execution failed: {e}", file=sys.stderr)

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
