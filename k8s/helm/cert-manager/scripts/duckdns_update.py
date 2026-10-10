#!/usr/bin/env python3
"""
DuckDNS A/AAAA record updater.

Re-pushes the configured subdomain -> IP mappings to the DuckDNS API every
run, so a DNS-01 challenge cleanup (which calls the API with clear=true and
nukes the A/AAAA records alongside the TXT record) is only a transient
outage until the next scheduled run.

Config and token are injected via a VSO-managed secret mounted at /creds.
Uses only the Python standard library (urllib, json, os, sys).
"""

import json
import os
import sys
import urllib.parse
import urllib.request

DUCKDNS_API = "https://www.duckdns.org/update"


def main():
    with open("/creds/config.json") as f:
        config = json.load(f)

    token = os.environ["DUCKDNS_TOKEN"]
    if not token:
        print("DUCKDNS_TOKEN is empty", file=sys.stderr)
        return 1

    failures = 0
    for subdomain, spec in config.items():
        params = {
            "domains": subdomain,
            "token": token,
            "verbose": "true",
        }
        if "ip" in spec:
            params["ip"] = spec["ip"]
        if "ipv6" in spec:
            params["ipv6"] = spec["ipv6"]

        url = f"{DUCKDNS_API}?{urllib.parse.urlencode(params)}"
        try:
            with urllib.request.urlopen(url, timeout=30) as resp:
                body = resp.read().decode()
        except Exception as e:
            print(f"ERROR {subdomain}: request failed: {e}", file=sys.stderr)
            failures += 1
            continue

        # Verbose response shape:
        # OK
        # 192.168.x.x [current A, can be blank]
        # fd92:acff::1 [current AAAA, can be blank]
        # UPDATED [or NOCHANGE]
        lines = body.strip().splitlines()
        if not lines or lines[0] != "OK":
            print(f"ERROR {subdomain}: KO: {body.strip()[:200]}", file=sys.stderr)
            failures += 1
            continue

        status = lines[3].strip() if len(lines) > 3 else "UNKNOWN"
        print(f"OK {subdomain}: {status} a={lines[1].strip() if len(lines) > 1 else ''} "
              f"aaaa={lines[2].strip() if len(lines) > 2 else ''}")

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
