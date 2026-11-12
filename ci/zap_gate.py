#!/usr/bin/env python3
"""DAST gate: summarise a ZAP JSON report (-J) and fail on alerts at or above a risk.

usage: zap_gate.py REPORT --fail-on {low,medium,high} [--suppressions FILE]
                   [--require-uri REGEX ...]

An alert instance blocks when its risk is at or above --fail-on, its confidence
is not "false positive" (0), and no suppression matches it. A suppression matches
one rule (pluginid) on URLs matching a regular expression, never a whole rule
everywhere, and stops applying after its "expires" date. Each one needs a reason;
docs/SECURITY_GATES.md lists them.

--require-uri is a coverage check. A scan that never reached the application
reports no alerts, and a gate that only counts alerts would pass it. Each REGEX
must match the URL of at least one alert instance of any risk, informational
ones included (ZAP raises those on almost every response); otherwise the gate
fails because the scan did not cover the target.
"""
import argparse
import datetime
import json
import re
import sys
from collections import Counter

RISKS = {0: "info", 1: "low", 2: "medium", 3: "high"}
LEVEL = {"low": 1, "medium": 2, "high": 3}


def load_suppressions(path):
    if not path:
        return []
    with open(path, encoding="utf-8") as f:
        entries = json.load(f).get("suppressions", [])
    today = datetime.date.today()
    active = []
    for e in entries:
        for key in ("id", "pluginid", "uri_regex", "reason", "expires"):
            if not e.get(key):
                sys.exit("suppression %r is missing %r" % (e.get("id"), key))
        if datetime.date.fromisoformat(e["expires"]) < today:
            print("  suppression %s expired on %s: no longer applied" % (e["id"], e["expires"]))
            continue
        e["_re"] = re.compile(e["uri_regex"])
        active.append(e)
    return active


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("report")
    ap.add_argument("--fail-on", required=True, choices=sorted(LEVEL))
    ap.add_argument("--suppressions")
    ap.add_argument("--require-uri", action="append", default=[])
    args = ap.parse_args()

    with open(args.report, encoding="utf-8") as f:
        data = json.load(f)
    sups = load_suppressions(args.suppressions)
    threshold = LEVEL[args.fail_on]

    by_risk = Counter()
    blocking, suppressed = [], 0
    seen_uris = set()
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            risk = int(alert["riskcode"])
            conf = int(alert["confidence"])
            by_risk[RISKS[risk]] += 1
            seen_uris.update(i.get("uri", "") for i in alert.get("instances", []))
            if risk < threshold or conf == 0:
                continue
            for inst in alert.get("instances", []):
                uri = inst.get("uri", "")
                if any(s["pluginid"] == str(alert["pluginid"]) and s["_re"].search(uri) for s in sups):
                    suppressed += 1
                    continue
                blocking.append((RISKS[risk], alert["pluginid"], alert["alert"], inst.get("method", ""), uri))

    print("ZAP: %d alert types (%s); %d instance(s) suppressed" % (
        sum(by_risk.values()),
        ", ".join("%s: %d" % (r, by_risk[r]) for r in ("high", "medium", "low", "info")),
        suppressed))
    seen = set()
    for risk, pid, name, method, uri in sorted(blocking, key=lambda b: (-LEVEL.get(b[0], 0), b[1], b[4])):
        key = (pid, method, uri)
        if key in seen:
            continue
        seen.add(key)
        print("  BLOCK %-6s %-6s %s  %s %s" % (risk, pid, name, method, uri))
    missing = [rx for rx in args.require_uri if not any(re.search(rx, u) for u in seen_uris)]
    for rx in missing:
        print("  COVERAGE: no response seen for %s" % rx)
    if missing:
        print("DAST gate FAILED: the scan did not reach %d required part(s) of the target" % len(missing))
        return 1
    if blocking:
        print("DAST gate FAILED: %d alert instance(s) at %s risk or above" % (len(blocking), args.fail_on))
        return 1
    print("DAST gate passed (threshold: %s)" % args.fail_on)
    return 0


if __name__ == "__main__":
    sys.exit(main())
