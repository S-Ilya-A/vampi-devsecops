#!/usr/bin/env python3
"""SAST gate: print a summary of a Semgrep JSON report and fail on blocking findings.

usage: semgrep_gate.py REPORT [--fail-on ERROR|WARNING|INFO]

Findings at or above --fail-on make the exit status 1. Findings suppressed with
`nosemgrep` never reach the report, so they cannot block; they are listed in
docs/SUPPRESSIONS.md instead.
"""
import argparse
import json
import sys
from collections import Counter

ORDER = ["INFO", "WARNING", "ERROR"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("report")
    ap.add_argument("--fail-on", default="ERROR", choices=ORDER)
    args = ap.parse_args()

    with open(args.report, encoding="utf-8") as f:
        data = json.load(f)
    results = data.get("results", [])
    threshold = ORDER.index(args.fail_on)

    by_sev = Counter(r["extra"]["severity"] for r in results)
    print("Semgrep: %d findings (%s)" % (
        len(results), ", ".join("%s: %d" % (s, by_sev[s]) for s in reversed(ORDER))))
    for err in data.get("errors", []):
        # Parse errors mean a file was only partly analysed: visible, not blocking.
        print("  scan error: %s" % err.get("message", err)[:200].replace("\n", " "))

    blocking = [r for r in results if ORDER.index(r["extra"]["severity"]) >= threshold]
    for r in sorted(blocking, key=lambda r: (r["path"], r["start"]["line"])):
        print("  BLOCK %-7s %s:%d  %s" % (
            r["extra"]["severity"], r["path"], r["start"]["line"], r["check_id"]))
    if blocking:
        print("SAST gate FAILED: %d finding(s) at %s or above" % (len(blocking), args.fail_on))
        return 1
    print("SAST gate passed (threshold: %s)" % args.fail_on)
    return 0


if __name__ == "__main__":
    sys.exit(main())
