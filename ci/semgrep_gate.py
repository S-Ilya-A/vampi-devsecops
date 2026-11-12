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
    timed_out = set()
    for err in data.get("errors", []):
        etype = err.get("type")
        etype = etype[0] if isinstance(etype, list) else etype
        path = err.get("path") or (err.get("spans") or [{}])[0].get("file", "?")
        if etype == "Timeout":
            # A rule that timed out did not analyse the file: its findings would
            # be silently missing, so this blocks like a finding does.
            timed_out.add(path)
            continue
        # Parse errors (mostly shell scripts) mean a file was only partly
        # analysed: visible, not blocking.
        print("  scan error (%s): %s" % (etype, str(err.get("message", ""))[:160].replace("\n", " ")))
    for path in sorted(timed_out):
        print("  COVERAGE: a rule timed out on %s; its results for that file are incomplete" % path)

    blocking = [r for r in results if ORDER.index(r["extra"]["severity"]) >= threshold]
    for r in sorted(blocking, key=lambda r: (r["path"], r["start"]["line"])):
        print("  BLOCK %-7s %s:%d  %s" % (
            r["extra"]["severity"], r["path"], r["start"]["line"], r["check_id"]))
    if timed_out:
        print("SAST gate FAILED: the scan did not fully cover %d file(s)" % len(timed_out))
        return 1
    if blocking:
        print("SAST gate FAILED: %d finding(s) at %s or above" % (len(blocking), args.fail_on))
        return 1
    print("SAST gate passed (threshold: %s)" % args.fail_on)
    return 0


if __name__ == "__main__":
    sys.exit(main())
