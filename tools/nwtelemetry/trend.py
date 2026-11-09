"""Trend report from the telemetry store.

usage: python -m nwtelemetry.trend [--since 7d|24h|2026-11-01] [--format table|json]
                                   [--ref master] [--compare OLD NEW] [--top 10]

Connection: --url/--user/--password/--ca, or TELEMETRY_URL, TELEMETRY_USER,
TELEMETRY_PASSWORD, TELEMETRY_CA. Defaults suit this machine
(https://127.0.0.1:9200, user analyst, password and CA from .local/telemetry/).

Sections:
  runs       findings per tool for every pipeline run in the window
  severity   severity distribution per tool in the newest run, and over the window
  changes    new / recurring / resolved findings between two runs (the newest two
             on the ref, or --compare). A scan missing from either run is not
             compared, so "the scanner did not run" never shows up as "resolved".
  app        what the staging application's logs say: authentication failures,
             denied and failing requests, injection-looking requests, use of
             sensitive endpoints, scanner user agents, and whether logs are still
             arriving.
Exit status: 0, or 2 when the store cannot be queried.
"""
import argparse
import datetime
import json
import os
import re
import sys

from .client import OpenSearch, OpenSearchError
from .normalize import SEVERITY_RANK

SEVERITIES = ["critical", "high", "medium", "low", "info"]
TOOLS = ["semgrep", "gitleaks", "grype", "trivy", "zap"]

# Request paths that look like an attack. Matched case-insensitively on the
# logged path (query string included).
SUSPICIOUS_PATTERNS = [
    "*'*", "*%27*", "*\"*", "*%22*",                  # quote breaking out of SQL or markup
    "*union*select*", "*union%20*", "* or 1=1*", "*%20or%201=1*", "*sleep(*", "*benchmark(*",
    "*<script*", "*%3cscript*", "*onerror*", "*javascript:*",
    "*../*", "*..%2f*", "*%2e%2e*", "*/etc/passwd*", "*win.ini*",
    "*${*", "*%24%7b*", "*{{*",                          # template / expression injection
]
# Endpoints whose use a security engineer wants to see, whoever called them.
SENSITIVE = {
    "debug endpoint (lists every user)": {"wildcard": {"path": {"value": "*/users/v1/_debug*"}}},
    "database re-seed (/createdb)": {"wildcard": {"path": {"value": "*/createdb*"}}},
    "user deletion": {"bool": {"filter": [{"term": {"method": "DELETE"}},
                                          {"wildcard": {"path": {"value": "*/users/v1/*"}}}]}},
    "password change": {"bool": {"filter": [{"term": {"method": "PUT"}},
                                            {"wildcard": {"path": {"value": "*/users/v1/*/password*"}}}]}},
}
SCANNER_AGENTS = ["*ZAP*", "*sqlmap*", "*Nikto*", "*nmap*", "*Nuclei*", "*curl/*", "*python-requests*",
                  "*Go-http-client*", "*masscan*", "*dirbuster*", "*gobuster*"]
STALE_LOGS = datetime.timedelta(hours=1)


# --------------------------------------------------------------------------- time
def parse_since(value, now=None):
    """'30m', '24h', '7d', '2w' (before now), or an ISO date/datetime (UTC if no zone)."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    m = re.fullmatch(r"\s*(\d+)\s*([mhdw])\s*", value or "")
    if m:
        n, unit = int(m.group(1)), m.group(2)
        return now - datetime.timedelta(**{{"m": "minutes", "h": "hours", "d": "days", "w": "weeks"}[unit]: n})
    try:
        dt = datetime.datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        raise ValueError("--since: expected a duration like 30m, 24h, 7d, 2w or a date like 2026-11-01, got %r"
                         % value) from None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    if dt > now:
        raise ValueError("--since: %s is in the future" % value)
    return dt


# --------------------------------------------------------------------------- store
class Store:
    """Queries against OpenSearch. Every method returns plain data, so the report
    logic below is tested without a server (tests use an in-memory Store)."""

    def __init__(self, client):
        self.c = client

    def runs(self, since, ref=None):
        """Pipeline runs in the window, newest first, with their scans."""
        filt = [{"range": {"@timestamp": {"gte": since.isoformat()}}}]
        if ref:
            filt.append({"term": {"ref": ref}})
        res = self.c.search("scans-*", {
            "size": 0, "query": {"bool": {"filter": filt}},
            "aggs": {"runs": {"terms": {"field": "pipeline_id", "size": 200, "order": {"_key": "desc"}},
                              "aggs": {"scans": {"top_hits": {"size": 50, "_source": {"excludes": ["error"]}}}}}}})
        runs = []
        for b in res.get("aggregations", {}).get("runs", {}).get("buckets", []):
            docs = [h["_source"] for h in b["scans"]["hits"]["hits"]]
            first = docs[0]
            runs.append({
                "pipeline_id": int(b["key"]), "commit": first.get("commit", ""), "ref": first.get("ref", ""),
                "time": first.get("@timestamp", ""), "url": first.get("pipeline_url", ""),
                "scans": {d["scan"]: {k: d.get(k) for k in ("tool", "status", "findings", "by_severity", "job_status")}
                          for d in docs}})
        return runs

    def findings(self, pipeline_id):
        """Every finding of one run (paged with search_after; a run can exceed 10 000)."""
        out, after = [], None
        while True:
            body = {"size": 5000, "query": {"term": {"pipeline_id": pipeline_id}},
                    "sort": [{"scan": "asc"}, {"fingerprint": "asc"}],
                    "_source": ["tool", "scan", "rule_id", "title", "severity", "fingerprint", "location",
                                "package", "installed_version", "fixed_version", "suppressed"]}
            if after:
                body["search_after"] = after
            hits = self.c.search("findings-*", body).get("hits", {}).get("hits", [])
            out.extend(h["_source"] for h in hits)
            if len(hits) < 5000:
                return out
            after = hits[-1]["sort"]

    def app_logs(self, since, top=10):
        rng = {"range": {"@timestamp": {"gte": since.isoformat()}}}
        ci = lambda pats, field: {"bool": {"should": [
            {"wildcard": {field: {"value": p, "case_insensitive": True}}} for p in pats], "minimum_should_match": 1}}
        terms = lambda field, size=top: {"terms": {"field": field, "size": size}}
        res = self.c.search("app-logs-*", {
            "size": 0, "track_total_hits": True, "query": {"bool": {"filter": [rng]}},
            "aggs": {
                "services": {"terms": {"field": "service", "size": 20},
                             "aggs": {"last": {"max": {"field": "@timestamp"}}}},
                "status": {"range": {"field": "status", "ranges": [
                    {"key": "2xx", "from": 200, "to": 300}, {"key": "3xx", "from": 300, "to": 400},
                    {"key": "4xx", "from": 400, "to": 500}, {"key": "5xx", "from": 500, "to": 600}]}},
                "login_failures": {"filter": {"bool": {"filter": [
                    {"wildcard": {"path": {"value": "*/users/v1/login*"}}}, {"range": {"status": {"gte": 400}}}]}},
                    "aggs": {"by_client": terms("client_ip")}},
                "denied": {"filter": {"terms": {"status": [401, 403]}}, "aggs": {"paths": terms("path")}},
                "server_errors": {"filter": {"range": {"status": {"gte": 500}}}, "aggs": {"paths": terms("path")}},
                "error_lines": {"filter": {"bool": {"filter": [{"term": {"service": "api"}}], "must": [
                    {"query_string": {"query": "Traceback OR Exception OR Error OR CRITICAL", "default_field": "log"}}],
                    "must_not": [{"exists": {"field": "status"}}]}},
                    "aggs": {"sample": {"top_hits": {"size": 5, "sort": [{"@timestamp": "desc"}], "_source": ["log", "@timestamp"]}}}},
                "suspicious": {"filter": ci(SUSPICIOUS_PATTERNS, "path"),
                               "aggs": {"paths": terms("path"), "clients": terms("client_ip"),
                                        "status": terms("status")}},
                "sensitive": {"filters": {"filters": SENSITIVE}, "aggs": {"status": terms("status")}},
                "scanners": {"filter": ci(SCANNER_AGENTS, "user_agent"), "aggs": {"agents": terms("user_agent")}},
            }})
        a = res.get("aggregations") or {}
        b = lambda agg, key="paths": {str(x["key"]): x["doc_count"] for x in agg.get(key, {}).get("buckets", [])}
        return {
            "total": res.get("hits", {}).get("total", {}).get("value", 0),
            "services": {x["key"]: {"events": x["doc_count"], "last_seen": x["last"].get("value_as_string")}
                         for x in a.get("services", {}).get("buckets", [])},
            "status": {x["key"]: x["doc_count"] for x in a.get("status", {}).get("buckets", [])},
            "login_failures": {"total": a.get("login_failures", {}).get("doc_count", 0),
                               "by_client": b(a.get("login_failures", {}), "by_client")},
            "denied": {"total": a.get("denied", {}).get("doc_count", 0), "paths": b(a.get("denied", {}))},
            "server_errors": {"total": a.get("server_errors", {}).get("doc_count", 0),
                              "paths": b(a.get("server_errors", {}))},
            "error_lines": {"total": a.get("error_lines", {}).get("doc_count", 0),
                            "latest": [h["_source"].get("log", "")[:200] for h in
                                       a.get("error_lines", {}).get("sample", {}).get("hits", {}).get("hits", [])]},
            "suspicious": {"total": a.get("suspicious", {}).get("doc_count", 0),
                           "paths": b(a.get("suspicious", {})), "clients": b(a.get("suspicious", {}), "clients"),
                           "status": b(a.get("suspicious", {}), "status")},
            "sensitive": {k: {"total": v["doc_count"], "status": b(v, "status")}
                          for k, v in a.get("sensitive", {}).get("buckets", {}).items()},
            "scanners": {"total": a.get("scanners", {}).get("doc_count", 0),
                         "agents": b(a.get("scanners", {}), "agents")},
        }


# --------------------------------------------------------------------------- analysis
def tool_counts(run):
    """{tool: findings} for one run; None for a tool none of whose scans reported."""
    out = {}
    for s in run["scans"].values():
        t = s["tool"]
        if s["status"] == "reported":
            out[t] = (out.get(t) or 0) + (s["findings"] or 0)
        else:
            out.setdefault(t, None)
    return out


def severity_table(runs):
    """Severity per tool for the newest run, and summed over all runs in the window."""
    def add(acc, run):
        for s in run["scans"].values():
            if s["status"] != "reported":
                continue
            row = acc.setdefault(s["tool"], {k: 0 for k in SEVERITIES})
            for k, v in (s.get("by_severity") or {}).items():
                row[k] = row.get(k, 0) + v
        return acc
    latest = add({}, runs[0]) if runs else {}
    window = {}
    for r in runs:
        add(window, r)
    return {"latest_run": runs[0]["pipeline_id"] if runs else None, "latest": latest, "window": window}


def diff_runs(old_run, new_run, old_findings, new_findings, top=10):
    """New / recurring / resolved between two runs, per scan, only for scans that
    reported in both runs."""
    compared = sorted(s for s in new_run["scans"]
                      if new_run["scans"][s]["status"] == "reported"
                      and old_run["scans"].get(s, {}).get("status") == "reported")
    skipped = sorted((set(old_run["scans"]) | set(new_run["scans"])) - set(compared))
    key = lambda f: (f["scan"], f["fingerprint"])
    old = {key(f): f for f in old_findings if f["scan"] in compared}
    new = {key(f): f for f in new_findings if f["scan"] in compared}
    rank = lambda f: (-SEVERITY_RANK.get(f["severity"], 0), f["scan"], f.get("title", ""))
    pick = lambda keys, src: sorted((src[k] for k in keys), key=rank)
    new_keys, gone_keys, kept_keys = new.keys() - old.keys(), old.keys() - new.keys(), new.keys() & old.keys()
    per_tool = {}
    for label, keys, src in (("new", new_keys, new), ("resolved", gone_keys, old), ("recurring", kept_keys, new)):
        for k in keys:
            t = per_tool.setdefault(src[k]["tool"], {"new": 0, "recurring": 0, "resolved": 0})
            t[label] += 1
    brief = lambda f: {k: f.get(k, "") for k in ("severity", "tool", "scan", "title", "location", "rule_id")}
    return {
        "old_pipeline": old_run["pipeline_id"], "new_pipeline": new_run["pipeline_id"],
        "compared_scans": compared, "not_compared": skipped,
        "per_tool": per_tool,
        "counts": {"new": len(new_keys), "recurring": len(kept_keys), "resolved": len(gone_keys)},
        "new": [brief(f) for f in pick(new_keys, new)[:top]],
        "resolved": [brief(f) for f in pick(gone_keys, old)[:top]],
        "recurring_by_severity": {s: sum(1 for k in kept_keys if new[k]["severity"] == s) for s in SEVERITIES},
    }


def app_notes(logs, now):
    """Plain-language observations a security engineer should not miss."""
    notes = []
    if not logs["total"]:
        notes.append("No application logs in the window: is Fluent Bit on the VM shipping?")
    for svc, info in sorted(logs["services"].items()):
        last = info.get("last_seen")
        if last:
            age = now - datetime.datetime.fromisoformat(last.replace("Z", "+00:00"))
            if age > STALE_LOGS:
                notes.append("No logs from '%s' for %s (last %s): shipping may have stopped." % (svc, str(age).split(".")[0], last))
    lf = logs["login_failures"]
    for client, n in lf["by_client"].items():
        if n >= 10:
            notes.append("%d failed logins from %s: password guessing?" % (n, client))
    if logs["suspicious"]["total"]:
        ok = sum(v for k, v in logs["suspicious"]["status"].items() if k.startswith("2"))
        notes.append("%d requests with injection or traversal patterns; %d of them got a 2xx answer."
                     % (logs["suspicious"]["total"], ok))
    if logs["server_errors"]["total"]:
        notes.append("%d server errors (5xx): unhandled input reaches the code; see the paths below."
                     % logs["server_errors"]["total"])
    for name, v in logs["sensitive"].items():
        if v["total"]:
            ok = sum(n for k, n in v["status"].items() if k.startswith("2"))
            notes.append("%s: %d calls, %d succeeded." % (name, v["total"], ok))
    if logs["scanners"]["total"]:
        notes.append("%d requests from scanner user agents (ZAP is ours; anything else is not)."
                     % logs["scanners"]["total"])
    return notes


def build_report(store, since, ref=None, compare=None, top=10, now=None):
    now = now or datetime.datetime.now(datetime.timezone.utc)
    runs = store.runs(since, ref)
    report = {"generated": now.isoformat(timespec="seconds"), "since": since.isoformat(timespec="seconds"),
              "ref": ref, "runs": [], "severity": severity_table(runs), "changes": None, "app": None}
    for r in runs:
        report["runs"].append({"pipeline_id": r["pipeline_id"], "time": r["time"], "commit": r["commit"][:8],
                               "ref": r["ref"], "tools": tool_counts(r)})
    by_id = {r["pipeline_id"]: r for r in runs}
    pair = None
    if compare:
        missing = [p for p in compare if p not in by_id]
        if missing:
            report["changes"] = {"error": "pipeline(s) %s not in the window" % ", ".join(map(str, missing))}
        else:
            pair = (by_id[compare[0]], by_id[compare[1]])
    elif len(runs) >= 2:
        pair = (runs[1], runs[0])
    if pair:
        report["changes"] = diff_runs(pair[0], pair[1], store.findings(pair[0]["pipeline_id"]),
                                      store.findings(pair[1]["pipeline_id"]), top)
    try:
        logs = store.app_logs(since, top)
    except OpenSearchError as e:
        # The CI account may read pipeline data but not application logs.
        report["app"] = {"error": str(e)}
    else:
        report["app"] = dict(logs, notes=app_notes(logs, now))
    return report


# --------------------------------------------------------------------------- output
def table(rows, headers):
    rows = [["" if c is None else str(c) for c in r] for r in rows]
    widths = [max(len(h), *(len(r[i]) for r in rows)) if rows else len(h) for i, h in enumerate(headers)]
    def line(cells):   # numbers (and "-" for "no data") right-aligned, text left-aligned
        return "  ".join(c.rjust(w) if i and (c.isdigit() or c == "-") else c.ljust(w)
                         for i, (c, w) in enumerate(zip(cells, widths))).rstrip()
    return "\n".join([line(headers), line(["-" * w for w in widths])] + [line(r) for r in rows])


def render_table(rep):
    out = ["Trend report  since %s%s  (generated %s)" % (rep["since"], "  ref " + rep["ref"] if rep["ref"] else "", rep["generated"]), ""]
    out.append("== Findings per tool per pipeline run  (- = no complete report from that tool)")
    if rep["runs"]:
        out.append(table([[r["pipeline_id"], r["time"][:16].replace("T", " "), r["commit"], r["ref"]]
                          + ["-" if r["tools"].get(t) is None else r["tools"][t] for t in TOOLS]
                          for r in rep["runs"]], ["pipeline", "time (UTC)", "commit", "ref"] + TOOLS))
    else:
        out.append("no pipeline runs in the window")
    out += ["", "== Severity distribution, newest run (#%s)" % rep["severity"]["latest_run"]]
    for key in ("latest", "window"):
        if key == "window":
            out += ["", "== Severity distribution, all runs in the window"]
        rows = [[t] + [rep["severity"][key][t].get(s, 0) for s in SEVERITIES]
                for t in TOOLS if t in rep["severity"][key]]
        out.append(table(rows, ["tool"] + SEVERITIES) if rows else "nothing")
    out += ["", "== Changes between runs"]
    ch = rep["changes"]
    if not ch:
        out.append("fewer than two runs in the window")
    elif "error" in ch:
        out.append(ch["error"])
    else:
        out.append("#%s -> #%s: %d new, %d recurring, %d resolved"
                   % (ch["old_pipeline"], ch["new_pipeline"], ch["counts"]["new"], ch["counts"]["recurring"], ch["counts"]["resolved"]))
        if ch["not_compared"]:
            out.append("not compared (no complete report in one of the runs): " + ", ".join(ch["not_compared"]))
        out.append(table([[t, v["new"], v["recurring"], v["resolved"]] for t, v in sorted(ch["per_tool"].items())],
                         ["tool", "new", "recurring", "resolved"]))
        for label in ("new", "resolved"):
            if ch[label]:
                out += ["", "%s (most severe first):" % label.capitalize()]
                out.append(table([[f["severity"], f["scan"], f["title"][:60], f["location"][:60]] for f in ch[label]],
                                 ["severity", "scan", "finding", "location"]))
    app = rep["app"]
    out += ["", "== Application logs (staging)"]
    if "error" in app:
        out.append("not available with this account: " + app["error"][:200])
        return "\n".join(out) + "\n"
    out.append("%d events; status classes: %s" % (app["total"], ", ".join("%s %d" % kv for kv in sorted(app["status"].items())) or "none"))
    for svc, info in sorted(app["services"].items()):
        out.append("  %-10s %7d events, last %s" % (svc, info["events"], info["last_seen"]))
    if app["notes"]:
        out += ["", "Worth a look:"] + ["  * " + n for n in app["notes"]]
    for title, sect in (("Injection-looking requests", app["suspicious"]["paths"]),
                        ("Server errors (5xx)", app["server_errors"]["paths"]),
                        ("Denied (401/403)", app["denied"]["paths"]),
                        ("Failed logins by client", app["login_failures"]["by_client"]),
                        ("Scanner user agents", app["scanners"]["agents"])):
        if sect:
            out += ["", title + ":", table([[k[:90], v] for k, v in sect.items()], ["", "requests"])]
    if app["error_lines"]["latest"]:
        out += ["", "Latest error lines from the API (%d in the window):" % app["error_lines"]["total"]]
        out += ["  " + line for line in app["error_lines"]["latest"]]
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------- main
def _default(path):
    return path if os.path.exists(path) else None


def main(argv=None):
    root = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", ".."))
    state = os.path.join(root, ".local", "telemetry")
    ap = argparse.ArgumentParser(prog="trend", description="Trend report from the telemetry store.")
    ap.add_argument("--since", default="7d", help="duration (30m, 24h, 7d, 2w) or date (2026-11-01); default 7d")
    ap.add_argument("--format", choices=["table", "json"], default="table")
    ap.add_argument("--ref", help="only pipelines on this branch or tag")
    ap.add_argument("--compare", nargs=2, type=int, metavar=("OLD", "NEW"), help="pipeline ids to compare")
    ap.add_argument("--top", type=int, default=10, help="rows per list (default 10)")
    ap.add_argument("--url", default=os.environ.get("TELEMETRY_URL", "https://127.0.0.1:9200"))
    ap.add_argument("--user", default=os.environ.get("TELEMETRY_USER", "analyst"))
    ap.add_argument("--password", default=os.environ.get("TELEMETRY_PASSWORD"))
    ap.add_argument("--ca", default=os.environ.get("TELEMETRY_CA") or _default(os.path.join(state, "certs", "ca.pem")))
    args = ap.parse_args(argv)
    try:
        since = parse_since(args.since)
    except ValueError as e:
        ap.error(str(e))
    password = args.password
    if password is None:
        pw_file = os.path.join(state, "%s-password" % args.user)
        if os.path.exists(pw_file):
            with open(pw_file, encoding="utf-8") as f:
                password = f.read().strip()
    store = Store(OpenSearch(args.url, args.user, password, args.ca))
    try:
        rep = build_report(store, since, args.ref, args.compare, args.top)
    except OpenSearchError as e:
        print("trend: cannot query %s: %s" % (args.url, e), file=sys.stderr)
        return 2
    sys.stdout.write(json.dumps(rep, indent=2) + "\n" if args.format == "json" else render_table(rep))
    return 0


if __name__ == "__main__":
    sys.exit(main())
