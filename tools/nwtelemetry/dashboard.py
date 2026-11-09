"""OpenSearch Dashboards saved objects for the telemetry streams, as ndjson.

  python -m nwtelemetry.dashboard > dashboard.ndjson

scripts/telemetry-up.sh imports the output (overwriting), so the dashboard is
defined here, in review, rather than clicked together and lost with the volume.
Fixed ids keep re-imports idempotent.
"""
import json
import sys

VERSION = "2.19.6"

INDEX_PATTERNS = {
    "nw-findings": "findings-*",
    "nw-scans": "scans-*",
    "nw-ci-jobs": "ci-jobs-*",
    "nw-app-logs": "app-logs-*",
}

# KQL for application log lines a security engineer wants to read one by one.
SECURITY_QUERY = (
    "status >= 500 or status : (401 or 403) "
    "or (path : *users/v1/login* and status >= 400) "
    "or path : *_debug* or path : *createdb* "
    "or (method : DELETE and path : *users/v1/*) "
    "or path : *%27* or path : *union* or path : *script* or path : *..%2F* "
    "or log : Traceback"
)


def _search_source(query="", ref=True):
    src = {"query": {"query": query, "language": "kuery"}, "filter": []}
    if ref:
        src["indexRefName"] = "kibanaSavedObjectMeta.searchSourceJSON.index"
    return json.dumps(src)


def _count(id_="1"):
    return {"id": id_, "enabled": True, "type": "count", "schema": "metric", "params": {}}


def _terms(id_, schema, field, size=10, order_by="1", order="desc", label=None):
    p = {"field": field, "size": size, "order": order, "orderBy": order_by,
         "otherBucket": False, "missingBucket": False}
    if label:
        p["customLabel"] = label
    return {"id": id_, "enabled": True, "type": "terms", "schema": schema, "params": p}


def vis(id_, title, vtype, index, aggs, params=None, query="", description=""):
    state = {"title": title, "type": vtype, "aggs": aggs,
             "params": dict({"type": vtype, "addTooltip": True, "addLegend": True, "legendPosition": "right"},
                            **(params or {}))}
    return {
        "type": "visualization", "id": id_,
        "attributes": {
            "title": title, "description": description, "version": 1, "uiStateJSON": "{}",
            "visState": json.dumps(state),
            "kibanaSavedObjectMeta": {"searchSourceJSON": _search_source(query)},
        },
        "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": index}],
    }


def objects():
    out = [{"type": "index-pattern", "id": pid, "attributes": {"title": title, "timeFieldName": "@timestamp"},
            "references": []} for pid, title in INDEX_PATTERNS.items()]
    stacked = {"seriesParams": [{"show": True, "type": "histogram", "mode": "stacked", "data": {"id": "1", "label": "Count"},
                                 "valueAxis": "ValueAxis-1"}]}
    run_axis = lambda id_: _terms(id_, "segment", "pipeline_id", size=15, order_by="_key", label="pipeline")
    visualizations = [
        vis("nw-findings-per-tool", "Findings per tool per pipeline run", "histogram", "nw-findings",
            [_count(), run_axis("2"), _terms("3", "group", "tool", size=10)], stacked,
            description="One document per finding per run; a run whose scan did not report has no bar for that tool."),
        vis("nw-severity-per-run", "Severity per pipeline run", "histogram", "nw-findings",
            [_count(), run_axis("2"), _terms("3", "group", "severity", size=5)], stacked),
        vis("nw-severity-pie", "Severity distribution (time range)", "pie", "nw-findings",
            [_count(), _terms("2", "segment", "severity", size=5)], {"isDonut": True},
            description="Counts a finding once per run it appeared in."),
        vis("nw-high-findings", "High and critical findings: runs they appeared in", "table", "nw-findings",
            [_count(), _terms("2", "bucket", "tool", size=5), _terms("3", "bucket", "title.raw", size=25, label="finding"),
             _terms("4", "bucket", "location", size=1, label="location")],
            {"perPage": 15}, query="severity : (critical or high)"),
        vis("nw-scan-status", "Scans that did not report", "table", "nw-scans",
            [_count(), _terms("2", "bucket", "scan", size=20), _terms("3", "bucket", "status", size=5)],
            {"perPage": 10}, query="not status : reported",
            description="A missing report means the gate did not run or crashed, not that it found nothing."),
        vis("nw-job-results", "CI job results per pipeline run", "histogram", "nw-ci-jobs",
            [_count(), run_axis("2"), _terms("3", "group", "status", size=6)], stacked),
        vis("nw-job-duration", "Average job duration (s)", "horizontal_bar", "nw-ci-jobs",
            [{"id": "1", "enabled": True, "type": "avg", "schema": "metric", "params": {"field": "duration_s"}},
             _terms("2", "segment", "job_name", size=20)]),
        vis("nw-app-status", "Application requests by status class", "histogram", "nw-app-logs",
            [_count(),
             {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
              "params": {"field": "@timestamp", "interval": "auto", "min_doc_count": 1, "extended_bounds": {}}},
             {"id": "3", "enabled": True, "type": "filters", "schema": "group", "params": {"filters": [
                 {"input": {"query": "status >= 500", "language": "kuery"}, "label": "5xx"},
                 {"input": {"query": "status >= 400 and status < 500", "language": "kuery"}, "label": "4xx"},
                 {"input": {"query": "status >= 200 and status < 400", "language": "kuery"}, "label": "2xx/3xx"}]}}],
            stacked),
        vis("nw-app-errors", "Paths answering 5xx or 401/403", "table", "nw-app-logs",
            [_count(), _terms("2", "bucket", "service", size=3), _terms("3", "bucket", "path", size=20),
             _terms("4", "bucket", "status", size=5)],
            {"perPage": 15}, query="status >= 500 or status : (401 or 403)"),
    ]
    out += visualizations
    out.append({
        "type": "search", "id": "nw-security-requests",
        "attributes": {
            "title": "Security-relevant application log lines",
            "description": "Errors, denials, failed logins, sensitive endpoints, injection-looking paths, tracebacks.",
            "columns": ["service", "method", "path", "status", "log"], "sort": [["@timestamp", "desc"]], "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": _search_source(SECURITY_QUERY)},
        },
        "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": "nw-app-logs"}],
    })
    layout = [  # (object id, type, x, y, w, h)
        ("nw-findings-per-tool", "visualization", 0, 0, 24, 14), ("nw-severity-per-run", "visualization", 24, 0, 24, 14),
        ("nw-high-findings", "visualization", 0, 14, 32, 16), ("nw-severity-pie", "visualization", 32, 14, 16, 16),
        ("nw-job-results", "visualization", 0, 30, 24, 14), ("nw-job-duration", "visualization", 24, 30, 24, 14),
        ("nw-scan-status", "visualization", 0, 44, 16, 12),
        ("nw-app-status", "visualization", 16, 44, 32, 12), ("nw-app-errors", "visualization", 0, 56, 24, 16),
        ("nw-security-requests", "search", 24, 56, 24, 16),
    ]
    panels, refs = [], []
    for i, (oid, otype, x, y, w, h) in enumerate(layout):
        panels.append({"version": VERSION, "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(i + 1)},
                       "panelIndex": str(i + 1), "embeddableConfig": {}, "panelRefName": "panel_%d" % i})
        refs.append({"name": "panel_%d" % i, "type": otype, "id": oid})
    out.append({
        "type": "dashboard", "id": "nw-security-overview",
        "attributes": {
            "title": "Northwind security overview", "version": 1, "timeRestore": True,
            "timeFrom": "now-7d", "timeTo": "now", "refreshInterval": {"pause": True, "value": 0},
            "description": "Scanner findings, CI job events and staging application logs (Task 4).",
            "panelsJSON": json.dumps(panels), "optionsJSON": json.dumps({"hideTitles": False, "useMargins": True}),
            "kibanaSavedObjectMeta": {"searchSourceJSON": _search_source(ref=False)},
        },
        "references": refs,
    })
    return out


def main():
    for o in objects():
        sys.stdout.write(json.dumps(o) + "\n")


if __name__ == "__main__":
    main()
