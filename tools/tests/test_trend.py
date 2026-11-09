import datetime
import io
import json
import unittest
from contextlib import redirect_stdout
from unittest import mock

from nwtelemetry import trend
from nwtelemetry.client import OpenSearchError

UTC = datetime.timezone.utc
NOW = datetime.datetime(2026, 11, 9, 12, 0, tzinfo=UTC)


def scan(tool, status="reported", findings=0, **sev):
    return {"tool": tool, "status": status, "findings": findings, "by_severity": sev, "job_status": "failed"}


def finding(scan_, fp, severity="high", tool=None, title=None):
    return {"tool": tool or scan_.split(":")[0].replace("sast", "semgrep").replace("sca", "grype"),
            "scan": scan_, "fingerprint": fp, "severity": severity, "title": title or fp, "location": "x", "rule_id": fp}


OLD = {"pipeline_id": 41, "commit": "a" * 40, "ref": "master", "time": "2026-11-08T10:00:00Z", "url": "",
       "scans": {"sast": scan("semgrep", findings=2, high=2), "sca": scan("grype", findings=2, high=1, medium=1),
                 "secrets": scan("gitleaks", findings=1, high=1)}}
NEW = {"pipeline_id": 42, "commit": "b" * 40, "ref": "master", "time": "2026-11-09T10:00:00Z", "url": "",
       "scans": {"sast": scan("semgrep", findings=2, high=1, medium=1), "sca": scan("grype", findings=1, medium=1),
                 "secrets": scan("gitleaks", status="missing")}}
FINDINGS = {
    41: [finding("sast", "s1"), finding("sast", "s2"), finding("sca", "g1"), finding("sca", "g2", "medium"),
         finding("secrets", "k1", tool="gitleaks")],
    42: [finding("sast", "s1"), finding("sast", "s3", "medium"), finding("sca", "g2", "medium")],
}
LOGS = {
    "total": 120, "services": {"api": {"events": 100, "last_seen": "2026-11-09T11:59:00Z"},
                               "frontend": {"events": 20, "last_seen": "2026-11-09T08:00:00Z"}},
    "status": {"2xx": 80, "4xx": 35, "5xx": 5},
    "login_failures": {"total": 12, "by_client": {"10.0.2.2": 12}},
    "denied": {"total": 3, "paths": {"/users/v1/name1": 3}},
    "server_errors": {"total": 5, "paths": {"/users/v1/'": 5}},
    "error_lines": {"total": 1, "latest": ["Traceback (most recent call last):"]},
    "suspicious": {"total": 7, "paths": {"/users/v1/'": 7}, "clients": {"10.0.2.2": 7}, "status": {"500": 5, "200": 2}},
    "sensitive": {"debug endpoint (lists every user)": {"total": 4, "status": {"200": 4}},
                  "user deletion": {"total": 0, "status": {}}},
    "scanners": {"total": 0, "agents": {}},
}


class FakeStore:
    def __init__(self, runs=(NEW, OLD), findings=FINDINGS, logs=LOGS):
        self._runs, self._findings, self._logs = list(runs), findings, logs

    def runs(self, since, ref=None):
        return [r for r in self._runs if not ref or r["ref"] == ref]

    def findings(self, pipeline_id):
        return list(self._findings.get(pipeline_id, []))

    def app_logs(self, since, top=10):
        return self._logs


class ParseSince(unittest.TestCase):
    def test_durations(self):
        self.assertEqual(trend.parse_since("30m", NOW), NOW - datetime.timedelta(minutes=30))
        self.assertEqual(trend.parse_since("24h", NOW), NOW - datetime.timedelta(hours=24))
        self.assertEqual(trend.parse_since(" 7d ", NOW), NOW - datetime.timedelta(days=7))
        self.assertEqual(trend.parse_since("2w", NOW), NOW - datetime.timedelta(weeks=2))

    def test_dates(self):
        self.assertEqual(trend.parse_since("2026-11-01", NOW), datetime.datetime(2026, 11, 1, tzinfo=UTC))
        self.assertEqual(trend.parse_since("2026-11-01T06:30:00Z", NOW), datetime.datetime(2026, 11, 1, 6, 30, tzinfo=UTC))
        tz = trend.parse_since("2026-11-01T06:30:00+03:00", NOW)
        self.assertEqual(tz.astimezone(UTC).hour, 3)

    def test_rejects_garbage_and_the_future(self):
        for bad in ("", "7", "7y", "yesterday", "2026-13-01"):
            with self.assertRaises(ValueError, msg=bad):
                trend.parse_since(bad, NOW)
        with self.assertRaises(ValueError):
            trend.parse_since("2027-01-01", NOW)


class Diff(unittest.TestCase):
    def test_new_recurring_resolved(self):
        d = trend.diff_runs(OLD, NEW, FINDINGS[41], FINDINGS[42])
        self.assertEqual(d["counts"], {"new": 1, "recurring": 2, "resolved": 2})
        self.assertEqual([f["rule_id"] for f in d["new"]], ["s3"])
        self.assertEqual(sorted(f["rule_id"] for f in d["resolved"]), ["g1", "s2"])
        self.assertEqual(d["per_tool"]["semgrep"], {"new": 1, "recurring": 1, "resolved": 1})

    def test_a_scan_that_did_not_report_is_not_resolved(self):
        d = trend.diff_runs(OLD, NEW, FINDINGS[41], FINDINGS[42])
        self.assertEqual(d["not_compared"], ["secrets"])
        self.assertNotIn("k1", [f["rule_id"] for f in d["resolved"]])
        self.assertNotIn("gitleaks", d["per_tool"])

    def test_most_severe_first_and_top_limit(self):
        old = dict(OLD, scans={"sast": scan("semgrep")})
        new = dict(NEW, scans={"sast": scan("semgrep")})
        fs = [finding("sast", "low1", "low"), finding("sast", "crit", "critical"), finding("sast", "med", "medium")]
        d = trend.diff_runs(old, new, [], fs, top=2)
        self.assertEqual([f["rule_id"] for f in d["new"]], ["crit", "med"])
        self.assertEqual(d["counts"]["new"], 3)


class Report(unittest.TestCase):
    def test_runs_and_severity(self):
        rep = trend.build_report(FakeStore(), NOW - datetime.timedelta(days=7), now=NOW)
        self.assertEqual([r["pipeline_id"] for r in rep["runs"]], [42, 41])
        self.assertEqual(rep["runs"][0]["tools"], {"semgrep": 2, "grype": 1, "gitleaks": None})
        self.assertEqual(rep["severity"]["latest_run"], 42)
        self.assertEqual(rep["severity"]["latest"]["semgrep"]["medium"], 1)
        self.assertEqual(rep["severity"]["window"]["semgrep"]["high"], 3)
        self.assertNotIn("gitleaks", rep["severity"]["latest"])
        self.assertEqual((rep["changes"]["old_pipeline"], rep["changes"]["new_pipeline"]), (41, 42))

    def test_compare_explicit_and_unknown(self):
        rep = trend.build_report(FakeStore(), NOW, compare=[42, 41], now=NOW)
        self.assertEqual(rep["changes"]["counts"]["new"], 2)     # reversed direction
        rep = trend.build_report(FakeStore(), NOW, compare=[1, 42], now=NOW)
        self.assertIn("error", rep["changes"])

    def test_single_run_has_no_changes(self):
        rep = trend.build_report(FakeStore(runs=[NEW]), NOW, now=NOW)
        self.assertIsNone(rep["changes"])
        self.assertIn("fewer than two runs", trend.render_table(rep))

    def test_app_notes(self):
        notes = trend.app_notes(LOGS, NOW)
        text = "\n".join(notes)
        self.assertIn("12 failed logins from 10.0.2.2", text)
        self.assertIn("No logs from 'frontend'", text)          # 4 h silent
        self.assertNotIn("'api'", text)
        self.assertIn("7 requests with injection or traversal patterns; 2 of them got a 2xx", text)
        self.assertIn("debug endpoint (lists every user): 4 calls, 4 succeeded", text)
        self.assertNotIn("user deletion", text)
        empty = dict(LOGS, total=0, services={})
        self.assertIn("Fluent Bit", trend.app_notes(empty, NOW)[0])

    def test_table_and_json_output(self):
        rep = trend.build_report(FakeStore(), NOW, now=NOW)
        text = trend.render_table(rep)
        for part in ("Findings per tool per pipeline run", "Severity distribution", "#41 -> #42: 1 new, 2 recurring, 2 resolved",
                     "not compared (no complete report in one of the runs): secrets", "Worth a look:", "/users/v1/'"):
            self.assertIn(part, text)
        row = [l for l in text.splitlines() if l.startswith("42 ")][0]
        self.assertIn("-", row.split())                           # gitleaks did not report
        self.assertEqual(json.loads(json.dumps(rep))["runs"][1]["pipeline_id"], 41)


    def test_app_section_degrades_without_log_access(self):
        store = FakeStore()
        store.app_logs = mock.Mock(side_effect=OpenSearchError("HTTP 403 no permissions"))
        rep = trend.build_report(store, NOW, now=NOW)
        self.assertIn("403", rep["app"]["error"])
        self.assertEqual(rep["changes"]["counts"]["new"], 1)      # the rest of the report is intact
        self.assertIn("not available with this account", trend.render_table(rep))


class StoreParsing(unittest.TestCase):
    """The OpenSearch-backed store turns aggregation responses into plain data."""

    def test_runs(self):
        client = mock.Mock()
        client.search.return_value = {"aggregations": {"runs": {"buckets": [{"key": 42, "scans": {"hits": {"hits": [
            {"_source": {"scan": "sast", "tool": "semgrep", "status": "reported", "findings": 3,
                         "by_severity": {"high": 3}, "commit": "b" * 40, "ref": "master", "@timestamp": "t", "pipeline_url": "u"}}]}}}]}}}
        runs = trend.Store(client).runs(NOW, "master")
        self.assertEqual(runs[0]["pipeline_id"], 42)
        self.assertEqual(runs[0]["scans"]["sast"]["findings"], 3)
        body = client.search.call_args[0][1]
        self.assertIn({"term": {"ref": "master"}}, body["query"]["bool"]["filter"])

    def test_findings_pages_with_search_after(self):
        client = mock.Mock()
        page = lambda n, start: {"hits": {"hits": [{"_source": {"fingerprint": str(start + i)}, "sort": ["s", str(start + i)]}
                                                   for i in range(n)]}}
        client.search.side_effect = [page(5000, 0), page(3, 5000)]
        out = trend.Store(client).findings(42)
        self.assertEqual(len(out), 5003)
        self.assertEqual(client.search.call_args_list[1][0][1]["search_after"], ["s", "4999"])

    def test_app_logs_with_no_index_yet(self):
        client = mock.Mock()
        client.search.return_value = {"hits": {"total": {"value": 0}, "hits": []}, "aggregations": {}}
        logs = trend.Store(client).app_logs(NOW)
        self.assertEqual(logs["total"], 0)
        self.assertEqual(logs["suspicious"]["paths"], {})


class Main(unittest.TestCase):
    def test_exit_2_when_store_unreachable(self):
        with mock.patch.object(trend, "build_report", side_effect=OpenSearchError("connection refused")), \
             mock.patch("sys.stderr", new=io.StringIO()) as err:
            self.assertEqual(trend.main(["--since", "1d", "--password", "x", "--url", "https://127.0.0.1:1"]), 2)
        self.assertIn("connection refused", err.getvalue())

    def test_json_format(self):
        with mock.patch.object(trend, "Store", return_value=FakeStore()), redirect_stdout(io.StringIO()) as out:
            self.assertEqual(trend.main(["--format", "json", "--password", "x"]), 0)
        self.assertEqual(json.loads(out.getvalue())["changes"]["counts"]["resolved"], 2)

    def test_bad_since_is_a_usage_error(self):
        with mock.patch("sys.stderr", new=io.StringIO()), self.assertRaises(SystemExit) as e:
            trend.main(["--since", "soon"])
        self.assertEqual(e.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
