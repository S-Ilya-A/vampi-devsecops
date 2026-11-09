import json
import os
import tempfile
import unittest

from nwtelemetry import dashboard, ship

FIX = os.path.join(os.path.dirname(__file__), "fixtures")
ENV = {"CI_PROJECT_PATH": "root/vampi-devsecops", "CI_PIPELINE_ID": "42", "CI_COMMIT_SHA": "b" * 40,
       "CI_COMMIT_REF_NAME": "master", "CI_PIPELINE_CREATED_AT": "2026-11-09T10:00:00Z",
       "CI_PIPELINE_URL": "http://gitlab/p/42", "CI_PIPELINE_SOURCE": "push", "CI_JOB_ID": "300"}
JOBS = [
    {"id": 290, "name": "sast-semgrep", "stage": "test", "status": "failed", "duration": 61.2, "queued_duration": 1.5,
     "started_at": "2026-11-09T10:01:00Z", "finished_at": "2026-11-09T10:02:01Z", "created_at": "2026-11-09T10:00:00Z",
     "failure_reason": "script_failure", "allow_failure": False, "ref": "master", "commit": {"id": "b" * 40},
     "runner": {"description": "local-docker"}, "user": {"username": "root"}, "web_url": "http://gitlab/j/290"},
    {"id": 295, "name": "sast-semgrep", "stage": "test", "status": "success", "duration": 58.0,
     "started_at": "2026-11-09T10:05:00Z", "finished_at": "2026-11-09T10:06:00Z", "created_at": "2026-11-09T10:04:00Z"},
    {"id": 300, "name": "telemetry-report", "stage": "report", "status": "running", "created_at": "2026-11-09T10:30:00Z"},
]


class Ship(unittest.TestCase):
    def test_job_events_skip_the_running_report_job(self):
        ev = ship.job_events(JOBS, ship.context(ENV), own_job_id="300")
        self.assertEqual([e["job_id"] for e in ev], [290, 295])
        self.assertEqual(ev[0]["duration_s"], 61.2)
        self.assertEqual(ev[0]["failure_reason"], "script_failure")
        self.assertEqual(ev[0]["@timestamp"], "2026-11-09T10:02:01Z")

    def test_ids_are_stable_so_reruns_overwrite(self):
        from nwtelemetry import normalize
        ctx = ship.context(ENV)
        f, s = normalize.normalize_dir(FIX)
        a = ship.build_actions(ctx, f, s, ship.job_events(JOBS, ctx, "300"))
        b = ship.build_actions(ctx, f, s, ship.job_events(JOBS, ctx, "300"))
        self.assertEqual([x[1] for x in a], [x[1] for x in b])
        self.assertEqual(len({x[1] for x in a}), len(a))
        indices = {x[0] for x in a}
        self.assertEqual(indices, {"findings-2026.11", "scans-2026.11", "ci-jobs-2026.11"})

    def test_scan_gets_status_of_latest_job_attempt(self):
        from nwtelemetry import normalize
        ctx = ship.context(ENV)
        f, s = normalize.normalize_dir(FIX)
        acts = ship.build_actions(ctx, f, s, ship.job_events(JOBS, ctx, "300"))
        sast = [d for i, _, d in acts if i.startswith("scans") and d["scan"] == "sast"][0]
        self.assertEqual(sast["job_status"], "success")          # retried 290 -> 295
        self.assertEqual(sast["pipeline_id"], 42)

    def test_dry_run_writes_bulk_ndjson(self):
        out = os.path.join(tempfile.mkdtemp(), "bulk.ndjson")
        env = dict(ENV)
        self.assertEqual(ship.main(["--reports", FIX, "--zap-suppressions", os.path.join(FIX, "zap-suppressions.json"),
                                    "--dry-run", out], env=env), 0)
        with open(out, encoding="utf-8") as fh:
            lines = [json.loads(l) for l in fh]
        self.assertEqual(len(lines) % 2, 0)
        self.assertTrue(all("index" in l for l in lines[0::2]))
        docs = lines[1::2]
        self.assertTrue(any(d.get("suppressed") == "S-02" for d in docs))
        self.assertTrue(all(d["pipeline_id"] == 42 for d in docs))


class Dashboard(unittest.TestCase):
    def test_saved_objects_reference_existing_objects(self):
        objs = dashboard.objects()
        ids = {(o["type"], o["id"]) for o in objs}
        for o in objs:
            for r in o["references"]:
                self.assertIn((r["type"], r["id"]), ids, o["id"])
            if o["type"] == "visualization":
                json.loads(o["attributes"]["visState"])
        dash = [o for o in objs if o["type"] == "dashboard"][0]
        self.assertEqual(len(json.loads(dash["attributes"]["panelsJSON"])), len(dash["references"]))


if __name__ == "__main__":
    unittest.main()
