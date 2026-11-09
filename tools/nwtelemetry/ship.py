"""CI report job: ship this pipeline's scanner findings, scan runs and job events.

usage: python -m nwtelemetry.ship --reports reports [--zap-suppressions FILE]
                                  [--dry-run OUT.ndjson]

Reads the pipeline context from GitLab's predefined variables and these settings:
  TELEMETRY_URL, TELEMETRY_USER, TELEMETRY_PASSWORD, TELEMETRY_CA (file)
  TELEMETRY_GITLAB_TOKEN   read_api token, to list this pipeline's jobs

Writes (document ids are fixed, so re-running the job overwrites, never duplicates):
  findings-YYYY.MM   one document per finding per pipeline
  scans-YYYY.MM      one document per scan per pipeline, also when its report is
                     missing (status "missing"), with counts by severity
  ci-jobs-YYYY.MM    one document per job, retried attempts included
"""
import argparse
import datetime
import json
import os
import sys
import urllib.request

from . import normalize
from .client import OpenSearch


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


def month_index(prefix, ts):
    return "%s-%s" % (prefix, ts[:7].replace("-", "."))


def context(env):
    return {
        "project": env.get("CI_PROJECT_PATH", ""),
        "pipeline_id": int(env.get("CI_PIPELINE_ID", "0")),
        "pipeline_url": env.get("CI_PIPELINE_URL", ""),
        "commit": env.get("CI_COMMIT_SHA", ""),
        "ref": env.get("CI_COMMIT_REF_NAME", ""),
        "pipeline_source": env.get("CI_PIPELINE_SOURCE", ""),
        # One timestamp for the whole run, so a run sorts as one point in time.
        "@timestamp": env.get("CI_PIPELINE_CREATED_AT") or utcnow().isoformat(),
    }


def gitlab_jobs(env):
    """This pipeline's jobs (retried attempts included) from the GitLab API."""
    token = env.get("TELEMETRY_GITLAB_TOKEN")
    if not token:
        print("TELEMETRY_GITLAB_TOKEN not set: job events not shipped", file=sys.stderr)
        return []
    jobs, page = [], 1
    while True:
        url = "%s/projects/%s/pipelines/%s/jobs?include_retried=true&per_page=100&page=%d" % (
            env["CI_API_V4_URL"], env["CI_PROJECT_ID"], env["CI_PIPELINE_ID"], page)
        req = urllib.request.Request(url, headers={"PRIVATE-TOKEN": token})
        with urllib.request.urlopen(req, timeout=30) as r:
            batch = json.loads(r.read())
        jobs.extend(batch)
        if len(batch) < 100:
            return jobs
        page += 1


def job_events(jobs, ctx, own_job_id=None):
    """GitLab job objects -> ci-jobs documents. The running report job itself is
    left out: it has no result yet."""
    out = []
    for j in jobs:
        if own_job_id and str(j["id"]) == str(own_job_id):
            continue
        ts = j.get("finished_at") or j.get("started_at") or j.get("created_at")
        out.append({
            "@timestamp": ts, "project": ctx["project"], "pipeline_id": ctx["pipeline_id"],
            "pipeline_url": ctx["pipeline_url"], "pipeline_source": ctx["pipeline_source"],
            "commit": (j.get("commit") or {}).get("id") or ctx["commit"], "ref": j.get("ref") or ctx["ref"],
            "job_id": j["id"], "job_name": j["name"], "stage": j.get("stage"), "status": j.get("status"),
            "duration_s": j.get("duration"), "queued_s": j.get("queued_duration"),
            "started_at": j.get("started_at"), "finished_at": j.get("finished_at"),
            "failure_reason": j.get("failure_reason") or "", "allow_failure": bool(j.get("allow_failure")),
            "runner": (j.get("runner") or {}).get("description") or "",
            "user": (j.get("user") or {}).get("username") or "", "web_url": j.get("web_url"),
        })
    return out


def build_actions(ctx, findings, scans, events):
    ts = ctx["@timestamp"]
    pid = ctx["pipeline_id"]
    status_by_job = {}
    for e in events:   # latest attempt of each job wins
        if e["job_name"] not in status_by_job or e["job_id"] > status_by_job[e["job_name"]][0]:
            status_by_job[e["job_name"]] = (e["job_id"], e["status"])
    actions = []
    for f in findings:
        doc = dict(ctx, **f)
        actions.append((month_index("findings", ts), "%s:%s:%s" % (pid, f["scan"], f["fingerprint"]), doc))
    for s in scans:
        doc = dict(ctx, **s)
        doc["job_status"] = status_by_job.get(s["job"], (0, ""))[1]
        actions.append((month_index("scans", ts), "%s:%s" % (pid, s["scan"]), doc))
    for e in events:
        actions.append((month_index("ci-jobs", e["@timestamp"] or ts), str(e["job_id"]), e))
    return actions


def main(argv=None, env=None):
    env = dict(os.environ if env is None else env)
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--reports", default="reports")
    ap.add_argument("--zap-suppressions", default=".zap/suppressions.json")
    ap.add_argument("--dry-run", metavar="FILE", help="write the bulk actions to FILE instead of shipping")
    args = ap.parse_args(argv)

    ctx = context(env)
    findings, scans = normalize.normalize_dir(args.reports, normalize.load_suppressions(args.zap_suppressions))
    try:
        events = job_events(gitlab_jobs(env), ctx, env.get("CI_JOB_ID")) if env.get("CI_API_V4_URL") else []
    except OSError as e:
        print("could not read the pipeline's jobs from GitLab: %s" % e, file=sys.stderr)
        events = []
    actions = build_actions(ctx, findings, scans, events)

    print("pipeline %s (%s @ %s)" % (ctx["pipeline_id"], ctx["ref"], ctx["commit"][:8]))
    for s in scans:
        sev = ", ".join("%s %d" % (k, s["by_severity"][k])
                        for k in ("critical", "high", "medium", "low", "info") if k in s["by_severity"])
        print("  %-20s %-10s %5d  %s" % (s["scan"], s["status"], s["findings"], sev))
    print("  %d job events" % len(events))

    if args.dry_run:
        with open(args.dry_run, "w", encoding="utf-8") as f:
            for index, doc_id, doc in actions:
                f.write(json.dumps({"index": {"_index": index, "_id": doc_id}}) + "\n")
                f.write(json.dumps(doc, default=str) + "\n")
        print("dry run: %d documents written to %s" % (len(actions), args.dry_run))
        return 0

    client = OpenSearch(env["TELEMETRY_URL"], env.get("TELEMETRY_USER"), env.get("TELEMETRY_PASSWORD"),
                        env.get("TELEMETRY_CA") or None)
    n = 0
    for i in range(0, len(actions), 500):
        n += client.bulk(actions[i:i + 500])
    print("shipped %d documents to %s" % (n, env["TELEMETRY_URL"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
