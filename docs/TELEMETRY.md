# Telemetry and trend report

## Bring-up

```bash
scripts/gitlab-up.sh       # GitLab + runner (the runner learns telemetry.northwind.test)
scripts/telemetry-up.sh    # OpenSearch + Dashboards, users, templates, dashboard, CI variables
scripts/staging-up.sh      # VM; gives its Fluent Bit the CA and the shipper password
scripts/trend --since 7d   # trend report, as the read-only analyst
```

`telemetry-up.sh --down` stops the stack and keeps its data. `--purge` also deletes the data, the CA and the passwords. Each script is safe to re-run. `telemetry-up.sh` re-applies users, roles, index templates, retention policies and the dashboard every time, so the running stack always matches the repository.

| | Address | Notes |
|---|---|---|
| OpenSearch | `https://127.0.0.1:9200` | own CA: `.local/telemetry/certs/ca.pem` |
| Dashboards | `http://127.0.0.1:5601` | dashboard "Northwind security overview" |

Both listen on the host's loopback only. Job containers reach OpenSearch as `telemetry.northwind.test` through the Docker host gateway. The staging VM reaches it through VirtualBox NAT (`10.0.2.2`, see docs/STAGING.md).

## The three streams

| Stream | Index | Written by | One document per |
|---|---|---|---|
| Scanner findings | `findings-YYYY.MM` | `telemetry-report` job (`python -m nwtelemetry.ship`) | finding per pipeline run |
| Scan runs | `scans-YYYY.MM` | same job | scan per pipeline run, including scans with no report |
| Pipeline job events | `ci-jobs-YYYY.MM` | same job, from the GitLab API | job attempt (retries included) |
| Application logs | `app-logs-YYYY.MM.DD` | Fluent Bit on the VM | log line (nginx access, Werkzeug access, API stderr, Postgres) |

**Findings, normalised.** Every scanner's report is reduced to one shape:
- `tool` and `scan`, for example `trivy` and `image:frontend`;
- `rule_id`, `title` and `location`;
- `severity`, mapped onto critical/high/medium/low/info, plus `severity_rank`;
- `package`, `installed_version`, `fixed_version` and `fix_available`;
- `cve`, or a CWE where that is all there is;
- `fingerprint`;
- `suppressed`, which names the S-number when a gate suppression covers the finding.

Each document also carries `pipeline_id`, `commit`, `ref` and the run's timestamp. With that, one query can answer "everything High or above with a fix, by tool, in the last run" across five different tools. The mapping is documented in `tools/nwtelemetry/normalize.py`.

**Fingerprints** decide whether a finding is "the same" in two runs. A fingerprint leaves out everything that changes when the finding did not:
- line numbers;
- image tags;
- the random user name the DAST session registers;
- ZAP's attack payloads.

ZAP needed the most care. Its active rules put payloads into every URL path segment, so a first version produced 4,165 one-off "findings" from one API scan, almost all of them "client error" responses to URLs like `/users/v1/<!--#EXEC cmd="ls /"-->/email`. Each URL now folds into the OpenAPI path template it matches (`PUT /users/v1/{username}/email`). That left 71 findings, but low and informational ones still appeared and vanished between identical runs: ZAP keeps only a sample of URLs for such alerts, and the sample changes. So Medium and High alerts are one finding per endpoint, and low and informational alerts are one finding per alert. The same API scan is now about ten findings, so repeated runs of the same code compare equal. A version bump does change the fingerprint (`lodash 4.17.15` → `4.17.21`), so the old finding shows as resolved.

**Missing is not zero.** The report job runs after everything else, even when gates failed. It records every scan, and a scan whose job did not run or wrote no report gets status `missing` (or `unreadable`), and a Semgrep scan in which a rule timed out gets `incomplete`. The trend tool does not compare such a scan, so "Gitleaks did not run" never shows up as "the leaked key is resolved".

**Secret values never leave the pipeline.** The Gitleaks normaliser drops the `Secret` and `Match` fields and keeps the rule, the file and the commit.

**Job events** come from the GitLab API through a project access token limited to `read_api`, stored as a protected, masked CI variable. The job token cannot list a pipeline's jobs. Each event records the job, stage, commit, ref, status, duration, queue time, failure reason, runner and whether the job was retried. The document id is the job id, so re-running the report job overwrites instead of duplicating.

**Application logs.** Docker's fluentd log driver on the VM sends every container's output to Fluent Bit (`staging/vm/fluent-bit.conf`). Fluent Bit:
1. strips Werkzeug's colour codes, which otherwise made every API request line unparseable;
2. parses nginx and Werkzeug access lines into `method`, `path`, `status` and `client_ip`;
3. adds `service` and `environment`;
4. ships to OpenSearch.

A filesystem buffer keeps logs while OpenSearch is down. This was tested: logs buffered on the VM before the stack existed arrived once it came up.

## Access control

The demo security configuration was rejected. Its private key is published with every OpenSearch download, and it creates users with published passwords (`kibanaro`/`kibanaro`, `logstash`/`logstash` and others). Instead, `telemetry-up.sh` generates a CA, a node certificate and an admin client certificate, plus one random password per account:

| Account | Role | May |
|---|---|---|
| `shipper` | `telemetry_shipper` | append to `app-logs-*`; nothing else, not even read |
| `ci` | `telemetry_ci` | write and read `findings-*`, `scans-*`, `ci-jobs-*`; not logs |
| `analyst` | `telemetry_reader` + Dashboards user, read-only mode | read all four streams |
| `dashboards` | `kibana_server` | Dashboards' own service account |
| `admin` | `all_access` | administration; security changes also need the admin certificate |

Checked by hand: `shipper` gets 403 on reading logs and on writing findings, `ci` gets 403 on writing logs, `analyst` gets 403 on writing and on the security API, and an anonymous request gets 401. Failed logins and denied requests against the store itself are audited in `security-auditlog-*`. Retention is 30 days for application logs and 180 days for pipeline data (ISM policies).

## Trend report

```
scripts/trend [--since 7d|24h|2026-11-01] [--format table|json] [--ref master]
              [--compare OLD NEW] [--top 10]
```

| Section | Shows |
|---|---|
| Findings per tool per pipeline run | one row per run, one column per tool, `-` when the tool's scans did not report |
| Severity distribution | per tool for the newest run, and over the window |
| Changes between runs | new, recurring and resolved findings between the newest two runs (or `--compare`), per tool, with the most severe new and resolved findings listed; scans missing from either run are named and left out |
| Application logs | events per service and the time of the last one; status classes; "worth a look" notes; top paths for each signal; the latest API error lines |

The "worth a look" signals:
- **Failed logins per client.** Ten or more from one client is flagged as possible password guessing (PT-10).
- **Injection-looking requests**, and how many of them were answered 2xx.
- **Server errors.** Unhandled input reaches the code.
- **Sensitive endpoints**, and whether calls to them succeeded: the debug endpoint that lists every user with their password (PT-02), `/createdb` (PT-08), user deletion, password change (PT-03).
- **Scanner user agents** other than ZAP.
- **Silence.** A service that has logged nothing for an hour. Logs that stop arriving are themselves a finding: the shipper failed, or the service hung (see "Known gaps").

The `telemetry-report` job prints the report for its own branch and keeps `reports/trend.txt` and `trend.json` as artefacts. In CI the application-log section says "not available with this account", because the CI account cannot read logs.

`tools/tests/` holds 40 unit tests. They run in the `telemetry-tests` job: standard library only, no server needed. They cover:
- the duration and date parsing;
- each normaliser, including fingerprint stability under line moves and tag changes, ZAP endpoint folding and suppression expiry;
- the rule that secret values are dropped;
- new/recurring/resolved, including "a missing scan is not resolved";
- report rendering;
- how the OpenSearch-backed store pages and parses responses, using a mock client.

## Dashboard

"Northwind security overview" is defined in `tools/nwtelemetry/dashboard.py` and imported by `telemetry-up.sh`, so it is reviewed like code and survives a purge. Its panels:
- findings per tool per run, and severity per run (stacked bars);
- High and Critical findings with the number of runs each has been open;
- severity distribution;
- scans that did not report;
- CI job results per run, and average job duration;
- application requests by status class over time;
- paths answering 5xx or 401/403;
- a saved search of security-relevant log lines.

## Known gaps

- **One client address for everything.** Every request reaches the VM through VirtualBox NAT, so the logged client address is always the NAT gateway. Per-client signals, such as failed logins per IP, would need the real client address forwarded (`X-Forwarded-For`) through every hop.
- **No application security events.** The application writes none: no login success or failure events, and no record of who changed which password. Only access-log lines and tracebacks are available. Structured events would make PT-03 visible, because a password change for another user would be a distinct event. That would be an application change; see NOTE.md.
- **Lines from before the parser fix.** Log lines shipped before the colour-code fix carry only the raw `log` field.
- **A hung request leaves no log line.** During one DAST run the ZAP active scan hit the e-mail ReDoS (PT-11) and the API stopped answering. A request that never completes produces no access-log line, so the only signal is the silence check and the jump in client-side timeouts.
