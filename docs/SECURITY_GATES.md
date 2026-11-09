# Security gates

The source of truth for what each pipeline gate scans, when it fails and why, and for every suppression in force. NOTE.md summarises it. A change to a threshold or a new suppression goes into this file in the same merge request as the configuration change, so the reviewer sees both together.

## Gates

| Gate | Job | Tool | Scope | Fails when | Artefacts (`reports/`) |
|---|---|---|---|---|---|
| SAST | `sast-semgrep` | Semgrep 1.95.0 | Python, JavaScript, Dockerfiles, YAML in the working tree; `tests/` and vendored minified JS excluded (`.semgrepignore`) | any finding of severity **ERROR** | `semgrep.json` |
| Secrets | `secrets-gitleaks` | Gitleaks 8.21.2 | every commit reachable from any branch or tag (`--log-opts=--all` after fetching all refs, `GIT_DEPTH: 0`) | **any** finding | `gitleaks.json` |
| SBOM | `sbom-syft` | Syft 1.18.1 | `requirements.txt` (pip) and `frontend/package-lock.json` (npm) | does not gate | `sbom.cdx.json` (CycloneDX), `sbom.syft.json` |
| SCA | `sca-grype` | Grype 0.99.1 | the SBOM above | **High or Critical** vulnerability **with a released fix** | `grype.json` (all severities, fixed and unfixed) |
| Image | `scan-image-api`, `scan-image-frontend` | Trivy 0.57.1 | the image just built (base OS packages, installed Python/npm packages, secrets in layers and image config) and the Dockerfile it was built from | **High or Critical** vulnerability **with a fix**, **any** secret, **High or Critical** Dockerfile misconfiguration | `trivy-image-<name>.json`, `trivy-config-<name>.json`, `sbom-image-<name>.cdx.json` |

Every report holds all severities, and every job uploads its reports even when it fails (`artifacts: when: always`). The threshold decides only whether the job fails; nothing is left out of the record.

## Why these thresholds

- **SAST, ERROR only.** Semgrep's ERROR level is reserved for rules with high confidence and real impact, and the project rules in `.semgrep/northwind.yml` use it only for patterns the team has agreed never to write: SQL built from strings, markup built from strings, debug servers, and deep-merging cross-origin messages. WARNING-level audit rules are too noisy to block on with no security engineer to triage them; they stay visible in the report.
- **Secrets, zero tolerance.** A leaked credential is exploitable whatever its "severity", and history counts because a deleted file is still in every clone. The only way through is to rotate the credential and record the old value as a suppression (see below).
- **SCA and images, High/Critical with a fix.** A developer can act on these today by bumping a version or a base image. Blocking on a vulnerability with no fix would block every pipeline on something nobody can change, which teaches people to suppress wholesale. Unfixed vulnerabilities stay in the reports and in the trend report (Task 4), so they are tracked rather than hidden.
- **Dockerfile misconfiguration, High/Critical.** These are cheap to fix (a `USER` line, `--no-cache`) and running as root is the one that matters for container escape.

## Why the project Semgrep rules exist

With only the registry rulesets (`p/default`, `p/security-audit`, `p/owasp-top-ten`, `p/flask`, `p/javascript`, `p/jwt`), Semgrep found **none** of the SQL injection or DOM XSS flaws listed in `docs/PENTEST_SUMMARY.md`. The query string is built in a local variable before reaching `text()`, and the XSS sinks are `innerHTML` assignments of a variable and jQuery `.html()` calls, which those rules do not model. A SAST gate that passes on the very code the pen test exploited is not a gate, so `.semgrep/northwind.yml` adds narrow rules for the house patterns.

## Offline behaviour

The scanners' data is kept in the GitLab CI cache: Semgrep registry rules in `.semgrep-registry/`, the Grype database in `.grypedb/`, and the Trivy databases in `.trivycache/`. The scanner jobs save their cache even when the gate fails (`cache: when: always`), and the runner keeps the CI cache in one named volume shared by its concurrent slots (`scripts/gitlab-up.sh`). Before that change each slot had its own anonymous cache volume, and a job that landed in the other slot found no database. GitLab's default is to save only on success, and a gate that always failed would then never have stored a database. Each job first tries to refresh its data and falls back to the cached copy if that fails. Grype refuses a database older than 30 days (`GRYPE_DB_MAX_ALLOWED_BUILT_AGE`), so a long-offline pipeline fails closed rather than passing on stale data. Trivy's misconfiguration checks are the ones embedded in the pinned release (`TRIVY_SKIP_CHECK_UPDATE`), so Dockerfile results only change when the Trivy version changes. The Trivy database comes from `ghcr.io` because the default mirror (`mirror.gcr.io`) was serving a missing blob when this was set up. The frontend's nginx base image ships Java archives (gettext's `libintl` jars), so Trivy also needs its Java DB. It is refreshed in a separate step with the same cached fallback, and the scans run with `TRIVY_SKIP_JAVA_DB_UPDATE` so they never download anything themselves. Both databases are cached (`.trivycache/db/`, `.trivycache/java-db/`). The per-image layer cache is not, because it is large and is rebuilt within the job anyway.

To test the fallback, run a pipeline whose update sources are unreachable. Pipeline variables override the ones in `.gitlab-ci.yml`:

```bash
curl -X POST -H "PRIVATE-TOKEN: $(cat .local/root-token)" -H 'Content-Type: application/json' \
  http://gitlab.northwind.test:8929/api/v4/projects/1/pipeline -d '{"ref":"master","variables":[
    {"key":"TRIVY_DB_REPOSITORY","value":"127.0.0.1:1/offline/trivy-db:2"},
    {"key":"TRIVY_JAVA_DB_REPOSITORY","value":"127.0.0.1:1/offline/trivy-java-db:1"},
    {"key":"GRYPE_DB_UPDATE_URL","value":"http://127.0.0.1:1/listing.json"},
    {"key":"SEMGREP_RULES_URL","value":"http://127.0.0.1:1/c/p"}]}'
```

Every scanner job should then log that it is using its cached copy and reach the same verdict as an online run.

**Grype version.** Grype was first pinned at 0.86.1. That release reads database schema v5, and the newest v5 database available was built on 2026-03-09, eight months old. Grype 0.86.1 also did not apply `GRYPE_DB_MAX_ALLOWED_BUILT_AGE`, so it accepted that database without complaint. Grype 0.99.1 uses schema v6, which is rebuilt daily, and it does enforce the age limit: with a 1-hour limit it refuses a database built 1 day ago. A pinned scanner can go stale silently, so the database build date is printed in every run (`grype db status`, also saved as `reports/grype-db-status.txt`), and the job stops with "no usable vulnerability DB" when there is none.

## Suppressions

A suppression must be:
- **narrow**: one occurrence or one exact value, never a whole rule, path or tool;
- **next to the configuration it affects**, with its S-number;
- **listed here** with its reason and a review date.

Disabling a rule, or adding a path to an ignore file to make a finding go away, is not allowed.

| ID | Tool | Finding | Where | Mechanism | Why it is a false positive | Review by |
|---|---|---|---|---|---|---|
| S-01 | Gitleaks, Semgrep | JWT (`jwt`, `generic.secrets.security.detected-jwt-token`) | `openapi_specs/openapi3.yml`, `auth_token` example of `/users/v1/login` | Gitleaks: exact-value allowlist in `.gitleaks.toml`. Semgrep: `nosemgrep` with the rule id on that line | A documentation example. Its `exp` is 2022-12-04, so it cannot be replayed, and its subject `John.Doe` is not a user of the application. An allowlist by value rather than by fingerprint survives the line moving, and still catches any other token in the same file. | 2027-05-01 |

How to add one per tool:
- **Semgrep**: `# nosemgrep: <full rule id>` on the line, followed by `-- S-NN`.
- **Gitleaks**: for a finding that lives only in history (for example a credential that has since been rotated), add its fingerprint to `.gitleaksignore`. For a value that stays in the tree, add an exact-value allowlist to `.gitleaks.toml`.
- **Trivy**: an entry in `.trivyignore.yaml` with `id`, `paths` or `purls`, a `statement` and an `expired_at`. After that date the finding blocks again.
- **Grype**: an `ignore` entry in `.grype.yaml` with the vulnerability id, the package name and version, and a comment carrying the S-number.
