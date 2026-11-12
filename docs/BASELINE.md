# Where this repository comes from

The assignment (`ASSIGNMENT.md`) describes an inherited repository called `parcel-tracker`: a Flask API, a static web page, Postgres and a GitLab CI pipeline. That repository was not supplied, so this baseline was built from an open-source, deliberately vulnerable project.

## Upstream

- [erev0s/VAmPI](https://github.com/erev0s/VAmPI), MIT licence (`LICENSE`). Its full history is kept. The last upstream commit is `f16052d`.
- VAmPI is a Flask/Connexion REST API covering the OWASP API Top 10. Its vulnerabilities are documented in its README, kept as `docs/VAMPI_README.md`.

## Changes made on top of upstream, before any security work

Each of these is a separate commit. The tag `baseline` marks the state the assignment starts from.

| Change | Why |
|---|---|
| `DATABASE_URL` support, `psycopg2-binary`, Postgres in `docker-compose.yaml` | The assignment's stack uses Postgres. Upstream used SQLite only |
| `frontend/`: a static jQuery client served by nginx, with npm dependencies | The assignment needs JavaScript code for SAST and a second dependency ecosystem for SCA |
| `tests/test_smoke.py` | Gives the existing pipeline something to run. Upstream had no tests |
| `.gitlab-ci.yml` (test + build + push); upstream's GitHub Actions workflow removed | The assignment starts from a working GitLab pipeline with no security controls |
| A commit that adds and then removes `deploy/s3-backup.env` | A **synthetic** credential in git history, for the full-history secrets scan. The key was generated randomly and never belonged to any AWS account |
| `docs/PENTEST_SUMMARY.md`, `docs/ENVIRONMENT.md`, `docs/SUBMISSION_TEMPLATE.md` | Written to stand in for the documents the assignment references |

The weaknesses in `frontend/` (DOM XSS through `innerHTML`, prototype pollution through `_.merge` on `postMessage` data, the token in `localStorage`, old library versions, nginx directory listing) were **added on purpose** to match the assignment's scenario. Everything in the API is upstream VAmPI.
