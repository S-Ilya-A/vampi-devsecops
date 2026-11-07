# DevSecOps technical assignment: parcel-tracker

## The situation

You have just joined Northwind Parcel, a forty-person logistics start-up, as its first DevSecOps engineer. The company's customer-facing service, `parcel-tracker`, is a Flask API, a static tracking page and a Postgres database, built and deployed by a GitLab CI pipeline that a developer set up two years ago. It works. Nobody has ever put a security control in it.

Last month a prospective enterprise customer sent a security questionnaire. Northwind failed it. A short external penetration test followed; its summary is in `docs/PENTEST_SUMMARY.md`. The engineering lead has asked you to make the pipeline enforce security, to stand up a proper staging environment, and to give the team visibility into what the scanners and the running service are saying.

This repository is what the developers handed you. Treat it as a real inherited codebase: read it, run it, and do not assume anything about it is fine.

## What you must build

You are expected to spend between 8 and 12 focused hours. Everything must run on a single laptop (assume 16 GB RAM and 8 cores) using Docker and one virtual machine. No hosted or paid services. After the initial image pulls, everything must work offline.

### Task 1: Stand up the environment

Run GitLab CE and a GitLab runner in Docker on your laptop. Import this repository into it. Get the existing pipeline to pass end to end, through the runner, before changing anything else.

Deliverable: a Bash script (or a small set of them) that does this from a clean machine, idempotently. Notes on the environment are in `docs/ENVIRONMENT.md`; the kit deliberately does not include a Compose file for GitLab.

### Task 2: Harden the existing pipeline

Extend `.gitlab-ci.yml` so that every pipeline run applies these gates and fails when they are breached:

- Static application security testing (SAST) covering both the Python and the JavaScript code.
- Secrets detection across the full git history, not only the working tree.
- Software composition analysis of both dependency ecosystems, producing a software bill of materials (SBOM) as an artefact.
- Container image scanning of both built images, including the base image and Dockerfile configuration.

Thresholds are yours to set, but they must be explicit and justified in your note. Scanner output must be stored as machine-readable pipeline artefacts. Where a finding is a false positive, suppress it in a way that is documented and reviewable rather than by disabling the rule.

### Task 3: Build a new pipeline for a staging VM

Northwind has no staging environment. Create one:

- A Bash script provisions a virtual machine with Vagrant or Multipass and prepares it to run the application.
- A new pipeline stage, or a child pipeline, deploys the current images to that VM over SSH.
- The pipeline then runs OWASP ZAP against the application on the VM and fails on a threshold you define. A passive baseline scan is a minimum; consider whether it is enough to find what the pen-test summary describes.
- A log shipper on the VM forwards the application's logs to the telemetry stack in Task 4.

The VM must be reproducible from your script alone. How the runner reaches the VM is your problem to solve.

### Task 4: Telemetry and analysis

Run OpenSearch and OpenSearch Dashboards in Docker. Ship three streams into it:

1. Scanner findings from every pipeline run, normalised enough to be queried together.
2. Pipeline job events: which job ran, on which commit, how long, and with what result.
3. Application logs from the running service on the VM.

Write a Python command-line tool that queries OpenSearch and prints a trend report. It must accept `--since` (a duration or a date) and `--format table|json`, and it must show at least:

- findings per tool per pipeline run;
- severity distribution;
- which findings are new, recurring, or resolved between two runs;
- anything in the application logs that a security engineer would want to know about.

The tool must have tests. Build at least one dashboard as well.

### Task 5: Fix at least two findings

Choose two or more of the findings your gates produced and fix them properly in the application or its configuration, not by suppression. Run the pipeline again and show, through your trend report, that they are resolved.

### Task 6: Write the explanatory note

Use `docs/SUBMISSION_TEMPLATE.md`. Include an architecture diagram, your design decisions with the alternatives you rejected, an honest list of what you did not do and why, and a one-paragraph answer to: "Northwind at 200 developers, 20 teams, 60 repositories, with the same security staffing: what breaks first in your design, and what would you change?"

## Time budget

This is guidance, not a rule. If you are far over on one item, write down where you got stuck and move on.

| Task | Hours |
|---|---|
| 1. Environment | 1 to 2 |
| 2. Existing pipeline gates | 2 to 3 |
| 3. VM and DAST pipeline | 2 to 2.5 |
| 4. Telemetry and analysis | 2 to 3 |
| 5 and 6. Fixes and note | 1 to 1.5 |

## Rules

- Pipeline jobs must run through the GitLab runner. Running a scanner by hand and pasting the output does not count.
- OWASP ZAP for DAST and OpenSearch for telemetry are fixed. For everything else, any open-source tool is acceptable if you justify the choice. Suggested defaults: Semgrep, Gitleaks, Trivy, Syft and Grype, Fluent Bit.
- No paid or hosted services, including free tiers of SaaS scanners.
- Commit as you go. Your history is part of the submission.
- Do not commit real credentials of your own. Synthetic ones you generate for the exercise are fine.

## Optional stretch goals

Only attempt these if the core is complete. They are not required for a strong submission.

- Sign both container images with Cosign and verify signatures in the deploy stage.
- Express the gate thresholds as policy-as-code with OPA or Conftest.
- Run MobSF static analysis in the pipeline against an Android debug APK of your choosing and report its findings alongside the others.

## What to submit

- Your repository as a `git bundle` or a tarball that includes the `.git` directory.
- Your note, as `NOTE.md` in the repository root, following the template.

## How we review

We read the note first, then the pipeline definitions, then the scripts, then the history. Submissions that meet the bar are invited to a sixty- to ninety-minute video call. You will share your screen, run the pipeline live, walk us through the design, and make a small change we ask for on the spot. Be ready to explain every line you submit.
