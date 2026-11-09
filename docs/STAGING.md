# Staging VM and DAST

## Bring-up

```bash
scripts/gitlab-up.sh       # GitLab + runner (once; re-run after pulling this change so the runner learns the staging host name)
scripts/staging-up.sh      # VM + deploy key + CI variables; safe to re-run
scripts/staging-up.sh --destroy
```

`staging-up.sh` does everything needed from a clean machine with VirtualBox and Vagrant installed:

1. Generates an ed25519 deploy key in `.local/` (git-ignored) on first run.
2. Creates the VM from `staging/Vagrantfile`, or starts it, then re-applies provisioning. The box is `bento/debian-12`, pinned to version 202510.26.0. The VM has 1.5 GB of RAM and 2 vCPUs.
3. Pins the VM's SSH host key.
4. Checks that the `deploy` user can use Docker.
5. Stores the key, the pinned host key and the ports as GitLab CI variables.

Provisioning (`staging/vm/provision.sh`, idempotent) does five things:
- installs Docker Engine and the Compose plugin;
- points Docker at the host's registry and Docker Hub mirror;
- creates a key-only `deploy` user and disables password and root SSH logins;
- generates a per-VM Postgres password in `/opt/vampi/.env`, readable only by `deploy`;
- starts Fluent Bit.

The VM is reproducible from the script alone. After the box, the Debian packages and the images have been fetched once, rebuilding it needs no internet: images come from the local registry and the mirror.

## How the runner reaches the VM, and the VM reaches the host

```
job container ──host-gateway──> host 127.0.0.1:2250/18088/15000 ──VirtualBox NAT port forward──> VM :22/:8088/:5000
VM ──10.0.2.2 (VirtualBox NAT = host loopback)──> registry :5050, mirror :5051, OpenSearch :9200
```

- Every forwarded port listens on the host's loopback only, so the VM is not reachable from the LAN.
- In job containers the name `staging.northwind.test` resolves to the Docker host gateway. The runner's `extra_hosts` setting is maintained by `gitlab-up.sh`.
- Inside the VM, `gitlab.northwind.test` and `telemetry.northwind.test` map to `10.0.2.2`.

These names were chosen over a host-only network for two reasons:
- **Nothing outside the laptop is exposed.** A host-only adapter creates a network the host and any other VM on it can reach.
- **It needs no route from Docker Desktop's VM into a VirtualBox network.** That route differs between Windows, macOS and Linux.

## Deploy (`deploy-staging`)

The job runs on protected branches only, because the SSH key is a protected variable. It does the following:
1. Copies `staging/compose.yml` to the VM.
2. Logs the VM's Docker in to the registry with the job's own short-lived token, passed on stdin.
3. Pulls the images by commit tag and runs `docker compose up --wait`.
4. Logs out again.
5. Re-seeds the demo data and checks that the API and the web client answer.

`StrictHostKeyChecking=yes` against the pinned host key means the job refuses to talk to anything else that answers on the port.

Staging is deployed even when a gate earlier in the pipeline failed. Staging is the target the DAST gate scans, not a release. A production deploy would require every gate to pass.

## DAST

| Job | Scan | Target | Fails on | Report |
|---|---|---|---|---|
| `dast-zap-baseline` | ZAP baseline: spider + AJAX spider, passive rules only | web client `:18088` | any alert of **Medium** risk or above | `reports/zap-baseline.json`, `.html` |
| `dast-zap-api` | ZAP API scan: imports `/openapi.json` and **actively** attacks every operation, with a bearer token | API `:15000` | any alert of **High** risk | `reports/zap-api.json`, `.html` |

**Is a passive baseline enough? No.** The pen-test summary says an unauthenticated crawl of the web client found almost none of its findings. PT-01, PT-03, PT-05 and PT-11 only appeared when the OpenAPI definition was replayed with a valid token. So `dast-zap-api` copies the testers' approach:
1. `ci/dast_session.py` registers its own unprivileged user, as the testers did.
2. It logs in, and ZAP adds the resulting token to every request (`ZAP_AUTH_HEADER_VALUE`).
3. ZAP imports the definition and runs the active rules against every operation.

The script also creates a book whose title contains markup, so the stored-XSS path (PT-07) has data in it.

**Why the thresholds differ.** A passive alert means a missing header or an information leak, so it is near-certain and cheap to fix. Medium is therefore affordable as a gate, and it covers PT-14. Active-scan Mediums include timing-based and heuristic results that need a human to confirm, and there is no security engineer to triage them. So only High blocks, which covers injection. Everything else is in the report and in the trend report.

**Bounds.** The active scan is limited to 2 minutes per rule and 12 minutes overall. Both DAST jobs share the `staging` resource group with the deploy job, so a deploy cannot replace the application in the middle of a scan, and the two scans run one after the other instead of competing for memory. What the resource group does not guarantee is that a scan sees the version its own pipeline deployed. Another pipeline's deploy can slip in between the two jobs. With one protected branch this is rare, and every scan report records the target. The fix would be a single job that deploys and then scans.

Which pen-test findings this set-up detects and which it misses is recorded in NOTE.md, from the actual reports.
