# shellcheck shell=bash
# Shared settings and helpers for the environment scripts. Source it, do not run it.

set -euo pipefail

# Git Bash on Windows rewrites arguments that look like paths (/etc/gitlab -> C:/...).
export MSYS_NO_PATHCONV=1

# pwd -W (Git Bash) gives C:/... which native Windows tools accept without conversion.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && { pwd -W 2>/dev/null || pwd; })"
STATE_DIR="${STATE_DIR:-$REPO_ROOT/.local}"   # generated secrets, git-ignored

# Pinned images: a re-run never needs the network once these are pulled.
GITLAB_IMAGE="${GITLAB_IMAGE:-gitlab/gitlab-ce:19.4.5-ce.0}"
RUNNER_IMAGE="${RUNNER_IMAGE:-gitlab/gitlab-runner:alpine-v19.4.2}"

# One name that the host browser, the runner, job containers and (later) the staging VM
# all use for GitLab and its registry. It resolves to:
#   host            127.0.0.1, via one line in the hosts file (see preflight)
#   GitLab itself   127.0.0.1 (--add-host)
#   runner + jobs   the Docker host gateway (--add-host / extra_hosts host-gateway)
#   staging VM      the hypervisor's address for the host (Task 3)
# host.docker.internal was rejected: Docker Desktop pins it to the host's LAN address in
# the hosts file, which goes stale when the network changes and is absent offline.
GITLAB_HOST="${GITLAB_HOST:-gitlab.northwind.test}"
GITLAB_BIND="${GITLAB_BIND:-127.0.0.1}"   # host address the published ports listen on
GITLAB_PORT="${GITLAB_PORT:-8929}"
REGISTRY_PORT="${REGISTRY_PORT:-5050}"
GITLAB_URL="http://${GITLAB_HOST}:${GITLAB_PORT}"
REGISTRY="${GITLAB_HOST}:${REGISTRY_PORT}"

NETWORK="${NETWORK:-devsecops}"
GITLAB_CONTAINER="${GITLAB_CONTAINER:-gitlab}"
RUNNER_CONTAINER="${RUNNER_CONTAINER:-gitlab-runner}"
RUNNER_CONCURRENCY="${RUNNER_CONCURRENCY:-2}"
# One named volume for the CI cache, shared by all concurrent job slots. With an
# anonymous "/cache" volume each slot gets its own, so a cache saved by a job in
# slot 0 is invisible to the next job if it lands in slot 1.
RUNNER_CACHE_VOLUME="${RUNNER_CACHE_VOLUME:-gitlab-runner-cache}"

MIRROR_IMAGE="${MIRROR_IMAGE:-registry:2.8.3}"
MIRROR_CONTAINER="${MIRROR_CONTAINER:-docker-mirror}"
MIRROR_PORT="${MIRROR_PORT:-5051}"
MIRROR_URL="http://${GITLAB_HOST}:${MIRROR_PORT}"

PROJECT_PATH="${PROJECT_PATH:-vampi-devsecops}"

# Local traffic must not go through a corporate/desktop HTTP proxy.
export NO_PROXY="${NO_PROXY:-},${GITLAB_HOST},localhost,127.0.0.1"
export no_proxy="$NO_PROXY"

PY="$(command -v python3 || command -v python || true)"

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m ok\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m !!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mERR\033[0m %s\n' "$*" >&2; exit 1; }

need() {
  local c
  for c in "$@"; do command -v "$c" >/dev/null 2>&1 || die "missing required command: $c"; done
}

# json_get <python-expression-on-d>  (reads JSON on stdin)
# e.g. echo '{"a":[{"b":1}]}' | json_get 'd["a"][0]["b"]'
json_get() {
  [ -n "$PY" ] || die "python3 is required for JSON parsing"
  "$PY" -c 'import json,sys
d=json.load(sys.stdin)
v=eval(sys.argv[1])
sys.stdout.buffer.write(("" if v is None else str(v)).encode() + b"\n")' "$1"
}

container_state() {  # prints running|exited|... or nothing if it does not exist
  docker inspect -f '{{.State.Status}}' "$1" 2>/dev/null || true
}

# api <METHOD> <path> [curl args...]   -- GitLab REST API as root
api() {
  local method="$1" path="$2"; shift 2
  curl -sS --fail-with-body -X "$method" \
    -H "PRIVATE-TOKEN: $(cat "$STATE_DIR/root-token")" \
    "$GITLAB_URL/api/v4$path" "$@"
}

# wait_until <timeout-seconds> <description> <command...>
wait_until() {
  local timeout="$1" what="$2"; shift 2
  local start; start=$(date +%s)
  until "$@" >/dev/null 2>&1; do
    if (( $(date +%s) - start > timeout )); then die "timed out after ${timeout}s waiting for $what"; fi
    sleep 5
  done
}

# json_get and rand_str write raw bytes: on Windows print() emits CRLF and $(...) keeps the CR.

# rand_str <length>: random letters and digits.
# (tr </dev/urandom | head would exit 141 on SIGPIPE under pipefail.)
rand_str() {
  "$PY" -c 'import secrets,string,sys
a=string.ascii_letters+string.digits
sys.stdout.buffer.write("".join(secrets.choice(a) for _ in range(int(sys.argv[1]))).encode())' "$1"
}

secret_file() {  # secret_file <name>: create a random secret once, print its path
  local f="$STATE_DIR/$1"
  if [ ! -s "$f" ]; then
    mkdir -p "$STATE_DIR"
    # letters+digits only, plus a fixed suffix to satisfy GitLab's complexity rules
    printf '%s' "$(rand_str 24)Aa1!" >"$f"
    chmod 600 "$f" 2>/dev/null || true
  fi
  printf '%s' "$f"
}
