# shellcheck shell=bash
# Shared settings and helpers for the environment scripts. Source it, do not run it.

set -euo pipefail

# Git Bash on Windows rewrites arguments that look like paths (/etc/gitlab -> C:/...).
export MSYS_NO_PATHCONV=1

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE_DIR="${STATE_DIR:-$REPO_ROOT/.local}"   # generated secrets, git-ignored

# Pinned images: a re-run never needs the network once these are pulled.
GITLAB_IMAGE="${GITLAB_IMAGE:-gitlab/gitlab-ce:19.4.5-ce.0}"
RUNNER_IMAGE="${RUNNER_IMAGE:-gitlab/gitlab-runner:alpine-v19.4.2}"

# One name that the host browser, the runner, job containers and (later) the staging VM
# can all resolve. Docker Desktop writes host.docker.internal into the host's hosts file
# and resolves it inside containers; on Linux we add it with host-gateway.
GITLAB_HOST="${GITLAB_HOST:-host.docker.internal}"
GITLAB_PORT="${GITLAB_PORT:-8929}"
REGISTRY_PORT="${REGISTRY_PORT:-5050}"
GITLAB_URL="http://${GITLAB_HOST}:${GITLAB_PORT}"
REGISTRY="${GITLAB_HOST}:${REGISTRY_PORT}"

NETWORK="${NETWORK:-devsecops}"
GITLAB_CONTAINER="${GITLAB_CONTAINER:-gitlab}"
RUNNER_CONTAINER="${RUNNER_CONTAINER:-gitlab-runner}"
RUNNER_CONCURRENCY="${RUNNER_CONCURRENCY:-2}"

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
print("" if v is None else v)' "$1"
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

secret_file() {  # secret_file <name>: create a random secret once, print its path
  local f="$STATE_DIR/$1"
  if [ ! -s "$f" ]; then
    mkdir -p "$STATE_DIR"
    # letters+digits only, plus a fixed suffix to satisfy GitLab's complexity rules
    printf '%s' "$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 24)Aa1!" >"$f"
    chmod 600 "$f" 2>/dev/null || true
  fi
  printf '%s' "$f"
}
