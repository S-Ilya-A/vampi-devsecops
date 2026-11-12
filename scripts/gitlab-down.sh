#!/usr/bin/env bash
# Stop GitLab and the runner.
#
#   scripts/gitlab-down.sh           stop containers, keep all data
#   scripts/gitlab-down.sh --purge   remove containers, volumes and .local/ secrets

# shellcheck source=scripts/lib.sh
source "$(dirname "$0")/lib.sh"

PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1

for c in "$RUNNER_CONTAINER" "$GITLAB_CONTAINER"; do
  if [ -n "$(container_state "$c")" ]; then
    if [ "$PURGE" = 1 ]; then docker rm -f "$c" >/dev/null; ok "removed $c"
    else docker stop "$c" >/dev/null; ok "stopped $c"; fi
  fi
done

if [ "$PURGE" = 1 ]; then
  docker volume rm -f gitlab-config gitlab-logs gitlab-data gitlab-runner-config "$RUNNER_CACHE_VOLUME" >/dev/null
  rm -f "$STATE_DIR/root-password" "$STATE_DIR/root-token"
  git -C "$REPO_ROOT" remote remove gitlab 2>/dev/null || true
  ok "volumes and secrets removed"
fi
