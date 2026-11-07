#!/usr/bin/env bash
# Task 1: GitLab CE + a Docker-executor runner on this machine, this repository imported
# into it, and its pipeline run to completion. Safe to re-run: every step checks first.
#
#   scripts/gitlab-up.sh              full bring-up, waits for the pipeline
#   scripts/gitlab-up.sh --no-wait    do not wait for the pipeline result
#
# Generated credentials go to .local/ (git-ignored):
#   root-password  GitLab root password (UI login)
#   root-token     root personal access token used by the scripts (API, git push)

# shellcheck source=scripts/lib.sh
source "$(dirname "$0")/lib.sh"

WAIT_PIPELINE=1
for a in "$@"; do
  case "$a" in
    --no-wait) WAIT_PIPELINE=0 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) die "unknown option: $a" ;;
  esac
done

need docker curl git
[ -n "$PY" ] || die "python3 is required"

# --------------------------------------------------------------------------- preflight
log "Preflight"
docker info >/dev/null 2>&1 || die "Docker daemon is not reachable"
mem=$(docker info --format '{{.MemTotal}}')
(( mem >= 7 * 1024 * 1024 * 1024 )) || warn "Docker has $((mem / 1024 / 1024)) MiB; GitLab wants ~4 GiB on its own"
resolved=$("$PY" -c "import socket,sys; print(socket.gethostbyname(sys.argv[1]))" "$GITLAB_HOST" 2>/dev/null || true)
if [[ "$resolved" != 127.* ]]; then
  warn "$GITLAB_HOST resolves to '${resolved:-nothing}', expected 127.0.0.1. Add it to the hosts file once:"
  case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*)
      warn "  (PowerShell as Administrator)"
      warn "  Add-Content \$env:SystemRoot\System32\drivers\etc\hosts \"\`n127.0.0.1 $GITLAB_HOST\"" ;;
    *)
      warn "  echo '127.0.0.1 $GITLAB_HOST' | sudo tee -a /etc/hosts" ;;
  esac
  die "hosts entry missing"
fi
ok "docker up, $GITLAB_HOST -> $resolved"

# --------------------------------------------------------------------------- network
if ! docker network inspect "$NETWORK" >/dev/null 2>&1; then
  docker network create "$NETWORK" >/dev/null
  ok "network $NETWORK created"
else
  ok "network $NETWORK exists"
fi

# --------------------------------------------------------------------------- GitLab
ROOT_PASSWORD_FILE=$(secret_file root-password)

# Single-process Puma, small Sidekiq, no bundled Prometheus stack or KAS: ~3 GiB RSS
# instead of ~5. Registry over plain HTTP on its own port; every Docker daemon that
# pulls from it must list it as an insecure registry (dind in CI, the staging VM).
read -r -d '' OMNIBUS <<EOF || true
external_url '${GITLAB_URL}'
nginx['listen_port'] = ${GITLAB_PORT}
registry_external_url 'http://${REGISTRY}'
registry_nginx['listen_port'] = ${REGISTRY_PORT}
gitlab_rails['registry_enabled'] = true
gitlab_rails['monitoring_whitelist'] = ['127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']
gitlab_rails['usage_ping_enabled'] = false
puma['worker_processes'] = 0
sidekiq['concurrency'] = 5
prometheus_monitoring['enable'] = false
gitlab_kas['enable'] = false
letsencrypt['enable'] = false
EOF

# Settings are fixed when the container is created, so a change of image, name or
# ports means recreating it. The data volumes survive.
GITLAB_CONFIG_HASH=$(printf '%s|%s|%s' "$GITLAB_IMAGE" "$GITLAB_BIND" "$OMNIBUS" | "$PY" -c 'import hashlib,sys;print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest()[:16])')
if [ -n "$(container_state "$GITLAB_CONTAINER")" ]; then
  current_hash=$(docker inspect -f '{{index .Config.Labels "devsecops.config-hash"}}' "$GITLAB_CONTAINER")
  if [ "$current_hash" != "$GITLAB_CONFIG_HASH" ]; then
    warn "GitLab container settings changed; recreating it (data volumes are kept)"
    docker rm -f "$GITLAB_CONTAINER" >/dev/null
  fi
fi

case "$(container_state "$GITLAB_CONTAINER")" in
  "")
    log "Starting GitLab ($GITLAB_IMAGE)"
    # Inside the container the public name points at itself, so GitLab's calls to its
    # own external_url (registry auth, webhooks) never leave the container.
    # Ports are published on loopback only: nothing on the LAN can reach this GitLab.
    docker run -d --name "$GITLAB_CONTAINER" \
      --label "devsecops.config-hash=$GITLAB_CONFIG_HASH" \
      --hostname "$GITLAB_HOST" \
      --network "$NETWORK" \
      --restart unless-stopped \
      --shm-size 256m \
      --add-host "$GITLAB_HOST:127.0.0.1" \
      -p "${GITLAB_BIND}:${GITLAB_PORT}:${GITLAB_PORT}" \
      -p "${GITLAB_BIND}:${REGISTRY_PORT}:${REGISTRY_PORT}" \
      -e GITLAB_ROOT_PASSWORD="$(cat "$ROOT_PASSWORD_FILE")" \
      -e GITLAB_OMNIBUS_CONFIG="$OMNIBUS" \
      -v gitlab-config:/etc/gitlab \
      -v gitlab-logs:/var/log/gitlab \
      -v gitlab-data:/var/opt/gitlab \
      "$GITLAB_IMAGE" >/dev/null
    ;;
  running) ok "GitLab container already running" ;;
  *) log "Starting existing GitLab container"; docker start "$GITLAB_CONTAINER" >/dev/null ;;
esac

log "Waiting for GitLab to become ready (first boot takes 3-6 minutes)"
gitlab_ready() { curl -sf "$GITLAB_URL/-/readiness?all=1" | grep -q '"status":"ok"'; }
wait_until 900 "GitLab readiness" gitlab_ready
ok "GitLab ready at $GITLAB_URL"

# --------------------------------------------------------------------------- root token
token_valid() { [ -s "$STATE_DIR/root-token" ] && api GET /user >/dev/null 2>&1; }
if token_valid; then
  ok "root API token valid"
else
  log "Creating root personal access token (rails runner, ~1 min)"
  mkdir -p "$STATE_DIR"
  new_token="glpat-$(rand_str 24)"
  docker exec -e NEW_TOKEN="$new_token" "$GITLAB_CONTAINER" gitlab-rails runner '
    u = User.find_by_username!("root")
    u.personal_access_tokens.active.where(name: "devsecops-bootstrap").each(&:revoke!)
    t = u.personal_access_tokens.new(
      name: "devsecops-bootstrap",
      scopes: %w[api read_repository write_repository],
      expires_at: 364.days.from_now)
    if t.respond_to?(:organization_id=) && t.organization_id.nil?
      t.organization_id = (u.try(:organization_id) || Organizations::Organization.first&.id)
    end
    t.set_token(ENV.fetch("NEW_TOKEN"))
    t.save!
  ' || die "could not create the root token"
  printf '%s' "$new_token" >"$STATE_DIR/root-token"
  chmod 600 "$STATE_DIR/root-token" 2>/dev/null || true
  token_valid || die "token was created but the API rejects it"
  ok "root API token stored in .local/root-token"
fi

# --------------------------------------------------------------------------- runner
case "$(container_state "$RUNNER_CONTAINER")" in
  "")
    log "Starting runner ($RUNNER_IMAGE)"
    docker run -d --name "$RUNNER_CONTAINER" \
      --network "$NETWORK" \
      --restart unless-stopped \
      --add-host "$GITLAB_HOST:host-gateway" \
      -v gitlab-runner-config:/etc/gitlab-runner \
      -v /var/run/docker.sock:/var/run/docker.sock \
      "$RUNNER_IMAGE" >/dev/null
    ;;
  running) ok "runner container already running" ;;
  *) docker start "$RUNNER_CONTAINER" >/dev/null ;;
esac

runner_registered() {
  docker exec "$RUNNER_CONTAINER" grep -qs 'token = "glrt-' /etc/gitlab-runner/config.toml &&
    docker exec "$RUNNER_CONTAINER" gitlab-runner verify 2>&1 | grep -q 'is valid'
}
if runner_registered; then
  ok "runner registered and verified"
else
  log "Registering runner"
  # Drop a stale local registration (e.g. after GitLab's volumes were wiped).
  docker exec "$RUNNER_CONTAINER" sh -c 'rm -f /etc/gitlab-runner/config.toml'
  runner_token=$(api POST /user/runners \
    --data-urlencode runner_type=instance_type \
    --data-urlencode description=local-docker \
    --data-urlencode run_untagged=true | json_get 'd["token"]')
  # privileged + /certs/client: the existing build jobs use Docker-in-Docker with TLS.
  # if-not-present: once an image is cached, jobs run without network access.
  # host-gateway: job containers reach GitLab and the registry under the same name.
  docker exec "$RUNNER_CONTAINER" gitlab-runner register --non-interactive \
    --url "$GITLAB_URL" \
    --token "$runner_token" \
    --name local-docker \
    --executor docker \
    --docker-image alpine:3.20 \
    --docker-privileged \
    --docker-volumes /certs/client \
    --docker-volumes /cache \
    --docker-extra-hosts "$GITLAB_HOST:host-gateway" \
    --docker-pull-policy if-not-present >/dev/null
  docker exec "$RUNNER_CONTAINER" sed -i "s/^concurrent = .*/concurrent = ${RUNNER_CONCURRENCY}/" /etc/gitlab-runner/config.toml
  wait_until 60 "runner verification" runner_registered
  ok "runner registered (concurrency $RUNNER_CONCURRENCY)"
fi

# --------------------------------------------------------------------------- project
project_json=$(api GET "/projects/root%2F${PROJECT_PATH}" 2>/dev/null || true)
if [ -z "$project_json" ] || ! printf '%s' "$project_json" | json_get 'd["id"]' >/dev/null 2>&1; then
  log "Creating project root/$PROJECT_PATH"
  project_json=$(api POST /projects \
    --data-urlencode "name=$PROJECT_PATH" \
    --data-urlencode "path=$PROJECT_PATH" \
    --data-urlencode visibility=private \
    --data-urlencode container_registry_access_level=enabled)
fi
PROJECT_ID=$(printf '%s' "$project_json" | json_get 'd["id"]')
ok "project root/$PROJECT_PATH (id $PROJECT_ID)"

log "Pushing branches and tags"
push_url="http://root:$(cat "$STATE_DIR/root-token")@${GITLAB_HOST}:${GITLAB_PORT}/root/${PROJECT_PATH}.git"
git -C "$REPO_ROOT" -c credential.helper= -c http.proxy= \
  push --quiet "$push_url" 'refs/heads/*:refs/heads/*' 'refs/tags/*:refs/tags/*'
# A credential-free remote for day-to-day use; git asks for the token as the password.
if ! git -C "$REPO_ROOT" remote get-url gitlab >/dev/null 2>&1; then
  git -C "$REPO_ROOT" remote add gitlab "$GITLAB_URL/root/${PROJECT_PATH}.git"
fi
ok "pushed"

# --------------------------------------------------------------------------- pipeline
BRANCH=$(git -C "$REPO_ROOT" rev-parse --abbrev-ref HEAD)
SHA=$(git -C "$REPO_ROOT" rev-parse HEAD)

pipeline_id=""
for _ in 1 2 3 4 5 6; do   # the push hook creates the pipeline asynchronously
  pipeline_id=$(api GET "/projects/$PROJECT_ID/pipelines?sha=$SHA&per_page=1" | json_get 'd[0]["id"] if d else None')
  [ -n "$pipeline_id" ] && break
  sleep 5
done
if [ -z "$pipeline_id" ]; then
  log "No pipeline for $SHA yet; creating one on $BRANCH"
  pipeline_id=$(api POST "/projects/$PROJECT_ID/pipeline?ref=$BRANCH" | json_get 'd["id"]')
fi
ok "pipeline #$pipeline_id: $GITLAB_URL/root/$PROJECT_PATH/-/pipelines/$pipeline_id"

[ "$WAIT_PIPELINE" = 1 ] || exit 0

log "Waiting for pipeline #$pipeline_id"
while :; do
  status=$(api GET "/projects/$PROJECT_ID/pipelines/$pipeline_id" | json_get 'd["status"]')
  case "$status" in
    success|failed|canceled|skipped) break ;;
  esac
  sleep 10
done

api GET "/projects/$PROJECT_ID/pipelines/$pipeline_id/jobs?per_page=100" | json_get '"\n".join(
  "    %-16s %-8s %-8s %6.1fs" % (j["name"], j["stage"], j["status"], j["duration"] or 0)
  for j in sorted(d, key=lambda j: j["id"]))'

[ "$status" = success ] || die "pipeline #$pipeline_id finished with status: $status"
ok "pipeline #$pipeline_id passed"
cat <<EOF

GitLab   $GITLAB_URL   (root / password in .local/root-password)
Registry $REGISTRY
EOF
