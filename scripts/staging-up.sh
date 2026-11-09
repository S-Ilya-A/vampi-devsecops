#!/usr/bin/env bash
# Create (or bring back, or update) the staging VM and wire it into GitLab CI.
# Safe to re-run: every step checks first; re-running re-applies provisioning.
#
#   scripts/staging-up.sh           create/start + provision the VM, set CI variables
#   scripts/staging-up.sh --destroy remove the VM (the deploy key and CI variables stay)
#
# Needs: VirtualBox, Vagrant, ssh/ssh-keygen/ssh-keyscan, and GitLab from gitlab-up.sh.
# After the box and Debian/Docker packages have been downloaded once, the VM can be
# rebuilt offline: Docker Hub images come through the host's mirror.
source "$(dirname "$0")/lib.sh"

STAGING_DIR="$REPO_ROOT/staging"
KEY="$STATE_DIR/staging-deploy-key"           # private key, git-ignored
KNOWN_HOSTS="$STATE_DIR/staging-known-hosts"   # pinned host key of the VM

find_tool() {  # find_tool <name> <fallback path>
  command -v "$1" 2>/dev/null || { [ -x "$2" ] && printf '%s' "$2"; } || die "missing required command: $1"
}
VAGRANT=$(find_tool vagrant "/c/Program Files/Vagrant/bin/vagrant.exe")
need ssh ssh-keygen ssh-keyscan curl
vagrant() { (cd "$STAGING_DIR" && "$VAGRANT" "$@"); }

export STAGING_SSH_PORT STAGING_WEB_PORT STAGING_API_PORT
export STAGING_HOST_NAMES="$GITLAB_HOST telemetry.northwind.test"

if [ "${1:-}" = "--destroy" ]; then
  vagrant destroy -f
  ok "staging VM destroyed"
  exit 0
fi

# --------------------------------------------------------------------------- deploy key
mkdir -p "$STATE_DIR"
if [ ! -s "$KEY" ]; then
  ssh-keygen -q -t ed25519 -N '' -C "gitlab-ci-deploy@$STAGING_VM_NAME" -f "$KEY"
  ok "generated deploy key $KEY"
else
  ok "deploy key exists"
fi
export STAGING_DEPLOY_PUBKEY="$(cat "$KEY.pub")"

# --------------------------------------------------------------------------- VM
state=$(vagrant status --machine-readable 2>/dev/null | awk -F, '$3=="state"{print $4}' | tr -d '\r')
case "$state" in
  running)
    log "VM running; re-applying provisioning"
    vagrant provision ;;
  not_created|"")
    log "Creating the staging VM (first run downloads packages: several minutes)"
    vagrant up --provider virtualbox ;;
  *)
    log "VM is $state; starting it and re-applying provisioning"
    vagrant up --provision ;;
esac
ok "VM $STAGING_VM_NAME up"

# --------------------------------------------------------------------------- host key
# Pin the VM's host key so the deploy job never trusts whatever answers on the port.
scanned=$(ssh-keyscan -p "$STAGING_SSH_PORT" -t ed25519 127.0.0.1 2>/dev/null | tr -d '\r')
[ -n "$scanned" ] || die "could not read the VM's SSH host key on 127.0.0.1:$STAGING_SSH_PORT"
printf '%s\n' "$scanned" | sed "s#^\[127.0.0.1\]:$STAGING_SSH_PORT#[$STAGING_HOST]:$STAGING_SSH_PORT#" >"$KNOWN_HOSTS"
# Same key under the loopback name, for checks from this machine.
printf '%s\n' "$scanned" >>"$KNOWN_HOSTS"
ok "host key pinned: $(ssh-keygen -lf "$KNOWN_HOSTS" | head -1 | awk '{print $2}')"

ssh_vm() {
  ssh -i "$KEY" -p "$STAGING_SSH_PORT" -o UserKnownHostsFile="$KNOWN_HOSTS" \
    -o StrictHostKeyChecking=yes -o BatchMode=yes deploy@127.0.0.1 "$@"
}
ssh_vm 'docker info --format "docker {{.ServerVersion}}, registries: {{range .RegistryConfig.Mirrors}}{{.}} {{end}}" && test -s /opt/vampi/.env' \
  || die "deploy user cannot use Docker on the VM"
ok "deploy user can reach Docker on the VM"

# --------------------------------------------------------------------------- CI variables
[ -s "$STATE_DIR/root-token" ] || die "no GitLab token; run scripts/gitlab-up.sh first"
PROJECT_ID=$(api GET "/projects/root%2F$PROJECT_PATH" | json_get 'd["id"]')

# set_project_var <key> <value> <variable_type env_var|file> <protected true|false>
set_project_var() {
  local args=(--data-urlencode "value=$2" --data-urlencode "variable_type=$3"
              --data-urlencode "protected=$4" --data-urlencode "masked=false")
  if api GET "/projects/$PROJECT_ID/variables/$1" >/dev/null 2>&1; then
    api PUT "/projects/$PROJECT_ID/variables/$1" "${args[@]}" >/dev/null
  else
    api POST "/projects/$PROJECT_ID/variables" --data-urlencode "key=$1" "${args[@]}" >/dev/null
  fi
}
# Protected: only pipelines on protected branches (master) get the key, so a pipeline
# from an arbitrary feature branch cannot deploy or read it.
set_project_var STAGING_SSH_KEY     "$(cat "$KEY")"          file    true
set_project_var STAGING_KNOWN_HOSTS "$(cat "$KNOWN_HOSTS")"  file    true
set_project_var STAGING_HOST        "$STAGING_HOST"          env_var false
set_project_var STAGING_SSH_PORT    "$STAGING_SSH_PORT"      env_var false
set_project_var STAGING_WEB_PORT    "$STAGING_WEB_PORT"      env_var false
set_project_var STAGING_API_PORT    "$STAGING_API_PORT"      env_var false
ok "CI variables set (STAGING_SSH_KEY and STAGING_KNOWN_HOSTS are protected)"

cat <<EOF

Staging VM ready.
  SSH (deploy key)  ssh -i $KEY -p $STAGING_SSH_PORT deploy@127.0.0.1
  Web client        http://127.0.0.1:$STAGING_WEB_PORT   (after the first deploy)
  API               http://127.0.0.1:$STAGING_API_PORT
From job containers the same ports are at $STAGING_HOST.
EOF
