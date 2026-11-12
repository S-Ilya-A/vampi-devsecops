#!/usr/bin/env bash
# Create (or bring back, or update) the staging VM and wire it into GitLab CI.
# Safe to re-run: every step checks first; re-running re-applies provisioning.
#
#   scripts/staging-up.sh           create/start + provision the VM, set CI variables
#   scripts/staging-up.sh --destroy remove the VM (the deploy key and CI variables stay)
#
# Needs: VirtualBox, Vagrant, ssh/ssh-keygen/ssh-keyscan, and GitLab from gitlab-up.sh.
# Deploys and re-provisioning work offline (images come through the host's registry
# and mirror). Creating the VM from scratch needs the network for Debian and Docker
# packages.
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

export STAGING_SSH_PORT STAGING_WEB_PORT STAGING_API_PORT STAGING_VM_CPUS STAGING_VM_MEMORY
export STAGING_HOST_NAMES="$GITLAB_HOST $TELEMETRY_HOST"
# Fluent Bit on the VM: the telemetry CA and the shipper password (telemetry-up.sh).
if [ -s "$STATE_DIR/telemetry/certs/ca.pem" ] && [ -s "$STATE_DIR/telemetry/shipper-password" ]; then
  TELEMETRY_CA_PEM="$(cat "$STATE_DIR/telemetry/certs/ca.pem")"
  TELEMETRY_SHIPPER_PASSWORD="$(cat "$STATE_DIR/telemetry/shipper-password")"
  export TELEMETRY_CA_PEM TELEMETRY_SHIPPER_PASSWORD
else
  warn "no telemetry stack yet: Fluent Bit on the VM will buffer logs (run scripts/telemetry-up.sh, then this again)"
fi

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
STAGING_DEPLOY_PUBKEY="$(cat "$KEY.pub")"
export STAGING_DEPLOY_PUBKEY

# --------------------------------------------------------------------------- VM
state=$(vagrant status --machine-readable 2>/dev/null | awk -F, '$3=="state"{print $4}' | tr -d '\r')
case "$state" in
  running)
    # CPU, memory and forwarded ports only change at boot; `vagrant provision`
    # would leave them. Forwarding lines look like
    #   Forwarding(1)="name,tcp,127.0.0.1,<host port>,,<guest port>"
    VBOXMANAGE=$(find_tool VBoxManage "/c/Program Files/Oracle/VirtualBox/VBoxManage.exe")
    have=$("$VBOXMANAGE" showvminfo "$STAGING_VM_NAME" --machinereadable | tr -d '\r"' \
           | awk -F'[=,]' '/^Forwarding/ {port[$7]=$5} {v[$1]=$2}
               END{printf "cpus=%s memory=%s ssh=%s web=%s api=%s ", v["cpus"], v["memory"], port["22"], port["8088"], port["5000"]}')
    want="cpus=$STAGING_VM_CPUS memory=$STAGING_VM_MEMORY ssh=$STAGING_SSH_PORT web=$STAGING_WEB_PORT api=$STAGING_API_PORT "
    if [ "$have" != "$want" ]; then
      log "VM has ${have}but the configuration says ${want}; rebooting it to apply"
      vagrant reload --provision
    else
      log "VM running; re-applying provisioning"
      vagrant provision
    fi ;;
  not_created|"")
    log "Creating the staging VM (first run downloads packages: several minutes)"
    vagrant up --provider virtualbox ;;
  *)
    log "VM is $state; starting it and re-applying provisioning"
    vagrant up --provision ;;
esac
ok "VM $STAGING_VM_NAME up"

# --------------------------------------------------------------------------- forwarded ports
# VirtualBox only logs a port forward it could not set up; the VM starts without
# it and Vagrant reports success. It happens on Windows when Hyper-V has reserved
# a block of ports that contains ours (the blocks change with every reboot), and
# the first symptom would be a deploy job failing with "connection refused".
# A forwarded port accepts connections on the host even when nothing listens in
# the guest yet, so this check also works before the first deploy.
unforwarded=""
for port in "$STAGING_SSH_PORT" "$STAGING_WEB_PORT" "$STAGING_API_PORT"; do
  (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null || unforwarded+=" $port"
done
if [ -n "$unforwarded" ]; then
  warn "VirtualBox is not forwarding host port(s)$unforwarded to the VM."
  warn "Something else holds the port, or (Windows) it is in a reserved range:"
  warn "  netsh interface ipv4 show excludedportrange protocol=tcp"
  warn "Pick a free port and re-run; the VM is rebooted to apply it, for example:"
  warn "  STAGING_WEB_PORT=28088 scripts/staging-up.sh"
  warn "(STAGING_SSH_PORT, STAGING_WEB_PORT, STAGING_API_PORT; see docs/STAGING.md)"
  die "port forwarding to the staging VM is incomplete"
fi
ok "forwarded ports answer on the host: $STAGING_SSH_PORT $STAGING_WEB_PORT $STAGING_API_PORT"

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
PROJECT_ID=$(project_id)

# Protected: only pipelines on protected branches (master) get the key, so a pipeline
# from an arbitrary feature branch cannot deploy or read it.
# $(...) strips the trailing newline, and OpenSSH refuses a private key file
# without one ("error in libcrypto"), so put it back.
nl=$'\n'
set_project_var "$PROJECT_ID" STAGING_SSH_KEY     "$(cat "$KEY")$nl"          file    true
set_project_var "$PROJECT_ID" STAGING_KNOWN_HOSTS "$(cat "$KNOWN_HOSTS")$nl"  file    true
set_project_var "$PROJECT_ID" STAGING_HOST        "$STAGING_HOST"          env_var false
set_project_var "$PROJECT_ID" STAGING_SSH_PORT    "$STAGING_SSH_PORT"      env_var false
set_project_var "$PROJECT_ID" STAGING_WEB_PORT    "$STAGING_WEB_PORT"      env_var false
set_project_var "$PROJECT_ID" STAGING_API_PORT    "$STAGING_API_PORT"      env_var false
ok "CI variables set (STAGING_SSH_KEY and STAGING_KNOWN_HOSTS are protected)"

cat <<EOF

Staging VM ready.
  SSH (deploy key)  ssh -i $KEY -p $STAGING_SSH_PORT deploy@127.0.0.1
  Web client        http://127.0.0.1:$STAGING_WEB_PORT   (after the first deploy)
  API               http://127.0.0.1:$STAGING_API_PORT
From job containers the same ports are at $STAGING_HOST.
EOF
