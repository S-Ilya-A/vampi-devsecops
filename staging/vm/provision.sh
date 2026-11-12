#!/usr/bin/env bash
# Runs inside the staging VM as root (Vagrant shell provisioner). Idempotent: every
# step checks first, so `vagrant provision` can be repeated at any time.
#
# Prepares the VM to run the application, but does not deploy it: the pipeline does
# that over SSH as the `deploy` user. Leaves the VM with
#   - Docker Engine + Compose plugin, pulling through the host's registry and mirror;
#   - a `deploy` user (key-only SSH, in the docker group) owning /opt/vampi;
#   - a per-VM Postgres password in /opt/vampi/.env (never leaves the VM);
#   - Fluent Bit receiving the containers' logs and shipping them to OpenSearch.
set -euo pipefail

SRC=/tmp/staging-vm
HOST_GW=10.0.2.2                      # VirtualBox NAT: the host's loopback
REGISTRY=gitlab.northwind.test:5050
MIRROR=http://gitlab.northwind.test:5051
export DEBIAN_FRONTEND=noninteractive

log() { printf '==> %s\n' "$*"; }

: "${DEPLOY_PUBKEY:?DEPLOY_PUBKEY must be set (scripts/staging-up.sh passes it)}"
: "${HOST_NAMES:=gitlab.northwind.test telemetry.northwind.test}"

log "host names -> $HOST_GW"
sed -i '/# northwind-host$/d' /etc/hosts
for name in $HOST_NAMES; do
  echo "$HOST_GW $name # northwind-host" >>/etc/hosts
done

log "Docker Engine"
if ! command -v docker >/dev/null || ! docker compose version >/dev/null 2>&1; then
  apt-get update -q
  apt-get install -y -q ca-certificates curl gnupg
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  . /etc/os-release
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $VERSION_CODENAME stable" \
    >/etc/apt/sources.list.d/docker.list
  apt-get update -q
  apt-get install -y -q docker-ce docker-ce-cli containerd.io docker-compose-plugin
fi

# The local registry is plain HTTP; Docker Hub pulls go through the host's mirror, so
# deploys and re-provisioning work offline (creating the VM still needs the network
# for the packages above). Logs stay readable with `docker logs` (local driver
# copy) while the fluentd driver set per service ships them.
daemon_json=$(cat <<EOF
{
  "insecure-registries": ["$REGISTRY"],
  "registry-mirrors": ["$MIRROR"],
  "log-driver": "local",
  "log-opts": {"max-size": "10m", "max-file": "3"}
}
EOF
)
if [ "$(cat /etc/docker/daemon.json 2>/dev/null)" != "$daemon_json" ]; then
  printf '%s\n' "$daemon_json" >/etc/docker/daemon.json
  systemctl restart docker
fi
systemctl enable --now docker >/dev/null

log "deploy user"
id deploy >/dev/null 2>&1 || useradd --create-home --shell /bin/bash deploy
usermod -aG docker deploy
install -d -m 0700 -o deploy -g deploy /home/deploy/.ssh
# Exactly one key: the CI deploy key. Re-provisioning with a new key replaces it.
printf '%s\n' "$DEPLOY_PUBKEY" >/home/deploy/.ssh/authorized_keys
chown deploy:deploy /home/deploy/.ssh/authorized_keys
chmod 0600 /home/deploy/.ssh/authorized_keys

log "SSH: own host keys"
# The bento box ships with SSH host keys generated when the box was built, so every
# VM made from it has the same private key and pinning it would prove nothing.
# Generate this VM's own keys once; staging-up.sh pins them afterwards.
if [ ! -e /etc/ssh/.northwind-hostkeys ]; then
  rm -f /etc/ssh/ssh_host_*
  ssh-keygen -A
  touch /etc/ssh/.northwind-hostkeys
  systemctl restart ssh
fi

log "SSH: keys only"
cat >/etc/ssh/sshd_config.d/10-staging.conf <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
EOF
systemctl reload ssh

log "application directory"
install -d -m 0750 -o deploy -g deploy /opt/vampi
if [ ! -s /opt/vampi/.env ]; then
  # Generated on the VM, readable only by deploy: the database password never
  # appears in git, in CI variables or in job logs.
  umask 077
  printf 'POSTGRES_PASSWORD=%s\n' "$(head -c 24 /dev/urandom | base64 | tr -d '/+=')" >/opt/vampi/.env
  chown deploy:deploy /opt/vampi/.env
fi

log "Fluent Bit (log shipper)"
install -d -m 0755 /opt/telemetry
install -m 0644 "$SRC/fluent-bit.conf" /opt/telemetry/fluent-bit.conf
install -m 0644 "$SRC/parsers.conf" /opt/telemetry/parsers.conf
install -m 0644 "$SRC/telemetry-compose.yml" /opt/telemetry/compose.yml
# The telemetry stack's CA (to verify OpenSearch) and the shipper account's
# password, from scripts/telemetry-up.sh via staging-up.sh. Without them Fluent Bit
# still runs and buffers to disk until they arrive.
if [ -n "${TELEMETRY_CA_PEM:-}" ]; then
  printf '%s\n' "$TELEMETRY_CA_PEM" >/opt/telemetry/ca.pem
fi
[ -s /opt/telemetry/ca.pem ] || : >/opt/telemetry/ca.pem
chmod 0644 /opt/telemetry/ca.pem
if [ -n "${TELEMETRY_SHIPPER_PASSWORD:-}" ]; then
  (umask 077; printf 'OPENSEARCH_PASSWORD=%s\n' "$TELEMETRY_SHIPPER_PASSWORD" >/opt/telemetry/.env)
fi
[ -e /opt/telemetry/.env ] || (umask 077; : >/opt/telemetry/.env)
grep -q '^OPENSEARCH_PASSWORD=.' /opt/telemetry/.env \
  || echo "WARNING: no telemetry credentials yet (run scripts/telemetry-up.sh, then staging-up.sh); logs are buffered"
# --force-recreate: picks up a changed config or password without a manual restart.
docker compose -f /opt/telemetry/compose.yml -p telemetry up -d --quiet-pull --force-recreate

log "done"
docker --version
docker compose version
