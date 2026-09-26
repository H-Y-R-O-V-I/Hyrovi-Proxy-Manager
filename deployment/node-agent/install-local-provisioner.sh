#!/usr/bin/env bash
set -Eeuo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
CONFIG_DIR=/etc/hyrovi-hpm-node
NODE_ENV="$CONFIG_DIR/node.env"
PROVISIONING_ENV="$CONFIG_DIR/provisioning.env"
LOCAL_TOKEN_FILE=${HYROVI_LOCAL_TOKEN_FILE:-/opt/hyrovi-hpm/data/nginx/hyrovi-control-plane/provisioning/local-agent-token}
CONTROLLER=${HYROVI_CONTROLLER:-http://127.0.0.1:8181/api/control-plane}
HPM_CONTAINER=${HYROVI_HPM_CONTAINER:-hyrovi-proxy-manager}

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root." >&2
  exit 1
fi
if [ ! -s "$LOCAL_TOKEN_FILE" ]; then
  echo "Missing local provisioner token: $LOCAL_TOKEN_FILE" >&2
  echo "Start the current HYROVI HPM controller once before installing the local provisioner." >&2
  exit 2
fi

install -d -m 700 "$CONFIG_DIR" /var/lib/hyrovi-hpm-node
cat > "$NODE_ENV" <<ENV
HYROVI_NODE_ID=local
HYROVI_CONTROLLER=$CONTROLLER
ENV
cat > "$PROVISIONING_ENV" <<ENV
HYROVI_LOCAL_TOKEN_FILE=$LOCAL_TOKEN_FILE
HYROVI_HPM_CONTAINER=$HPM_CONTAINER
ENV
chmod 600 "$NODE_ENV" "$PROVISIONING_ENV"

install -m 700 "$HERE/hyrovi-hpm-node-provisioning" /usr/local/sbin/hyrovi-hpm-node-provisioning
install -m 644 "$HERE/hyrovi-hpm-node-provisioning.service" /etc/systemd/system/hyrovi-hpm-node-provisioning.service
install -m 644 "$HERE/hyrovi-hpm-node-provisioning.timer" /etc/systemd/system/hyrovi-hpm-node-provisioning.timer
systemctl daemon-reload
systemctl enable --now hyrovi-hpm-node-provisioning.timer
systemctl start hyrovi-hpm-node-provisioning.service
systemctl --no-pager --full status hyrovi-hpm-node-provisioning.timer
