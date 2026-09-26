#!/usr/bin/env bash
set -Eeuo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
ENV_FILE=/etc/hyrovi-hpm-node/node.env

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root." >&2
  exit 1
fi
if [ ! -f "$ENV_FILE" ]; then
  echo "Missing $ENV_FILE. Create it from node.env.example and insert the one-time node token first." >&2
  exit 2
fi
chmod 600 "$ENV_FILE"
install -m 700 "$HERE/hyrovi-hpm-node-heartbeat" /usr/local/sbin/hyrovi-hpm-node-heartbeat
install -m 700 "$HERE/hyrovi-hpm-node-telemetry" /usr/local/sbin/hyrovi-hpm-node-telemetry
install -m 644 "$HERE/hyrovi-hpm-node-heartbeat.service" /etc/systemd/system/hyrovi-hpm-node-heartbeat.service
install -m 644 "$HERE/hyrovi-hpm-node-heartbeat.timer" /etc/systemd/system/hyrovi-hpm-node-heartbeat.timer
install -m 644 "$HERE/hyrovi-hpm-node-telemetry.service" /etc/systemd/system/hyrovi-hpm-node-telemetry.service
install -m 644 "$HERE/hyrovi-hpm-node-telemetry.timer" /etc/systemd/system/hyrovi-hpm-node-telemetry.timer
install -d -m 700 /var/lib/hyrovi-hpm-node
systemctl daemon-reload
systemctl enable --now hyrovi-hpm-node-heartbeat.timer hyrovi-hpm-node-telemetry.timer
systemctl start hyrovi-hpm-node-heartbeat.service hyrovi-hpm-node-telemetry.service
systemctl --no-pager --full status hyrovi-hpm-node-heartbeat.timer hyrovi-hpm-node-telemetry.timer
