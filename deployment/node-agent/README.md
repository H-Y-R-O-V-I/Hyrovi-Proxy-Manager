# HYROVI HPM remote node agent

This package connects a remote HYROVI Proxy Manager node to the controller without exposing its admin API.

## What it sends

- a signed heartbeat every 30 seconds with node status, addresses and capabilities;
- bounded security request telemetry from `/opt/nginx-proxy-manager/data/logs/hyrovi-sec.log`;
- bounded pseudonymous first-party analytics events from `/opt/nginx-proxy-manager/data/logs/hyrovi-analytics-events.log`.

The uploader strips query strings again on the controller, advances its persistent inode/offset cursor only after a successful upload, survives log rotation, and intentionally keeps each JSON request below the controller's normal ~100 KB body limit. It sends up to twelve small catch-up batches per run rather than increasing the public API body limit.

## Install

1. Create the node in **HPM → Nodes** and copy its one-time bootstrap token.
2. Copy `node.env.example` to `/etc/hyrovi-hpm-node/node.env`, fill in node ID, token and controller URL, and set mode `0600`.
3. Run `sudo ./install.sh`.

The real node token must never be committed. State is stored in `/var/lib/hyrovi-hpm-node/telemetry-state.json` with mode `0600`.
