# HYROVI HPM remote node agent

This package connects a remote HYROVI Proxy Manager node to the controller without exposing its admin API.

## What it sends

- a signed heartbeat every 30 seconds with node status, addresses and capabilities;
- bounded security request telemetry from `/opt/nginx-proxy-manager/data/logs/hyrovi-sec.log`;
- bounded pseudonymous first-party analytics events from `/opt/nginx-proxy-manager/data/logs/hyrovi-analytics-events.log`.
- allowlisted proxy-host provisioning jobs. The agent can create HPM proxy hosts, apply HYROVI Sec overrides, route DNS to the node's existing Cloudflare Tunnel, add a specific ingress rule only when the tunnel wildcard does not already cover the hostname, validate Nginx/Cloudflare configuration, and report the result to the controller. It does not execute arbitrary controller-supplied shell commands.

The Raspberry Pi controller uses only the local provisioning timer, installed with `sudo ./install-local-provisioner.sh`. Remote nodes use `sudo ./install.sh`, which installs heartbeat, telemetry and provisioning. The local installer reads the controller-generated token directly from the mounted HPM data directory and never turns the Pi into a fake remote node.

The uploader strips query strings again on the controller, advances its persistent inode/offset cursor only after a successful upload, survives log rotation, and intentionally keeps each JSON request below the controller's normal ~100 KB body limit. It sends up to twelve small catch-up batches per run rather than increasing the public API body limit.

## Install

1. Create the node in **HPM → Nodes** and copy its one-time bootstrap token.
2. Copy `node.env.example` to `/etc/hyrovi-hpm-node/node.env`, fill in node ID, token and controller URL, and set mode `0600`.
3. Run `sudo ./install.sh`.

The real node token must never be committed. State is stored in `/var/lib/hyrovi-hpm-node/telemetry-state.json` with mode `0600`.
