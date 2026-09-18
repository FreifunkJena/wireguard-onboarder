# Freifunk Jena WireGuard Onboarder

Debian package `freifunk-jena-wireguard-onboarder`: a Python 3 HTTP service that
lets LibreMesh nodes register a WireGuard public key and their **node IP** for
the **innercity** VPN, and automatically provisions a second **WAN** tunnel peer
with a **server-allocated** IP. Stale peers are removed by a handshake watchdog.

## Features

- `POST /register` with `public_key` + `address` (LibreMesh node IP → innercity)
- Same registration upserts a peer on the WAN WireGuard interface; IP from `address_pool`
- Upsert by public key (innercity node IP can change; WAN IP stays sticky)
- Rate limit: one registration per HTTP client IP every 300 seconds
- Watchdog: managed peers without a recent handshake on either tunnel for 600s are deleted from both confs
- Stdlib only (no pip runtime dependencies)

## API

### `POST /register`

```json
{"public_key": "<wg public key>", "address": "10.66.0.12", "comment": "optional"}
```

Success:

- `201` created — new peer on both tunnels
- `200` updated — same public key, innercity IP changed (WAN IP sticky)
- `208` already_registered — same public key and same innercity IP

```json
{
  "status": "created",
  "public_key": "...",
  "innercity": {"interface": "wg-innercity", "allowed_ips": "10.66.0.12/32"},
  "wan": {"interface": "wg-wan", "allowed_ips": "10.99.0.2/32"}
}
```

Use `wan.allowed_ips` on the node as the WAN tunnel interface `Address`.

Errors: `400` validation, `409` innercity address conflict (different key), `429` rate limit,
`503` conf/sync failure or WAN pool exhausted.

### `GET /health` / `GET /peers`

Liveness and managed peer list (handshake age across both tunnels).

## Configuration

`/etc/freifunk-jena-wireguard-onboarder/config.ini`:

```ini
[server]
listen = 0.0.0.0
port = 8080
rate_limit_seconds = 300

[wireguard.innercity]
interface = wg-innercity
config_path = /etc/wireguard/wg-innercity.conf
allowed_cidr = 10.66.0.0/24
reserved = 10.66.0.1

[wireguard.wan]
interface = wg-wan
config_path = /etc/wireguard/wg-wan.conf
address_pool = 10.99.0.0/24
reserved = 10.99.0.1

[watchdog]
peer_timeout_seconds = 600
check_interval_seconds = 30
state_path = /var/lib/freifunk-jena-wireguard-onboarder/state.json
```

Both WireGuard interfaces must already exist on the server. There is **no
authentication**; restrict listen address or firewall the port.

LibreMesh nodes should call `/register` on boot, when the node IP changes, and
after long offline periods.

## Build the Debian package

```sh
dpkg-buildpackage -us -uc -b
```

## Run from source (dev)

```sh
PYTHONPATH=src python3 -m freifunk_jena_wireguard_onboarder -c conf/config.ini --no-sync -v
```

## Tests

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## Maintainer

Martin Michel <martin@mmdev.app>

## License

GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later).
See [`LICENSE`](LICENSE).
