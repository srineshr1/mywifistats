# mywifistats

Live CLI/TUI dashboard for your WiFi link, LAN devices, and (optionally) router client list.

Works as a normal Linux WiFi **client** — no root required for the basics.

## Features

- **Your WiFi link**: SSID, BSSID, signal, channel, bitrates, uptime
- **Live bandwidth** for this machine (from interface counters)
- **LAN devices** from the kernel neighbor table (IP, MAC, vendor, status)
- **Router backend** for ZTE F670L / F670LV9.0: login and pull connected host list (WiFi + Ethernet)
- **TUI** (default), plus `--once` and `--json`

## Install

```bash
cargo install --path .
```

Or run from the repo:

```bash
cargo run --release -- --once
```

## Quick start

```bash
# Live dashboard
mywifistats

# One-shot tables
mywifistats --once

# JSON snapshot
mywifistats --json

# Diagnose
mywifistats doctor
```

## Router credentials (ZTE F670L)

Your gateway was detected as a **ZTE F670LV9.0**. With credentials, the tool can list clients the router knows about (more complete than ARP alone).

```bash
# Write sample config
mywifistats init-config

# Preferred: password via env
export MYWIFISTATS_ROUTER_PASSWORD='your-router-password'
mywifistats
```

Config file: `~/.config/mywifistats/config.toml`

```toml
# interface = "wlan0"

[router]
enabled = true
base_url = "http://192.168.1.1"
username = "admin"
backend = "zte_f670l"
# password = "..."   # optional; prefer env
```

Env overrides:

| Variable | Purpose |
|----------|---------|
| `MYWIFISTATS_ROUTER_PASSWORD` | Router password |
| `MYWIFISTATS_ROUTER_USER` | Username |
| `MYWIFISTATS_ROUTER_URL` | Base URL |
| `MYWIFISTATS_INTERFACE` | Wireless interface |
| `MYWIFISTATS_ROUTER_ENABLED` | `true` / `false` |

Disable router for a run: `mywifistats --no-router`.

## TUI keys

| Key | Action |
|-----|--------|
| `q` / Esc | Quit |
| `r` | Refresh now |
| `s` | Cycle sort |
| `j` / `↓` | Next row |
| `k` / `↑` | Previous row |
| `?` | Help |

## How data is collected

| Source | What you get |
|--------|----------------|
| `iw` + `/sys/class/net/.../statistics` | Your association + accurate local RX/TX |
| `ip neigh` | Other devices seen on the LAN |
| ZTE admin API (optional) | Hostnames / WiFi vs Ethernet from the router |

### Per-device data usage

A laptop in client mode **cannot** see other devices’ true byte counters without help from the router (or being the AP).

- **This machine**: always accurate
- **Other devices**: only if the router firmware exposes per-host traffic after login. The tool probes for that; many F670L builds only expose the device list (hostname/IP/MAC), not per-host traffic. The UI says so when that’s the case.

## Requirements

- Linux
- `iw`, `ip` (iproute2)
- Optional: router admin password for client list

## License

MIT
# mywifistats
