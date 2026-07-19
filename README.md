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
# Interactive setup (interface + router password)
mywifistats setup

# Live dashboard
mywifistats

# One-shot tables / JSON / diagnose
mywifistats --once
mywifistats --json
mywifistats doctor
```

## Setup TUI

Run **`mywifistats setup`**, or press **`c`** inside the dashboard.

You can set:

- Wireless interface (or leave auto)
- Router on/off, URL, username, password
- Test login before saving

Config is written to `~/.config/mywifistats/config.toml` (mode `0600`).

```bash
# Or password via env only (not stored)
export MYWIFISTATS_ROUTER_PASSWORD='your-router-password'
mywifistats
```

Env overrides: `MYWIFISTATS_ROUTER_PASSWORD`, `MYWIFISTATS_ROUTER_USER`, `MYWIFISTATS_ROUTER_URL`, `MYWIFISTATS_INTERFACE`, `MYWIFISTATS_ROUTER_ENABLED`.

## TUI keys

| Key | Action |
|-----|--------|
| `q` / Esc | Quit |
| `r` | Refresh now |
| `s` | Cycle sort |
| `c` | Open setup |
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
