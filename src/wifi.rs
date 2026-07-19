use crate::model::{TrafficCounters, WifiLink};
use anyhow::{bail, Context, Result};
use std::fs;
use std::net::IpAddr;
use std::process::Command;

pub fn detect_interface(preferred: Option<&str>) -> Result<String> {
    if let Some(name) = preferred {
        if iface_exists(name) {
            return Ok(name.to_string());
        }
        bail!("interface '{name}' not found");
    }

    // Prefer wireless iface that is UP.
    let out = run_cmd(&["ip", "-br", "link"])?;
    let mut candidates: Vec<String> = Vec::new();
    for line in out.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        let name = parts[0].split('@').next().unwrap_or(parts[0]);
        if !is_wireless(name) {
            continue;
        }
        if parts[1].contains("UP") {
            candidates.insert(0, name.to_string());
        } else {
            candidates.push(name.to_string());
        }
    }

    if let Some(name) = candidates.into_iter().next() {
        return Ok(name);
    }

    // Fallback: default route device
    if let Ok(route) = run_cmd(&["ip", "route", "show", "default"]) {
        if let Some(dev) = route
            .split_whitespace()
            .skip_while(|t| *t != "dev")
            .nth(1)
        {
            return Ok(dev.to_string());
        }
    }

    bail!("no wireless interface found; pass --interface")
}

fn iface_exists(name: &str) -> bool {
    std::path::Path::new(&format!("/sys/class/net/{name}")).exists()
}

fn is_wireless(name: &str) -> bool {
    std::path::Path::new(&format!("/sys/class/net/{name}/wireless")).exists()
        || name.starts_with("wlan")
        || name.starts_with("wlp")
}

pub fn read_traffic(iface: &str) -> Result<TrafficCounters> {
    let rx = read_u64(&format!("/sys/class/net/{iface}/statistics/rx_bytes"))?;
    let tx = read_u64(&format!("/sys/class/net/{iface}/statistics/tx_bytes"))?;
    Ok(TrafficCounters {
        rx_bytes: rx,
        tx_bytes: tx,
    })
}

fn read_u64(path: &str) -> Result<u64> {
    let s = fs::read_to_string(path).with_context(|| format!("reading {path}"))?;
    s.trim()
        .parse()
        .with_context(|| format!("parsing {path}"))
}

pub fn collect_wifi(iface: &str) -> Result<WifiLink> {
    let mut link = WifiLink {
        iface: iface.to_string(),
        ssid: None,
        bssid: None,
        freq_mhz: None,
        channel: None,
        channel_width_mhz: None,
        signal_dbm: None,
        rx_bitrate_mbps: None,
        tx_bitrate_mbps: None,
        connected_secs: None,
        ip: None,
        gateway: None,
    };

    if let Ok(out) = run_cmd(&["iw", "dev", iface, "link"]) {
        parse_iw_link(&out, &mut link);
    }
    if let Ok(out) = run_cmd(&["iw", "dev", iface, "info"]) {
        parse_iw_info(&out, &mut link);
    }
    if let Ok(out) = run_cmd(&["iw", "dev", iface, "station", "dump"]) {
        parse_station_dump(&out, &mut link);
    }

    link.ip = primary_ipv4(iface);
    link.gateway = default_gateway(Some(iface)).or_else(|| default_gateway(None));

    Ok(link)
}

fn parse_iw_link(out: &str, link: &mut WifiLink) {
    for line in out.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("Connected to ") {
            let bssid = rest.split_whitespace().next().unwrap_or("").to_string();
            if !bssid.is_empty() {
                link.bssid = Some(bssid);
            }
        } else if let Some(ssid) = t.strip_prefix("SSID: ") {
            link.ssid = Some(ssid.to_string());
        } else if let Some(freq) = t.strip_prefix("freq: ") {
            let n: f64 = freq
                .split_whitespace()
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0.0);
            if n > 0.0 {
                link.freq_mhz = Some(n.round() as u32);
            }
        } else if let Some(sig) = t.strip_prefix("signal: ") {
            if let Some(dbm) = sig
                .split_whitespace()
                .next()
                .and_then(|s| s.parse::<i32>().ok())
            {
                link.signal_dbm = Some(dbm);
            }
        } else if let Some(rest) = t.strip_prefix("rx bitrate: ") {
            link.rx_bitrate_mbps = parse_bitrate(rest);
        } else if let Some(rest) = t.strip_prefix("tx bitrate: ") {
            link.tx_bitrate_mbps = parse_bitrate(rest);
        }
    }
}

fn parse_iw_info(out: &str, link: &mut WifiLink) {
    for line in out.lines() {
        let t = line.trim();
        if let Some(ssid) = t.strip_prefix("ssid ") {
            if link.ssid.is_none() {
                link.ssid = Some(ssid.to_string());
            }
        } else if t.starts_with("channel ") {
            // channel 64 (5320 MHz), width: 80 MHz, center1: 5290 MHz
            let parts: Vec<&str> = t.split_whitespace().collect();
            if parts.len() >= 2 {
                if let Ok(ch) = parts[1].parse::<u32>() {
                    link.channel = Some(ch);
                }
            }
            if let Some(idx) = parts.iter().position(|p| *p == "width:") {
                if let Some(w) = parts.get(idx + 1).and_then(|s| s.parse::<u32>().ok()) {
                    link.channel_width_mhz = Some(w);
                }
            }
            if link.freq_mhz.is_none() {
                if let Some(paren) = t.find('(') {
                    let rest = &t[paren + 1..];
                    if let Some(mhz) = rest.split_whitespace().next() {
                        if let Ok(f) = mhz.parse::<u32>() {
                            link.freq_mhz = Some(f);
                        }
                    }
                }
            }
        }
    }
}

fn parse_station_dump(out: &str, link: &mut WifiLink) {
    for line in out.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("signal:") {
            if let Some(dbm) = rest
                .split_whitespace()
                .find_map(|s| s.parse::<i32>().ok())
            {
                link.signal_dbm = Some(dbm);
            }
        } else if let Some(rest) = t.strip_prefix("tx bitrate:") {
            link.tx_bitrate_mbps = parse_bitrate(rest);
        } else if let Some(rest) = t.strip_prefix("rx bitrate:") {
            link.rx_bitrate_mbps = parse_bitrate(rest);
        } else if let Some(rest) = t.strip_prefix("connected time:") {
            if let Some(secs) = rest
                .split_whitespace()
                .next()
                .and_then(|s| s.parse::<u64>().ok())
            {
                link.connected_secs = Some(secs);
            }
        }
    }
}

fn parse_bitrate(s: &str) -> Option<f64> {
    s.split_whitespace().next()?.parse().ok()
}

fn primary_ipv4(iface: &str) -> Option<IpAddr> {
    let out = run_cmd(&["ip", "-4", "-o", "addr", "show", "dev", iface]).ok()?;
    for line in out.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if let Some(idx) = parts.iter().position(|p| *p == "inet") {
            if let Some(cidr) = parts.get(idx + 1) {
                let ip = cidr.split('/').next()?;
                return ip.parse().ok();
            }
        }
    }
    None
}

pub fn default_gateway(iface: Option<&str>) -> Option<IpAddr> {
    let out = run_cmd(&["ip", "route", "show", "default"]).ok()?;
    for line in out.lines() {
        if !line.contains("default") {
            continue;
        }
        if let Some(want) = iface {
            let dev = line
                .split_whitespace()
                .skip_while(|t| *t != "dev")
                .nth(1);
            if dev != Some(want) {
                continue;
            }
        }
        let mut parts = line.split_whitespace();
        while let Some(t) = parts.next() {
            if t == "via" {
                if let Some(gw) = parts.next() {
                    return gw.parse().ok();
                }
            }
        }
    }
    None
}

pub fn local_mac(iface: &str) -> Option<String> {
    fs::read_to_string(format!("/sys/class/net/{iface}/address"))
        .ok()
        .map(|s| s.trim().to_ascii_lowercase())
}

fn run_cmd(args: &[&str]) -> Result<String> {
    let (bin, rest) = args.split_first().context("empty command")?;
    let out = Command::new(bin)
        .args(rest)
        .output()
        .with_context(|| format!("running {bin}"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        bail!("{bin} failed: {err}");
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}
