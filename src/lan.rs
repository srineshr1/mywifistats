use crate::model::{normalize_mac, Device, DeviceSource, LinkKind};
use crate::oui;
use anyhow::{Context, Result};
use std::net::IpAddr;
use std::process::Command;

/// Discover devices from the kernel neighbor table on `iface`.
pub fn discover_neighbors(iface: &str, gateway: Option<IpAddr>, self_ip: Option<IpAddr>) -> Result<Vec<Device>> {
    let out = Command::new("ip")
        .args(["neigh", "show", "dev", iface])
        .output()
        .context("running ip neigh")?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        anyhow::bail!("ip neigh failed: {err}");
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut devices = Vec::new();

    for line in text.lines() {
        if let Some(dev) = parse_neigh_line(line, gateway) {
            devices.push(dev);
        }
    }

    // Ensure self is present
    if let Some(ip) = self_ip {
        let mac = crate::wifi::local_mac(iface);
        let vendor = mac.as_deref().and_then(oui::lookup_vendor).map(str::to_string);
        devices.push(Device {
            hostname: Some(hostname_local()),
            ip: Some(ip),
            mac,
            vendor,
            link: LinkKind::Wifi,
            online: true,
            is_self: true,
            is_gateway: false,
            blocked: false,
            bytes_rx: None,
            bytes_tx: None,
            rate_rx_bps: None,
            rate_tx_bps: None,
            source: DeviceSource::Local,
        });
    }

    // Reverse DNS for devices missing hostname (best-effort, short timeout feel)
    for dev in &mut devices {
        if dev.hostname.is_none() {
            if let Some(ip) = dev.ip {
                dev.hostname = reverse_dns(ip);
            }
        }
    }

    Ok(devices)
}

fn parse_neigh_line(line: &str, gateway: Option<IpAddr>) -> Option<Device> {
    // 192.168.1.1 lladdr 34:24:3e:b3:91:b4 REACHABLE
    // fe80::1 dev wlan0 lladdr ... router STALE
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.is_empty() {
        return None;
    }
    let ip: IpAddr = parts[0].parse().ok()?;
    // Skip pure link-local clutter unless it is the only identity (keep IPv4 mainly)
    if matches!(ip, IpAddr::V6(v6) if v6.is_unicast_link_local()) {
        return None;
    }

    let mut mac = None;
    let mut state = "";
    let mut i = 1;
    while i < parts.len() {
        match parts[i] {
            "lladdr" => {
                if let Some(m) = parts.get(i + 1) {
                    mac = normalize_mac(m);
                    i += 2;
                    continue;
                }
            }
            "REACHABLE" | "STALE" | "DELAY" | "PROBE" | "FAILED" | "PERMANENT" | "NOARP"
            | "NONE" | "INCOMPLETE" => {
                state = parts[i];
            }
            _ => {}
        }
        i += 1;
    }

    // FAILED / incomplete without MAC — skip
    if mac.is_none() && matches!(state, "FAILED" | "INCOMPLETE" | "NONE" | "") {
        return None;
    }

    let online = matches!(state, "REACHABLE" | "DELAY" | "PROBE" | "PERMANENT");
    let is_gateway = gateway == Some(ip);
    let vendor = mac.as_deref().and_then(oui::lookup_vendor).map(str::to_string);

    Some(Device {
        hostname: if is_gateway {
            Some("gateway".into())
        } else {
            None
        },
        ip: Some(ip),
        mac,
        vendor,
        link: LinkKind::Unknown,
        online,
        is_self: false,
        is_gateway,
        blocked: false,
        bytes_rx: None,
        bytes_tx: None,
        rate_rx_bps: None,
        rate_tx_bps: None,
        source: DeviceSource::Lan,
    })
}

fn hostname_local() -> String {
    Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| {
            let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if s.is_empty() {
                None
            } else {
                Some(s)
            }
        })
        .unwrap_or_else(|| "this-machine".into())
}

fn reverse_dns(ip: IpAddr) -> Option<String> {
    // Best-effort via getent (no extra DNS crates).
    let out = Command::new("getent")
        .args(["hosts", &ip.to_string()])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    // 192.168.1.7 hostname.local
    let mut parts = text.split_whitespace();
    let _ip = parts.next()?;
    let name = parts.next()?;
    if name == ip.to_string() {
        return None;
    }
    // strip trailing dot
    Some(name.trim_end_matches('.').to_string())
}
