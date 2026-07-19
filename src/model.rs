use serde::Serialize;
use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkKind {
    Wifi,
    Ethernet,
    Unknown,
}

impl LinkKind {
    pub fn as_str(self) -> &'static str {
        match self {
            LinkKind::Wifi => "WiFi",
            LinkKind::Ethernet => "ETH",
            LinkKind::Unknown => "?",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct TrafficCounters {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct TrafficRates {
    pub rx_bps: u64,
    pub tx_bps: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct WifiLink {
    pub iface: String,
    pub ssid: Option<String>,
    pub bssid: Option<String>,
    pub freq_mhz: Option<u32>,
    pub channel: Option<u32>,
    pub channel_width_mhz: Option<u32>,
    pub signal_dbm: Option<i32>,
    pub rx_bitrate_mbps: Option<f64>,
    pub tx_bitrate_mbps: Option<f64>,
    pub connected_secs: Option<u64>,
    pub ip: Option<IpAddr>,
    pub gateway: Option<IpAddr>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Device {
    pub hostname: Option<String>,
    pub ip: Option<IpAddr>,
    pub mac: Option<String>,
    pub vendor: Option<String>,
    pub link: LinkKind,
    pub online: bool,
    pub is_self: bool,
    pub is_gateway: bool,
    /// True if MAC appears on the router firewall block list.
    pub blocked: bool,
    pub bytes_rx: Option<u64>,
    pub bytes_tx: Option<u64>,
    pub rate_rx_bps: Option<u64>,
    pub rate_tx_bps: Option<u64>,
    pub source: DeviceSource,
}

#[derive(Debug, Clone, Serialize)]
pub struct BlockedDevice {
    /// Router instance id (e.g. DEV.FW.CHAIN1.MACF1) for unblock.
    pub inst_id: String,
    pub name: String,
    pub mac: String,
    pub protocol: Option<String>,
    pub filter_type: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct MacFilterStatus {
    pub enabled: bool,
    /// e.g. "Discard" = blacklist, "Accept" = whitelist
    pub mode: String,
    pub can_block: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceSource {
    Lan,
    Router,
    Merged,
    Local,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct RouterStatus {
    pub enabled: bool,
    pub name: Option<String>,
    pub connected: bool,
    pub device_count: usize,
    pub per_host_traffic: bool,
    pub can_block: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct NetworkSnapshot {
    #[serde(serialize_with = "serialize_system_time")]
    pub collected_at: SystemTime,
    pub wifi: Option<WifiLink>,
    pub local_traffic: TrafficCounters,
    pub local_rates: TrafficRates,
    pub devices: Vec<Device>,
    pub blocked: Vec<BlockedDevice>,
    pub mac_filter: MacFilterStatus,
    pub router: RouterStatus,
    pub errors: Vec<String>,
}

fn serialize_system_time<S>(t: &SystemTime, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let secs = t
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    serializer.serialize_u64(secs)
}

impl NetworkSnapshot {
    pub fn empty() -> Self {
        Self {
            collected_at: SystemTime::now(),
            wifi: None,
            local_traffic: TrafficCounters::default(),
            local_rates: TrafficRates::default(),
            devices: Vec::new(),
            blocked: Vec::new(),
            mac_filter: MacFilterStatus::default(),
            router: RouterStatus::default(),
            errors: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortKey {
    Hostname,
    Ip,
    Mac,
    Usage,
    Link,
}

impl SortKey {
    pub fn next(self) -> Self {
        match self {
            SortKey::Hostname => SortKey::Ip,
            SortKey::Ip => SortKey::Mac,
            SortKey::Mac => SortKey::Usage,
            SortKey::Usage => SortKey::Link,
            SortKey::Link => SortKey::Hostname,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            SortKey::Hostname => "hostname",
            SortKey::Ip => "ip",
            SortKey::Mac => "mac",
            SortKey::Usage => "usage",
            SortKey::Link => "link",
        }
    }
}

pub fn format_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} {}", UNITS[i])
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

pub fn format_bps(bps: u64) -> String {
    // Display as bits/s for network feel when large, but keep simple B/s
    const UNITS: [&str; 5] = ["B/s", "KiB/s", "MiB/s", "GiB/s", "TiB/s"];
    let mut v = bps as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{bps} {}", UNITS[i])
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

pub fn format_duration(secs: u64) -> String {
    let d = Duration::from_secs(secs);
    let s = d.as_secs();
    let h = s / 3600;
    let m = (s % 3600) / 60;
    let sec = s % 60;
    if h > 0 {
        format!("{h}h{m:02}m")
    } else if m > 0 {
        format!("{m}m{sec:02}s")
    } else {
        format!("{sec}s")
    }
}

pub fn normalize_mac(mac: &str) -> Option<String> {
    let hex: String = mac
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    if hex.len() != 12 {
        return None;
    }
    Some(
        hex.as_bytes()
            .chunks(2)
            .map(|c| std::str::from_utf8(c).unwrap_or("00"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}
