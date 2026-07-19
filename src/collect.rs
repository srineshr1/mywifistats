use crate::config::Config;
use crate::lan;
use crate::model::{
    normalize_mac, Device, DeviceSource, LinkKind, NetworkSnapshot, RouterStatus, SortKey,
};
use crate::rate::RateTracker;
use crate::router::zte_f670l::ZteF670l;
use crate::router::RouterBackend;
use crate::wifi;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::SystemTime;

pub struct Collector {
    iface: String,
    config: Config,
    rates: RateTracker,
    router: Option<Box<dyn RouterBackend>>,
    router_init_attempted: bool,
    no_router: bool,
}

impl Collector {
    pub fn new(config: Config, iface_override: Option<String>, no_router: bool) -> Result<Self> {
        let preferred = iface_override
            .as_deref()
            .or(config.interface.as_deref());
        let iface = wifi::detect_interface(preferred)?;
        Ok(Self {
            iface,
            config,
            rates: RateTracker::new(),
            router: None,
            router_init_attempted: false,
            no_router,
        })
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Apply a new config (e.g. after setup TUI) and reset the router session.
    pub fn reconfigure(&mut self, config: Config) -> Result<()> {
        let preferred = config.interface.as_deref();
        self.iface = wifi::detect_interface(preferred)?;
        self.config = config;
        self.router = None;
        self.router_init_attempted = false;
        Ok(())
    }

    fn ensure_router(&mut self) {
        if self.no_router || !self.config.router.enabled {
            return;
        }
        if self.router.is_some() || self.router_init_attempted {
            return;
        }
        self.router_init_attempted = true;

        let Some(password) = self.config.router_password() else {
            return;
        };

        match self.config.router.backend.as_str() {
            "zte_f670l" | "zte" | "" => {
                match ZteF670l::new(
                    &self.config.router.base_url,
                    &self.config.router.username,
                    &password,
                ) {
                    Ok(mut z) => match z.login() {
                        Ok(()) => {
                            self.router = Some(Box::new(z));
                        }
                        Err(_) => {
                            // Keep for retry message via temporary status
                            self.router = Some(Box::new(z));
                        }
                    },
                    Err(_) => {}
                }
            }
            other => {
                let _ = other;
            }
        }
    }

    pub fn collect(&mut self) -> NetworkSnapshot {
        let mut snap = NetworkSnapshot::empty();
        snap.collected_at = SystemTime::now();

        match wifi::collect_wifi(&self.iface) {
            Ok(w) => snap.wifi = Some(w),
            Err(e) => snap.errors.push(format!("wifi: {e}")),
        }

        match wifi::read_traffic(&self.iface) {
            Ok(t) => {
                snap.local_rates = self.rates.update_local(&t);
                snap.local_traffic = t;
            }
            Err(e) => snap.errors.push(format!("traffic: {e}")),
        }

        let gateway = snap.wifi.as_ref().and_then(|w| w.gateway);
        let self_ip = snap.wifi.as_ref().and_then(|w| w.ip);
        let self_mac = wifi::local_mac(&self.iface).and_then(|m| normalize_mac(&m));

        let mut lan_devices = match lan::discover_neighbors(&self.iface, gateway, self_ip) {
            Ok(d) => d,
            Err(e) => {
                snap.errors.push(format!("lan: {e}"));
                Vec::new()
            }
        };

        // Attach local traffic to self device
        for d in &mut lan_devices {
            if d.is_self {
                d.bytes_rx = Some(snap.local_traffic.rx_bytes);
                d.bytes_tx = Some(snap.local_traffic.tx_bytes);
                d.rate_rx_bps = Some(snap.local_rates.rx_bps);
                d.rate_tx_bps = Some(snap.local_rates.tx_bps);
                d.link = LinkKind::Wifi;
            }
        }

        self.ensure_router();

        let mut router_devices = Vec::new();
        let mut router_status = RouterStatus {
            enabled: self.config.router.enabled && !self.no_router,
            name: Some("ZTE F670L".into()),
            connected: false,
            device_count: 0,
            per_host_traffic: false,
            can_block: false,
            message: if self.no_router {
                "disabled (--no-router)".into()
            } else if !self.config.router.enabled {
                "disabled in config".into()
            } else if self.config.router_password().is_none() {
                "no password (set MYWIFISTATS_ROUTER_PASSWORD or config)".into()
            } else {
                "connecting…".into()
            },
        };

        if let Some(r) = self.router.as_mut() {
            router_status.name = Some(r.name().to_string());
            if !r.is_logged_in() {
                match r.login() {
                    Ok(()) => {}
                    Err(e) => {
                        router_status.message = format!("login failed: {e}");
                        snap.errors.push(format!("router login: {e}"));
                    }
                }
            }
            if r.is_logged_in() {
                match r.list_devices() {
                    Ok(devs) => {
                        router_devices = devs;
                        let caps = r.capabilities();
                        router_status.connected = true;
                        router_status.device_count = router_devices.len();
                        router_status.per_host_traffic = caps.per_host_traffic;
                        router_status.can_block = caps.can_block;
                        router_status.message = caps.message;
                    }
                    Err(e) => {
                        router_status.message = format!("device list failed: {e}");
                        snap.errors.push(format!("router devices: {e}"));
                    }
                }
                match r.list_blocked() {
                    Ok(blocked) => {
                        let n = blocked.len();
                        snap.blocked = blocked;
                        router_status.can_block = true;
                        router_status.message = format!(
                            "login OK · {} client(s) · {} blocked · rates: this PC only",
                            router_status.device_count, n
                        );
                    }
                    Err(e) => {
                        snap.errors.push(format!("blocked list: {e}"));
                    }
                }
                match r.mac_filter_status() {
                    Ok(st) => {
                        router_status.can_block = st.can_block || router_status.can_block;
                        snap.mac_filter = st;
                    }
                    Err(_) => {
                        // Infer from blocked list if global status fails
                        if !snap.blocked.is_empty() {
                            snap.mac_filter.enabled = true;
                            snap.mac_filter.mode = "Discard".into();
                            snap.mac_filter.can_block = true;
                            router_status.can_block = true;
                        }
                    }
                }
            } else {
                let caps = r.capabilities();
                if router_status.message.starts_with("connecting") {
                    router_status.message = caps.message;
                }
            }
        }

        snap.devices = merge_devices(lan_devices, router_devices, gateway, self_mac.as_deref());

        // Mark blocked from MAC filter list
        let blocked_macs: std::collections::HashSet<String> =
            snap.blocked.iter().map(|b| b.mac.clone()).collect();
        for d in &mut snap.devices {
            if let Some(m) = &d.mac {
                if blocked_macs.contains(m) {
                    d.blocked = true;
                }
            }
        }

        // Rate sample for devices with counters
        for d in &mut snap.devices {
            if let Some(mac) = &d.mac {
                let (rx_r, tx_r) = self.rates.update_device(mac, d.bytes_rx, d.bytes_tx);
                if d.rate_rx_bps.is_none() {
                    d.rate_rx_bps = rx_r;
                }
                if d.rate_tx_bps.is_none() {
                    d.rate_tx_bps = tx_r;
                }
            }
        }

        snap.router = router_status;
        sort_devices(&mut snap.devices, SortKey::Hostname);
        snap
    }

    /// Block selected device by MAC via router. Returns status message.
    pub fn block_device(&mut self, mac: &str, name: &str) -> Result<String> {
        self.ensure_router();
        let Some(r) = self.router.as_mut() else {
            anyhow::bail!("router not available — configure password in setup");
        };
        if !r.is_logged_in() {
            r.login()?;
        }
        r.block_device(mac, name)?;
        Ok(format!("Blocked {name} ({mac}) on router firewall"))
    }

    /// Unblock by router instance id.
    pub fn unblock_device(&mut self, inst_id: &str) -> Result<String> {
        self.ensure_router();
        let Some(r) = self.router.as_mut() else {
            anyhow::bail!("router not available — configure password in setup");
        };
        if !r.is_logged_in() {
            r.login()?;
        }
        r.unblock_device(inst_id)?;
        Ok(format!("Unblocked rule {inst_id}"))
    }

    /// Unblock by MAC (looks up inst id).
    pub fn unblock_mac(&mut self, mac: &str) -> Result<String> {
        let mac = normalize_mac(mac).context("invalid MAC")?;
        self.ensure_router();
        let Some(r) = self.router.as_mut() else {
            anyhow::bail!("router not available");
        };
        if !r.is_logged_in() {
            r.login()?;
        }
        let list = r.list_blocked()?;
        let rule = list
            .into_iter()
            .find(|b| b.mac == mac)
            .with_context(|| format!("no block rule for {mac}"))?;
        r.unblock_device(&rule.inst_id)?;
        Ok(format!("Unblocked {} ({})", rule.name, mac))
    }

    pub fn doctor_report(&mut self) -> String {
        let snap = self.collect();
        let mut lines = Vec::new();
        lines.push(format!("Interface: {} ", self.iface));
        if let Some(w) = &snap.wifi {
            lines.push(format!(
                "  SSID: {}",
                w.ssid.as_deref().unwrap_or("(not associated)")
            ));
            lines.push(format!(
                "  BSSID: {}",
                w.bssid.as_deref().unwrap_or("-")
            ));
            lines.push(format!(
                "  Signal: {}  Channel: {}  Width: {} MHz  Freq: {} MHz",
                w.signal_dbm
                    .map(|s| format!("{s} dBm"))
                    .unwrap_or_else(|| "-".into()),
                w.channel
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "-".into()),
                w.channel_width_mhz
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "-".into()),
                w.freq_mhz
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "-".into()),
            ));
            lines.push(format!(
                "  Bitrate RX/TX: {} / {} MBit/s",
                w.rx_bitrate_mbps
                    .map(|b| format!("{b:.0}"))
                    .unwrap_or_else(|| "-".into()),
                w.tx_bitrate_mbps
                    .map(|b| format!("{b:.0}"))
                    .unwrap_or_else(|| "-".into()),
            ));
            lines.push(format!(
                "  IP: {}  Gateway: {}",
                w.ip
                    .map(|i| i.to_string())
                    .unwrap_or_else(|| "-".into()),
                w.gateway
                    .map(|i| i.to_string())
                    .unwrap_or_else(|| "-".into()),
            ));
            if let Some(secs) = w.connected_secs {
                lines.push(format!(
                    "  Connected: {}",
                    crate::model::format_duration(secs)
                ));
            }
        } else {
            lines.push("  (no wifi link info)".into());
        }

        lines.push(format!(
            "Local traffic: ↓ {}  ↑ {}",
            crate::model::format_bytes(snap.local_traffic.rx_bytes),
            crate::model::format_bytes(snap.local_traffic.tx_bytes),
        ));
        lines.push(format!(
            "Devices discovered: {} (LAN+router merge)",
            snap.devices.len()
        ));
        lines.push(format!(
            "Router: enabled={}  connected={}  name={}  per-host-traffic={}  can-block={}",
            snap.router.enabled,
            snap.router.connected,
            snap.router.name.as_deref().unwrap_or("-"),
            snap.router.per_host_traffic,
            snap.router.can_block,
        ));
        lines.push(format!("  {}", snap.router.message));
        lines.push(format!(
            "MAC filter: enabled={}  mode={}  blocked={}",
            snap.mac_filter.enabled,
            snap.mac_filter.mode,
            snap.blocked.len()
        ));
        for b in &snap.blocked {
            lines.push(format!("  - {}  {}  ({})", b.name, b.mac, b.inst_id));
        }
        lines.push(
            "Note: per-device data rates are only available for this PC; the ZTE firmware does not expose other clients' traffic counters."
                .into(),
        );
        if !snap.errors.is_empty() {
            lines.push("Errors:".into());
            for e in &snap.errors {
                lines.push(format!("  - {e}"));
            }
        }
        lines.push(format!(
            "Config: {}",
            crate::config::Config::config_path().display()
        ));
        if self.config.needs_setup_hint() {
            lines.push(
                "Hint: run `mywifistats setup` or press c in the TUI to add router password.".into(),
            );
        }
        lines.join("\n")
    }
}

fn merge_devices(
    lan: Vec<Device>,
    router: Vec<Device>,
    gateway: Option<IpAddr>,
    self_mac: Option<&str>,
) -> Vec<Device> {
    // Key by MAC when possible, else IP
    let mut map: HashMap<String, Device> = HashMap::new();

    let key_of = |d: &Device| -> String {
        if let Some(m) = &d.mac {
            format!("mac:{m}")
        } else if let Some(ip) = d.ip {
            format!("ip:{ip}")
        } else {
            format!("host:{}", d.hostname.as_deref().unwrap_or("?"))
        }
    };

    for d in lan {
        map.insert(key_of(&d), d);
    }

    for r in router {
        let k = key_of(&r);
        if let Some(existing) = map.get_mut(&k) {
            // Prefer router hostname / link type
            if r.hostname.is_some() {
                existing.hostname = r.hostname;
            }
            if existing.ip.is_none() {
                existing.ip = r.ip;
            }
            if existing.mac.is_none() {
                existing.mac = r.mac;
            }
            if r.link != LinkKind::Unknown {
                existing.link = r.link;
            }
            existing.online = existing.online || r.online;
            if r.bytes_rx.is_some() {
                existing.bytes_rx = r.bytes_rx;
            }
            if r.bytes_tx.is_some() {
                existing.bytes_tx = r.bytes_tx;
            }
            if existing.vendor.is_none() {
                existing.vendor = r.vendor;
            }
            existing.blocked = existing.blocked || r.blocked;
            existing.source = DeviceSource::Merged;
        } else {
            map.insert(k, r);
        }
    }

    let mut out: Vec<Device> = map.into_values().collect();
    for d in &mut out {
        if let (Some(sm), Some(m)) = (self_mac, d.mac.as_deref()) {
            if sm == m {
                d.is_self = true;
            }
        }
        if let Some(gw) = gateway {
            if d.ip == Some(gw) {
                d.is_gateway = true;
                if d.hostname.is_none() {
                    d.hostname = Some("gateway".into());
                }
            }
        }
    }
    out
}

pub fn sort_devices(devices: &mut [Device], key: SortKey) {
    devices.sort_by(|a, b| {
        // Self first, then gateway, then rest
        b.is_self
            .cmp(&a.is_self)
            .then(b.is_gateway.cmp(&a.is_gateway))
            .then(match key {
                SortKey::Hostname => a
                    .hostname
                    .as_deref()
                    .unwrap_or("~")
                    .cmp(b.hostname.as_deref().unwrap_or("~")),
                SortKey::Ip => a
                    .ip
                    .map(|i| i.to_string())
                    .unwrap_or_default()
                    .cmp(&b.ip.map(|i| i.to_string()).unwrap_or_default()),
                SortKey::Mac => a
                    .mac
                    .as_deref()
                    .unwrap_or("")
                    .cmp(b.mac.as_deref().unwrap_or("")),
                SortKey::Usage => {
                    let au = a.bytes_rx.unwrap_or(0) + a.bytes_tx.unwrap_or(0);
                    let bu = b.bytes_rx.unwrap_or(0) + b.bytes_tx.unwrap_or(0);
                    bu.cmp(&au)
                }
                SortKey::Link => a.link.as_str().cmp(b.link.as_str()),
            })
    });
}
