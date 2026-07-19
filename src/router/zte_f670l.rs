use super::{RouterBackend, RouterCaps};
use crate::model::{normalize_mac, Device, DeviceSource, LinkKind};
use crate::oui;
use anyhow::{bail, Context, Result};
use reqwest::blocking::{Client, ClientBuilder};
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

/// ZTE F670L / F670LV9.0 admin web API client.
pub struct ZteF670l {
    base_url: String,
    username: String,
    password: String,
    client: Client,
    session_token: String,
    logged_in: bool,
    per_host_traffic: bool,
    last_message: String,
}

impl ZteF670l {
    pub fn new(base_url: &str, username: &str, password: &str) -> Result<Self> {
        let base = base_url.trim_end_matches('/').to_string();
        let client = ClientBuilder::new()
            .cookie_store(true)
            .timeout(Duration::from_secs(8))
            .danger_accept_invalid_certs(true) // home routers often use self-signed certs
            .user_agent("mywifistats/0.1")
            .build()
            .context("building HTTP client")?;
        Ok(Self {
            base_url: base,
            username: username.to_string(),
            password: password.to_string(),
            client,
            session_token: String::new(),
            logged_in: false,
            per_host_traffic: false,
            last_message: "not connected".into(),
        })
    }

    fn get_text(&self, path_and_query: &str) -> Result<String> {
        let url = format!("{}{}", self.base_url, path_and_query);
        let resp = self
            .client
            .get(&url)
            .send()
            .with_context(|| format!("GET {url}"))?;
        if !resp.status().is_success() {
            bail!("GET {url} -> HTTP {}", resp.status());
        }
        resp.text().context("reading response body")
    }

    fn warm_session(&mut self) -> Result<()> {
        let _ = self.get_text("/")?;
        Ok(())
    }

    fn fetch_login_token(&self) -> Result<String> {
        let body = self.get_text("/?_type=loginData&_tag=login_token")?;
        // <ajax_response_xml_root>59177285</ajax_response_xml_root>
        if let Ok(doc) = roxmltree::Document::parse(&body) {
            if let Some(text) = doc
                .descendants()
                .find(|n| n.has_tag_name("ajax_response_xml_root"))
                .and_then(|n| n.text())
            {
                return Ok(text.trim().to_string());
            }
        }
        // fallback: strip tags
        let stripped: String = body
            .chars()
            .filter(|c| c.is_ascii_digit() || c.is_ascii_alphabetic())
            .collect();
        if stripped.is_empty() {
            bail!("could not parse login token from router response");
        }
        Ok(stripped)
    }

    fn hash_password(password: &str, token: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        hasher.update(token.as_bytes());
        hex::encode(hasher.finalize())
    }

    fn do_login(&mut self) -> Result<()> {
        self.warm_session()?;
        let token = self.fetch_login_token()?;
        let hashed = Self::hash_password(&self.password, &token);

        let url = format!("{}/?_type=loginData&_tag=login_entry", self.base_url);
        let mut form = HashMap::new();
        form.insert("action", "login".to_string());
        form.insert("Username", self.username.clone());
        form.insert("Password", hashed);
        form.insert("_sessionTOKEN", self.session_token.clone());

        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );

        let resp = self
            .client
            .post(&url)
            .headers(headers)
            .form(&form)
            .send()
            .with_context(|| format!("POST login {url}"))?;

        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        if !status.is_success() {
            bail!("login HTTP {status}: {}", truncate(&body, 200));
        }

        // Response JSON: { "sess_token": "...", "login_need_refresh": true/false, ... }
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
            if let Some(t) = v.get("sess_token").and_then(|x| x.as_str()) {
                self.session_token = t.to_string();
            }
            // login errors sometimes include loginErrMsg / lockingTime without refresh
            if let Some(err) = v.get("loginErrMsg").and_then(|x| x.as_str()) {
                if !err.is_empty() {
                    bail!("router login failed: {err}");
                }
            }
            // If login_need_refresh is true, session is good
            if v.get("login_need_refresh").and_then(|x| x.as_bool()) == Some(true)
                || !self.session_token.is_empty()
            {
                self.logged_in = true;
                self.last_message = "login OK".into();
                return Ok(());
            }
            // Some firmwares return empty error on success
            if v.get("login_error").is_none() {
                self.logged_in = true;
                self.last_message = "login OK".into();
                return Ok(());
            }
        }

        // HTML redirect / empty body after set-cookie may also mean success
        if body.contains("login_need_refresh") || body.is_empty() || status.as_u16() == 200 {
            // try a protected endpoint
            match self.fetch_accessdev("ALL") {
                Ok(devs) => {
                    self.logged_in = true;
                    self.last_message = format!("login OK ({} devices)", devs.len());
                    return Ok(());
                }
                Err(e) => {
                    bail!(
                        "login response unclear and device fetch failed: {e}; body={}",
                        truncate(&body, 180)
                    );
                }
            }
        }

        bail!("login failed: {}", truncate(&body, 200));
    }

    fn fetch_accessdev(&self, device_type: &str) -> Result<Vec<Device>> {
        // Note firmware typo: DeveiceType
        let path = format!(
            "/?_type=hiddenData&_tag=accessdev_data&DeveiceType={device_type}"
        );
        let body = self.get_text(&path)?;
        parse_accessdev_xml(&body, device_type)
    }

    /// Probe optional traffic-related tags (best-effort; firmware-dependent).
    fn probe_traffic_capability(&mut self) {
        // Common-ish ZTE tags — if any return host byte fields we flip the flag.
        let probes = [
            "/?_type=hiddenData&_tag=wlan_client_stat",
            "/?_type=hiddenData&_tag=lan_host_stat",
            "/?_type=hiddenData&_tag=eth_device_stat",
            "/?_type=menuData&_tag=wlan_status_data",
        ];
        for p in probes {
            if let Ok(body) = self.get_text(p) {
                let lower = body.to_ascii_lowercase();
                if lower.contains("bytessent")
                    || lower.contains("bytesreceived")
                    || lower.contains("rxbytes")
                    || lower.contains("txbytes")
                    || lower.contains("totalbytes")
                {
                    self.per_host_traffic = true;
                    self.last_message =
                        format!("login OK; per-host traffic via {}", p.split('=').last().unwrap_or("?"));
                    return;
                }
            }
        }
        self.per_host_traffic = false;
        if self.logged_in {
            self.last_message =
                "login OK; devices yes, per-host traffic not exposed by this firmware".into();
        }
    }
}

impl RouterBackend for ZteF670l {
    fn name(&self) -> &str {
        "ZTE F670L"
    }

    fn login(&mut self) -> Result<()> {
        self.do_login()?;
        self.probe_traffic_capability();
        Ok(())
    }

    fn list_devices(&mut self) -> Result<Vec<Device>> {
        if !self.logged_in {
            self.login()?;
        }
        // Prefer separate WLAN + ETH so link kind is accurate; fall back to ALL.
        let mut devices = Vec::new();
        match (
            self.fetch_accessdev("WLAN"),
            self.fetch_accessdev("ETH"),
        ) {
            (Ok(mut w), Ok(mut e)) => {
                for d in &mut w {
                    d.link = LinkKind::Wifi;
                }
                for d in &mut e {
                    d.link = LinkKind::Ethernet;
                }
                devices.append(&mut w);
                devices.append(&mut e);
            }
            _ => {
                devices = self.fetch_accessdev("ALL").context("accessdev ALL")?;
            }
        }

        // If empty after "logged in", session may have expired — re-login once.
        if devices.is_empty() {
            self.logged_in = false;
            self.do_login()?;
            devices = self.fetch_accessdev("ALL").unwrap_or_default();
        }

        Ok(devices)
    }

    fn capabilities(&self) -> RouterCaps {
        RouterCaps {
            per_host_traffic: self.per_host_traffic,
            message: self.last_message.clone(),
        }
    }

    fn is_logged_in(&self) -> bool {
        self.logged_in
    }
}

fn parse_accessdev_xml(body: &str, device_type: &str) -> Result<Vec<Device>> {
    // Responses are XML-ish with Instance blocks under OBJ_ACCESSDEV_ID.
    // Field names appear as child elements or ParaName/ParaValue pairs depending on firmware.
    if body.trim().is_empty() {
        return Ok(Vec::new());
    }

    // If HTML login page came back, treat as auth failure
    if body.contains("Frm_Password") || body.contains("loginData") && body.contains("<html") {
        bail!("session expired or not authenticated");
    }

    let mut devices = Vec::new();

    // Strategy 1: roxmltree structured parse
    if let Ok(doc) = roxmltree::Document::parse(body) {
        // Find Instance nodes
        for inst in doc.descendants().filter(|n| n.has_tag_name("Instance")) {
            if let Some(dev) = device_from_instance(inst, device_type) {
                devices.push(dev);
            }
        }
        if !devices.is_empty() {
            return Ok(devices);
        }

        // Some firmwares put fields as sibling elements with names HostName etc.
        // Group by walking OBJ_ACCESSDEV_ID children
        for obj in doc
            .descendants()
            .filter(|n| n.tag_name().name().contains("ACCESSDEV"))
        {
            for child in obj.children().filter(|n| n.is_element()) {
                if child.has_tag_name("Instance") {
                    if let Some(dev) = device_from_instance(child, device_type) {
                        devices.push(dev);
                    }
                }
            }
        }
        if !devices.is_empty() {
            return Ok(devices);
        }
    }

    // Strategy 2: regex-ish line scrape for HostName / IPAddress / MACAddress blocks
    devices = scrape_devices_loose(body, device_type);
    Ok(devices)
}

fn device_from_instance(inst: roxmltree::Node<'_, '_>, device_type: &str) -> Option<Device> {
    let mut map: HashMap<String, String> = HashMap::new();

    for n in inst.descendants().filter(|n| n.is_element()) {
        let name = n.tag_name().name().to_string();
        if let Some(text) = n.text().map(str::trim).filter(|s| !s.is_empty()) {
            // ParaName / ParaValue pattern
            if name.eq_ignore_ascii_case("ParaName") {
                if let Some(val_node) = n.next_sibling_element() {
                    if val_node.tag_name().name().eq_ignore_ascii_case("ParaValue") {
                        if let Some(v) = val_node.text().map(str::trim) {
                            map.insert(text.to_string(), v.to_string());
                        }
                    }
                }
            } else if !name.eq_ignore_ascii_case("Instance")
                && !name.eq_ignore_ascii_case("ParaValue")
            {
                map.entry(name).or_insert_with(|| text.to_string());
            }
        }
        // Also attributes
        for attr in n.attributes() {
            map.entry(attr.name().to_string())
                .or_insert_with(|| attr.value().to_string());
        }
    }

    // Children as Name=Value via ID pattern used by some ZTE pages
    // Look for known keys case-insensitively
    let get = |keys: &[&str]| -> Option<String> {
        for (k, v) in &map {
            for want in keys {
                if k.eq_ignore_ascii_case(want) {
                    return Some(v.clone());
                }
            }
        }
        None
    };

    let hostname = get(&["HostName", "Hostname", "hostName"]);
    let ip_s = get(&["IPAddress", "IpAddress", "IP", "ipAddress"]);
    let mac_s = get(&["MACAddress", "MacAddress", "MAC", "macAddress"]);

    if hostname.is_none() && ip_s.is_none() && mac_s.is_none() {
        return None;
    }

    let mac = mac_s.as_deref().and_then(normalize_mac);
    let ip = ip_s.and_then(|s| s.parse::<IpAddr>().ok());
    let vendor = mac.as_deref().and_then(oui::lookup_vendor).map(str::to_string);
    let link = match device_type {
        "WLAN" => LinkKind::Wifi,
        "ETH" => LinkKind::Ethernet,
        _ => LinkKind::Unknown,
    };

    let bytes_rx = get(&["BytesReceived", "RxBytes", "rx_bytes", "TotalBytesReceived"])
        .and_then(|s| s.parse().ok());
    let bytes_tx = get(&["BytesSent", "TxBytes", "tx_bytes", "TotalBytesSent"])
        .and_then(|s| s.parse().ok());

    Some(Device {
        hostname: hostname.filter(|h| !h.is_empty() && h != "Unknown"),
        ip,
        mac,
        vendor,
        link,
        online: true,
        is_self: false,
        is_gateway: false,
        bytes_rx,
        bytes_tx,
        rate_rx_bps: None,
        rate_tx_bps: None,
        source: DeviceSource::Router,
    })
}

fn scrape_devices_loose(body: &str, device_type: &str) -> Vec<Device> {
    // Split on Instance boundaries if present
    let chunks: Vec<&str> = if body.contains("Instance") {
        body.split("Instance").collect()
    } else {
        vec![body]
    };

    let mut out = Vec::new();
    for chunk in chunks {
        let hostname = extract_tagish(chunk, &["HostName", "Hostname"]);
        let ip = extract_tagish(chunk, &["IPAddress", "IpAddress"]);
        let mac = extract_tagish(chunk, &["MACAddress", "MacAddress", "MAC"]);
        if hostname.is_none() && ip.is_none() && mac.is_none() {
            continue;
        }
        let mac_n = mac.as_deref().and_then(normalize_mac);
        let vendor = mac_n
            .as_deref()
            .and_then(oui::lookup_vendor)
            .map(str::to_string);
        let link = match device_type {
            "WLAN" => LinkKind::Wifi,
            "ETH" => LinkKind::Ethernet,
            _ => LinkKind::Unknown,
        };
        out.push(Device {
            hostname: hostname.filter(|h| !h.is_empty()),
            ip: ip.and_then(|s| s.parse().ok()),
            mac: mac_n,
            vendor,
            link,
            online: true,
            is_self: false,
            is_gateway: false,
            bytes_rx: None,
            bytes_tx: None,
            rate_rx_bps: None,
            rate_tx_bps: None,
            source: DeviceSource::Router,
        });
    }
    out
}

fn extract_tagish(chunk: &str, names: &[&str]) -> Option<String> {
    for name in names {
        // <HostName>foo</HostName> or <ParaName>HostName</ParaName><ParaValue>foo</ParaValue>
        let open = format!("<{name}>");
        let close = format!("</{name}>");
        if let Some(i) = chunk.find(&open) {
            let rest = &chunk[i + open.len()..];
            if let Some(j) = rest.find(&close) {
                let v = rest[..j].trim();
                if !v.is_empty() {
                    return Some(v.to_string());
                }
            }
        }
        let pn = format!(">{name}<");
        if let Some(i) = chunk.find(&pn) {
            let rest = &chunk[i..];
            if let Some(pv) = rest.find("<ParaValue>") {
                let rest2 = &rest[pv + "<ParaValue>".len()..];
                if let Some(j) = rest2.find("</ParaValue>") {
                    let v = rest2[..j].trim();
                    if !v.is_empty() {
                        return Some(v.to_string());
                    }
                }
            }
        }
    }
    None
}

fn truncate(s: &str, n: usize) -> String {
    let t: String = s.chars().take(n).collect();
    if s.chars().count() > n {
        format!("{t}…")
    } else {
        t
    }
}
