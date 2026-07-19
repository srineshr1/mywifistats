use super::{RouterBackend, RouterCaps};
use crate::model::{normalize_mac, Device, DeviceSource, LinkKind};
use crate::oui;
use anyhow::{bail, Context, Result};
use reqwest::blocking::{Client, ClientBuilder};
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE, REFERER};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

/// ZTE F670L / F670LV9.0 admin web API client.
///
/// Verified against F670LV9.0 (V9.0.11P1N40):
/// - Login: SHA-256(password + login_token), with page `_sessionTOKEN`
/// - Devices: `/?_type=menuData&_tag=wlan_homepage_lua.lua`
///   (fields HostName / IPAddress / MACAddress)
/// - Also works: `/?_type=hiddenData&_tag=accessdev_data&DeveiceType=ALL`
///   (fields `_LuQUID_HostName` / `_LuQUID_IPAddress` / `_LuQUID_MACAddress`)
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
            .timeout(Duration::from_secs(10))
            .danger_accept_invalid_certs(true)
            .user_agent(
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 \
                 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            )
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
            .header(REFERER, format!("{}/", self.base_url))
            .header("X-Requested-With", "XMLHttpRequest")
            .send()
            .with_context(|| format!("GET {url}"))?;
        if !resp.status().is_success() {
            bail!("GET {url} -> HTTP {}", resp.status());
        }
        resp.text().context("reading response body")
    }

    /// GET homepage; extract hidden `_sessionTOKEN` if present.
    fn warm_session(&mut self) -> Result<()> {
        let body = self.get_text("/")?;
        if let Some(tok) = extract_session_token_from_html(&body) {
            self.session_token = tok;
        }
        Ok(())
    }

    fn fetch_login_token(&self) -> Result<String> {
        let body = self.get_text("/?_type=loginData&_tag=login_token")?;
        if let Ok(doc) = roxmltree::Document::parse(&body) {
            if let Some(text) = doc
                .descendants()
                .find(|n| n.has_tag_name("ajax_response_xml_root"))
                .and_then(|n| n.text())
            {
                let t = text.trim();
                if !t.is_empty() {
                    return Ok(t.to_string());
                }
            }
        }
        // Fallback: first tag contents
        if let Some(start) = body.find('>') {
            if let Some(end) = body[start + 1..].find('<') {
                let t = body[start + 1..start + 1 + end].trim();
                if !t.is_empty() {
                    return Ok(t.to_string());
                }
            }
        }
        bail!("could not parse login token from router response");
    }

    fn hash_password(password: &str, token: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        hasher.update(token.as_bytes());
        hex::encode(hasher.finalize())
    }

    fn do_login(&mut self) -> Result<()> {
        self.logged_in = false;
        self.warm_session()?;
        let token = self.fetch_login_token()?;
        let hashed = Self::hash_password(&self.password, &token);

        let url = format!("{}/?_type=loginData&_tag=login_entry", self.base_url);
        let mut form = HashMap::new();
        form.insert("action", "login".to_string());
        form.insert("Username", self.username.clone());
        form.insert("Password", hashed);
        // Must send page session token (may be empty on some firmwares)
        form.insert("_sessionTOKEN", self.session_token.clone());

        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded; charset=UTF-8"),
        );
        headers.insert(
            REFERER,
            HeaderValue::from_str(&format!("{}/", self.base_url)).unwrap_or(HeaderValue::from_static("*")),
        );
        headers.insert(
            "X-Requested-With",
            HeaderValue::from_static("XMLHttpRequest"),
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

        let v: serde_json::Value = serde_json::from_str(&body)
            .with_context(|| format!("login response not JSON: {}", truncate(&body, 180)))?;

        if let Some(t) = v.get("sess_token").and_then(|x| x.as_str()) {
            self.session_token = t.to_string();
        }

        // Failed login always includes a message — even when sess_token is present.
        if let Some(err) = v.get("loginErrMsg").and_then(|x| x.as_str()) {
            if !err.trim().is_empty() {
                self.last_message = format!("login failed: {err}");
                bail!("{}", self.last_message);
            }
        }

        // Lockout after too many failures
        if let Some(lock) = v.get("lockingTime").and_then(|x| x.as_i64()) {
            if lock > 0 {
                let prompt = v
                    .get("promptMsg")
                    .and_then(|x| x.as_str())
                    .unwrap_or("locked out");
                self.last_message = format!("login locked ({lock}s): {prompt}");
                bail!("{}", self.last_message);
            }
        }

        let refreshed = v
            .get("login_need_refresh")
            .and_then(|x| x.as_bool())
            .unwrap_or(false);

        if !refreshed {
            // Some firmwares omit the flag but return empty error + sess_token.
            // Only accept if we can load the homepage as authenticated.
        }

        // Critical: reload homepage so the SID session is fully established
        // (matches browser `top.location.href = top.location.href`).
        let home = self.get_text("/")?;
        let authenticated = home.contains("Logout") || !home.contains("Frm_Password");
        if !authenticated && !refreshed {
            self.last_message = "login response unclear (still on login page)".into();
            bail!("{}", self.last_message);
        }

        if let Some(tok) = extract_session_token_from_html(&home) {
            self.session_token = tok;
        }

        self.logged_in = true;
        self.last_message = "login OK".into();
        Ok(())
    }

    fn fetch_devices_xml(&self) -> Result<(String, LinkKind)> {
        // Preferred: homepage WLAN device list (verified on F670LV9.0)
        let paths = [
            (
                "/?_type=menuData&_tag=wlan_homepage_lua.lua",
                LinkKind::Wifi,
            ),
            (
                "/?_type=menuData&_tag=wlan_homepage_lua.lua&InstNum=5",
                LinkKind::Wifi,
            ),
            (
                "/?_type=hiddenData&_tag=accessdev_data&DeveiceType=ALL",
                LinkKind::Unknown,
            ),
            (
                "/?_type=hiddenData&_tag=accessdev_data&DeveiceType=WLAN",
                LinkKind::Wifi,
            ),
            (
                "/?_type=hiddenData&_tag=accessdev_data&DeveiceType=ETH",
                LinkKind::Ethernet,
            ),
        ];

        let mut last_err = None;
        for (path, kind) in paths {
            match self.get_text(path) {
                Ok(body) => {
                    if body.contains("SessionTimeout") {
                        last_err = Some(anyhow::anyhow!("session timeout on {path}"));
                        continue;
                    }
                    if body.contains("OBJ_ACCESSDEV") || body.contains("HostName") {
                        return Ok((body, kind));
                    }
                    last_err = Some(anyhow::anyhow!(
                        "unexpected device payload on {path}: {}",
                        truncate(&body, 120)
                    ));
                }
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no device endpoint worked")))
    }

    fn probe_traffic_capability(&mut self) {
        let probes = [
            "/?_type=menuData&_tag=wlan_homepage_lua.lua",
            "/?_type=hiddenData&_tag=wlan_client_stat",
            "/?_type=menuData&_tag=wlan_client_stat",
        ];
        for p in probes {
            if let Ok(body) = self.get_text(p) {
                let lower = body.to_ascii_lowercase();
                if lower.contains("bytessent")
                    || lower.contains("bytesreceived")
                    || lower.contains("rxbytes")
                    || lower.contains("txbytes")
                {
                    self.per_host_traffic = true;
                    self.last_message = "login OK; per-host traffic available".into();
                    return;
                }
            }
        }
        self.per_host_traffic = false;
        if self.logged_in {
            self.last_message =
                "login OK; device list available (no per-host traffic on this firmware)".into();
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

        let (body, default_link) = match self.fetch_devices_xml() {
            Ok(v) => v,
            Err(e) => {
                // Session may have expired — re-login once
                self.logged_in = false;
                self.do_login()?;
                self.fetch_devices_xml()
                    .map_err(|e2| anyhow::anyhow!("device list failed after re-login: {e2} (was: {e})"))?
            }
        };

        let mut devices = parse_accessdev_xml(&body, default_link)?;
        if devices.is_empty() && body.contains("SessionTimeout") {
            self.logged_in = false;
            bail!("session timed out fetching devices");
        }

        // Annotate
        for d in &mut devices {
            d.source = DeviceSource::Router;
            if d.link == LinkKind::Unknown {
                d.link = default_link;
            }
        }

        self.last_message = format!(
            "login OK · {} client(s){}",
            devices.len(),
            if self.per_host_traffic {
                " · per-host traffic"
            } else {
                " · list only"
            }
        );

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

fn extract_session_token_from_html(html: &str) -> Option<String> {
    // id="_sessionTOKEN" ... value="..."
    for pat in [
        r#"id="_sessionTOKEN""#,
        r#"name="_sessionTOKEN""#,
        r#"id='_sessionTOKEN'"#,
    ] {
        if let Some(i) = html.find(pat) {
            let slice = &html[i..html.len().min(i + 200)];
            if let Some(v) = slice.find("value=\"") {
                let rest = &slice[v + 7..];
                if let Some(end) = rest.find('"') {
                    return Some(rest[..end].to_string());
                }
            }
            if let Some(v) = slice.find("value='") {
                let rest = &slice[v + 7..];
                if let Some(end) = rest.find('\'') {
                    return Some(rest[..end].to_string());
                }
            }
        }
    }
    None
}

fn parse_accessdev_xml(body: &str, default_link: LinkKind) -> Result<Vec<Device>> {
    if body.trim().is_empty() {
        return Ok(Vec::new());
    }
    if body.contains("Frm_Password") && body.contains("<html") {
        bail!("session expired or not authenticated");
    }
    if body.contains("SessionTimeout") {
        bail!("session timeout");
    }

    let mut devices = Vec::new();

    if let Ok(doc) = roxmltree::Document::parse(body) {
        for inst in doc.descendants().filter(|n| n.has_tag_name("Instance")) {
            if let Some(dev) = device_from_instance(inst, default_link) {
                devices.push(dev);
            }
        }
    }

    if devices.is_empty() {
        devices = scrape_devices_loose(body, default_link);
    }

    Ok(devices)
}

fn device_from_instance(inst: roxmltree::Node<'_, '_>, default_link: LinkKind) -> Option<Device> {
    let mut map: HashMap<String, String> = HashMap::new();

    // Walk children in order — ParaName immediately followed by ParaValue
    let children: Vec<_> = inst.children().filter(|n| n.is_element()).collect();
    let mut i = 0;
    while i < children.len() {
        let n = children[i];
        let name = n.tag_name().name();
        if name.eq_ignore_ascii_case("ParaName") {
            let key = n.text().map(str::trim).unwrap_or("").to_string();
            if i + 1 < children.len() {
                let v = children[i + 1];
                if v.tag_name().name().eq_ignore_ascii_case("ParaValue") {
                    let val = v.text().map(str::trim).unwrap_or("").to_string();
                    if !key.is_empty() {
                        map.insert(key, val);
                    }
                    i += 2;
                    continue;
                }
            }
        } else if let Some(text) = n.text().map(str::trim).filter(|s| !s.is_empty()) {
            map.entry(name.to_string()).or_insert_with(|| text.to_string());
        }
        i += 1;
    }

    // Also scan descendants for nested layouts
    for n in inst.descendants().filter(|n| n.is_element()) {
        let name = n.tag_name().name();
        if name.eq_ignore_ascii_case("ParaName") {
            let key = n.text().map(str::trim).unwrap_or("");
            if let Some(sib) = n.next_sibling_element() {
                if sib.tag_name().name().eq_ignore_ascii_case("ParaValue") {
                    if let Some(v) = sib.text().map(str::trim) {
                        if !key.is_empty() {
                            map.entry(key.to_string()).or_insert_with(|| v.to_string());
                        }
                    }
                }
            }
        }
    }

    let get = |suffixes: &[&str]| -> Option<String> {
        for (k, v) in &map {
            for s in suffixes {
                if k.eq_ignore_ascii_case(s)
                    || k.ends_with(s)
                    || k.to_ascii_lowercase().ends_with(&s.to_ascii_lowercase())
                {
                    if !v.is_empty() {
                        return Some(v.clone());
                    }
                }
            }
        }
        None
    };

    let hostname = get(&[
        "HostName",
        "Hostname",
        "hostName",
        "_LuQUID_HostName",
    ]);
    let ip_s = get(&[
        "IPAddress",
        "IpAddress",
        "IP",
        "_LuQUID_IPAddress",
        "IPv4Address",
    ]);
    let mac_s = get(&[
        "MACAddress",
        "MacAddress",
        "MAC",
        "_LuQUID_MACAddress",
    ]);

    if hostname.is_none() && ip_s.is_none() && mac_s.is_none() {
        return None;
    }

    let mac = mac_s.as_deref().and_then(normalize_mac);
    let ip = ip_s.and_then(|s| s.parse::<IpAddr>().ok());
    let vendor = mac
        .as_deref()
        .and_then(oui::lookup_vendor)
        .map(str::to_string);

    let bytes_rx = get(&[
        "BytesReceived",
        "RxBytes",
        "rx_bytes",
        "TotalBytesReceived",
    ])
    .and_then(|s| s.parse().ok());
    let bytes_tx = get(&["BytesSent", "TxBytes", "tx_bytes", "TotalBytesSent"])
        .and_then(|s| s.parse().ok());

    Some(Device {
        hostname: hostname.filter(|h| !h.is_empty() && h != "Unknown"),
        ip,
        mac,
        vendor,
        link: default_link,
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

fn scrape_devices_loose(body: &str, default_link: LinkKind) -> Vec<Device> {
    // Split on Instance boundaries
    let chunks: Vec<&str> = if body.contains("<Instance>") {
        body.split("<Instance>").skip(1).collect()
    } else if body.contains("Instance") {
        body.split("Instance").collect()
    } else {
        vec![body]
    };

    let mut out = Vec::new();
    for chunk in chunks {
        let hostname = extract_para(chunk, &["HostName", "_LuQUID_HostName", "Hostname"]);
        let ip = extract_para(chunk, &["IPAddress", "_LuQUID_IPAddress", "IpAddress"]);
        let mac = extract_para(chunk, &["MACAddress", "_LuQUID_MACAddress", "MAC"]);
        if hostname.is_none() && ip.is_none() && mac.is_none() {
            continue;
        }
        let mac_n = mac.as_deref().and_then(normalize_mac);
        let vendor = mac_n
            .as_deref()
            .and_then(oui::lookup_vendor)
            .map(str::to_string);
        out.push(Device {
            hostname: hostname.filter(|h| !h.is_empty()),
            ip: ip.and_then(|s| s.parse().ok()),
            mac: mac_n,
            vendor,
            link: default_link,
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

fn extract_para(chunk: &str, names: &[&str]) -> Option<String> {
    for name in names {
        // <ParaName>HostName</ParaName><ParaValue>foo</ParaValue>
        let needle = format!(">{name}<");
        if let Some(i) = chunk.find(&needle) {
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
        // <HostName>foo</HostName>
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_luquid_fields() {
        let xml = r#"<?xml version="1.0"?>
        <ajax_response_xml_root>
        <OBJ_ACCESSDEV_ID>
        <Instance>
        <ParaName>_LuQUID_MACAddress</ParaName><ParaValue>a6:54:f2:99:de:68</ParaValue>
        <ParaName>_LuQUID_HostName</ParaName><ParaValue>OnePlus-11R-5G</ParaValue>
        <ParaName>_LuQUID_IPAddress</ParaName><ParaValue>192.168.1.5</ParaValue>
        </Instance>
        <Instance>
        <ParaName>_LuQUID_MACAddress</ParaName><ParaValue>50:28:4a:22:13:16</ParaValue>
        <ParaName>_LuQUID_HostName</ParaName><ParaValue>ricky</ParaValue>
        <ParaName>_LuQUID_IPAddress</ParaName><ParaValue>192.168.1.6</ParaValue>
        </Instance>
        </OBJ_ACCESSDEV_ID>
        </ajax_response_xml_root>"#;
        let devs = parse_accessdev_xml(xml, LinkKind::Wifi).unwrap();
        assert_eq!(devs.len(), 2);
        assert_eq!(devs[0].hostname.as_deref(), Some("OnePlus-11R-5G"));
        assert_eq!(devs[1].hostname.as_deref(), Some("ricky"));
    }

    #[test]
    fn parse_homepage_fields() {
        let xml = r#"<ajax_response_xml_root>
        <OBJ_ACCESSDEV_ID>
        <Instance>
        <ParaName>HostName</ParaName><ParaValue>Nothing-Phone-3a</ParaValue>
        <ParaName>IPAddress</ParaName><ParaValue>192.168.1.7</ParaValue>
        <ParaName>MACAddress</ParaName><ParaValue>3c:b0:ed:74:6c:02</ParaValue>
        </Instance>
        </OBJ_ACCESSDEV_ID>
        </ajax_response_xml_root>"#;
        let devs = parse_accessdev_xml(xml, LinkKind::Wifi).unwrap();
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].hostname.as_deref(), Some("Nothing-Phone-3a"));
        assert!(devs[0].mac.is_some());
    }
}
