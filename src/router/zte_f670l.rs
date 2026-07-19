use super::{RouterBackend, RouterCaps};
use crate::model::{
    normalize_mac, BlockedDevice, Device, DeviceSource, LinkKind, MacFilterStatus,
};
use crate::oui;
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::rngs::OsRng;
use reqwest::blocking::{Client, ClientBuilder};
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE, REFERER};
use rsa::pkcs8::DecodePublicKey;
use rsa::{Pkcs1v15Encrypt, RsaPublicKey};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

/// Hard-coded from F670LV9.0 admin page (JSEncrypt public key).
const ZTE_PUBKEY_PEM: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAodPTerkUVCYmv28SOfRV
7UKHVujx/HjCUTAWy9l0L5H0JV0LfDudTdMNPEKloZsNam3YrtEnq6jqMLJV4ASb
1d6axmIgJ636wyTUS99gj4BKs6bQSTUSE8h/QkUYv4gEIt3saMS0pZpd90y6+B/9
hZxZE/RKU8e+zgRqp1/762TB7vcjtjOwXRDEL0w71Jk9i8VUQ59MR1Uj5E8X3WIc
fYSK5RWBkMhfaTRM6ozS9Bqhi40xlSOb3GBxCmliCifOJNLoO9kFoWgAIw5hkSIb
GH+4Csop9Uy8VvmmB+B3ubFLN35qIa5OG5+SDXn4L7FeAA5lRiGxRi8tsWrtew8w
nwIDAQAB
-----END PUBLIC KEY-----";

/// ZTE F670L / F670LV9.0 admin web API client.
pub struct ZteF670l {
    base_url: String,
    username: String,
    password: String,
    client: Client,
    session_token: String,
    logged_in: bool,
    per_host_traffic: bool,
    can_block: bool,
    last_message: String,
    pub_key: RsaPublicKey,
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
        let pub_key = RsaPublicKey::from_public_key_pem(ZTE_PUBKEY_PEM)
            .context("loading ZTE RSA public key")?;
        Ok(Self {
            base_url: base,
            username: username.to_string(),
            password: password.to_string(),
            client,
            session_token: String::new(),
            logged_in: false,
            per_host_traffic: false,
            can_block: false,
            last_message: "not connected".into(),
            pub_key,
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
        self.can_block = false;
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
            HeaderValue::from_static("application/x-www-form-urlencoded; charset=UTF-8"),
        );
        headers.insert(
            REFERER,
            HeaderValue::from_str(&format!("{}/", self.base_url))
                .unwrap_or(HeaderValue::from_static("*")),
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

        if let Some(err) = v.get("loginErrMsg").and_then(|x| x.as_str()) {
            if !err.trim().is_empty() {
                self.last_message = format!("login failed: {err}");
                bail!("{}", self.last_message);
            }
        }

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

    /// Refresh CSRF token from the MAC-filter admin page (required for Apply/Delete).
    fn refresh_filter_token(&mut self) -> Result<()> {
        self.prime_filter_menu()
    }

    fn make_check_header(&self, post_body: &str) -> Result<String> {
        let mut hasher = Sha256::new();
        hasher.update(post_body.as_bytes());
        let dig_hex = hex::encode(hasher.finalize());
        let mut rng = OsRng;
        let encrypted = self
            .pub_key
            .encrypt(&mut rng, Pkcs1v15Encrypt, dig_hex.as_bytes())
            .context("RSA encrypt Check header")?;
        Ok(B64.encode(encrypted))
    }

    fn post_filter(&mut self, post_body: &str) -> Result<String> {
        let check = self.make_check_header(post_body)?;
        let url = format!(
            "{}/?_type=menuData&_tag=firewall_macfilterv3_lua.lua",
            self.base_url
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded; charset=UTF-8"),
        );
        headers.insert(
            REFERER,
            HeaderValue::from_str(&format!("{}/", self.base_url))
                .unwrap_or(HeaderValue::from_static("*")),
        );
        headers.insert(
            "X-Requested-With",
            HeaderValue::from_static("XMLHttpRequest"),
        );
        headers.insert(
            "Check",
            HeaderValue::from_str(&check).context("Check header")?,
        );

        let resp = self
            .client
            .post(&url)
            .headers(headers)
            .body(post_body.to_string())
            .send()
            .with_context(|| format!("POST {url}"))?;
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        if !status.is_success() {
            bail!("POST filter HTTP {status}: {}", truncate(&body, 200));
        }
        if body.contains("SessionTimeout") {
            bail!("session timeout on filter POST");
        }
        // IF_ERRORID 0 = success
        if let Some(id) = extract_xml_text(&body, "IF_ERRORID") {
            if id != "0" {
                let msg = extract_xml_text(&body, "IF_ERRORSTR")
                    .unwrap_or_else(|| format!("error id {id}"));
                // HTML entities like &#32;
                let msg = msg
                    .replace("&#32;", " ")
                    .replace("&amp;", "&")
                    .replace("&lt;", "<")
                    .replace("&gt;", ">");
                bail!("router rejected change: {msg} ({id})");
            }
        }
        Ok(body)
    }

    fn fetch_devices_xml(&self) -> Result<(String, LinkKind)> {
        let paths = [
            (
                "/?_type=menuData&_tag=wlan_homepage_lua.lua",
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

    /// Firmware requires opening the filter admin page before MAC-filter
    /// menuData endpoints accept the session (otherwise SessionTimeout).
    fn prime_filter_menu(&mut self) -> Result<()> {
        let body = self.get_text("/?_type=menuView&_tag=filterCriteria")?;
        if let Some(tok) = extract_session_token_from_html(&body) {
            self.session_token = tok;
        }
        if body.contains("SessionTimeout") {
            bail!("session timeout opening filter page");
        }
        Ok(())
    }

    fn fetch_blocked_xml(&mut self) -> Result<String> {
        self.prime_filter_menu()?;
        let body = self.get_text("/?_type=menuData&_tag=firewall_macfilterv3_lua.lua")?;
        if body.contains("SessionTimeout") {
            bail!("session timeout fetching MAC filter");
        }
        Ok(body)
    }

    fn fetch_filter_global(&mut self) -> Result<MacFilterStatus> {
        // prime already done by list_blocked; still safe to call again
        let _ = self.prime_filter_menu();
        let body = self.get_text("/?_type=menuData&_tag=firewall_filterglobal_lua.lua")?;
        if body.contains("SessionTimeout") {
            bail!("session timeout fetching filter global");
        }
        let enabled = extract_para_value(&body, "MacFilterEnable")
            .map(|v| v == "1")
            .unwrap_or(false);
        let mode = extract_para_value(&body, "MacFilterTarget").unwrap_or_else(|| "unknown".into());
        Ok(MacFilterStatus {
            enabled,
            mode,
            can_block: true,
        })
    }

    fn probe_capabilities(&mut self) {
        self.per_host_traffic = false;
        match self.fetch_blocked_xml() {
            Ok(_) => self.can_block = true,
            Err(_) => self.can_block = false,
        }
        if self.logged_in {
            self.last_message = if self.can_block {
                "login OK · block supported · no per-host traffic on this firmware".into()
            } else {
                "login OK · device list only".into()
            };
        }
    }

    fn ensure_logged_in(&mut self) -> Result<()> {
        if !self.logged_in {
            self.login()?;
        }
        Ok(())
    }
}

impl RouterBackend for ZteF670l {
    fn name(&self) -> &str {
        "ZTE F670L"
    }

    fn login(&mut self) -> Result<()> {
        self.do_login()?;
        self.probe_capabilities();
        Ok(())
    }

    fn list_devices(&mut self) -> Result<Vec<Device>> {
        self.ensure_logged_in()?;
        let (body, default_link) = match self.fetch_devices_xml() {
            Ok(v) => v,
            Err(e) => {
                self.logged_in = false;
                self.do_login()?;
                self.fetch_devices_xml().map_err(|e2| {
                    anyhow::anyhow!("device list failed after re-login: {e2} (was: {e})")
                })?
            }
        };

        let mut devices = parse_accessdev_xml(&body, default_link)?;
        for d in &mut devices {
            d.source = DeviceSource::Router;
            if d.link == LinkKind::Unknown {
                d.link = default_link;
            }
        }

        self.last_message = format!(
            "login OK · {} client(s) · rates: this PC only (no per-host traffic on firmware)",
            devices.len()
        );

        Ok(devices)
    }

    fn list_blocked(&mut self) -> Result<Vec<BlockedDevice>> {
        self.ensure_logged_in()?;
        let body = match self.fetch_blocked_xml() {
            Ok(b) => b,
            Err(_) => {
                self.logged_in = false;
                self.do_login()?;
                self.fetch_blocked_xml()?
            }
        };
        self.can_block = true;
        Ok(parse_mac_filter_xml(&body))
    }

    fn mac_filter_status(&mut self) -> Result<MacFilterStatus> {
        self.ensure_logged_in()?;
        let mut st = self.fetch_filter_global().unwrap_or_default();
        st.can_block = self.can_block;
        Ok(st)
    }

    fn block_device(&mut self, mac: &str, name: &str) -> Result<()> {
        self.ensure_logged_in()?;
        let mac = normalize_mac(mac).context("invalid MAC address")?;
        let name = sanitize_name(name);

        // Already blocked?
        let existing = self.list_blocked()?;
        if existing.iter().any(|b| b.mac == mac) {
            bail!("device {mac} is already blocked");
        }

        self.refresh_filter_token()?;
        // Type must be Bridge%2BRoute (+ encoded) for the Check hash / body
        let post = format!(
            "IF_ACTION=Apply&_InstID=-1&Name={name}&SrcMacAddr={mac}&DstMacAddr={mac}&Type=Bridge%2BRoute&Protocol=IP&_sessionTOKEN={}",
            self.session_token
        );
        self.post_filter(&post)?;
        self.last_message = format!("blocked {name} ({mac})");
        Ok(())
    }

    fn unblock_device(&mut self, inst_id: &str) -> Result<()> {
        self.ensure_logged_in()?;
        if inst_id.is_empty() {
            bail!("missing rule id");
        }
        self.refresh_filter_token()?;
        let post = format!(
            "IF_ACTION=Delete&_InstID={inst_id}&_sessionTOKEN={}",
            self.session_token
        );
        self.post_filter(&post)?;
        self.last_message = format!("unblocked rule {inst_id}");
        Ok(())
    }

    fn capabilities(&self) -> RouterCaps {
        RouterCaps {
            per_host_traffic: self.per_host_traffic,
            can_block: self.can_block,
            message: self.last_message.clone(),
        }
    }

    fn is_logged_in(&self) -> bool {
        self.logged_in
    }
}

fn sanitize_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | ' ' | '.'))
        .take(32)
        .collect();
    let t = cleaned.trim();
    if t.is_empty() {
        "blocked".into()
    } else {
        // URL-encode spaces for form body (use %20)
        t.replace(' ', "%20")
    }
}

fn extract_session_token_from_html(html: &str) -> Option<String> {
    // _sessionTmpToken = "\x41\x42..."
    if let Some(i) = html.find("_sessionTmpToken") {
        let slice = &html[i..html.len().min(i + 400)];
        if let Some(q) = slice.find('"') {
            let rest = &slice[q + 1..];
            if let Some(end) = rest.find('"') {
                let raw = &rest[..end];
                if raw.contains("\\x") {
                    return decode_js_hex_string(raw);
                }
                if !raw.is_empty() {
                    return Some(raw.to_string());
                }
            }
        }
    }
    for pat in [r#"id="_sessionTOKEN""#, r#"name="_sessionTOKEN""#] {
        if let Some(i) = html.find(pat) {
            let slice = &html[i..html.len().min(i + 200)];
            if let Some(v) = slice.find("value=\"") {
                let rest = &slice[v + 7..];
                if let Some(end) = rest.find('"') {
                    return Some(rest[..end].to_string());
                }
            }
        }
    }
    None
}

fn decode_js_hex_string(s: &str) -> Option<String> {
    // \x59\x66\x59...
    let mut bytes = Vec::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' && chars.peek() == Some(&'x') {
            chars.next();
            let h1 = chars.next()?;
            let h2 = chars.next()?;
            let hex: String = [h1, h2].iter().collect();
            bytes.push(u8::from_str_radix(&hex, 16).ok()?);
        } else {
            bytes.push(c as u8);
        }
    }
    String::from_utf8(bytes).ok()
}

fn extract_xml_text(body: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let i = body.find(&open)?;
    let rest = &body[i + open.len()..];
    let j = rest.find(&close)?;
    Some(rest[..j].trim().to_string())
}

fn extract_para_value(body: &str, name: &str) -> Option<String> {
    let needle = format!(">{name}<");
    let i = body.find(&needle)?;
    let rest = &body[i..];
    let pv = rest.find("<ParaValue>")?;
    let rest2 = &rest[pv + "<ParaValue>".len()..];
    let j = rest2.find("</ParaValue>")?;
    Some(rest2[..j].trim().to_string())
}

fn parse_mac_filter_xml(body: &str) -> Vec<BlockedDevice> {
    let mut out = Vec::new();
    if !body.contains("OBJ_MACFILTER") && !body.contains("SrcMacAddr") {
        return out;
    }
    for chunk in body.split("<Instance>").skip(1) {
        let map = para_map_from_chunk(chunk);
        let inst = map.get("_InstID").cloned().unwrap_or_default();
        let mac_raw = map
            .get("SrcMacAddr")
            .cloned()
            .or_else(|| map.get("DstMacAddr").cloned())
            .unwrap_or_default();
        let Some(mac) = normalize_mac(&mac_raw) else {
            continue;
        };
        let name = map
            .get("Name")
            .cloned()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| mac.clone());
        out.push(BlockedDevice {
            inst_id: inst,
            name,
            mac,
            protocol: map.get("Protocol").cloned(),
            filter_type: map.get("Type").cloned(),
        });
    }
    out
}

fn para_map_from_chunk(chunk: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let mut rest = chunk;
    while let Some(i) = rest.find("<ParaName>") {
        rest = &rest[i + "<ParaName>".len()..];
        let Some(j) = rest.find("</ParaName>") else {
            break;
        };
        let key = rest[..j].trim().to_string();
        rest = &rest[j + "</ParaName>".len()..];
        if let Some(pv) = rest.find("<ParaValue>") {
            rest = &rest[pv + "<ParaValue>".len()..];
            if let Some(k) = rest.find("</ParaValue>") {
                let val = rest[..k].trim().to_string();
                rest = &rest[k + "</ParaValue>".len()..];
                map.insert(key, val);
            }
        }
    }
    map
}

fn parse_accessdev_xml(body: &str, default_link: LinkKind) -> Result<Vec<Device>> {
    if body.trim().is_empty() {
        return Ok(Vec::new());
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
        }
        i += 1;
    }

    for n in inst.descendants().filter(|n| n.is_element()) {
        if n.tag_name().name().eq_ignore_ascii_case("ParaName") {
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
                    || k.to_ascii_lowercase()
                        .ends_with(&s.to_ascii_lowercase())
                {
                    if !v.is_empty() {
                        return Some(v.clone());
                    }
                }
            }
        }
        None
    };

    let hostname = get(&["HostName", "Hostname", "_LuQUID_HostName"]);
    let ip_s = get(&["IPAddress", "IpAddress", "_LuQUID_IPAddress"]);
    let mac_s = get(&["MACAddress", "MacAddress", "_LuQUID_MACAddress"]);
    if hostname.is_none() && ip_s.is_none() && mac_s.is_none() {
        return None;
    }

    let mac = mac_s.as_deref().and_then(normalize_mac);
    let ip = ip_s.and_then(|s| s.parse::<IpAddr>().ok());
    let vendor = mac
        .as_deref()
        .and_then(oui::lookup_vendor)
        .map(str::to_string);

    Some(Device {
        hostname: hostname.filter(|h| !h.is_empty() && h != "Unknown"),
        ip,
        mac,
        vendor,
        link: default_link,
        online: true,
        is_self: false,
        is_gateway: false,
        blocked: false,
        bytes_rx: None,
        bytes_tx: None,
        rate_rx_bps: None,
        rate_tx_bps: None,
        source: DeviceSource::Router,
    })
}

fn scrape_devices_loose(body: &str, default_link: LinkKind) -> Vec<Device> {
    let chunks: Vec<&str> = if body.contains("<Instance>") {
        body.split("<Instance>").skip(1).collect()
    } else {
        vec![body]
    };
    let mut out = Vec::new();
    for chunk in chunks {
        let map = para_map_from_chunk(chunk);
        let hostname = map
            .get("HostName")
            .or_else(|| map.get("_LuQUID_HostName"))
            .cloned();
        let ip = map
            .get("IPAddress")
            .or_else(|| map.get("_LuQUID_IPAddress"))
            .and_then(|s| s.parse().ok());
        let mac = map
            .get("MACAddress")
            .or_else(|| map.get("_LuQUID_MACAddress"))
            .and_then(|s| normalize_mac(s));
        if hostname.is_none() && ip.is_none() && mac.is_none() {
            continue;
        }
        let vendor = mac
            .as_deref()
            .and_then(oui::lookup_vendor)
            .map(str::to_string);
        out.push(Device {
            hostname,
            ip,
            mac,
            vendor,
            link: default_link,
            online: true,
            is_self: false,
            is_gateway: false,
            blocked: false,
            bytes_rx: None,
            bytes_tx: None,
            rate_rx_bps: None,
            rate_tx_bps: None,
            source: DeviceSource::Router,
        });
    }
    out
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
    fn parse_blocked() {
        let xml = r#"<ajax_response_xml_root><OBJ_MACFILTER_ID>
        <Instance>
        <ParaName>_InstID</ParaName><ParaValue>DEV.FW.CHAIN1.MACF1</ParaValue>
        <ParaName>Type</ParaName><ParaValue>Bridge+Route</ParaValue>
        <ParaName>Protocol</ParaName><ParaValue>IP</ParaValue>
        <ParaName>Name</ParaName><ParaValue>Opppo</ParaValue>
        <ParaName>SrcMacAddr</ParaName><ParaValue>3e:17:6d:4f:fa:bd</ParaValue>
        <ParaName>DstMacAddr</ParaName><ParaValue>3e:17:6d:4f:fa:bd</ParaValue>
        </Instance></OBJ_MACFILTER_ID></ajax_response_xml_root>"#;
        let list = parse_mac_filter_xml(xml);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "Opppo");
        assert_eq!(list[0].mac, "3e:17:6d:4f:fa:bd");
    }

    #[test]
    fn parse_luquid_fields() {
        let xml = r#"<?xml version="1.0"?><ajax_response_xml_root>
        <OBJ_ACCESSDEV_ID>
        <Instance>
        <ParaName>_LuQUID_MACAddress</ParaName><ParaValue>a6:54:f2:99:de:68</ParaValue>
        <ParaName>_LuQUID_HostName</ParaName><ParaValue>OnePlus-11R-5G</ParaValue>
        <ParaName>_LuQUID_IPAddress</ParaName><ParaValue>192.168.1.5</ParaValue>
        </Instance>
        </OBJ_ACCESSDEV_ID></ajax_response_xml_root>"#;
        let devs = parse_accessdev_xml(xml, LinkKind::Wifi).unwrap();
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].hostname.as_deref(), Some("OnePlus-11R-5G"));
    }

    #[test]
    fn decode_token() {
        let s = r#"\x59\x66\x59\x4a"#;
        assert_eq!(decode_js_hex_string(s).as_deref(), Some("YfYJ"));
    }
}
