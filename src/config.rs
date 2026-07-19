use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    /// Wireless interface; auto-detected if unset.
    pub interface: Option<String>,
    #[serde(default)]
    pub router: RouterConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouterConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_router_url")]
    pub base_url: String,
    #[serde(default = "default_username")]
    pub username: String,
    /// Prefer `password_env` or MYWIFISTATS_ROUTER_PASSWORD.
    pub password: Option<String>,
    /// Name of env var holding the password (default MYWIFISTATS_ROUTER_PASSWORD).
    pub password_env: Option<String>,
    /// Backend kind; only "zte_f670l" for now.
    #[serde(default = "default_backend")]
    pub backend: String,
}

fn default_true() -> bool {
    true
}
fn default_router_url() -> String {
    "http://192.168.1.1".into()
}
fn default_username() -> String {
    "admin".into()
}
fn default_backend() -> String {
    "zte_f670l".into()
}

impl Default for RouterConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            base_url: default_router_url(),
            username: default_username(),
            password: None,
            password_env: None,
            backend: default_backend(),
        }
    }
}

impl Config {
    pub fn config_path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("mywifistats")
            .join("config.toml")
    }

    pub fn load() -> Result<Self> {
        let path = Self::config_path();
        let mut cfg = if path.exists() {
            let text = fs::read_to_string(&path)
                .with_context(|| format!("reading config {}", path.display()))?;
            toml::from_str(&text).with_context(|| format!("parsing config {}", path.display()))?
        } else {
            Config::default()
        };

        // Env overrides
        if let Ok(iface) = std::env::var("MYWIFISTATS_INTERFACE") {
            if !iface.is_empty() {
                cfg.interface = Some(iface);
            }
        }
        if let Ok(url) = std::env::var("MYWIFISTATS_ROUTER_URL") {
            if !url.is_empty() {
                cfg.router.base_url = url;
            }
        }
        if let Ok(user) = std::env::var("MYWIFISTATS_ROUTER_USER") {
            if !user.is_empty() {
                cfg.router.username = user;
            }
        }
        if let Ok(en) = std::env::var("MYWIFISTATS_ROUTER_ENABLED") {
            cfg.router.enabled = matches!(en.to_ascii_lowercase().as_str(), "1" | "true" | "yes");
        }

        Ok(cfg)
    }

    pub fn router_password(&self) -> Option<String> {
        let env_name = self
            .router
            .password_env
            .as_deref()
            .unwrap_or("MYWIFISTATS_ROUTER_PASSWORD");
        if let Ok(p) = std::env::var(env_name) {
            if !p.is_empty() {
                return Some(p);
            }
        }
        self.router
            .password
            .clone()
            .filter(|p| !p.is_empty())
    }

}
