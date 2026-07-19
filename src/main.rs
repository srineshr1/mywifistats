mod cli;
mod collect;
mod config;
mod lan;
mod model;
mod oui;
mod rate;
mod router;
mod ui;
mod wifi;

use crate::cli::{Cli, Commands};
use crate::collect::Collector;
use crate::config::Config;
use anyhow::{Context, Result};
use clap::Parser;
use std::fs;
use std::os::unix::fs::PermissionsExt;

fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut cfg = Config::load()?;

    if cli.no_router {
        cfg.router.enabled = false;
    }
    if let Some(iface) = &cli.interface {
        cfg.interface = Some(iface.clone());
    }

    match cli.command {
        Some(Commands::InitConfig { force }) => return init_config(force),
        Some(Commands::Doctor) => {
            let mut collector = Collector::new(cfg, cli.interface, cli.no_router)?;
            println!("{}", collector.doctor_report());
            return Ok(());
        }
        None => {}
    }

    let mut collector = Collector::new(cfg, cli.interface.clone(), cli.no_router)?;

    if cli.json {
        // Two samples so rates can be non-zero when possible
        let _ = collector.collect();
        std::thread::sleep(std::time::Duration::from_millis(cli.interval_ms.min(2000)));
        let snap = collector.collect();
        println!("{}", serde_json::to_string_pretty(&snap)?);
        return Ok(());
    }

    if cli.once {
        let _ = collector.collect();
        std::thread::sleep(std::time::Duration::from_millis(800));
        let snap = collector.collect();
        ui::print_once(&snap);
        return Ok(());
    }

    ui::run_tui(&mut collector, cli.interval_ms)
}

fn init_config(force: bool) -> Result<()> {
    let path = Config::config_path();
    if path.exists() && !force {
        anyhow::bail!(
            "config already exists at {} (pass --force to overwrite)",
            path.display()
        );
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let sample = r#"# mywifistats configuration
# interface = "wlan0"

[router]
enabled = true
base_url = "http://192.168.1.1"
username = "admin"
backend = "zte_f670l"
# Prefer environment variable over storing password here:
#   export MYWIFISTATS_ROUTER_PASSWORD='your-password'
# password_env = "MYWIFISTATS_ROUTER_PASSWORD"
# password = "your-password"
"#;
    fs::write(&path, sample).with_context(|| format!("writing {}", path.display()))?;
    let mut perms = fs::metadata(&path)?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(&path, perms)?;
    println!("Wrote {}", path.display());
    println!("Set MYWIFISTATS_ROUTER_PASSWORD or edit password in the file.");
    Ok(())
}
