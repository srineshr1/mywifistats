mod cli;
mod collect;
mod config;
mod lan;
mod model;
mod oui;
mod rate;
mod router;
mod setup;
mod ui;
mod wifi;

use crate::cli::{Cli, Commands};
use crate::collect::Collector;
use crate::config::Config;
use anyhow::Result;
use clap::Parser;

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
        Some(Commands::InitConfig { force }) => {
            if Config::config_path().exists() && !force {
                anyhow::bail!(
                    "config already exists at {} (pass --force to overwrite, or run `mywifistats setup`)",
                    Config::config_path().display()
                );
            }
            cfg.save()?;
            println!("Wrote {}", Config::config_path().display());
            println!("Run `mywifistats setup` to configure interactively.");
            return Ok(());
        }
        Some(Commands::Setup) => {
            let saved = setup::run_setup(&cfg)?;
            if saved {
                println!("Config saved to {}", Config::config_path().display());
            } else {
                println!("Setup cancelled — no changes saved.");
            }
            return Ok(());
        }
        Some(Commands::Doctor) => {
            let mut collector = Collector::new(cfg, cli.interface, cli.no_router)?;
            println!("{}", collector.doctor_report());
            return Ok(());
        }
        None => {}
    }

    let mut collector = Collector::new(cfg, cli.interface.clone(), cli.no_router)?;

    if cli.json {
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
