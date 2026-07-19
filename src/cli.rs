use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "mywifistats",
    about = "Live WiFi / LAN device stats dashboard",
    version
)]
pub struct Cli {
    /// Print one snapshot and exit (no TUI).
    #[arg(long, short = '1')]
    pub once: bool,

    /// Output machine-readable JSON snapshot.
    #[arg(long)]
    pub json: bool,

    /// Refresh interval in milliseconds (TUI).
    #[arg(long, default_value_t = 1500)]
    pub interval_ms: u64,

    /// Wireless interface (overrides config / auto-detect).
    #[arg(long, short = 'i', global = true)]
    pub interface: Option<String>,

    /// Disable router backend for this run.
    #[arg(long, global = true)]
    pub no_router: bool,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Diagnose interface, gateway, and router connectivity.
    Doctor,
    /// Write a sample config file to ~/.config/mywifistats/config.toml
    InitConfig {
        /// Overwrite existing config.
        #[arg(long)]
        force: bool,
    },
}
