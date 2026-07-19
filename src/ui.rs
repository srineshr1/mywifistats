use crate::collect::{sort_devices, Collector};
use crate::model::{
    format_bps, format_bytes, format_duration, NetworkSnapshot, SortKey,
};
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState};
use ratatui::Terminal;
use std::io::{stdout, Stdout};
use std::time::{Duration, Instant};

pub fn run_tui(collector: &mut Collector, interval_ms: u64) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = run_loop(&mut terminal, collector, interval_ms);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    collector: &mut Collector,
    interval_ms: u64,
) -> Result<()> {
    let tick = Duration::from_millis(interval_ms.max(500));
    let mut last = Instant::now() - tick;
    let mut snap = collector.collect();
    let mut sort = SortKey::Hostname;
    let mut table_state = TableState::default();
    table_state.select(Some(0));
    let mut show_help = false;

    loop {
        if last.elapsed() >= tick {
            snap = collector.collect();
            sort_devices(&mut snap.devices, sort);
            last = Instant::now();
        }

        terminal.draw(|f| {
            if show_help {
                draw_help(f.area(), f);
            } else {
                draw_dashboard(f.area(), f, &snap, sort, &mut table_state);
            }
        })?;

        let timeout = tick
            .checked_sub(last.elapsed())
            .unwrap_or(Duration::from_millis(50));
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Char('r') => {
                        snap = collector.collect();
                        sort_devices(&mut snap.devices, sort);
                        last = Instant::now();
                    }
                    KeyCode::Char('s') => {
                        sort = sort.next();
                        sort_devices(&mut snap.devices, sort);
                    }
                    KeyCode::Char('?') | KeyCode::Char('h') => {
                        show_help = !show_help;
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        let i = table_state.selected().unwrap_or(0);
                        let max = snap.devices.len().saturating_sub(1);
                        table_state.select(Some((i + 1).min(max)));
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        let i = table_state.selected().unwrap_or(0);
                        table_state.select(Some(i.saturating_sub(1)));
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

fn draw_dashboard(
    area: Rect,
    f: &mut ratatui::Frame,
    snap: &NetworkSnapshot,
    sort: SortKey,
    table_state: &mut TableState,
) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(6),
            Constraint::Min(5),
            Constraint::Length(2),
        ])
        .split(area);

    draw_header(chunks[0], f, snap);
    draw_devices(chunks[1], f, snap, sort, table_state);
    draw_footer(chunks[2], f, snap, sort);
}

fn draw_header(area: Rect, f: &mut ratatui::Frame, snap: &NetworkSnapshot) {
    let mut lines = Vec::new();
    if let Some(w) = &snap.wifi {
        let ssid = w.ssid.as_deref().unwrap_or("(disconnected)");
        let sig = w
            .signal_dbm
            .map(|s| format!("{s} dBm"))
            .unwrap_or_else(|| "-".into());
        let ch = match (w.channel, w.channel_width_mhz) {
            (Some(c), Some(width)) => format!("ch {c} ({width} MHz)"),
            (Some(c), None) => format!("ch {c}"),
            _ => "-".into(),
        };
        let br = format!(
            "↓{}/↑{} Mbit/s",
            w.rx_bitrate_mbps
                .map(|b| format!("{b:.0}"))
                .unwrap_or_else(|| "-".into()),
            w.tx_bitrate_mbps
                .map(|b| format!("{b:.0}"))
                .unwrap_or_else(|| "-".into()),
        );
        lines.push(Line::from(vec![
            Span::styled(
                " WiFi ",
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
            Span::styled(ssid, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw(format!(
                "  {}  signal {}  {}  {}",
                w.iface, sig, ch, br
            )),
        ]));
        lines.push(Line::from(format!(
            "  BSSID {}  IP {}  GW {}  up {}",
            w.bssid.as_deref().unwrap_or("-"),
            w.ip.map(|i| i.to_string()).unwrap_or_else(|| "-".into()),
            w.gateway
                .map(|i| i.to_string())
                .unwrap_or_else(|| "-".into()),
            w.connected_secs
                .map(format_duration)
                .unwrap_or_else(|| "-".into()),
        )));
    } else {
        lines.push(Line::from(" WiFi: no link info"));
    }

    lines.push(Line::from(vec![
        Span::styled(" Traffic ", Style::default().fg(Color::Black).bg(Color::Green)),
        Span::raw(format!(
            "  live ↓{}  ↑{}   total ↓{}  ↑{}",
            format_bps(snap.local_rates.rx_bps),
            format_bps(snap.local_rates.tx_bps),
            format_bytes(snap.local_traffic.rx_bytes),
            format_bytes(snap.local_traffic.tx_bytes),
        )),
    ]));

    let router_color = if snap.router.connected {
        Color::Green
    } else if snap.router.enabled {
        Color::Yellow
    } else {
        Color::DarkGray
    };
    lines.push(Line::from(vec![
        Span::styled(
            " Router ",
            Style::default().fg(Color::Black).bg(router_color),
        ),
        Span::raw(format!(
            "  {} — {}",
            snap.router.name.as_deref().unwrap_or("none"),
            snap.router.message
        )),
    ]));

    if !snap.errors.is_empty() {
        lines.push(Line::from(Span::styled(
            format!("  ! {}", snap.errors[0]),
            Style::default().fg(Color::Red),
        )));
    }

    let p = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" mywifistats "),
    );
    f.render_widget(p, area);
}

fn draw_devices(
    area: Rect,
    f: &mut ratatui::Frame,
    snap: &NetworkSnapshot,
    sort: SortKey,
    table_state: &mut TableState,
) {
    let header = Row::new(vec![
        Cell::from("#"),
        Cell::from("Hostname"),
        Cell::from("IP"),
        Cell::from("MAC"),
        Cell::from("Vendor"),
        Cell::from("Link"),
        Cell::from("Status"),
        Cell::from("Data ↓/↑"),
        Cell::from("Rate ↓/↑"),
    ])
    .style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    )
    .height(1);

    let rows = snap.devices.iter().enumerate().map(|(i, d)| {
        let name = {
            let mut n = d.hostname.clone().unwrap_or_else(|| "-".into());
            if d.is_self {
                n = format!("{n} *");
            } else if d.is_gateway {
                n = format!("{n} (gw)");
            }
            n
        };
        let data = match (d.bytes_rx, d.bytes_tx) {
            (Some(rx), Some(tx)) => format!("{}/{}", format_bytes(rx), format_bytes(tx)),
            (Some(rx), None) => format!("{} / -", format_bytes(rx)),
            _ => "-".into(),
        };
        let rate = match (d.rate_rx_bps, d.rate_tx_bps) {
            (Some(rx), Some(tx)) => format!("{}/{}", format_bps(rx), format_bps(tx)),
            _ => "-".into(),
        };
        let status = if d.online { "up" } else { "stale" };
        let style = if d.is_self {
            Style::default().fg(Color::Cyan)
        } else if !d.online {
            Style::default().fg(Color::DarkGray)
        } else {
            Style::default().fg(Color::Green)
        };
        Row::new(vec![
            Cell::from(format!("{}", i + 1)),
            Cell::from(name),
            Cell::from(d.ip.map(|i| i.to_string()).unwrap_or_else(|| "-".into())),
            Cell::from(d.mac.clone().unwrap_or_else(|| "-".into())),
            Cell::from(d.vendor.clone().unwrap_or_else(|| "-".into())),
            Cell::from(d.link.as_str()),
            Cell::from(status),
            Cell::from(data),
            Cell::from(rate),
        ])
        .style(style)
    });

    let table = Table::new(
        rows,
        [
            Constraint::Length(3),
            Constraint::Length(18),
            Constraint::Length(15),
            Constraint::Length(18),
            Constraint::Length(14),
            Constraint::Length(5),
            Constraint::Length(6),
            Constraint::Length(18),
            Constraint::Length(18),
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(format!(
        " Devices ({}) · sort: {} ",
        snap.devices.len(),
        sort.label()
    )))
    .row_highlight_style(
        Style::default()
            .bg(Color::DarkGray)
            .add_modifier(Modifier::BOLD),
    )
    .highlight_symbol(">> ");

    f.render_stateful_widget(table, area, table_state);
}

fn draw_footer(area: Rect, f: &mut ratatui::Frame, snap: &NetworkSnapshot, sort: SortKey) {
    let text = format!(
        " q quit  r refresh  s sort ({})  ↑↓ move  ? help  ·  {} device(s)",
        sort.label(),
        snap.devices.len()
    );
    let p = Paragraph::new(text).style(Style::default().fg(Color::DarkGray));
    f.render_widget(p, area);
}

fn draw_help(area: Rect, f: &mut ratatui::Frame) {
    let text = vec![
        Line::from("mywifistats help"),
        Line::from(""),
        Line::from("q / Esc   Quit"),
        Line::from("r         Refresh now"),
        Line::from("s         Cycle sort (hostname → ip → mac → usage → link)"),
        Line::from("j / ↓     Next device"),
        Line::from("k / ↑     Previous device"),
        Line::from("? / h     Toggle this help"),
        Line::from(""),
        Line::from("Data sources:"),
        Line::from("  • Local WiFi via iw + /sys stats (this machine traffic)"),
        Line::from("  • LAN neighbors via ip neigh (IP/MAC/status)"),
        Line::from("  • Router (ZTE F670L) when credentials configured"),
        Line::from(""),
        Line::from("Config: ~/.config/mywifistats/config.toml"),
        Line::from("Env:    MYWIFISTATS_ROUTER_PASSWORD"),
        Line::from(""),
        Line::from("Press ? to return"),
    ];
    let p = Paragraph::new(text).block(Block::default().borders(Borders::ALL).title(" Help "));
    f.render_widget(p, area);
}

pub fn print_once(snap: &NetworkSnapshot) {
    println!("=== WiFi ===");
    if let Some(w) = &snap.wifi {
        println!(
            "SSID: {}  iface: {}  signal: {}",
            w.ssid.as_deref().unwrap_or("-"),
            w.iface,
            w.signal_dbm
                .map(|s| format!("{s} dBm"))
                .unwrap_or_else(|| "-".into())
        );
        println!(
            "Channel: {}  Width: {} MHz  Freq: {} MHz",
            w.channel
                .map(|c| c.to_string())
                .unwrap_or_else(|| "-".into()),
            w.channel_width_mhz
                .map(|c| c.to_string())
                .unwrap_or_else(|| "-".into()),
            w.freq_mhz
                .map(|c| c.to_string())
                .unwrap_or_else(|| "-".into()),
        );
        println!(
            "Bitrate RX/TX: {} / {} MBit/s  BSSID: {}",
            w.rx_bitrate_mbps
                .map(|b| format!("{b:.0}"))
                .unwrap_or_else(|| "-".into()),
            w.tx_bitrate_mbps
                .map(|b| format!("{b:.0}"))
                .unwrap_or_else(|| "-".into()),
            w.bssid.as_deref().unwrap_or("-")
        );
        println!(
            "IP: {}  Gateway: {}  Connected: {}",
            w.ip.map(|i| i.to_string()).unwrap_or_else(|| "-".into()),
            w.gateway
                .map(|i| i.to_string())
                .unwrap_or_else(|| "-".into()),
            w.connected_secs
                .map(format_duration)
                .unwrap_or_else(|| "-".into())
        );
    } else {
        println!("(no link)");
    }
    println!(
        "Local traffic live ↓{} ↑{}  total ↓{} ↑{}",
        format_bps(snap.local_rates.rx_bps),
        format_bps(snap.local_rates.tx_bps),
        format_bytes(snap.local_traffic.rx_bytes),
        format_bytes(snap.local_traffic.tx_bytes)
    );
    println!(
        "\n=== Router: {} ===",
        snap.router.message
    );

    let mut table = comfy_table::Table::new();
    table.set_header(vec![
        "#", "Hostname", "IP", "MAC", "Vendor", "Link", "Status", "Data ↓/↑", "Rate ↓/↑",
    ]);
    for (i, d) in snap.devices.iter().enumerate() {
        let mut name = d.hostname.clone().unwrap_or_else(|| "-".into());
        if d.is_self {
            name.push_str(" *");
        }
        let data = match (d.bytes_rx, d.bytes_tx) {
            (Some(rx), Some(tx)) => format!("{}/{}", format_bytes(rx), format_bytes(tx)),
            _ => "-".into(),
        };
        let rate = match (d.rate_rx_bps, d.rate_tx_bps) {
            (Some(rx), Some(tx)) => format!("{}/{}", format_bps(rx), format_bps(tx)),
            _ => "-".into(),
        };
        table.add_row(vec![
            (i + 1).to_string(),
            name,
            d.ip.map(|i| i.to_string()).unwrap_or_else(|| "-".into()),
            d.mac.clone().unwrap_or_else(|| "-".into()),
            d.vendor.clone().unwrap_or_else(|| "-".into()),
            d.link.as_str().to_string(),
            if d.online { "up" } else { "stale" }.into(),
            data,
            rate,
        ]);
    }
    println!("\n{table}");
    if !snap.errors.is_empty() {
        println!("\nWarnings:");
        for e in &snap.errors {
            println!("  - {e}");
        }
    }
}
