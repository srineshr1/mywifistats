use crate::collect::{sort_devices, Collector};
use crate::config::Config;
use crate::model::{
    format_bps, format_bytes, format_duration, NetworkSnapshot, SortKey, WifiLink,
};
use crate::setup;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ViewMode {
    Devices,
    Blocked,
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
    let mut view = ViewMode::Devices;
    let mut status_msg: Option<(String, bool)> = None; // message, is_error
    let mut confirm_block: Option<usize> = None; // pending device index

    loop {
        if last.elapsed() >= tick && confirm_block.is_none() {
            snap = collector.collect();
            sort_devices(&mut snap.devices, sort);
            last = Instant::now();
        }

        terminal.draw(|f| {
            if show_help {
                draw_help(f.area(), f);
            } else {
                draw_dashboard(
                    f.area(),
                    f,
                    &snap,
                    sort,
                    &mut table_state,
                    view,
                    status_msg.as_ref(),
                    confirm_block,
                );
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

                // Confirm dialog for block
                if let Some(idx) = confirm_block {
                    match key.code {
                        KeyCode::Char('y') | KeyCode::Char('Y') => {
                            confirm_block = None;
                            if let Some(dev) = snap.devices.get(idx) {
                                if dev.is_self {
                                    status_msg =
                                        Some(("Cannot block this machine".into(), true));
                                } else if let Some(mac) = &dev.mac {
                                    let name = dev
                                        .hostname
                                        .clone()
                                        .unwrap_or_else(|| "device".into());
                                    match collector.block_device(mac, &name) {
                                        Ok(msg) => {
                                            status_msg = Some((msg, false));
                                            snap = collector.collect();
                                            sort_devices(&mut snap.devices, sort);
                                        }
                                        Err(e) => status_msg = Some((format!("{e}"), true)),
                                    }
                                } else {
                                    status_msg =
                                        Some(("Device has no MAC address".into(), true));
                                }
                            }
                            last = Instant::now();
                        }
                        KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                            confirm_block = None;
                            status_msg = Some(("Block cancelled".into(), false));
                        }
                        _ => {}
                    }
                    continue;
                }

                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => {
                        if show_help {
                            show_help = false;
                        } else {
                            break;
                        }
                    }
                    KeyCode::Char('r') => {
                        snap = collector.collect();
                        sort_devices(&mut snap.devices, sort);
                        last = Instant::now();
                        status_msg = Some(("Refreshed".into(), false));
                    }
                    KeyCode::Char('s') if view == ViewMode::Devices => {
                        sort = sort.next();
                        sort_devices(&mut snap.devices, sort);
                    }
                    KeyCode::Char('b') | KeyCode::Tab => {
                        view = match view {
                            ViewMode::Devices => ViewMode::Blocked,
                            ViewMode::Blocked => ViewMode::Devices,
                        };
                        table_state.select(Some(0));
                        status_msg = None;
                    }
                    KeyCode::Char('x') if view == ViewMode::Devices => {
                        if !snap.router.can_block && !snap.router.connected {
                            status_msg = Some((
                                "Block needs router login — press c for setup".into(),
                                true,
                            ));
                        } else if let Some(i) = table_state.selected() {
                            confirm_block = Some(i);
                        }
                    }
                    KeyCode::Char('u') if view == ViewMode::Blocked => {
                        if let Some(i) = table_state.selected() {
                            if let Some(rule) = snap.blocked.get(i) {
                                match collector.unblock_device(&rule.inst_id) {
                                    Ok(msg) => {
                                        status_msg = Some((msg, false));
                                        snap = collector.collect();
                                        sort_devices(&mut snap.devices, sort);
                                        if snap.blocked.is_empty() {
                                            table_state.select(Some(0));
                                        } else {
                                            let max = snap.blocked.len().saturating_sub(1);
                                            table_state
                                                .select(Some(i.min(max)));
                                        }
                                    }
                                    Err(e) => status_msg = Some((format!("{e}"), true)),
                                }
                                last = Instant::now();
                            }
                        }
                    }
                    KeyCode::Char('c') => {
                        disable_raw_mode()?;
                        execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
                        terminal.show_cursor()?;

                        let cfg = collector.config().clone();
                        let saved = setup::run_setup(&cfg)?;

                        enable_raw_mode()?;
                        execute!(terminal.backend_mut(), EnterAlternateScreen)?;
                        terminal.clear()?;

                        if saved {
                            if let Ok(new_cfg) = Config::load() {
                                let _ = collector.reconfigure(new_cfg);
                            }
                        }
                        snap = collector.collect();
                        sort_devices(&mut snap.devices, sort);
                        last = Instant::now();
                    }
                    KeyCode::Char('?') | KeyCode::Char('h') => {
                        show_help = !show_help;
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        let i = table_state.selected().unwrap_or(0);
                        let max = match view {
                            ViewMode::Devices => snap.devices.len().saturating_sub(1),
                            ViewMode::Blocked => snap.blocked.len().saturating_sub(1),
                        };
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
    view: ViewMode,
    status_msg: Option<&(String, bool)>,
    confirm_block: Option<usize>,
) {
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(9), // top cards
            Constraint::Length(3), // router strip
            Constraint::Length(if status_msg.is_some() || confirm_block.is_some() {
                3
            } else {
                0
            }),
            Constraint::Min(6), // devices / blocked
            Constraint::Length(1), // footer
        ])
        .split(area);

    draw_top_cards(root[0], f, snap);
    draw_router_strip(root[1], f, snap);
    if confirm_block.is_some() || status_msg.is_some() {
        draw_status_bar(root[2], f, snap, status_msg, confirm_block);
    }
    match view {
        ViewMode::Devices => draw_devices(root[3], f, snap, sort, table_state),
        ViewMode::Blocked => draw_blocked(root[3], f, snap, table_state),
    }
    draw_footer(root[4], f, snap, sort, view);
}

fn draw_status_bar(
    area: Rect,
    f: &mut ratatui::Frame,
    snap: &NetworkSnapshot,
    status_msg: Option<&(String, bool)>,
    confirm_block: Option<usize>,
) {
    let line = if let Some(idx) = confirm_block {
        let name = snap
            .devices
            .get(idx)
            .and_then(|d| d.hostname.clone())
            .unwrap_or_else(|| "device".into());
        let mac = snap
            .devices
            .get(idx)
            .and_then(|d| d.mac.clone())
            .unwrap_or_else(|| "?".into());
        Line::from(vec![
            Span::styled(
                " CONFIRM ",
                Style::default().fg(Color::Black).bg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("  Block {name} ({mac}) on router?  "),
                Style::default().fg(Color::White),
            ),
            Span::styled(" y ", Style::default().fg(Color::Black).bg(Color::Green)),
            Span::raw(" yes  "),
            Span::styled(" n ", Style::default().fg(Color::Black).bg(Color::DarkGray)),
            Span::raw(" no"),
        ])
    } else if let Some((msg, err)) = status_msg {
        Line::from(vec![
            Span::styled(
                if *err { " ERROR " } else { " OK " },
                Style::default()
                    .fg(Color::Black)
                    .bg(if *err { Color::Red } else { Color::Green }),
            ),
            Span::raw("  "),
            Span::styled(
                msg.as_str(),
                Style::default().fg(if *err { Color::Red } else { Color::Green }),
            ),
        ])
    } else {
        Line::from("")
    };
    f.render_widget(
        Paragraph::new(line).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        ),
        area,
    );
}

fn draw_top_cards(area: Rect, f: &mut ratatui::Frame, snap: &NetworkSnapshot) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(area);

    draw_wifi_card(cols[0], f, snap.wifi.as_ref());
    draw_traffic_card(cols[1], f, snap);
}

fn signal_bars(dbm: Option<i32>) -> (&'static str, Color) {
    let Some(s) = dbm else {
        return ("····", Color::DarkGray);
    };
    // Typical WiFi: -30 excellent … -90 unusable
    if s >= -50 {
        ("████", Color::Green)
    } else if s >= -60 {
        ("███·", Color::Green)
    } else if s >= -70 {
        ("██··", Color::Yellow)
    } else if s >= -80 {
        ("█···", Color::Red)
    } else {
        ("····", Color::Red)
    }
}

fn draw_wifi_card(area: Rect, f: &mut ratatui::Frame, wifi: Option<&WifiLink>) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(Span::styled(
            " WiFi link ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let lines: Vec<Line> = if let Some(w) = wifi {
        let ssid = w
            .ssid
            .clone()
            .unwrap_or_else(|| "(disconnected)".into());
        let (bars, bar_color) = signal_bars(w.signal_dbm);
        let sig = w
            .signal_dbm
            .map(|s| format!("{s} dBm"))
            .unwrap_or_else(|| "n/a".into());
        let ch = match (w.channel, w.channel_width_mhz, w.freq_mhz) {
            (Some(c), Some(width), Some(freq)) => format!("{c} · {width} MHz · {freq} MHz"),
            (Some(c), Some(width), None) => format!("{c} · {width} MHz"),
            (Some(c), _, _) => format!("{c}"),
            _ => "n/a".into(),
        };
        let br = format!(
            "↓ {}  ↑ {} Mbit/s",
            w.rx_bitrate_mbps
                .map(|b| format!("{b:.0}"))
                .unwrap_or_else(|| "-".into()),
            w.tx_bitrate_mbps
                .map(|b| format!("{b:.0}"))
                .unwrap_or_else(|| "-".into()),
        );
        let addr = format!(
            "{}  →  {}",
            w.ip.map(|i| i.to_string()).unwrap_or_else(|| "-".into()),
            w.gateway
                .map(|i| i.to_string())
                .unwrap_or_else(|| "-".into()),
        );
        let bssid = format!(
            "{}  ·  up {}",
            w.bssid.as_deref().unwrap_or("-"),
            w.connected_secs
                .map(format_duration)
                .unwrap_or_else(|| "-".into()),
        );
        let iface = w.iface.clone();
        vec![
            kv_line_owned("SSID", ssid, Color::Cyan),
            Line::from(vec![
                Span::styled("  Signal   ", Style::default().fg(Color::DarkGray)),
                Span::styled(format!("{bars} "), Style::default().fg(bar_color)),
                Span::styled(sig, Style::default().fg(Color::White)),
                Span::styled(format!("  ·  {iface}"), Style::default().fg(Color::DarkGray)),
            ]),
            kv_line_owned("Channel", ch, Color::White),
            kv_line_owned("Bitrate", br, Color::White),
            kv_line_owned("Address", addr, Color::White),
            kv_line_owned("BSSID", bssid, Color::DarkGray),
        ]
    } else {
        vec![Line::from(Span::styled(
            "  No WiFi link info",
            Style::default().fg(Color::Red),
        ))]
    };

    f.render_widget(Paragraph::new(lines), inner);
}

fn draw_traffic_card(area: Rect, f: &mut ratatui::Frame, snap: &NetworkSnapshot) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Green))
        .title(Span::styled(
            " Traffic · this machine ",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  Live      ", Style::default().fg(Color::DarkGray)),
            Span::styled("↓ ", Style::default().fg(Color::Green)),
            Span::styled(
                format_bps(snap.local_rates.rx_bps),
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("            ", Style::default()),
            Span::styled("↑ ", Style::default().fg(Color::Magenta)),
            Span::styled(
                format_bps(snap.local_rates.tx_bps),
                Style::default()
                    .fg(Color::Magenta)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Total     ", Style::default().fg(Color::DarkGray)),
            Span::styled("↓ ", Style::default().fg(Color::Green)),
            Span::styled(
                format_bytes(snap.local_traffic.rx_bytes),
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(vec![
            Span::styled("            ", Style::default()),
            Span::styled("↑ ", Style::default().fg(Color::Magenta)),
            Span::styled(
                format_bytes(snap.local_traffic.tx_bytes),
                Style::default().fg(Color::White),
            ),
        ]),
    ];
    f.render_widget(Paragraph::new(lines), inner);
}

fn draw_router_strip(area: Rect, f: &mut ratatui::Frame, snap: &NetworkSnapshot) {
    let (badge_bg, badge_fg, badge) = if snap.router.connected {
        (Color::Green, Color::Black, " ONLINE ")
    } else if !snap.router.enabled {
        (Color::DarkGray, Color::White, " OFF ")
    } else if snap.router.message.contains("no password")
        || snap.router.message.contains("not connected")
    {
        (Color::Yellow, Color::Black, " SETUP ")
    } else {
        (Color::Red, Color::White, " ERROR ")
    };

    let mut spans = vec![
        Span::styled(
            " Router ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Blue)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" "),
        Span::styled(badge, Style::default().fg(badge_fg).bg(badge_bg)),
        Span::raw("  "),
        Span::styled(
            snap.router.name.as_deref().unwrap_or("none"),
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("  ·  ", Style::default().fg(Color::DarkGray)),
        Span::styled(&snap.router.message, Style::default().fg(Color::Gray)),
    ];

    if !snap.router.connected && snap.router.enabled {
        spans.push(Span::styled(
            "  →  press c for setup",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ));
    } else if snap.router.connected {
        spans.push(Span::styled(
            format!(
                "  ·  {} clients  ·  {} blocked",
                snap.router.device_count,
                snap.blocked.len()
            ),
            Style::default().fg(Color::Green),
        ));
        if !snap.router.per_host_traffic {
            spans.push(Span::styled(
                "  ·  rates: this PC only",
                Style::default().fg(Color::DarkGray),
            ));
        }
    }

    if !snap.errors.is_empty() {
        spans.push(Span::styled(
            format!("  ! {}", snap.errors[0]),
            Style::default().fg(Color::Red),
        ));
    }

    let p = Paragraph::new(Line::from(spans)).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    f.render_widget(p, area);
}

fn kv_line_owned(key: &str, value: String, value_color: Color) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("  {key:<8} "), Style::default().fg(Color::DarkGray)),
        Span::styled(value, Style::default().fg(value_color)),
    ])
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
        Cell::from("State"),
        Cell::from("↓ Data"),
        Cell::from("↑ Data"),
        Cell::from("↓ Rate"),
        Cell::from("↑ Rate"),
    ])
    .style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    )
    .height(1);

    let rows = snap.devices.iter().enumerate().map(|(i, d)| {
        let name = {
            let base = d.hostname.clone().unwrap_or_else(|| "—".into());
            if d.is_self {
                format!("★ {base}")
            } else if d.is_gateway {
                format!("⌂ {base}")
            } else if d.blocked {
                format!("⊘ {base}")
            } else {
                base
            }
        };
        let style = if d.blocked {
            Style::default().fg(Color::Red)
        } else if d.is_self {
            Style::default().fg(Color::Cyan)
        } else if !d.online {
            Style::default().fg(Color::DarkGray)
        } else {
            Style::default().fg(Color::Green)
        };

        let state = if d.blocked {
            "blocked"
        } else if d.online {
            "online"
        } else {
            "stale"
        };
        let state_cell = Cell::from(state).style(if d.blocked {
            Style::default().fg(Color::Red)
        } else if d.online {
            Style::default().fg(Color::Green)
        } else {
            Style::default().fg(Color::DarkGray)
        });

        // Rates only for this machine (and any device with counters)
        let rate_na = "n/a";
        Row::new(vec![
            Cell::from(format!("{}", i + 1)),
            Cell::from(name),
            Cell::from(d.ip.map(|i| i.to_string()).unwrap_or_else(|| "—".into())),
            Cell::from(d.mac.clone().unwrap_or_else(|| "—".into())),
            Cell::from(d.vendor.clone().unwrap_or_else(|| "—".into())),
            Cell::from(d.link.as_str()),
            state_cell,
            Cell::from(
                d.bytes_rx
                    .map(format_bytes)
                    .unwrap_or_else(|| if d.is_self { "—".into() } else { rate_na.into() }),
            ),
            Cell::from(
                d.bytes_tx
                    .map(format_bytes)
                    .unwrap_or_else(|| if d.is_self { "—".into() } else { rate_na.into() }),
            ),
            Cell::from(
                d.rate_rx_bps
                    .map(format_bps)
                    .unwrap_or_else(|| if d.is_self { "—".into() } else { rate_na.into() }),
            ),
            Cell::from(
                d.rate_tx_bps
                    .map(format_bps)
                    .unwrap_or_else(|| if d.is_self { "—".into() } else { rate_na.into() }),
            ),
        ])
        .style(style)
    });

    let widths = [
        Constraint::Length(3),
        Constraint::Length(16),
        Constraint::Length(15),
        Constraint::Length(18),
        Constraint::Length(12),
        Constraint::Length(5),
        Constraint::Length(8),
        Constraint::Length(10),
        Constraint::Length(10),
        Constraint::Length(10),
        Constraint::Length(10),
    ];

    let note = if snap.router.per_host_traffic {
        ""
    } else {
        "  ·  n/a rates = not exposed by router"
    };
    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray))
                .title(Span::styled(
                    format!(
                        " Devices ({})  ·  sort: {}{} ",
                        snap.devices.len(),
                        sort.label(),
                        note
                    ),
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                )),
        )
        .row_highlight_style(
            Style::default()
                .bg(Color::Rgb(40, 40, 50))
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(" │ ");

    f.render_stateful_widget(table, area, table_state);
}

fn draw_blocked(
    area: Rect,
    f: &mut ratatui::Frame,
    snap: &NetworkSnapshot,
    table_state: &mut TableState,
) {
    let header = Row::new(vec![
        Cell::from("#"),
        Cell::from("Name"),
        Cell::from("MAC"),
        Cell::from("Protocol"),
        Cell::from("Type"),
        Cell::from("Rule ID"),
    ])
    .style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    )
    .height(1);

    let mode = if snap.mac_filter.mode.is_empty() {
        "—".into()
    } else {
        snap.mac_filter.mode.clone()
    };
    let title = format!(
        " Blocked devices ({})  ·  filter {}  ·  mode: {} ",
        snap.blocked.len(),
        if snap.mac_filter.enabled {
            "ON"
        } else {
            "OFF"
        },
        mode
    );

    let rows = if snap.blocked.is_empty() {
        vec![Row::new(vec![
            Cell::from(""),
            Cell::from("No blocked devices"),
            Cell::from("—"),
            Cell::from("—"),
            Cell::from("—"),
            Cell::from("press b to go back · x on a device to block"),
        ])
        .style(Style::default().fg(Color::DarkGray))]
    } else {
        snap.blocked
            .iter()
            .enumerate()
            .map(|(i, b)| {
                Row::new(vec![
                    Cell::from(format!("{}", i + 1)),
                    Cell::from(b.name.clone()),
                    Cell::from(b.mac.clone()),
                    Cell::from(b.protocol.clone().unwrap_or_else(|| "—".into())),
                    Cell::from(b.filter_type.clone().unwrap_or_else(|| "—".into())),
                    Cell::from(b.inst_id.clone()),
                ])
                .style(Style::default().fg(Color::Red))
            })
            .collect()
    };

    let table = Table::new(
        rows,
        [
            Constraint::Length(3),
            Constraint::Length(18),
            Constraint::Length(18),
            Constraint::Length(10),
            Constraint::Length(14),
            Constraint::Min(16),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Red))
            .title(Span::styled(
                title,
                Style::default()
                    .fg(Color::Red)
                    .add_modifier(Modifier::BOLD),
            )),
    )
    .row_highlight_style(
        Style::default()
            .bg(Color::Rgb(50, 30, 30))
            .add_modifier(Modifier::BOLD),
    )
    .highlight_symbol(" │ ");

    f.render_stateful_widget(table, area, table_state);
}

fn draw_footer(
    area: Rect,
    f: &mut ratatui::Frame,
    snap: &NetworkSnapshot,
    sort: SortKey,
    view: ViewMode,
) {
    let mut spans = Vec::new();
    let keys: &[(&str, &str)] = match view {
        ViewMode::Devices => &[
            ("q", "quit"),
            ("r", "refresh"),
            ("s", "sort"),
            ("x", "block"),
            ("b", "blocked"),
            ("c", "setup"),
            ("?", "help"),
        ],
        ViewMode::Blocked => &[
            ("q", "quit"),
            ("r", "refresh"),
            ("u", "unblock"),
            ("b", "devices"),
            ("c", "setup"),
            ("?", "help"),
        ],
    };
    for (key, label) in keys {
        spans.push(Span::styled(
            format!(" {key} "),
            Style::default().fg(Color::Black).bg(Color::DarkGray),
        ));
        spans.push(Span::styled(
            format!(" {label}  "),
            Style::default().fg(Color::Gray),
        ));
    }
    spans.push(Span::styled(
        format!(
            "· {} · {} online · {} blocked",
            match view {
                ViewMode::Devices => format!("sort={}", sort.label()),
                ViewMode::Blocked => "blocked list".into(),
            },
            snap.devices.len(),
            snap.blocked.len()
        ),
        Style::default().fg(Color::DarkGray),
    ));
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn draw_help(area: Rect, f: &mut ratatui::Frame) {
    let text = vec![
        Line::from(Span::styled(
            "mywifistats help",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from("  q / Esc     Quit (or close help)"),
        Line::from("  r           Refresh snapshot now"),
        Line::from("  s           Cycle sort (devices view)"),
        Line::from("  b / Tab     Toggle Devices ↔ Blocked list"),
        Line::from("  x           Block selected device (router MAC filter)"),
        Line::from("  u           Unblock selected rule (blocked view)"),
        Line::from("  c           Open setup (interface + router credentials)"),
        Line::from("  j / ↓       Next row"),
        Line::from("  k / ↑       Previous row"),
        Line::from("  ? / h       Toggle this help"),
        Line::from(""),
        Line::from(Span::styled(
            "Why other devices show n/a for rates",
            Style::default().fg(Color::Yellow),
        )),
        Line::from("  Your laptop is a WiFi client — only the router sees every"),
        Line::from("  device's packets. This ZTE firmware exposes the client list"),
        Line::from("  (name/IP/MAC) and MAC filter, but NOT per-host byte counters."),
        Line::from("  Live ↓/↑ for ★ this machine comes from local interface stats."),
        Line::from(""),
        Line::from(Span::styled("Blocking", Style::default().fg(Color::Yellow))),
        Line::from("  Uses the router's firewall MAC filter (blacklist mode)."),
        Line::from("  Requires router login (setup). Cannot block this PC."),
        Line::from(""),
        Line::from(format!("  Config: {}", Config::config_path().display())),
        Line::from(""),
        Line::from(Span::styled(
            "Press ? to return",
            Style::default().fg(Color::DarkGray),
        )),
    ];
    let p = Paragraph::new(text).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .title(" Help "),
    );
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
    println!("\n=== Router: {} ===", snap.router.message);
    println!(
        "MAC filter: {}  mode={}  blocked={}",
        if snap.mac_filter.enabled { "ON" } else { "OFF" },
        snap.mac_filter.mode,
        snap.blocked.len()
    );
    println!("Note: per-device rates are only for this PC (router firmware has no per-host traffic).");

    let mut table = comfy_table::Table::new();
    table.set_header(vec![
        "#", "Hostname", "IP", "MAC", "Vendor", "Link", "State", "↓ Data", "↑ Data", "↓ Rate",
        "↑ Rate",
    ]);
    for (i, d) in snap.devices.iter().enumerate() {
        let mut name = d.hostname.clone().unwrap_or_else(|| "-".into());
        if d.is_self {
            name.push_str(" *");
        }
        if d.blocked {
            name.push_str(" [blocked]");
        }
        let na = if d.is_self { "-" } else { "n/a" };
        table.add_row(vec![
            (i + 1).to_string(),
            name,
            d.ip.map(|i| i.to_string()).unwrap_or_else(|| "-".into()),
            d.mac.clone().unwrap_or_else(|| "-".into()),
            d.vendor.clone().unwrap_or_else(|| "-".into()),
            d.link.as_str().to_string(),
            if d.blocked {
                "blocked"
            } else if d.online {
                "online"
            } else {
                "stale"
            }
            .into(),
            d.bytes_rx.map(format_bytes).unwrap_or_else(|| na.into()),
            d.bytes_tx.map(format_bytes).unwrap_or_else(|| na.into()),
            d.rate_rx_bps.map(format_bps).unwrap_or_else(|| na.into()),
            d.rate_tx_bps.map(format_bps).unwrap_or_else(|| na.into()),
        ]);
    }
    println!("\n{table}");

    if !snap.blocked.is_empty() {
        println!("\n=== Blocked ===");
        for b in &snap.blocked {
            println!("  {}  {}  ({})", b.name, b.mac, b.inst_id);
        }
    }

    if !snap.errors.is_empty() {
        println!("\nWarnings:");
        for e in &snap.errors {
            println!("  - {e}");
        }
    }
}
