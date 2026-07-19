use crate::config::Config;
use crate::router::zte_f670l::ZteF670l;
use crate::router::RouterBackend;
use crate::wifi;
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::Terminal;
use std::io::{stdout, Stdout};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    Interface,
    RouterEnabled,
    BaseUrl,
    Username,
    Password,
    Backend,
}

impl Field {
    const ALL: [Field; 6] = [
        Field::Interface,
        Field::RouterEnabled,
        Field::BaseUrl,
        Field::Username,
        Field::Password,
        Field::Backend,
    ];

    fn label(self) -> &'static str {
        match self {
            Field::Interface => "Interface",
            Field::RouterEnabled => "Router enabled",
            Field::BaseUrl => "Router URL",
            Field::Username => "Username",
            Field::Password => "Password",
            Field::Backend => "Backend",
        }
    }

    fn help(self) -> &'static str {
        match self {
            Field::Interface => "Wireless interface (empty = auto-detect)",
            Field::RouterEnabled => "Space to toggle · fetch clients from home router",
            Field::BaseUrl => "Usually http://192.168.1.1",
            Field::Username => "Router admin username (often admin)",
            Field::Password => "Router admin password · stored in config (mode 0600)",
            Field::Backend => "zte_f670l for ZTE F670L / F670LV9.0",
        }
    }

    fn next(self) -> Self {
        let i = Self::ALL.iter().position(|f| *f == self).unwrap_or(0);
        Self::ALL[(i + 1) % Self::ALL.len()]
    }

    fn prev(self) -> Self {
        let i = Self::ALL.iter().position(|f| *f == self).unwrap_or(0);
        Self::ALL[(i + Self::ALL.len() - 1) % Self::ALL.len()]
    }

    fn is_text(self) -> bool {
        !matches!(self, Field::RouterEnabled)
    }
}

struct SetupState {
    interface: String,
    router_enabled: bool,
    base_url: String,
    username: String,
    password: String,
    backend: String,
    focus: Field,
    editing: bool,
    status: String,
    status_ok: bool,
    saved: bool,
    password_was_set: bool,
}

impl SetupState {
    fn from_config(cfg: &Config) -> Self {
        let password = cfg.router.password.clone().unwrap_or_default();
        let password_was_set = !password.is_empty() || cfg.router_password().is_some();
        // Prefer stored password; if only env has it, leave blank but note in status
        let (password, note) = if !password.is_empty() {
            (password, String::new())
        } else if cfg.router_password().is_some() {
            (
                String::new(),
                "Password currently set via environment variable.".into(),
            )
        } else {
            (String::new(), String::new())
        };

        let detected = wifi::detect_interface(cfg.interface.as_deref())
            .unwrap_or_else(|_| "wlan0".into());

        Self {
            interface: cfg.interface.clone().unwrap_or_default(),
            router_enabled: cfg.router.enabled,
            base_url: if cfg.router.base_url.is_empty() {
                "http://192.168.1.1".into()
            } else {
                cfg.router.base_url.clone()
            },
            username: if cfg.router.username.is_empty() {
                "admin".into()
            } else {
                cfg.router.username.clone()
            },
            password,
            backend: if cfg.router.backend.is_empty() {
                "zte_f670l".into()
            } else {
                cfg.router.backend.clone()
            },
            focus: Field::Interface,
            editing: false,
            status: if note.is_empty() {
                format!("Detected interface: {detected} · Tab fields · Enter edit · s save")
            } else {
                note
            },
            status_ok: true,
            saved: false,
            password_was_set,
        }
    }

    fn field_value(&self, f: Field) -> String {
        match f {
            Field::Interface => {
                if self.interface.is_empty() {
                    "(auto)".into()
                } else {
                    self.interface.clone()
                }
            }
            Field::RouterEnabled => {
                if self.router_enabled {
                    "Yes".into()
                } else {
                    "No".into()
                }
            }
            Field::BaseUrl => self.base_url.clone(),
            Field::Username => self.username.clone(),
            Field::Password => {
                if self.editing && self.focus == Field::Password {
                    self.password.clone()
                } else if self.password.is_empty() {
                    if self.password_was_set {
                        "(set — enter to change)".into()
                    } else {
                        "(empty)".into()
                    }
                } else {
                    "•".repeat(self.password.chars().count().clamp(4, 24))
                }
            }
            Field::Backend => self.backend.clone(),
        }
    }

    fn active_buffer_mut(&mut self) -> Option<&mut String> {
        match self.focus {
            Field::Interface => Some(&mut self.interface),
            Field::BaseUrl => Some(&mut self.base_url),
            Field::Username => Some(&mut self.username),
            Field::Password => Some(&mut self.password),
            Field::Backend => Some(&mut self.backend),
            Field::RouterEnabled => None,
        }
    }

    fn to_config(&self) -> Config {
        let mut cfg = Config::default();
        cfg.interface = if self.interface.trim().is_empty() {
            None
        } else {
            Some(self.interface.trim().to_string())
        };
        cfg.router.enabled = self.router_enabled;
        cfg.router.base_url = self.base_url.trim().to_string();
        cfg.router.username = self.username.trim().to_string();
        cfg.router.backend = if self.backend.trim().is_empty() {
            "zte_f670l".into()
        } else {
            self.backend.trim().to_string()
        };
        // Keep existing password if user left blank and one was set before
        if self.password.is_empty() {
            // load previous from disk to preserve
            if let Ok(old) = Config::load() {
                cfg.router.password = old.router.password.filter(|p| !p.is_empty());
            } else {
                cfg.router.password = None;
            }
        } else {
            cfg.router.password = Some(self.password.clone());
        }
        cfg
    }

    fn test_connection(&mut self) {
        if !self.router_enabled {
            self.status = "Router disabled — enable it to test.".into();
            self.status_ok = false;
            return;
        }
        let cfg = self.to_config();
        let Some(password) = cfg.router_password() else {
            self.status = "No password set — enter password first.".into();
            self.status_ok = false;
            return;
        };
        self.status = "Testing login…".into();
        self.status_ok = true;

        match ZteF670l::new(&cfg.router.base_url, &cfg.router.username, &password) {
            Ok(mut z) => match z.login() {
                Ok(()) => match z.list_devices() {
                    Ok(devs) => {
                        let caps = z.capabilities();
                        self.status = format!(
                            "OK — {} · {} device(s) · {}",
                            z.name(),
                            devs.len(),
                            if caps.per_host_traffic {
                                "per-host traffic available"
                            } else {
                                "device list only (no per-host traffic)"
                            }
                        );
                        self.status_ok = true;
                    }
                    Err(e) => {
                        self.status = format!("Login OK but device list failed: {e}");
                        self.status_ok = false;
                    }
                },
                Err(e) => {
                    self.status = format!("Login failed: {e}");
                    self.status_ok = false;
                }
            },
            Err(e) => {
                self.status = format!("Client error: {e}");
                self.status_ok = false;
            }
        }
    }

    fn save(&mut self) -> Result<()> {
        let cfg = self.to_config();
        // Validate interface if set
        if let Some(iface) = &cfg.interface {
            if !std::path::Path::new(&format!("/sys/class/net/{iface}")).exists() {
                self.status = format!("Interface '{iface}' not found");
                self.status_ok = false;
                anyhow::bail!("interface not found");
            }
        }
        cfg.save()?;
        self.saved = true;
        self.status = format!("Saved {}", Config::config_path().display());
        self.status_ok = true;
        if !self.password.is_empty() {
            self.password_was_set = true;
        }
        Ok(())
    }
}

/// Run setup TUI. Returns `true` if config was saved.
pub fn run_setup(initial: &Config) -> Result<bool> {
    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = run_setup_loop(&mut terminal, initial);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}

fn run_setup_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    initial: &Config,
) -> Result<bool> {
    let mut state = SetupState::from_config(initial);

    loop {
        terminal.draw(|f| draw_setup(f.area(), f, &state))?;

        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                if state.editing {
                    match key.code {
                        KeyCode::Esc => {
                            state.editing = false;
                            state.status = "Edit cancelled".into();
                            state.status_ok = true;
                        }
                        KeyCode::Enter => {
                            state.editing = false;
                            state.status = format!("{} updated", state.focus.label());
                            state.status_ok = true;
                            if state.focus == Field::Password && !state.password.is_empty() {
                                state.password_was_set = true;
                            }
                        }
                        KeyCode::Backspace => {
                            if let Some(buf) = state.active_buffer_mut() {
                                buf.pop();
                            }
                        }
                        KeyCode::Char(c) => {
                            if let Some(buf) = state.active_buffer_mut() {
                                buf.push(c);
                            }
                        }
                        _ => {}
                    }
                } else {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => {
                            if state.saved {
                                return Ok(true);
                            }
                            return Ok(false);
                        }
                        KeyCode::Tab | KeyCode::Down | KeyCode::Char('j') => {
                            state.focus = state.focus.next();
                        }
                        KeyCode::BackTab | KeyCode::Up | KeyCode::Char('k') => {
                            state.focus = state.focus.prev();
                        }
                        KeyCode::Enter => {
                            if state.focus.is_text() {
                                // Clear password placeholder when starting edit if empty display
                                if state.focus == Field::Password {
                                    // keep existing typed password
                                }
                                state.editing = true;
                                state.status =
                                    format!("Editing {} — Enter confirm · Esc cancel", state.focus.label());
                                state.status_ok = true;
                            } else {
                                state.router_enabled = !state.router_enabled;
                            }
                        }
                        KeyCode::Char(' ') if state.focus == Field::RouterEnabled => {
                            state.router_enabled = !state.router_enabled;
                        }
                        KeyCode::Char('t') | KeyCode::Char('T') => {
                            state.test_connection();
                        }
                        KeyCode::Char('s') | KeyCode::Char('S') => match state.save() {
                            Ok(()) => {
                                // brief pause feel — stay open so user sees message; next q exits with saved
                            }
                            Err(e) => {
                                if !state.status.contains("not found") {
                                    state.status = format!("Save failed: {e}");
                                    state.status_ok = false;
                                }
                            }
                        },
                        KeyCode::Char('w') | KeyCode::Char('W') => {
                            // save and quit
                            match state.save() {
                                Ok(()) => return Ok(true),
                                Err(e) => {
                                    state.status = format!("Save failed: {e}");
                                    state.status_ok = false;
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}

fn draw_setup(area: Rect, f: &mut ratatui::Frame, state: &SetupState) {
    f.render_widget(Clear, area);

    let outer = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(Span::styled(
            " mywifistats · setup ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ));
    let inner = outer.inner(area);
    f.render_widget(outer, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(Field::ALL.len() as u16 + 2),
            Constraint::Length(3),
            Constraint::Length(4),
            Constraint::Min(1),
            Constraint::Length(2),
        ])
        .split(inner);

    // Intro
    let intro = Paragraph::new(vec![
        Line::from(Span::styled(
            "Configure WiFi interface and home router access",
            Style::default().fg(Color::White),
        )),
        Line::from(Span::styled(
            format!("Config file: {}", Config::config_path().display()),
            Style::default().fg(Color::DarkGray),
        )),
    ]);
    f.render_widget(intro, chunks[0]);

    // Fields
    let mut field_lines = Vec::new();
    for fkey in Field::ALL {
        let selected = state.focus == fkey;
        let editing = selected && state.editing;
        let marker = if editing {
            "▸"
        } else if selected {
            "›"
        } else {
            " "
        };
        let label_style = if selected {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Gray)
        };
        let val_style = if editing {
            Style::default()
                .fg(Color::Black)
                .bg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else if selected {
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Cyan)
        };

        let value = state.field_value(fkey);
        let display_val = if editing {
            format!(" {value}█ ")
        } else {
            format!(" {value} ")
        };

        // Toggle visual for enabled
        let value_spans = if fkey == Field::RouterEnabled {
            let on = state.router_enabled;
            vec![
                Span::styled(format!("{marker} "), label_style),
                Span::styled(format!("{:16}", fkey.label()), label_style),
                Span::styled(
                    if on { " ● Yes " } else { " ○ No  " },
                    if on {
                        Style::default().fg(Color::Black).bg(Color::Green)
                    } else {
                        Style::default().fg(Color::Black).bg(Color::DarkGray)
                    },
                ),
            ]
        } else {
            vec![
                Span::styled(format!("{marker} "), label_style),
                Span::styled(format!("{:16}", fkey.label()), label_style),
                Span::styled(display_val, val_style),
            ]
        };
        field_lines.push(Line::from(value_spans));
    }

    let fields = Paragraph::new(field_lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Settings ")
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    f.render_widget(fields, chunks[1]);

    // Field help
    let help = Paragraph::new(Line::from(vec![
        Span::styled("  ", Style::default()),
        Span::styled(state.focus.help(), Style::default().fg(Color::DarkGray)),
    ]));
    f.render_widget(help, chunks[2]);

    // Status
    let status_color = if state.status_ok {
        Color::Green
    } else {
        Color::Red
    };
    let status = Paragraph::new(Line::from(vec![
        Span::styled(
            " Status ",
            Style::default().fg(Color::Black).bg(status_color),
        ),
        Span::raw("  "),
        Span::styled(&state.status, Style::default().fg(status_color)),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    )
    .wrap(Wrap { trim: true });
    f.render_widget(status, chunks[3]);

    // Actions
    let actions = Paragraph::new(vec![
        Line::from(vec![
            Span::styled(" t ", Style::default().fg(Color::Black).bg(Color::Blue)),
            Span::raw(" Test login   "),
            Span::styled(" s ", Style::default().fg(Color::Black).bg(Color::Green)),
            Span::raw(" Save   "),
            Span::styled(" w ", Style::default().fg(Color::Black).bg(Color::Cyan)),
            Span::raw(" Save & quit   "),
            Span::styled(" q ", Style::default().fg(Color::Black).bg(Color::DarkGray)),
            Span::raw(" Quit"),
        ]),
        Line::from(Span::styled(
            " Tab/↑↓ move · Enter edit (or toggle) · Esc cancel edit",
            Style::default().fg(Color::DarkGray),
        )),
    ])
    .alignment(Alignment::Left);
    f.render_widget(actions, chunks[5]);
}
