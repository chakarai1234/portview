//! Interactive TUI dashboard (ratatui + crossterm) — the default experience.
//!
//! A live, auto-refreshing table of every open socket with full process
//! attribution. Navigate with the keyboard, filter/sort live, open a detail
//! pane, and kill the selected process (with a confirmation prompt).
//!
//! Crossterm is imported via `ratatui::crossterm` so its version is always the
//! one ratatui was built against.

use crate::collector::{self, CollectOptions};
use crate::killer;
use crate::model::PortEntry;

use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState, Wrap};
use ratatui::{DefaultTerminal, Frame};

use std::time::{Duration, Instant};

/// How the table is sorted. Cycled with the `s` key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SortKey {
    Port,
    Pid,
    Process,
    Proto,
}

impl SortKey {
    fn next(self) -> Self {
        match self {
            SortKey::Port => SortKey::Pid,
            SortKey::Pid => SortKey::Process,
            SortKey::Process => SortKey::Proto,
            SortKey::Proto => SortKey::Port,
        }
    }
    fn label(self) -> &'static str {
        match self {
            SortKey::Port => "port",
            SortKey::Pid => "pid",
            SortKey::Process => "process",
            SortKey::Proto => "proto",
        }
    }
}

/// Transient status line message (e.g. result of a kill) with an expiry.
struct StatusMsg {
    text: String,
    is_error: bool,
    until: Instant,
}

/// Which modal, if any, is currently overlaid.
enum Modal {
    None,
    /// Confirm killing the given pid/name; `force` toggled with TAB.
    KillConfirm {
        pid: u32,
        name: String,
        force: bool,
    },
    /// Live filter text entry.
    Filter,
    /// Full detail view of the selected entry.
    Detail,
}

/// All mutable application state for the TUI.
struct App {
    /// Every socket from the last refresh (unfiltered).
    all: Vec<PortEntry>,
    /// Indices into `all` that pass the current filters (what's displayed).
    visible: Vec<usize>,
    state: TableState,

    // View toggles / query
    show_tcp: bool,
    show_udp: bool,
    listening_only: bool,
    /// Include reserved ports (0-1023). When false, only >= 1024 are collected.
    include_reserved: bool,
    sort: SortKey,
    filter: String,

    // Chrome
    modal: Modal,
    status: Option<StatusMsg>,
    elevated: bool,

    // Refresh bookkeeping
    last_refresh: Instant,
    refresh_every: Duration,
    error: Option<String>,
}

impl App {
    fn new(include_reserved: bool) -> Self {
        let mut app = App {
            all: Vec::new(),
            visible: Vec::new(),
            state: TableState::default(),
            show_tcp: true,
            show_udp: true,
            listening_only: false,
            include_reserved,
            sort: SortKey::Port,
            filter: String::new(),
            modal: Modal::None,
            status: None,
            elevated: collector::is_elevated(),
            last_refresh: Instant::now() - Duration::from_secs(60),
            refresh_every: Duration::from_millis(2000),
            error: None,
        };
        app.refresh();
        app
    }

    /// Pull a fresh socket snapshot. Proto/listening/text filters are applied
    /// in memory (instant toggles); the reserved-port filter is applied at
    /// collection time so toggling it triggers a re-scan.
    fn refresh(&mut self) {
        let opts = CollectOptions {
            include_reserved: self.include_reserved,
            ..CollectOptions::default()
        };
        match collector::collect(opts) {
            Ok(entries) => {
                self.all = entries;
                self.error = None;
            }
            Err(e) => {
                self.error = Some(e);
            }
        }
        self.last_refresh = Instant::now();
        self.recompute_visible();
    }

    /// Rebuild `visible` from `all` applying proto toggles, listening filter,
    /// the free-text filter, and the current sort. Keeps the selection roughly
    /// in place.
    fn recompute_visible(&mut self) {
        let needle = self.filter.to_lowercase();

        let mut idxs: Vec<usize> = self
            .all
            .iter()
            .enumerate()
            .filter(|(_, e)| match e.protocol {
                crate::model::Protocol::Tcp => self.show_tcp,
                crate::model::Protocol::Udp => self.show_udp,
            })
            .filter(|(_, e)| !self.listening_only || e.is_listening())
            .filter(|(_, e)| needle.is_empty() || entry_matches(e, &needle))
            .map(|(i, _)| i)
            .collect();

        idxs.sort_by(|&a, &b| self.compare(&self.all[a], &self.all[b]));
        self.visible = idxs;

        // Clamp / initialise the selection.
        if self.visible.is_empty() {
            self.state.select(None);
        } else {
            let sel = self
                .state
                .selected()
                .unwrap_or(0)
                .min(self.visible.len() - 1);
            self.state.select(Some(sel));
        }
    }

    fn compare(&self, a: &PortEntry, b: &PortEntry) -> std::cmp::Ordering {
        use std::cmp::Ordering;
        match self.sort {
            SortKey::Port => a.local_port.cmp(&b.local_port),
            SortKey::Pid => a.pid.unwrap_or(u32::MAX).cmp(&b.pid.unwrap_or(u32::MAX)),
            SortKey::Process => a
                .name_str()
                .to_lowercase()
                .cmp(&b.name_str().to_lowercase()),
            SortKey::Proto => a.proto_label().cmp(&b.proto_label()),
        }
        .then_with(|| a.local_port.cmp(&b.local_port))
        .then(Ordering::Equal)
    }

    /// The currently-selected entry, if any.
    fn selected_entry(&self) -> Option<&PortEntry> {
        let sel = self.state.selected()?;
        let idx = *self.visible.get(sel)?;
        self.all.get(idx)
    }

    fn select_next(&mut self) {
        if self.visible.is_empty() {
            return;
        }
        let i = self
            .state
            .selected()
            .map_or(0, |i| (i + 1) % self.visible.len());
        self.state.select(Some(i));
    }

    fn select_prev(&mut self) {
        if self.visible.is_empty() {
            return;
        }
        let i = self.state.selected().map_or(0, |i| {
            if i == 0 {
                self.visible.len() - 1
            } else {
                i - 1
            }
        });
        self.state.select(Some(i));
    }

    fn set_status(&mut self, text: impl Into<String>, is_error: bool) {
        self.status = Some(StatusMsg {
            text: text.into(),
            is_error,
            until: Instant::now() + Duration::from_secs(5),
        });
    }
}

/// Does an entry match the lowercase free-text needle? Searches the fields a
/// developer would type: port, process name, proto, pid, exe path, service.
fn entry_matches(e: &PortEntry, needle: &str) -> bool {
    e.local_port.to_string().contains(needle)
        || e.name_str().to_lowercase().contains(needle)
        || e.proto_label().to_lowercase().contains(needle)
        || e.pid_str().contains(needle)
        || e.exe_str().to_lowercase().contains(needle)
        || e.service_str().to_lowercase().contains(needle)
}

/// Entry point — set up the terminal, run the loop, always restore.
pub fn run(include_reserved: bool) -> Result<(), String> {
    let mut terminal = ratatui::init();
    let result = main_loop(&mut terminal, include_reserved);
    ratatui::restore();
    result
}

fn main_loop(terminal: &mut DefaultTerminal, include_reserved: bool) -> Result<(), String> {
    let mut app = App::new(include_reserved);

    loop {
        terminal
            .draw(|f| draw(f, &mut app))
            .map_err(|e| format!("render error: {e}"))?;

        // Poll so the loop ticks even without input (for auto-refresh).
        let poll = Duration::from_millis(200);
        if event::poll(poll).map_err(|e| format!("input poll error: {e}"))? {
            if let Event::Key(key) = event::read().map_err(|e| format!("input error: {e}"))? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                // Ctrl-C always quits, regardless of modal.
                if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
                    return Ok(());
                }
                if handle_key(&mut app, key.code) {
                    return Ok(()); // quit requested
                }
            }
        }

        // Expire stale status messages.
        if let Some(s) = &app.status {
            if Instant::now() >= s.until {
                app.status = None;
            }
        }

        // Auto-refresh when idle and no modal is blocking.
        if matches!(app.modal, Modal::None | Modal::Detail)
            && app.last_refresh.elapsed() >= app.refresh_every
        {
            app.refresh();
        }
    }
}

/// Handle a key press. Returns `true` if the app should quit.
fn handle_key(app: &mut App, code: KeyCode) -> bool {
    // Modal-specific handling first.
    match &mut app.modal {
        Modal::KillConfirm { pid, force, .. } => {
            match code {
                KeyCode::Char('y') | KeyCode::Enter => {
                    let (pid, force) = (*pid, *force);
                    app.modal = Modal::None;
                    match killer::kill(pid, force) {
                        Ok(msg) => app.set_status(msg, false),
                        Err(msg) => app.set_status(msg, true),
                    }
                    // Give the OS a moment, then refresh so the row disappears.
                    app.refresh();
                }
                KeyCode::Tab => {
                    *force = !*force;
                }
                KeyCode::Char('n') | KeyCode::Esc => {
                    app.modal = Modal::None;
                }
                _ => {}
            }
            return false;
        }
        Modal::Filter => {
            match code {
                KeyCode::Enter | KeyCode::Esc => {
                    app.modal = Modal::None;
                }
                KeyCode::Backspace => {
                    app.filter.pop();
                    app.recompute_visible();
                }
                KeyCode::Char(c) => {
                    app.filter.push(c);
                    app.recompute_visible();
                }
                _ => {}
            }
            return false;
        }
        Modal::Detail => {
            // Any of these close the detail pane.
            if matches!(code, KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q')) {
                app.modal = Modal::None;
            }
            return false;
        }
        Modal::None => {}
    }

    // Normal mode.
    match code {
        KeyCode::Char('q') | KeyCode::Esc => return true,
        KeyCode::Down | KeyCode::Char('j') => app.select_next(),
        KeyCode::Up | KeyCode::Char('k') => app.select_prev(),
        KeyCode::Char('g') => app.state.select(if app.visible.is_empty() {
            None
        } else {
            Some(0)
        }),
        KeyCode::Char('G') => app.state.select(if app.visible.is_empty() {
            None
        } else {
            Some(app.visible.len() - 1)
        }),
        KeyCode::Char('r') => {
            app.refresh();
            app.set_status("Refreshed.", false);
        }
        KeyCode::Char('l') => {
            app.listening_only = !app.listening_only;
            app.recompute_visible();
        }
        KeyCode::Char('t') => {
            app.show_tcp = !app.show_tcp;
            app.recompute_visible();
        }
        KeyCode::Char('u') => {
            app.show_udp = !app.show_udp;
            app.recompute_visible();
        }
        KeyCode::Char('a') => {
            // Toggle reserved ports (0-1023). This changes what's collected, so
            // re-scan rather than just re-filter.
            app.include_reserved = !app.include_reserved;
            app.refresh();
            app.set_status(
                if app.include_reserved {
                    "Showing all ports (incl. reserved 0-1023)."
                } else {
                    "Hiding reserved ports (showing >= 1024)."
                },
                false,
            );
        }
        KeyCode::Char('s') => {
            app.sort = app.sort.next();
            app.recompute_visible();
        }
        KeyCode::Char('/') => {
            app.modal = Modal::Filter;
        }
        KeyCode::Enter => {
            if app.selected_entry().is_some() {
                app.modal = Modal::Detail;
            }
        }
        KeyCode::Char('K') | KeyCode::Char('x') | KeyCode::Delete => {
            // Kill the selected process (capital K / x / Del). Lowercase k is
            // navigation (vim up), so killing uses a distinct, deliberate key.
            if let Some(e) = app.selected_entry() {
                match e.pid {
                    Some(pid) => {
                        let name = e.name_str().to_string();
                        app.modal = Modal::KillConfirm {
                            pid,
                            name,
                            force: false,
                        };
                    }
                    None => app.set_status(
                        "No PID resolved for this socket — cannot kill (try sudo).",
                        true,
                    ),
                }
            }
        }
        _ => {}
    }
    false
}

// ─────────────────────────────────────────────────────────────────────────────
//  Rendering
// ─────────────────────────────────────────────────────────────────────────────

fn draw(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header
            Constraint::Min(5),    // table
            Constraint::Length(1), // status line
            Constraint::Length(1), // key bar
        ])
        .split(f.area());

    draw_header(f, app, chunks[0]);
    draw_table(f, app, chunks[1]);
    draw_status(f, app, chunks[2]);
    draw_keybar(f, chunks[3]);

    match &app.modal {
        Modal::KillConfirm { pid, name, force } => draw_kill_modal(f, *pid, name, *force),
        Modal::Detail => draw_detail_modal(f, app),
        Modal::Filter => draw_filter_modal(f, app),
        Modal::None => {}
    }
}

fn draw_header(f: &mut Frame, app: &App, area: Rect) {
    let total = app.all.len();
    let shown = app.visible.len();
    let listening = app.all.iter().filter(|e| e.is_listening()).count();

    let mut spans = vec![
        Span::styled("portview", Style::default().fg(Color::Cyan).bold()),
        Span::raw("  "),
        Span::styled(
            format!("{shown}/{total} sockets"),
            Style::default().fg(Color::White),
        ),
        Span::raw("  "),
        Span::styled(
            format!("{listening} listening"),
            Style::default().fg(Color::Green),
        ),
        Span::raw("   "),
        Span::styled(
            format!(
                "[{}{}{}]  ports:{}  sort:{}",
                if app.show_tcp { "TCP " } else { "" },
                if app.show_udp { "UDP " } else { "" },
                if app.listening_only {
                    "LISTEN-only"
                } else {
                    "all"
                },
                if app.include_reserved {
                    ">=0"
                } else {
                    ">=1024"
                },
                app.sort.label(),
            ),
            Style::default().fg(Color::Yellow),
        ),
    ];

    if !app.filter.is_empty() {
        spans.push(Span::raw("  "));
        spans.push(Span::styled(
            format!("filter:\"{}\"", app.filter),
            Style::default().fg(Color::Magenta),
        ));
    }

    if !app.elevated {
        spans.push(Span::raw("  "));
        spans.push(Span::styled(
            "(unprivileged — some PIDs hidden; sudo for full view)",
            Style::default().fg(Color::Red),
        ));
    }

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Open TCP/UDP Ports ");
    f.render_widget(Paragraph::new(Line::from(spans)).block(block), area);
}

fn draw_table(f: &mut Frame, app: &mut App, area: Rect) {
    if let Some(err) = &app.error {
        let p = Paragraph::new(format!("Collection error: {err}"))
            .style(Style::default().fg(Color::Red))
            .block(Block::default().borders(Borders::ALL));
        f.render_widget(p, area);
        return;
    }

    let header = Row::new(vec![
        Cell::from("PROTO"),
        Cell::from("LOCAL ADDRESS"),
        Cell::from("REMOTE"),
        Cell::from("STATE"),
        Cell::from("PID"),
        Cell::from("USER"),
        Cell::from("PROCESS"),
        Cell::from("SERVICE"),
    ])
    .style(
        Style::default()
            .add_modifier(Modifier::BOLD)
            .fg(Color::Black)
            .bg(Color::Gray),
    )
    .height(1);

    let rows: Vec<Row> = app
        .visible
        .iter()
        .map(|&i| {
            let e = &app.all[i];
            let state = e.state.clone().unwrap_or_else(|| "-".into());
            let state_cell = Cell::from(state.clone()).style(state_style(&state));
            Row::new(vec![
                Cell::from(e.proto_label()),
                Cell::from(truncate(&e.local_endpoint(), 26)),
                Cell::from(truncate(&e.remote_endpoint(), 22)),
                state_cell,
                Cell::from(e.pid_str()),
                Cell::from(truncate(e.user.as_deref().unwrap_or("-"), 12)),
                Cell::from(truncate(e.name_str(), 22)),
                Cell::from(e.service_str().to_string()),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(6),
        Constraint::Length(26),
        Constraint::Length(22),
        Constraint::Length(12),
        Constraint::Length(7),
        Constraint::Length(12),
        Constraint::Length(22),
        Constraint::Min(10),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .row_highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ")
        .block(Block::default().borders(Borders::ALL));

    f.render_stateful_widget(table, area, &mut app.state);
}

fn draw_status(f: &mut Frame, app: &App, area: Rect) {
    if let Some(s) = &app.status {
        let style = if s.is_error {
            Style::default().fg(Color::White).bg(Color::Red)
        } else {
            Style::default().fg(Color::Black).bg(Color::Green)
        };
        f.render_widget(Paragraph::new(format!(" {} ", s.text)).style(style), area);
    }
}

fn draw_keybar(f: &mut Frame, area: Rect) {
    let keys = "[↑/↓/j/k] move  [Enter] details  [K/x/Del] kill  [/] filter  [l] listening  [a]ll-ports  [t]cp  [u]dp  [s]ort  [r]efresh  [q] quit";
    f.render_widget(
        Paragraph::new(keys).style(Style::default().fg(Color::DarkGray)),
        area,
    );
}

fn draw_kill_modal(f: &mut Frame, pid: u32, name: &str, force: bool) {
    let area = centered_rect(60, 30, f.area());
    f.render_widget(Clear, area);

    let signal = if force {
        "SIGKILL (forced, -9)"
    } else {
        "SIGTERM (graceful)"
    };

    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            format!("  Kill process \"{name}\" (PID {pid})?"),
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(vec![
            Span::raw("  Signal: "),
            Span::styled(
                signal,
                Style::default()
                    .fg(if force { Color::Red } else { Color::Yellow })
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "  [y] confirm   [Tab] toggle force   [n/Esc] cancel",
            Style::default().fg(Color::Gray),
        )),
    ];

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Confirm kill ")
        .border_style(Style::default().fg(Color::Red));
    f.render_widget(Paragraph::new(lines).block(block), area);
}

fn draw_filter_modal(f: &mut Frame, app: &App) {
    let area = centered_rect(60, 18, f.area());
    f.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Filter (port / process / proto / pid / path) ")
        .border_style(Style::default().fg(Color::Magenta));
    let text = vec![
        Line::from(""),
        Line::from(format!("  > {}", app.filter)),
        Line::from(""),
        Line::from(Span::styled(
            "  [Enter/Esc] close   [Backspace] delete",
            Style::default().fg(Color::Gray),
        )),
    ];
    f.render_widget(Paragraph::new(text).block(block), area);
}

fn draw_detail_modal(f: &mut Frame, app: &App) {
    let area = centered_rect(80, 70, f.area());
    f.render_widget(Clear, area);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Socket / Process Detail — [Esc] close ")
        .border_style(Style::default().fg(Color::Cyan));

    let Some(e) = app.selected_entry() else {
        f.render_widget(Paragraph::new("Nothing selected.").block(block), area);
        return;
    };

    let kv = |k: &str, v: String| -> Line {
        Line::from(vec![
            Span::styled(format!("  {k:<14}"), Style::default().fg(Color::Cyan)),
            Span::raw(v),
        ])
    };

    let lines = vec![
        Line::from(""),
        kv("Protocol", e.proto_label()),
        kv("Local", e.local_endpoint()),
        kv("Remote", e.remote_endpoint()),
        kv("State", e.state.clone().unwrap_or_else(|| "-".into())),
        kv("Service", e.service.clone().unwrap_or_else(|| "-".into())),
        Line::from(""),
        kv("PID", e.pid_str()),
        kv(
            "PPID",
            e.ppid.map(|p| p.to_string()).unwrap_or_else(|| "-".into()),
        ),
        kv("Process", e.name_str().to_string()),
        kv("User", e.user.clone().unwrap_or_else(|| "-".into())),
        kv("Uptime", e.uptime_human()),
        Line::from(""),
        kv("Executable", e.exe_str().to_string()),
        Line::from(""),
        Line::from(Span::styled(
            "  Command line:",
            Style::default().fg(Color::Cyan),
        )),
        Line::from(format!(
            "  {}",
            e.cmdline.clone().unwrap_or_else(|| "-".into())
        )),
    ];

    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(block),
        area,
    );
}

/// Style for a TCP state cell inside the table.
fn state_style(state: &str) -> Style {
    match state {
        "LISTEN" => Style::default()
            .fg(Color::Green)
            .add_modifier(Modifier::BOLD),
        "ESTABLISHED" => Style::default().fg(Color::Cyan),
        "TIME_WAIT" | "CLOSE_WAIT" | "FIN_WAIT1" | "FIN_WAIT2" | "CLOSING" | "LAST_ACK"
        | "SYN_SENT" | "SYN_RECV" => Style::default().fg(Color::Yellow),
        "-" => Style::default().fg(Color::DarkGray),
        _ => Style::default(),
    }
}

/// Compute a centered rectangle `pct_x` × `pct_y` percent of `r`.
fn centered_rect(pct_x: u16, pct_y: u16, r: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - pct_y) / 2),
            Constraint::Percentage(pct_y),
            Constraint::Percentage((100 - pct_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - pct_x) / 2),
            Constraint::Percentage(pct_x),
            Constraint::Percentage((100 - pct_x) / 2),
        ])
        .split(vertical[1])[1]
}

/// Truncate to `max` chars with an ellipsis (TUI cells have no auto-clip with
/// our fixed widths, so we clip defensively).
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else if max == 0 {
        String::new()
    } else {
        let kept: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{kept}…")
    }
}
