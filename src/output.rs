//! One-shot CLI rendering — the non-interactive output layer.
//!
//! Two presentations of a `Vec<PortEntry>`:
//!   * `print_table` — a colour-coded, aligned, optionally maximally-verbose
//!     human table.
//!   * `print_json`  — machine-readable JSON for scripting/piping.
//!
//! Colour is applied via crossterm's styling, imported through `ratatui` so the
//! crossterm version can never drift from the TUI's.

use crate::model::PortEntry;
use ratatui::crossterm::style::Stylize;

/// Print a JSON array of entries to stdout (pretty-printed).
pub fn print_json(entries: &[PortEntry]) -> Result<(), String> {
    let json = serde_json::to_string_pretty(entries)
        .map_err(|e| format!("failed to serialize JSON: {e}"))?;
    println!("{json}");
    Ok(())
}

/// Print a human-readable table.
///
/// `verbose = false` → compact columns (proto, local, remote, state, pid,
/// user, process, service).
/// `verbose = true`  → adds ppid, uptime, full executable path, and the
/// command line on an indented continuation row per entry.
pub fn print_table(entries: &[PortEntry], verbose: bool, elevated: bool) {
    if entries.is_empty() {
        println!("No matching sockets found.");
        return;
    }

    // ── Header ──────────────────────────────────────────────────────────────
    let header = if verbose {
        format!(
            "{:<6} {:<24} {:<22} {:<12} {:>7} {:>7} {:<12} {:<20} {:<10} {}",
            "PROTO",
            "LOCAL",
            "REMOTE",
            "STATE",
            "PID",
            "PPID",
            "USER",
            "PROCESS",
            "UPTIME",
            "SERVICE"
        )
    } else {
        format!(
            "{:<6} {:<24} {:<22} {:<12} {:>7} {:<12} {:<20} {}",
            "PROTO", "LOCAL", "REMOTE", "STATE", "PID", "USER", "PROCESS", "SERVICE"
        )
    };
    println!("{}", header.bold());

    // ── Rows ──────────────────────────────────────────────────────────────────
    for e in entries {
        let proto = e.proto_label();
        let local = truncate(&e.local_endpoint(), 24);
        let remote = truncate(&e.remote_endpoint(), 22);
        let state = e.state.as_deref().unwrap_or("-");
        let user = truncate(e.user.as_deref().unwrap_or("-"), 12);
        let name = truncate(e.name_str(), 20);
        let service = e.service_str();

        // Colour the state column to make listeners pop.
        let state_col = colorize_state(state);

        if verbose {
            let row = format!(
                "{:<6} {:<24} {:<22} {:<12} {:>7} {:>7} {:<12} {:<20} {:<10} {}",
                proto,
                local,
                remote,
                state,
                e.pid_str(),
                e.ppid.map(|p| p.to_string()).unwrap_or_else(|| "-".into()),
                user,
                name,
                e.uptime_human(),
                service,
            );
            // Re-style only the STATE substring by printing the row, then the
            // detail lines beneath. (Simplicity over per-cell ANSI surgery.)
            println!("{row}");
            println!("        exe : {}", e.exe_str().dark_grey());
            if let Some(cmd) = &e.cmdline {
                println!("        args: {}", truncate(cmd, 160).dark_grey());
            }
        } else {
            let row = format!(
                "{:<6} {:<24} {:<22} {:<12} {:>7} {:<12} {:<20} {}",
                proto,
                local,
                remote,
                state_col,
                e.pid_str(),
                user,
                name,
                service
            );
            println!("{row}");
        }
    }

    // ── Footer summary + privilege hint ──────────────────────────────────────
    let listening = entries.iter().filter(|e| e.is_listening()).count();
    let unresolved = entries.iter().filter(|e| e.pid.is_none()).count();
    println!();
    println!(
        "{}",
        format!(
            "{} sockets ({} listening){}",
            entries.len(),
            listening,
            if unresolved > 0 {
                format!(", {unresolved} without resolved PID")
            } else {
                String::new()
            }
        )
        .bold()
    );

    if !elevated && unresolved > 0 {
        println!(
            "{}",
            "Tip: re-run with sudo to resolve PIDs and executable paths for all processes."
                .yellow()
        );
    }
}

/// Apply a state-appropriate colour to the STATE cell (non-verbose mode).
fn colorize_state(state: &str) -> String {
    let padded = format!("{state:<12}");
    match state {
        "LISTEN" => padded.green().to_string(),
        "ESTABLISHED" => padded.cyan().to_string(),
        "TIME_WAIT" | "CLOSE_WAIT" | "FIN_WAIT1" | "FIN_WAIT2" | "CLOSING" | "LAST_ACK" => {
            padded.yellow().to_string()
        }
        "-" => padded.dark_grey().to_string(),
        _ => padded,
    }
}

/// Truncate a string to `max` display chars, appending `…` when cut.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_keeps_short_strings() {
        assert_eq!(truncate("abc", 10), "abc");
    }

    #[test]
    fn truncate_cuts_long_strings_with_ellipsis() {
        assert_eq!(truncate("abcdefgh", 4), "abc…");
    }
}
