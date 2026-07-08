//! Privilege escalation — auto re-exec under `sudo` when not already root.
//!
//! Resolving socket→PID and executable paths for *other users'* processes (and
//! killing them) requires root on both macOS and Linux. To make `portview`
//! "just work" with a complete view, by default it re-launches itself via
//! `sudo` if it isn't already privileged.
//!
//! Single responsibility: decide whether to escalate, and if so, replace the
//! current process with a sudo-wrapped copy of itself.
//!
//! Opt out with `--no-sudo`. Auto-escalation is also skipped for `--json`
//! (machine output must never block on an interactive password prompt) and when
//! there is no TTY to read a password from.

use std::env;
use std::process::Command;

use crate::collector::is_elevated;

/// Result of an escalation decision, returned to `main` so it can adjust hints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Elevation {
    /// Already running as root — nothing to do.
    AlreadyRoot,
    /// Re-exec was skipped (opted out, JSON output, no TTY, or not supported).
    Skipped,
}

/// Ensure the process is privileged, re-exec'ing via `sudo` if needed.
///
/// * `wants_sudo` — `false` if the user passed `--no-sudo`.
/// * `is_json`    — `true` for `list --json`; we never prompt for those.
///
/// On a successful re-exec this function **does not return** (the process image
/// is replaced on Unix). Otherwise it returns how things stand.
pub fn ensure_root(wants_sudo: bool, is_json: bool) -> Elevation {
    if is_elevated() {
        return Elevation::AlreadyRoot;
    }

    // Respect explicit opt-out and non-interactive/JSON contexts.
    if !wants_sudo || is_json {
        return Elevation::Skipped;
    }

    #[cfg(unix)]
    {
        // Don't try to prompt for a password if there's no controlling TTY
        // (e.g. running inside a pipe or CI) — sudo would just fail/hang.
        if !stdin_is_tty() {
            return Elevation::Skipped;
        }

        // Build: sudo <self-exe> <original args...>
        let exe = match env::current_exe() {
            Ok(p) => p,
            Err(_) => return Elevation::Skipped,
        };
        let args: Vec<String> = env::args().skip(1).collect();

        eprintln!("portview: elevating with sudo for full port/process visibility (use --no-sudo to skip)…");

        // Replace the current process so the TUI/terminal handoff is seamless.
        // `exec` only returns on failure.
        use std::os::unix::process::CommandExt;
        let err = Command::new("sudo").arg(exe).args(&args).exec();

        // If we get here, exec failed (sudo missing, denied, etc.). Fall back to
        // running unprivileged rather than aborting.
        eprintln!("portview: sudo escalation failed ({err}); continuing unprivileged.");
        Elevation::Skipped
    }

    #[cfg(not(unix))]
    {
        Elevation::Skipped
    }
}

/// Is stdin a terminal? Used to avoid prompting for a sudo password when there
/// is nowhere to type it.
#[cfg(unix)]
fn stdin_is_tty() -> bool {
    // SAFETY: isatty has no preconditions; STDIN_FILENO is always valid to query.
    unsafe { nix::libc::isatty(nix::libc::STDIN_FILENO) == 1 }
}
