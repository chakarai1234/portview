//! Process termination — a thin, careful wrapper over POSIX `kill(2)` via `nix`,
//! used by both the `kill` CLI subcommand and the TUI's kill action.
//!
//! Single responsibility: turn (pid, force) into a signal delivery with a
//! human-readable result. It translates raw errnos (EPERM, ESRCH) into guidance
//! the user can act on ("try sudo", "no such process").

use nix::errno::Errno;
use nix::sys::signal::{kill as nix_kill, Signal};
use nix::unistd::Pid;

/// Outcome of a kill attempt — `Ok` carries a success message, `Err` carries an
/// actionable explanation.
pub type KillResult = Result<String, String>;

/// Send a termination signal to `pid`.
///
/// `force = false` → `SIGTERM` (graceful; the process can clean up).
/// `force = true`  → `SIGKILL` (immediate; cannot be caught or ignored).
///
/// Note the two distinct `Pid` types in this project: callers pass a raw `u32`
/// (from `sysinfo`/`netstat2`); we convert to `nix::unistd::Pid` here so the
/// boundary stays in one place.
pub fn kill(pid: u32, force: bool) -> KillResult {
    // Guard the u32 → i32 conversion. `kill(0, …)` signals the whole process
    // group and `kill(-1, …)` signals EVERY process on the system (catastrophic
    // under sudo), so a PID of 0 or one that would wrap negative is rejected
    // outright instead of being passed to the kernel.
    if pid == 0 {
        return Err("Refusing PID 0: that would signal the entire process group.".into());
    }
    let raw: i32 = match i32::try_from(pid) {
        Ok(v) => v,
        Err(_) => {
            return Err(format!(
                "Invalid PID {pid}: out of range (PIDs must fit in a 31-bit signed integer)."
            ))
        }
    };

    let signal = if force {
        Signal::SIGKILL
    } else {
        Signal::SIGTERM
    };

    // nix::unistd::Pid wraps an i32; `raw` was range-checked above.
    let target = Pid::from_raw(raw);

    match nix_kill(target, signal) {
        Ok(()) => Ok(format!(
            "Sent {} to PID {pid}.",
            if force { "SIGKILL (forced)" } else { "SIGTERM" }
        )),
        Err(Errno::EPERM) => Err(format!(
            "Permission denied killing PID {pid}. Re-run with sudo to terminate processes you don't own."
        )),
        Err(Errno::ESRCH) => Err(format!(
            "No such process: PID {pid} does not exist (it may have already exited)."
        )),
        Err(e) => Err(format!("Failed to kill PID {pid}: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pid_zero_is_rejected() {
        let err = kill(0, false).unwrap_err();
        assert!(err.contains("PID 0"));
    }

    #[test]
    fn pid_above_i32_max_is_rejected() {
        // u32::MAX would wrap to -1 (= signal every process) without the guard.
        let err = kill(u32::MAX, true).unwrap_err();
        assert!(err.contains("out of range"));

        let err = kill(i32::MAX as u32 + 1, false).unwrap_err();
        assert!(err.contains("out of range"));
    }
}
