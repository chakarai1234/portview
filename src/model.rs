//! Data model — the single canonical representation of one open socket and the
//! process that owns it, shared by the collector, the CLI output layer, and the
//! TUI. One struct, one responsibility (Single Responsibility): hold the data
//! and format it for display.

use serde::Serialize;
use std::net::IpAddr;

/// Transport protocol of a socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    /// Short label including IP family, e.g. `TCP` / `TCP6` / `UDP` / `UDP6`.
    pub fn label(&self, is_v6: bool) -> String {
        let base = match self {
            Protocol::Tcp => "TCP",
            Protocol::Udp => "UDP",
        };
        if is_v6 {
            format!("{base}6")
        } else {
            base.to_string()
        }
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "TCP"),
            Protocol::Udp => write!(f, "UDP"),
        }
    }
}

/// One fully-enriched open socket: the network endpoint plus the owning process.
///
/// Every field that may be unavailable without root (PID, exe path, user) is an
/// `Option`, so the app degrades gracefully when run unprivileged.
#[derive(Debug, Clone, Serialize)]
pub struct PortEntry {
    pub protocol: Protocol,
    pub local_addr: IpAddr,
    pub local_port: u16,
    /// `None` for UDP (connectionless) and for TCP sockets with no peer.
    pub remote_addr: Option<IpAddr>,
    pub remote_port: Option<u16>,
    /// TCP state (LISTEN, ESTABLISHED, …). `None` for UDP.
    pub state: Option<String>,
    pub pid: Option<u32>,
    pub ppid: Option<u32>,
    pub process_name: Option<String>,
    pub exe_path: Option<String>,
    pub cmdline: Option<String>,
    pub user: Option<String>,
    /// Process uptime in seconds, if the owning process was resolved.
    pub uptime_secs: Option<u64>,
    /// Friendly name for a well-known port (e.g. 5432 → "PostgreSQL").
    pub service: Option<String>,
}

impl PortEntry {
    /// True if this is a TCP socket in the LISTEN state, or any UDP socket
    /// (UDP is connectionless, so a bound UDP socket is effectively "listening").
    pub fn is_listening(&self) -> bool {
        match self.protocol {
            Protocol::Udp => true,
            Protocol::Tcp => self
                .state
                .as_deref()
                .map(|s| s.eq_ignore_ascii_case("LISTEN"))
                .unwrap_or(false),
        }
    }

    /// `true` when the local address is IPv6.
    pub fn is_v6(&self) -> bool {
        self.local_addr.is_ipv6()
    }

    /// Protocol label including IP family — `TCP`, `TCP6`, `UDP`, `UDP6`.
    pub fn proto_label(&self) -> String {
        self.protocol.label(self.is_v6())
    }

    /// `host:port` for the local endpoint, bracketing IPv6 hosts.
    pub fn local_endpoint(&self) -> String {
        fmt_endpoint(self.local_addr, self.local_port)
    }

    /// `host:port` for the remote endpoint, or `-` if there is none.
    pub fn remote_endpoint(&self) -> String {
        match (self.remote_addr, self.remote_port) {
            (Some(addr), Some(port)) => fmt_endpoint(addr, port),
            _ => "-".to_string(),
        }
    }

    /// Human-readable uptime such as `3d 4h`, `12m`, or `45s`.
    pub fn uptime_human(&self) -> String {
        match self.uptime_secs {
            Some(s) => fmt_uptime(s),
            None => "-".to_string(),
        }
    }

    /// PID as a display string, or `-`.
    pub fn pid_str(&self) -> String {
        self.pid
            .map(|p| p.to_string())
            .unwrap_or_else(|| "-".into())
    }

    /// Process name, or `-`.
    pub fn name_str(&self) -> &str {
        self.process_name.as_deref().unwrap_or("-")
    }

    /// Executable path, or `-`.
    pub fn exe_str(&self) -> &str {
        self.exe_path.as_deref().unwrap_or("-")
    }

    /// Service name, or empty string (so it can be appended unobtrusively).
    pub fn service_str(&self) -> &str {
        self.service.as_deref().unwrap_or("")
    }
}

/// Format an address and port as `host:port`, wrapping IPv6 in `[]`.
fn fmt_endpoint(addr: IpAddr, port: u16) -> String {
    match addr {
        IpAddr::V4(v4) => format!("{v4}:{port}"),
        IpAddr::V6(v6) => format!("[{v6}]:{port}"),
    }
}

/// Turn a number of seconds into a compact human duration: `3d 4h`, `2h 5m`,
/// `12m`, `45s`. Shows at most the two most-significant units.
fn fmt_uptime(secs: u64) -> String {
    let days = secs / 86_400;
    let hours = (secs % 86_400) / 3_600;
    let mins = (secs % 3_600) / 60;
    let s = secs % 60;

    if days > 0 {
        format!("{days}d {hours}h")
    } else if hours > 0 {
        format!("{hours}h {mins}m")
    } else if mins > 0 {
        format!("{mins}m {s}s")
    } else {
        format!("{s}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn uptime_formats() {
        assert_eq!(fmt_uptime(45), "45s");
        assert_eq!(fmt_uptime(125), "2m 5s");
        assert_eq!(fmt_uptime(3_600 + 5 * 60), "1h 5m");
        assert_eq!(fmt_uptime(3 * 86_400 + 4 * 3_600), "3d 4h");
    }

    #[test]
    fn endpoint_brackets_ipv6() {
        assert_eq!(
            fmt_endpoint(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
            "127.0.0.1:8080"
        );
        assert_eq!(
            fmt_endpoint(IpAddr::V6(Ipv6Addr::LOCALHOST), 443),
            "[::1]:443"
        );
    }

    #[test]
    fn udp_is_always_listening() {
        let e = PortEntry {
            protocol: Protocol::Udp,
            local_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            local_port: 53,
            remote_addr: None,
            remote_port: None,
            state: None,
            pid: None,
            ppid: None,
            process_name: None,
            exe_path: None,
            cmdline: None,
            user: None,
            uptime_secs: None,
            service: None,
        };
        assert!(e.is_listening());
    }
}
