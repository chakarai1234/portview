//! The collection engine — the heart of the application.
//!
//! It enumerates every TCP/UDP socket via `netstat2`, then enriches each one
//! with the owning process's details via a single `sysinfo` snapshot, and
//! finally annotates well-known ports with a service name. The result is a
//! `Vec<PortEntry>` that every other layer (CLI table, JSON, TUI) consumes.
//!
//! Design notes:
//! - One `System` + one `Users` snapshot per collection pass — O(sockets) work,
//!   not O(sockets × processes).
//! - Per-socket errors from netstat2 are skipped, never fatal (common on macOS
//!   without root, where foreign sockets return EPERM under the hood).
//! - Everything that may be unavailable unprivileged is an `Option`.

use crate::model::{PortEntry, Protocol};
use crate::services;
use netstat2::{
    iterate_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, TcpState,
};
use sysinfo::{Pid, ProcessesToUpdate, System, Users};

/// Highest port in the IANA "well-known / system" range. Ports `0..=1023` are
/// considered reserved; by default we hide them and show only `>= 1024`.
pub const RESERVED_MAX: u16 = 1023;

/// Filters controlling what the collector returns. The TUI keeps all sockets
/// and filters in-memory; the CLI uses these to scope at collection time.
#[derive(Debug, Clone, Copy)]
pub struct CollectOptions {
    pub tcp: bool,
    pub udp: bool,
    pub listening_only: bool,
    /// When `false` (the default), hide reserved ports (`0..=1023`) and show
    /// only `>= 1024`. When `true`, include the reserved range too.
    pub include_reserved: bool,
}

impl Default for CollectOptions {
    fn default() -> Self {
        Self {
            tcp: true,
            udp: true,
            listening_only: false,
            include_reserved: false,
        }
    }
}

impl CollectOptions {
    /// Translate the proto toggles into netstat2 flags. If neither `tcp` nor
    /// `udp` is set we treat it as "both" (an empty selection shows nothing
    /// useful, which is never what the user wants).
    fn protocol_flags(&self) -> ProtocolFlags {
        match (self.tcp, self.udp) {
            (true, false) => ProtocolFlags::TCP,
            (false, true) => ProtocolFlags::UDP,
            _ => ProtocolFlags::TCP | ProtocolFlags::UDP,
        }
    }
}

/// Best-effort check for whether we're running with the privileges needed to
/// resolve every socket's owning process. On Unix, that means euid 0 (root).
/// Used only to surface a friendly "re-run with sudo" hint — never to gate work.
pub fn is_elevated() -> bool {
    #[cfg(unix)]
    {
        nix::unistd::geteuid().is_root()
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// Collect all sockets matching `opts`, fully enriched and sorted by port.
///
/// Returns an error only if socket enumeration cannot start at all; individual
/// unreadable sockets are silently skipped.
pub fn collect(opts: CollectOptions) -> Result<Vec<PortEntry>, String> {
    // Single process snapshot for the whole pass.
    let mut sys = System::new();
    sys.refresh_processes(ProcessesToUpdate::All, true);
    let users = Users::new_with_refreshed_list();

    let af = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let proto = opts.protocol_flags();

    let socket_iter =
        iterate_sockets_info(af, proto).map_err(|e| format!("failed to enumerate sockets: {e}"))?;

    let mut entries: Vec<PortEntry> = Vec::new();

    for item in socket_iter {
        // Skip sockets we can't read (EPERM on macOS for foreign sockets, etc.).
        let info = match item {
            Ok(info) => info,
            Err(_) => continue,
        };

        // A socket may have 0, 1, or several owning PIDs. With 0 PIDs (common
        // unprivileged) we still emit the row so the port is visible, just
        // without process attribution. With several, we emit one row per PID.
        let pids: Vec<Option<u32>> = if info.associated_pids.is_empty() {
            vec![None]
        } else {
            info.associated_pids.iter().copied().map(Some).collect()
        };

        match &info.protocol_socket_info {
            ProtocolSocketInfo::Tcp(tcp) => {
                // Hide reserved ports (0..=1023) unless explicitly included.
                if !opts.include_reserved && tcp.local_port <= RESERVED_MAX {
                    continue;
                }
                let listening = tcp.state == TcpState::Listen;
                if opts.listening_only && !listening {
                    continue;
                }
                for pid in pids {
                    entries.push(enrich(
                        Protocol::Tcp,
                        tcp.local_addr,
                        tcp.local_port,
                        Some(tcp.remote_addr),
                        Some(tcp.remote_port),
                        Some(tcp_state_str(&tcp.state)),
                        pid,
                        &sys,
                        &users,
                    ));
                }
            }
            ProtocolSocketInfo::Udp(udp) => {
                // Hide reserved ports (0..=1023) unless explicitly included.
                if !opts.include_reserved && udp.local_port <= RESERVED_MAX {
                    continue;
                }
                // UDP is connectionless: every bound socket counts as listening,
                // so `listening_only` never filters UDP out.
                for pid in pids {
                    entries.push(enrich(
                        Protocol::Udp,
                        udp.local_addr,
                        udp.local_port,
                        None,
                        None,
                        None,
                        pid,
                        &sys,
                        &users,
                    ));
                }
            }
        }
    }

    sort_entries(&mut entries);
    Ok(entries)
}

/// Build a fully-populated `PortEntry`, looking up process details from the
/// shared snapshot when a PID is known.
#[allow(clippy::too_many_arguments)]
fn enrich(
    protocol: Protocol,
    local_addr: std::net::IpAddr,
    local_port: u16,
    remote_addr: Option<std::net::IpAddr>,
    remote_port: Option<u16>,
    state: Option<String>,
    pid: Option<u32>,
    sys: &System,
    users: &Users,
) -> PortEntry {
    let mut entry = PortEntry {
        protocol,
        local_addr,
        local_port,
        remote_addr,
        remote_port,
        state,
        pid,
        ppid: None,
        process_name: None,
        exe_path: None,
        cmdline: None,
        user: None,
        uptime_secs: None,
        service: None,
    };

    if let Some(raw_pid) = pid {
        if let Some(proc_) = sys.process(Pid::from_u32(raw_pid)) {
            entry.process_name = Some(proc_.name().to_string_lossy().into_owned());

            entry.exe_path = proc_
                .exe()
                .map(|p| p.display().to_string())
                .filter(|s| !s.is_empty());

            let args: Vec<String> = proc_
                .cmd()
                .iter()
                .map(|a| a.to_string_lossy().into_owned())
                .collect();
            if !args.is_empty() {
                entry.cmdline = Some(args.join(" "));
            }

            entry.ppid = proc_.parent().map(|p| p.as_u32());
            entry.uptime_secs = Some(proc_.run_time());

            // Resolve numeric uid → username when possible; fall back to the
            // raw uid string so the column is never blank for an owned process.
            entry.user = proc_.user_id().map(|uid| {
                users
                    .get_user_by_id(uid)
                    .map(|u| u.name().to_string())
                    .unwrap_or_else(|| uid.to_string())
            });
        }
    }

    // Label the port with its well-known service only when the owning process
    // actually looks like that service; a bare port number proves nothing.
    entry.service = services::lookup_verified(
        local_port,
        entry.process_name.as_deref(),
        entry.cmdline.as_deref(),
    )
    .map(str::to_string);

    entry
}

/// Stable, predictable ordering: by local port, then protocol, then PID.
fn sort_entries(entries: &mut [PortEntry]) {
    entries.sort_by(|a, b| {
        a.local_port
            .cmp(&b.local_port)
            .then_with(|| a.protocol.to_string().cmp(&b.protocol.to_string()))
            .then_with(|| a.pid.cmp(&b.pid))
    });
}

/// Render a netstat2 `TcpState` as the conventional uppercase label.
fn tcp_state_str(state: &TcpState) -> String {
    match state {
        TcpState::Closed => "CLOSED",
        TcpState::Listen => "LISTEN",
        TcpState::SynSent => "SYN_SENT",
        TcpState::SynReceived => "SYN_RECV",
        TcpState::Established => "ESTABLISHED",
        TcpState::FinWait1 => "FIN_WAIT1",
        TcpState::FinWait2 => "FIN_WAIT2",
        TcpState::CloseWait => "CLOSE_WAIT",
        TcpState::Closing => "CLOSING",
        TcpState::LastAck => "LAST_ACK",
        TcpState::TimeWait => "TIME_WAIT",
        TcpState::DeleteTcb => "DELETE_TCB",
        // netstat2 may add states across platforms/versions; fall back safely.
        other => return format!("{other:?}").to_uppercase(),
    }
    .to_string()
}
