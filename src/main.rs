//! portview — verbose cross-platform (macOS + Linux) TCP/UDP port & process
//! viewer with kill support.
//!
//! This file is the CLI entry point only: it parses arguments with clap and
//! dispatches to the right layer. With no subcommand it launches the live TUI.
//! All real work lives in the focused modules below.

mod collector;
mod elevate;
mod killer;
mod model;
mod output;
mod services;
mod tui;

use clap::{Parser, Subcommand};
use collector::CollectOptions;
use std::process::ExitCode;

/// Verbose TCP/UDP port viewer with process attribution and kill support.
///
/// Run with no arguments to launch the interactive TUI. Use `list` for a
/// one-shot table (or `--json` for scripting), and `kill` to terminate a
/// process by PID. By default portview elevates with sudo for a complete view
/// and hides reserved ports (0-1023).
#[derive(Parser, Debug)]
#[command(name = "portview", version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    /// Verbose output (adds PPID, uptime, executable path, and command line to
    /// the `list` table). Has no effect on `--json` (which is always full).
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Also show reserved/system ports (0-1023). By default only ports >= 1024
    /// are shown.
    #[arg(short = 'a', long = "all", global = true)]
    all_ports: bool,

    /// Do NOT auto-elevate with sudo. By default portview re-runs itself under
    /// sudo (when not already root) so it can resolve every process and kill
    /// across users.
    #[arg(long = "no-sudo", global = true)]
    no_sudo: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// List open sockets to stdout (table by default, or JSON).
    List {
        /// Emit JSON instead of a human table.
        #[arg(long)]
        json: bool,
        /// Show only TCP sockets.
        #[arg(long)]
        tcp: bool,
        /// Show only UDP sockets.
        #[arg(long)]
        udp: bool,
        /// Show only listening sockets (TCP LISTEN + all UDP).
        #[arg(short, long)]
        listening: bool,
    },
    /// Terminate a process by PID (SIGTERM by default; -9/--force for SIGKILL).
    Kill {
        /// Target process ID.
        pid: u32,
        /// Force kill: send SIGKILL instead of SIGTERM. Available as -9 or --force.
        #[arg(short = '9', long = "force")]
        force: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    // Is this a JSON `list`? If so we must never auto-prompt for a sudo password
    // (it would hang/garble machine output in a pipe).
    let is_json = matches!(cli.command, Some(Commands::List { json: true, .. }));

    // Auto-elevate by default. On a successful re-exec this does not return.
    elevate::ensure_root(!cli.no_sudo, is_json);

    let include_reserved = cli.all_ports;

    match cli.command {
        // No subcommand → interactive dashboard.
        None => match tui::run(include_reserved) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("Error: {e}");
                ExitCode::FAILURE
            }
        },

        Some(Commands::List {
            json,
            tcp,
            udp,
            listening,
        }) => {
            // If neither --tcp nor --udp is given, include both; otherwise
            // honour exactly what was requested.
            let (tcp, udp) = if !tcp && !udp {
                (true, true)
            } else {
                (tcp, udp)
            };
            let opts = CollectOptions {
                tcp,
                udp,
                listening_only: listening,
                include_reserved,
            };

            match collector::collect(opts) {
                Ok(entries) => {
                    if json {
                        if let Err(e) = output::print_json(&entries) {
                            eprintln!("Error: {e}");
                            return ExitCode::FAILURE;
                        }
                    } else {
                        output::print_table(&entries, cli.verbose, collector::is_elevated());
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    ExitCode::FAILURE
                }
            }
        }

        Some(Commands::Kill { pid, force }) => match killer::kill(pid, force) {
            Ok(msg) => {
                println!("{msg}");
                ExitCode::SUCCESS
            }
            Err(msg) => {
                eprintln!("{msg}");
                ExitCode::FAILURE
            }
        },
    }
}
