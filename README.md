# portview

A **verbose, cross-platform (macOS + Linux) TCP/UDP port viewer** for developers,
written in Rust. See every open port, exactly which process owns it (PID, full
executable path, command line, user, uptime), and kill it — from either a live
interactive TUI or a scriptable CLI.

Built for the everyday "**what's running on port 3000 and how do I stop it?**"
question.

---

## Features

- **Every TCP & UDP socket**, IPv4 and IPv6, in one view.
- **Full process attribution per port:** PID, PPID, process name, **full
  executable path**, command-line arguments, owning user, and process uptime.
- **Well-known service hints** — `5432 → PostgreSQL`, `6379 → Redis`,
  `5173 → Vite dev`, `9092 → Kafka`, and ~100 more.
- **Kill processes** gracefully (SIGTERM) or forcibly (SIGKILL / `-9`).
- **Two interfaces from one binary:**
  - **Interactive TUI** (default) — live auto-refresh, keyboard nav, live
    filter, sort, listening/TCP/UDP toggles, a detail pane, and kill-with-confirm.
  - **CLI** — one-shot `list` table, `--json` for scripting, and `kill <PID>`.
- **Native** — pure Rust (`netstat2` + `sysinfo`); no shelling out to `lsof`/`ss`.
- **Sudo by default** — auto-elevates with `sudo` so it can resolve *every*
  process and kill across users. Opt out with `--no-sudo`.
- **Reserved ports hidden by default** — shows only application ports (`>= 1024`);
  reveal system ports (`0–1023`) with `--all` / `-a` (or `[a]` in the TUI).
- **Degrades gracefully without root** — always shows ports; resolves PIDs and
  paths where permitted and tells you when `sudo` is needed for the rest.

---

## Install

### Linux (from a GitHub release)

Download the latest prebuilt binary and put it on your `PATH` — no Rust
toolchain needed:

```bash
# x86_64 (Intel/AMD). For ARM64 servers/Raspberry Pi use: aarch64-unknown-linux-gnu
REPO="<owner>/portview"   # ← replace <owner> with the GitHub username/org
TARGET="x86_64-unknown-linux-gnu"
TAG=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep -m1 '"tag_name"' | cut -d '"' -f4)

curl -fsSL -o portview.tar.gz \
  "https://github.com/${REPO}/releases/download/${TAG}/portview-${TAG}-${TARGET}.tar.gz"
tar -xzf portview.tar.gz
sudo install -m 755 "portview-${TAG}-${TARGET}/portview" /usr/local/bin/portview
rm -rf portview.tar.gz "portview-${TAG}-${TARGET}"

portview --version
```

Every release also ships a `SHA256SUMS` file; verify the download with
`sha256sum -c` before installing if you want the extra assurance.

### macOS (from a GitHub release)

Same steps as Linux, with the macOS target — `aarch64-apple-darwin` for Apple
Silicon or `x86_64-apple-darwin` for Intel — and `shasum -a 256 -c` for the
checksum.

### Build from source

Requires a Rust toolchain (`cargo`). Tested with Rust 1.96.

```bash
# from the project root
cargo build --release

# binary lands at:
./target/release/portview

# (optional) install to ~/.cargo/bin so `portview` is on your PATH
cargo install --path .
```

Works on **macOS** and **Linux** with the same source — platform differences are
handled internally.

---

## Usage

### Interactive TUI (default)

```bash
portview            # launches the live dashboard (auto-elevates with sudo)
portview --no-sudo  # run unprivileged (no password prompt)
portview --all      # also include reserved ports 0–1023
```

> By default portview re-runs itself under `sudo` (you'll be asked for your
> password once) so every process resolves. See [Permissions](#permissions).

**Keys:**

| Key | Action |
|-----|--------|
| `↑` / `↓` or `j` / `k` | Move selection |
| `g` / `G` | Jump to top / bottom |
| `Enter` | Open the detail pane (full path, args, PPID, uptime) |
| `K` / `x` / `Del` | Kill the selected process (asks to confirm) |
| `/` | Live filter (port / process / proto / pid / path) |
| `l` | Toggle listening-only |
| `a` | Toggle reserved ports (0–1023) |
| `t` | Toggle TCP |
| `u` | Toggle UDP |
| `s` | Cycle sort (port → pid → process → proto) |
| `r` | Force refresh |
| `q` / `Esc` / `Ctrl-C` | Quit |

In the **kill confirmation** popup: `y` confirms, `Tab` toggles SIGTERM↔SIGKILL,
`n`/`Esc` cancels.

### CLI — list

```bash
portview list                      # app ports (>=1024), compact table
portview list --all                # include reserved/system ports (0–1023)
portview list --verbose            # + PPID, uptime, exe path, command line
portview list --listening          # only listeners (TCP LISTEN + all UDP)
portview list --tcp                # TCP only
portview list --udp                # UDP only
portview list --tcp --listening    # combine filters
portview list --json               # machine-readable JSON (never prompts for sudo)
portview list --no-sudo            # skip auto-elevation
```

Global flags (`--all`/`-a`, `--no-sudo`, `--verbose`/`-v`) work on any
subcommand, e.g. `portview --all list --listening`.

Example — find what owns port 3000:

```bash
portview list --listening | grep 3000
```

Pipe JSON into `jq`:

```bash
portview list --json | jq '.[] | select(.local_port == 5432)'
```

### CLI — kill

```bash
portview kill 8821          # graceful SIGTERM
portview kill 8821 -9       # forceful SIGKILL
portview kill 8821 --force  # same as -9
```

Typical workflow:

```bash
portview list --listening | grep 3000   # find the PID
portview kill <PID>                      # stop it
```

---

## Permissions

**portview elevates with `sudo` by default.** When you run it interactively and
you're not already root, it re-launches itself via `sudo` (one password prompt)
so it can resolve and kill every process. This is skipped automatically when:

- you pass `--no-sudo`,
- the command is `list --json` (machine output must never block on a prompt), or
- there's no terminal to read a password from (e.g. inside a pipe or CI).

If `sudo` is unavailable or denied, portview falls back to running unprivileged
rather than failing.

Why it matters — mapping a socket to its owning process requires inspecting that
process, and the OS restricts this for processes you **don't own**:

| Data | Without root | With `sudo` |
|------|--------------|-------------|
| Open ports (the list) | ✅ always shown | ✅ |
| PID for **your own** processes | ✅ | ✅ |
| PID for **other users'** processes | ⚠️ often hidden (shown as `-`) | ✅ |
| Executable path of other users' procs | ⚠️ may be hidden (esp. on Linux `/proc/<pid>/exe`) | ✅ |
| Killing other users' processes | ❌ permission denied | ✅ |

When run unprivileged (e.g. `--no-sudo`), `portview` shows a hint and a red
banner in the TUI. The default auto-sudo gives you the complete picture without
typing `sudo` yourself; you can still do it explicitly:

```bash
sudo portview
sudo portview list --listening --verbose
```

### Reserved ports

By default portview hides the IANA well-known/system range (`0–1023`) and shows
only application ports (`>= 1024`). To include reserved ports, use `--all` / `-a`
on the CLI, or press `[a]` in the TUI.

> Note on SSH tunnels: if you use SSH local port-forwarding, many forwarded
> ports will correctly show **`ssh`** as the owning process — that is the real
> local owner of those listening sockets.

---

## How it works

```
netstat2  ──► enumerate every TCP/UDP socket (addr, port, state, owning PIDs)
   │
   ▼
sysinfo   ──► enrich each PID (name, exe path, args, user, ppid, uptime)
   │
   ▼
services  ──► annotate well-known ports (5432 → PostgreSQL, …)
   │
   ▼
PortEntry ──► rendered by either the CLI (table / JSON) or the TUI dashboard
   │
   ▼
nix       ──► kill(pid, SIGTERM | SIGKILL) on demand
```

Module layout:

| File | Role |
|------|------|
| `src/main.rs` | CLI parsing (clap) + dispatch |
| `src/elevate.rs` | Auto re-exec under `sudo` when not root |
| `src/collector.rs` | The engine: netstat2 + sysinfo → `Vec<PortEntry>` |
| `src/model.rs` | `PortEntry` data type + formatters |
| `src/services.rs` | Well-known port → service-name map |
| `src/killer.rs` | SIGTERM/SIGKILL via `nix`, with friendly errors |
| `src/output.rs` | CLI table + JSON rendering |
| `src/tui.rs` | Interactive ratatui dashboard |

---

## Development

```bash
cargo build            # debug build
cargo test             # run unit tests
cargo run -- list      # run the CLI without installing
cargo run              # run the TUI
cargo clippy           # lints
```

### Releasing

Releases are automated by `.github/workflows/release.yml`. Push a version tag
and GitHub Actions builds macOS (Intel + Apple Silicon) and Linux (x86_64 +
ARM64) binaries, runs the tests, and publishes a GitHub Release with tarballs
and a `SHA256SUMS` file:

```bash
git tag v0.1.0
git push origin v0.1.0
```

The workflow can also be started manually from the Actions tab
(*Run workflow*), in which case the tag is derived from the version in
`Cargo.toml`.

## License

MIT
