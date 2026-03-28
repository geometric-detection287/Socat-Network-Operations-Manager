<p align="center">
  <h1 align="center">Socat Network Operations Manager</h1>
  <p align="center">
    A comprehensive socat-based network listener, forwarder, tunneler, and traffic redirector<br>with reliability and multi-session management.
  </p>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-2.3.0-blue?style=flat-square" alt="Version 2.3.0">
  <img src="https://img.shields.io/badge/shell-bash%204.4%2B-4EAA25?style=flat-square&logo=gnubash&logoColor=white" alt="Bash 4.4+">
  <img src="https://img.shields.io/badge/platform-linux-FCC624?style=flat-square&logo=linux&logoColor=black" alt="Linux">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="MIT License">
  <img src="https://img.shields.io/badge/Contributor%20Covenant-2.1-4baaaa?style=flat-square" alt="Code of Conduct">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/ShellCheck-passing-7B68EE?style=flat-square&logo=gnubash&logoColor=white" alt="ShellCheck">
  <img src="https://github.com/Sandler73/Socat-Network-Operations-Manager/actions/workflows/test.yml/badge.svg" alt="CI Tests">
  <img src="https://img.shields.io/badge/BATS-220%20tests-blue?style=flat-square" alt="220 BATS Tests">
</p>

<p align="center">
  <img src="https://img.shields.io/github/last-commit/Sandler73/Socat-Network-Operations-Manager?style=flat-square&color=FF6F3C&label=last%20commit" alt="Last Commit">
  <img src="https://img.shields.io/badge/maintained-yes-brightgreen?style=flat-square" alt="Maintained">
  <img src="https://img.shields.io/badge/PRs-welcome-azure?style=flat-square" alt="PRs Welcome">
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> ·
  <a href="#operational-modes">Modes</a> ·
  <a href="USAGE_GUIDE.md">Usage Guide</a> ·
  <a href="CHANGELOG.md">Changelog</a> ·
  <a href="SECURITY.md">Security</a> ·
  <a href="#testing">Testing</a> ·
  <a href="#contributing">Contributing</a>
</p>

---

**[Full Documentation Wiki](https://github.com/Sandler73/Socat-Network-Operations-Manager/wiki)** — detailed guides, architecture, scenarios, and developer reference.

---

## Table of Contents

- [Overview](#overview)
- [Key Highlights](#key-highlights)
- [Features](#features)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
  - [Mode Examples](#mode-examples)
- [Operational Modes](#operational-modes)
  - [listen](#listen-mode)
  - [batch](#batch-mode)
  - [forward](#forward-mode)
  - [tunnel](#tunnel-mode)
  - [redirect](#redirect-mode)
  - [status](#status-mode)
  - [stop](#stop-mode)
- [Global Options](#global-options)
- [Session Management](#session-management)
- [Protocol Selection](#protocol-selection)
- [Traffic Capture](#traffic-capture)
- [Watchdog Auto-Restart](#watchdog-auto-restart)
- [Logging](#logging)
- [Directory Structure](#directory-structure)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)
- [Testing](#testing)
- [Contributing](#contributing)
- [Documentation](#documentation)
- [Version History](#version-history)
- [Acknowledgments](#acknowledgments)
- [License](#license)
- [Support](#support)

---

## Overview

`socat_manager.sh` provides a unified command-line interface for managing socat-based network operations. It wraps socat's powerful but complex syntax into six intuitive operational modes, adding session tracking, process group isolation, protocol-aware lifecycle management, traffic capture, and automatic restart capabilities.

Every launched socat process receives a unique 8-character hex **Session ID**, is placed in its own **process group** via `setsid`, and is tracked in a persistent `.session` metadata file. This enables reliable status queries and clean shutdowns across terminal sessions and script invocations — you can launch a redirector in one terminal, check its status from another, and stop it from a third.

<p align="right">(<a href="#table-of-contents">back to top</a>)</p>

---

## Key Highlights

| | Feature | Description |
|---|---------|-------------|
| 🔀 | **Six Operational Modes** | listen, batch, forward, tunnel, redirect — plus status and stop for lifecycle management |
| 🔌 | **Protocol Flexibility** | TCP4, TCP6, UDP4, UDP6 individually (`--proto`) or both TCP+UDP simultaneously (`--dual-stack`) |
| 📡 | **Traffic Capture** | Verbose hex dump logging (`--capture`) on all modes — listen, batch, forward, tunnel, redirect |
| 🔖 | **Session Tracking** | Unique 8-char hex Session IDs with persistent `.session` metadata files |
| 🔒 | **Process Isolation** | Each socat process in its own process group via `setsid` with PID-file handoff |
| 🛡️ | **Protocol-Aware Stop** | Stopping TCP does not affect UDP on the same port, and vice versa |
| 🖥️ | **Interactive Menu** | Run with no arguments for a guided, menu-driven interface with validation and cancel support |
| ⚡ | **Non-Blocking Launch** | Script returns to prompt immediately — no terminal blocking |
| 🔄 | **Watchdog Auto-Restart** | Exponential backoff (1s→60s cap) with configurable max restarts |
| 📦 | **Batch Operations** | Launch listeners on port lists, ranges, or config files in a single command |
| 📝 | **Structured Logging** | OWASP/NIST SP 800-92 compliant format with correlation IDs and per-session audit trails |

<p align="right">(<a href="#table-of-contents">back to top</a>)</p>

---

## Features

### Core Capabilities

- **Six operational modes**: listen, batch, forward, tunnel, redirect, status, stop
- **Protocol flexibility**: TCP4, TCP6, UDP4, UDP6 individually via `--proto`, or both TCP and UDP simultaneously via `--dual-stack`
- **Traffic capture**: Verbose hex dump logging (`--capture`) available on all operational modes (listen, batch, forward, tunnel, redirect)
- **Session management**: Unique 8-char hex Session IDs with `.session` metadata files for persistent tracking
- **Process group isolation**: Each socat process launched via `setsid` with PID-file handoff for reliable cross-invocation tracking
- **Protocol-aware stop**: Stopping a TCP session does not affect a UDP session on the same port, and vice versa
- **Non-blocking launch**: Script returns to prompt immediately after launching sessions — no terminal blocking
- **Watchdog auto-restart**: Exponential backoff (1s, 2s, 4s... 60s cap) with configurable max restarts
- **Interactive menu**: No-args launches a full-featured menu with guided input, validation, dependency checking, and cancel support
- **Batch operations**: Launch listeners on port lists, ranges, or config files in a single command

### Input Validation and Security

- Whitelist-based port, hostname, protocol, file path, and session ID validation
- Command injection prevention on all user-supplied inputs (hostnames, paths)
- Path traversal protection on file path parameters
- Session directory permissions restricted to 700
- Session files restricted to 600
- Private key files restricted to 600
- Only socat processes targeted during port-based fallback kill (process name verification)
- No shell metacharacters permitted in hostname or path parameters

See [SECURITY.md](SECURITY.md) for the full threat model, implemented controls, and secure deployment guidelines.

### Logging and Audit

- Structured master execution log with correlation IDs (OWASP/NIST SP 800-92 compliant format)
- Per-session log files for independent audit trails
- Per-session error logs for stderr capture
- Traffic capture logs (socat `-v` hex dumps) per session and protocol
- Console output with color-coded severity levels (DEBUG, INFO, WARNING, ERROR, CRITICAL)

<p align="right">(<a href="#table-of-contents">back to top</a>)</p>

---

## Architecture

### Process Launch Model

```
socat_manager.sh (launcher)
    │
    ├── setsid bash -c 'echo $$ > pidfile; exec socat ...' &>/dev/null &
    │       │
    │       └── socat (PID == PGID, session leader)
    │               ├── socat fork (child for connection 1)
    │               ├── socat fork (child for connection 2)
    │               └── ...
    │
    ├── Reads real socat PID from pidfile
    ├── Registers session: SID, PID, PGID, protocol, port, command
    └── Returns to prompt (non-blocking)
```

**Key design decisions:**

1. **`setsid`** creates a new process group. Socat becomes the group leader (PID == PGID), so `kill -TERM -${PGID}` terminates socat and all its `fork` children in one operation.

2. **PID-file handoff**: The inner `bash -c` writes `$$` to a staging file before `exec socat`. Since `exec` preserves the PID, the parent reads the actual socat PID (not a dead wrapper PID).

3. **No `$()` subshell**: Session IDs are returned via a global variable (`LAUNCH_SID`) rather than command substitution, preventing stdout file descriptor inheritance that would block the terminal.

4. **Full detachment via `setsid`**: The process runs in a new session and process group, so it's not in the parent shell's job table. Combined with `&>/dev/null` redirections, no file descriptors or job references leak back to the launching terminal.

### Session File Format

```
# socat_manager session file v2.2
SESSION_ID=a1b2c3d4
SESSION_NAME=redir-tcp4-8443-example.com-443
PID=12345
PGID=12345
MODE=redirect
PROTOCOL=tcp4
LOCAL_PORT=8443
REMOTE_HOST=example.com
REMOTE_PORT=443
SOCAT_CMD=socat -v TCP4-LISTEN:8443,reuseaddr,fork,backlog=128 TCP4:example.com:443
STARTED=2026-03-20T14:30:00
CORRELATION=a1b2c3d4
LAUNCHER_PID=9999
```

### Stop Sequence

```
1. Read session metadata (PID, PGID, PROTOCOL)
2. Signal watchdog via .stop file (if applicable)
3. SIGTERM entire process group: kill -TERM -${PGID}
4. SIGTERM specific PID + children: kill -TERM ${PID}; pkill -TERM -P ${PID}
5. Wait grace period (5 seconds, checking every 0.5s)
6. SIGKILL if still alive: kill -KILL -${PGID}
7. Fallback: protocol-scoped port-based kill via ss/lsof (socat processes only)
8. Verify port freed (protocol-scoped, avoids cross-protocol interference)
9. Remove session file after confirmed dead
```

<p align="right">(<a href="#table-of-contents">back to top</a>)</p>

---

## Prerequisites

### Required

| Dependency | Purpose | Install |
|------------|---------|---------|
| **socat** | Core network operations | `sudo apt-get install -y socat` |
| **bash** 4.4+ | Script execution (associative arrays, `setsid`) | Pre-installed on most Linux |
| **coreutils** | `setsid`, `kill`, `sleep`, `date`, `sha256sum` | Pre-installed on most Linux |

### Optional

| Dependency | Purpose | Install |
|------------|---------|---------|
| **openssl** | TLS certificate generation (tunnel mode) | `sudo apt-get install -y openssl` |
| **ss** (iproute2) | Port status checking, session verification | `sudo apt-get install -y iproute2` |
| **netstat** (net-tools) | Fallback port status checking | `sudo apt-get install -y net-tools` |
| **lsof** | Fallback process-by-port discovery | `sudo apt-get install -y lsof` |
| **pstree** (psmisc) | Process tree display in `status` detail view | `sudo apt-get install -y psmisc` |

### System Requirements

- Linux kernel with `/proc/sys/kernel/random/uuid` (session ID generation)
- Root/sudo for privileged ports (<1024)
- Bash 4.4+ for associative arrays and `${var,,}` lowercase expansion

### Compatibility

Tested via [GitHub Actions CI](.github/workflows/test.yml) on every push across 8 environments:

| Distribution | Version | Bash | CI Status | Package Manager | Notes |
|-------------|---------|------|-----------|-----------------|-------|
| **Ubuntu** | 22.04 LTS | 5.1 | ✅ Verified | `apt` | CI runner (native) |
| **Ubuntu** | 24.04 LTS | 5.2 | ✅ Verified | `apt` | CI runner (native) |
| **Ubuntu** | 24.04 LTS | 4.4 | ✅ Verified | `apt` | Minimum bash version (compiled from source) |
| **Debian** | 12 (Bookworm) | 5.2 | ✅ Verified | `apt` | Docker container |
| **Kali Linux** | Rolling | 5.2 | ✅ Verified | `apt` | Docker container; socat typically pre-installed |
| **Rocky Linux** | 9 | 5.1 | ✅ Verified | `dnf` | Docker container; RHEL binary-compatible |
| **AlmaLinux** | 9 | 5.1 | ✅ Verified | `dnf` | Docker container; RHEL binary-compatible |
| **Arch Linux** | Rolling | 5.2 | ✅ Verified | `pacman` | Docker container |

**Also expected to work** on any Linux distribution with bash 4.4+ and standard coreutils, including Fedora, openSUSE, Amazon Linux 2023, and Raspberry Pi OS. RHEL 8/9 are supported via the binary-compatible Rocky Linux and AlmaLinux test coverage.

<p align="right">(<a href="#table-of-contents">back to top</a>)</p>

---

## Quick Start

```bash
# 1. Install socat
sudo apt-get update && sudo apt-get install -y socat

# 2. Clone or download
git clone https://github.com/Sandler73/Socat-Network-Operations-Manager.git
cd socat-manager

# 3. Install system-wide (or skip this and run directly with ./socat_manager.sh)
sudo make install

# 4. Launch the interactive menu (no arguments)
sudo socat-manager

# Or use CLI mode directly:
socat-manager listen --port 8080    # Start a TCP listener
socat-manager status                # Check session status
socat-manager stop --all            # Stop everything
```

**Interactive menu**: Running with no arguments launches a guided, menu-driven interface with validated input and cancel support (type `q` at any prompt to return to the main menu). Also accessible via `socat-manager menu`.

**Direct CLI**: All commands work exactly as shown — `socat-manager listen --port 8080`, `socat-manager status`, etc. Full CLI reference in the [Usage Guide](USAGE_GUIDE.md).

**Alternative**: Run directly without installing — `chmod +x socat_manager.sh && sudo ./socat_manager.sh`

### Mode Examples

Quick copy-paste examples for each operational mode. See the [Usage Guide](USAGE_GUIDE.md) for complete options, dual-stack configuration, and operational scenarios.

**Listen** — Start a TCP/UDP listener that captures incoming data:
```bash
socat-manager listen --port 8080
socat-manager listen --port 5353 --proto udp4
socat-manager listen --port 8080 --dual-stack --capture
```

**Batch** — Launch listeners on multiple ports simultaneously:
```bash
socat-manager batch --ports 8080,8081,8082
socat-manager batch --range 9000-9010
socat-manager batch --file conf/ports.conf --proto udp4
```

**Forward** — Relay traffic from a local port to a remote host:
```bash
socat-manager forward --lport 8080 --rhost 10.0.0.5 --rport 80
socat-manager forward --lport 5353 --rhost 10.0.0.1 --rport 53 --proto udp4
socat-manager forward --lport 443 --rhost backend.local --rport 8443 --capture
```

**Tunnel** — Create a TLS-encrypted tunnel (auto-generates certificates):
```bash
socat-manager tunnel --port 4443 --rhost 10.0.0.5 --rport 22
socat-manager tunnel --port 8443 --rhost db.internal --rport 3306 --capture
```

**Redirect** — Transparent port redirection with optional traffic capture:
```bash
socat-manager redirect --lport 80 --rhost 192.168.1.10 --rport 8080
socat-manager redirect --lport 53 --rhost 10.0.0.1 --rport 5353 --proto udp4
socat-manager redirect --lport 443 --rhost backend --rport 8443 --dual-stack
```

**Status** — View active sessions and session details:
```bash
socat-manager status
socat-manager status --detail
socat-manager status --cleanup
```

**Stop** — Terminate sessions by name, port, PID, or all at once:
```bash
socat-manager stop --all
socat-manager stop --name listen-tcp4-8080
socat-manager stop --port 8080
socat-manager stop --pid 12345
```

<p align="right">(<a href="#table-of-contents">back to top</a>)</p>

---

## Operational Modes

### listen Mode

Start a single TCP or UDP listener that captures incoming data to a log file.

```bash
# Basic TCP listener
./socat_manager.sh listen --port 8080

# UDP listener
./socat_manager.sh listen --port 5353 --proto udp4

# TCP + UDP simultaneously
./socat_manager.sh listen --port 8080 --dual-stack

# With traffic capture
./socat_manager.sh listen --port 8080 --capture

# Bind to specific interface
./socat_manager.sh listen --port 8080 --bind 192.168.1.100

# With auto-restart
./socat_manager.sh listen --port 8080 --watchdog
```

**Options:**

| Option | Description |
|--------|-------------|
| `-p, --port <PORT>` | Port number to listen on (required) |
| `--proto <PROTO>` | Protocol: tcp, tcp4, tcp6, udp, udp4, udp6 (default: tcp4) |
| `--dual-stack` | Also start listener on alternate protocol |
| `--capture` | Enable verbose hex dump traffic logging |
| `--bind <ADDR>` | Bind to specific IP address |
| `--name <n>` | Custom session name |
| `--logfile <PATH>` | Custom data log file path |
| `--watchdog` | Enable auto-restart on crash |
| `--socat-opts <OPTS>` | Additional socat address options |

### batch Mode

Start multiple listeners from port lists, ranges, or config files.

```bash
# Port list
sudo ./socat_manager.sh batch --ports "21,22,23,25,80,443"

# Port range
./socat_manager.sh batch --range 8000-8010

# Port range with dual-stack and capture
./socat_manager.sh batch --range 8000-8005 --dual-stack --capture

# UDP-only batch
./socat_manager.sh batch --ports "5353,5354,5355" --proto udp4

# From config file
./socat_manager.sh batch --config ./ports.conf
```

**Config file format** (`ports.conf`):

```
# One port per line. Comments and blank lines are ignored.
8080
8443
9090
# 9999  ← commented out, skipped
```

**Options:**

| Option | Description |
|--------|-------------|
| `--ports <LIST>` | Comma-separated port list |
| `--range <START-END>` | Port range (max 1000 ports) |
| `--config <FILE>` | Config file (one port per line) |
| `--proto <PROTO>` | Protocol for all listeners (default: tcp4) |
| `--dual-stack` | Start both TCP and UDP per port |
| `--capture` | Enable traffic capture for all listeners |
| `--watchdog` | Enable auto-restart for all listeners |

### forward Mode

Create a bidirectional port forwarder between a local port and a remote target.

```bash
# TCP forwarder
./socat_manager.sh forward --lport 8080 --rhost 192.168.1.10 --rport 80

# UDP forwarder (e.g., DNS relay)
./socat_manager.sh forward --lport 5353 --rhost 10.0.0.1 --rport 53 --proto udp4

# Dual-stack forwarder
./socat_manager.sh forward --lport 8080 --rhost 192.168.1.10 --rport 80 --dual-stack

# With traffic capture
./socat_manager.sh forward --lport 8080 --rhost 192.168.1.10 --rport 80 --capture

# Cross-protocol forwarding (TCP listen → UDP remote)
./socat_manager.sh forward --lport 8080 --rhost 10.0.0.5 --rport 53 --proto tcp4 --remote-proto udp4
```

**Options:**

| Option | Description |
|--------|-------------|
| `--lport <PORT>` | Local port to listen on (required) |
| `--rhost <HOST>` | Remote host to forward to (required) |
| `--rport <PORT>` | Remote port to forward to (required) |
| `--proto <PROTO>` | Listen protocol (default: tcp4) |
| `--remote-proto <PROTO>` | Remote protocol (default: matches `--proto`) |
| `--dual-stack` | Also start forwarder on alternate protocol |
| `--capture` | Enable traffic capture |
| `--logfile <PATH>` | Custom capture log file |
| `--name <n>` | Custom session name |
| `--watchdog` | Enable auto-restart |

### tunnel Mode

Create an encrypted TLS/SSL tunnel. Accepts TLS connections on a local port and forwards plaintext traffic to a remote target. Auto-generates self-signed certificates if none provided.

```bash
# Basic tunnel (auto-generates self-signed cert)
./socat_manager.sh tunnel --port 4443 --rhost 10.0.0.5 --rport 22

# With custom certificate
./socat_manager.sh tunnel --port 8443 --rhost db.internal --rport 5432 \
    --cert /etc/ssl/cert.pem --key /etc/ssl/key.pem

# Tunnel with plaintext UDP forwarder on same port
./socat_manager.sh tunnel --port 4443 --rhost 10.0.0.5 --rport 22 --dual-stack

# With capture (logs decrypted traffic)
./socat_manager.sh tunnel --port 4443 --rhost 10.0.0.5 --rport 22 --capture

# Custom Common Name for self-signed cert
./socat_manager.sh tunnel --port 4443 --rhost 10.0.0.5 --rport 22 --cn myhost.local
```

> **Note:** TLS tunnels are TCP-only by design. `--proto udp4` will produce a clear error with guidance to use `forward --proto udp4` instead. `--dual-stack` adds a plaintext UDP forwarder with a warning that UDP traffic is not encrypted.

**Options:**

| Option | Description |
|--------|-------------|
| `-p, --port <PORT>` | Local TLS listen port (required) |
| `--rhost <HOST>` | Remote target host (required) |
| `--rport <PORT>` | Remote target port (required) |
| `--cert <PATH>` | Path to PEM certificate file |
| `--key <PATH>` | Path to PEM private key file |
| `--cn <CN>` | Common Name for self-signed cert (default: localhost) |
| `--proto <PROTO>` | Validates protocol (tcp accepted; udp rejected with guidance) |
| `--dual-stack` | Also start plaintext UDP forwarder on same port |
| `--capture` | Enable capture of decrypted traffic |
| `--logfile <PATH>` | Custom capture log file |
| `--name <n>` | Custom session name |
| `--watchdog` | Enable auto-restart |

**Connecting to a tunnel:**

```bash
socat - OPENSSL:localhost:4443,verify=0
```

### redirect Mode

Redirect/proxy traffic transparently between a local port and a remote target. Optionally captures bidirectional traffic hex dumps.

```bash
# TCP redirect
./socat_manager.sh redirect --lport 8443 --rhost example.com --rport 443

# UDP redirect (e.g., DNS proxy)
./socat_manager.sh redirect --lport 5353 --rhost 8.8.8.8 --rport 53 --proto udp4

# Dual-stack redirect
./socat_manager.sh redirect --lport 8443 --rhost example.com --rport 443 --dual-stack

# With traffic capture
./socat_manager.sh redirect --lport 8443 --rhost example.com --rport 443 --capture

# Full dual-stack with capture
./socat_manager.sh redirect --lport 8443 --rhost example.com --rport 443 --dual-stack --capture
```

**Options:**

| Option | Description |
|--------|-------------|
| `--lport <PORT>` | Local listen port (required) |
| `--rhost <HOST>` | Remote target host (required) |
| `--rport <PORT>` | Remote target port (required) |
| `--proto <PROTO>` | Protocol: tcp, tcp4, tcp6, udp, udp4, udp6 (default: tcp4) |
| `--dual-stack` | Also start redirector on alternate protocol |
| `--capture` | Enable traffic capture (hex dump) |
| `--logfile <PATH>` | Custom capture log file |
| `--name <n>` | Custom session name |
| `--watchdog` | Enable auto-restart |

### status Mode

Display all active managed sessions or detailed information for a specific session.

```bash
# List all sessions
./socat_manager.sh status

# Detail by Session ID
./socat_manager.sh status a1b2c3d4

# Detail by session name
./socat_manager.sh status redir-tcp4-8443-example.com-443

# Detail by port (shows all protocols on that port)
./socat_manager.sh status 8443

# Include system-level listener info
./socat_manager.sh status --verbose

# Clean up dead session files
./socat_manager.sh status --cleanup
```

**Status table output example:**

```
  ─── Active Sessions ───

  SID        SESSION                      PID      PGID     MODE       PROTO  LPORT  REMOTE                 STATUS
  ────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  a1b2c3d4   redir-tcp4-8443-example.com  12345    12345    redirect   tcp4   8443   example.com:443        ALIVE
  e5f67890   redir-udp4-8443-example.com  12346    12346    redirect   udp4   8443   example.com:443        ALIVE

  Sessions: 2 alive, 0 dead, 2 total
```

**Detail view** (when querying by SID, name, or port) includes: all session metadata fields, process tree (via `pstree`), port binding status per protocol, socat command string, and associated log file paths.

### stop Mode

Stop one or more sessions by session ID, name, port, PID, or all.

```bash
# Stop by Session ID
./socat_manager.sh stop a1b2c3d4

# Stop by session name
./socat_manager.sh stop --name redir-tcp4-8443-example.com-443

# Stop all sessions on a port (both protocols if dual-stack)
./socat_manager.sh stop --port 8443

# Stop by PID
./socat_manager.sh stop --pid 12345

# Stop everything
./socat_manager.sh stop --all
```

> **Protocol isolation:** Stopping a TCP session on port 8443 does **not** affect a UDP session on the same port. Each protocol's stop operation is scoped to its own protocol only. The `--port` flag is the exception — it stops all sessions on that port across all protocols.

<p align="right">(<a href="#table-of-contents">back to top</a>)</p>

---

## Global Options

These options are available on all operational modes:

| Option | Description |
|--------|-------------|
| `--proto <PROTOCOL>` | Select protocol: `tcp`, `tcp4`, `tcp6`, `udp`, `udp4`, `udp6`. Default: `tcp4`. Tunnel mode accepts TCP only. |
| `--dual-stack` | Launch sessions on both TCP and UDP simultaneously. Each gets its own Session ID. |
| `--capture` | Enable socat `-v` verbose hex dump traffic logging. Capture log per session/protocol. |
| `--watchdog` | Enable automatic restart with exponential backoff on process crash. |
| `-v, --verbose` | Enable DEBUG-level console output. |
| `-h, --help` | Show context-sensitive help (per mode). |
| `--version` | Show version string and exit. |

<p align="right">(<a href="#table-of-contents">back to top</a>)</p>

---

## Session Management

Every socat process launched by `socat_manager.sh` receives:

1. A **unique 8-character hex Session ID** (e.g., `a1b2c3d4`) generated from `/proc/sys/kernel/random/uuid` with collision checking.

2. A **`.session` metadata file** in the `sessions/` directory (permissions 600) containing PID, PGID, mode, protocol, ports, timestamps, full socat command, correlation ID, and launcher PID.

3. An **isolated process group** via `setsid`, making the socat process its own session leader and group leader. This enables `kill -TERM -${PGID}` to terminate the entire process tree (parent + all forked children).

Sessions persist across terminal exits and script invocations. The `status` command reads session files to report on all managed processes. The `stop` command uses PID, PGID, and protocol-scoped port verification to ensure complete shutdown.

**Backward compatibility:** If legacy `.pid` session files from v1.x are detected, they are automatically migrated to the v2.x `.session` format on startup.

<p align="right">(<a href="#table-of-contents">back to top</a>)</p>

---

## Protocol Selection

### Individual Protocol (`--proto`)

Select a specific protocol for the session:

```bash
./socat_manager.sh listen --port 8080 --proto tcp4    # TCP4 (default)
./socat_manager.sh listen --port 5353 --proto udp4    # UDP4
./socat_manager.sh listen --port 8080 --proto tcp6    # TCP6 (IPv6)
./socat_manager.sh listen --port 5353 --proto udp6    # UDP6 (IPv6)
```

### Dual-Stack (`--dual-stack`)

Launch both TCP and UDP on the same port. Each protocol gets its own Session ID:

```bash
./socat_manager.sh redirect --lport 8443 --rhost example.com --rport 443 --dual-stack
# Output:
#   [✓] Redirector active: tcp4:8443 → example.com:443 (SID a1b2c3d4)
#   [✓] Redirector active: udp4:8443 → example.com:443 (SID e5f67890)
```

Stop operations are protocol-aware:

```bash
./socat_manager.sh stop a1b2c3d4       # Stop only TCP (UDP remains active)
./socat_manager.sh stop e5f67890       # Stop only UDP
./socat_manager.sh stop --port 8443    # Stop both (all protocols on port)
```

<p align="right">(<a href="#table-of-contents">back to top</a>)</p>

---

## Traffic Capture

The `--capture` flag enables socat's `-v` (verbose) mode, which produces hex dump output of all traffic on stderr. The launcher redirects this stderr to a per-session capture log file:

```bash
# Capture on any mode
./socat_manager.sh listen --port 8080 --capture
./socat_manager.sh forward --lport 8080 --rhost 10.0.0.1 --rport 80 --capture
./socat_manager.sh tunnel --port 4443 --rhost 10.0.0.5 --rport 22 --capture
./socat_manager.sh redirect --lport 8443 --rhost example.com --rport 443 --capture
./socat_manager.sh batch --ports "8080,8443" --capture
```

Capture log files are written to: `logs/capture-<proto>-<port>-<host>-<rport>-<timestamp>.log`

For tunnel mode, capture logs contain **decrypted** traffic between the TLS termination point and the remote target.

For dual-stack with capture, each protocol gets its own capture log.

<p align="right">(<a href="#table-of-contents">back to top</a>)</p>

---

## Watchdog Auto-Restart

The `--watchdog` flag enables automatic restart if the socat process crashes:

```bash
./socat_manager.sh listen --port 8080 --watchdog
```

| Parameter | Value |
|-----------|-------|
| Initial restart delay | 1 second |
| Backoff pattern | Exponential: 1s, 2s, 4s, 8s, 16s, 32s, 60s |
| Maximum backoff | 60 seconds (capped) |
| Maximum restarts | 10 (default, configurable in source) |
| Graceful stop | Writes `.stop` signal file; watchdog checks between restarts |

<p align="right">(<a href="#table-of-contents">back to top</a>)</p>

---

## Logging

### Log Types

| Log | Path | Description |
|-----|------|-------------|
| Master execution | `logs/socat_manager-<timestamp>.log` | All operations for this script invocation |
| Session-specific | `logs/session-<sid>-<timestamp>.log` | Per-session audit trail |
| Session errors | `logs/session-<sid>-error.log` | Socat stderr output (non-capture mode) |
| Listener data | `logs/listener-<proto>-<port>.log` | Raw incoming data (listen/batch modes) |
| Traffic capture | `logs/capture-<proto>-<port>-<timestamp>.log` | Hex dump traffic (when `--capture` enabled) |

### Log Format

Master and session logs use structured format compliant with OWASP Logging Cheat Sheet and NIST SP 800-92:

```
2026-03-20T14:30:00.123 [INFO] [corr:a1b2c3d4] [session] Session registered: name=redir-tcp4-8443 pid=12345 pgid=12345 mode=redirect proto=tcp4 port=8443
```

<p align="right">(<a href="#table-of-contents">back to top</a>)</p>

---

## Directory Structure

```
socat-manager/                    # Repository root
├── socat_manager.sh              # Main script (chmod +x)
├── Makefile                      # Build, test, install, package
├── .shellcheckrc                 # ShellCheck configuration
├── .gitignore                    # Git ignore rules
├── bin/
│   └── socat-manager             # System-wide wrapper script
├── templates/
│   └── activate.sh              # Virtual environment activation template
├── tests/                       # BATS test suite (220 tests)
│   ├── helpers/test_helper.bash  # Shared setup/teardown
│   ├── stubs/                    # Mock binaries (socat, ss, openssl)
│   ├── fixtures/                 # Test data (session files, port configs)
│   ├── unit/                     # Unit tests (validation, session)
│   └── integration/              # Integration tests (lifecycle, dual-stack, capture)
├── .github/
│   ├── workflows/test.yml        # CI: lint + BATS on push/PR
│   ├── workflows/release.yml     # CD: build + publish on tag
│   ├── ISSUE_TEMPLATE/           # Bug report, feature request, security
│   └── PULL_REQUEST_TEMPLATE.md  # PR checklist
├── README.md                     # This file
├── USAGE_GUIDE.md                # Detailed usage and deployment guide
├── CONTRIBUTING.md               # Development setup and contribution guide
├── CHANGELOG.md                  # Version history and change details
├── SECURITY.md                   # Security policy and threat model
├── CODE_OF_CONDUCT.md            # Contributor code of conduct
└── LICENSE                       # MIT License
```

Runtime directories (`sessions/`, `logs/`, `certs/`, `conf/`) are created automatically on first run and excluded from version control by `.gitignore`.

<p align="right">(<a href="#table-of-contents">back to top</a>)</p>

---

## Security Considerations

### Input Validation

- All ports validated as integers in range 1-65535
- All hostnames validated against IPv4, IPv6, and RFC 1123 patterns
- Shell metacharacters (`; | & $ \` ( ) { } [ ] < > ! #`) blocked in hostnames
- Path traversal (`..`) and injection characters blocked in file paths
- Session IDs validated as exactly 8 lowercase hex characters
- Protocol strings validated against whitelist (tcp4, tcp6, udp4, udp6)

### Process Isolation

- Each socat process runs in its own process group (`setsid`)
- Session files have restricted permissions (600)
- Session directory has restricted permissions (700)
- Private key files generated with 600 permissions
- Port-based fallback kill only targets processes with comm name `socat` (verified via `ps`)

### What This Tool Does NOT Do

- Does not encrypt traffic (except tunnel mode TLS)
- Does not authenticate connections to the listener/forwarder/redirector
- Does not implement rate limiting or connection throttling
- Does not filter or inspect traffic content (capture is passive hex dump)
- Self-signed certificates (tunnel mode default) are not trusted by clients unless explicitly configured

For the full security policy, threat model, implemented controls, known limitations, and secure deployment guidelines, see [SECURITY.md](SECURITY.md).

<p align="right">(<a href="#table-of-contents">back to top</a>)</p>

---

## Troubleshooting

### Session appears DEAD in status but port is still bound

The original process may have been killed without going through `socat_manager.sh stop`. Run:

```bash
./socat_manager.sh status --cleanup    # Remove stale session files
./socat_manager.sh status --verbose    # Show system-level socat listeners via ss
```

Then manually kill any orphaned socat processes:

```bash
ss -tlnp | grep :8443                  # Find PID
kill <PID>                              # Or: kill -9 <PID>
```

### "Port already in use" when launching

Another process is bound to the port. Check with:

```bash
ss -tlnp | grep :<PORT>               # TCP
ss -ulnp | grep :<PORT>               # UDP
```

### Watchdog keeps restarting

The socat process is crashing immediately. Check the session error log:

```bash
cat logs/session-<SID>-error.log
```

Common causes: invalid remote host (DNS resolution failure), connection refused on remote port, certificate errors (tunnel mode).

### Stop falls through to SIGKILL

If SIGTERM doesn't work within the grace period (5 seconds), socat may have child processes that aren't responding to SIGTERM. This is expected behavior — SIGKILL is the fallback. Check:

```bash
./socat_manager.sh status <SID>        # Verify it's actually stopped
ss -tlnp | grep :<PORT>               # Verify port is freed
```

For additional troubleshooting scenarios, see the [Usage Guide](USAGE_GUIDE.md#11-troubleshooting).

<p align="right">(<a href="#table-of-contents">back to top</a>)</p>

---

## Testing

The project includes a comprehensive test suite built on [BATS](https://github.com/bats-core/bats-core) (Bash Automated Testing System) with 220 tests covering validation, session management, lifecycle operations, protocol-scoped stop, and traffic capture.

```bash
# Run the full test suite (lint + all tests)
make test

# Run unit tests only (fast, ~2 seconds)
make test-unit

# Run integration tests only (uses mock socat/ss stubs)
make test-integration

# Run ShellCheck linting only
make lint

# Run a specific test file
bats tests/unit/validation.bats

# Run a specific test by name
bats tests/integration/dual_stack.bats --filter "stopping TCP preserves UDP"
```

| Test File | Tests | Coverage |
|-----------|-------|----------|
| `tests/unit/validation.bats` | 68 | All `validate_*` functions, `generate_session_id`, `get_alt_protocol` |
| `tests/unit/session.bats` | 30 | `session_register`, `session_read_field`, `session_find_by_*`, `session_cleanup_dead` |
| `tests/integration/lifecycle.bats` | 23 | Launch, PID-file handoff, stop, non-blocking, multi-session, command builders |
| `tests/integration/dual_stack.bats` | 8 | Protocol-scoped stop, dual-stack launch, port isolation |
| `tests/integration/capture.bats` | 14 | Capture flag in all builders, stderr redirect, dual-stack capture isolation |

Tests use mock stubs for socat, ss, and openssl so they run without real network operations or dependencies. See [CONTRIBUTING.md](CONTRIBUTING.md) for details on writing and running tests.

**CI/CD**: Every push and PR runs the test suite automatically via [GitHub Actions](.github/workflows/test.yml) across a matrix of bash versions (4.4, 5.1, 5.2) and Ubuntu releases (22.04, 24.04). Releases are automated via [tag-triggered workflow](.github/workflows/release.yml).

<p align="right">(<a href="#table-of-contents">back to top</a>)</p>

---

## Contributing

Contributions are welcome and appreciated. To contribute:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/your-feature-name`)
3. **Commit** your changes with clear, descriptive messages (`git commit -m 'Add: description of change'`)
4. **Push** to your branch (`git push origin feature/your-feature-name`)
5. **Open** a Pull Request with a detailed description of the change, its motivation, and testing performed

### Guidelines

- Run `make test` before submitting — all 220 tests must pass
- Run `make lint` — ShellCheck must report no warnings
- Follow the existing code style: comprehensive function documentation headers (Description, Parameters, Returns), inline comments explaining non-obvious logic, and consistent formatting
- All user-supplied inputs must pass through the existing validation functions
- New CLI flags must be added to the mode argument parser, command builder, help function, and at least one BATS test
- Update `CHANGELOG.md` with your changes under an `[Unreleased]` section
- Read and follow the [Code of Conduct](CODE_OF_CONDUCT.md)
- Report security vulnerabilities privately per [SECURITY.md](SECURITY.md) — do not open public issues for security bugs

For the complete development guide including environment setup, test architecture, coding standards, and PR process, see [CONTRIBUTING.md](CONTRIBUTING.md).

<p align="right">(<a href="#table-of-contents">back to top</a>)</p>

---

## Documentation

| Document | Description |
|----------|-------------|
| [README.md](README.md) | Project overview, features, architecture, and quick reference (this file) |
| [USAGE_GUIDE.md](USAGE_GUIDE.md) | Detailed usage, installation methods (direct, make install, venv), testing guide, operational scenarios, and troubleshooting |
| [CHANGELOG.md](CHANGELOG.md) | Complete version history with detailed change descriptions per release |
| [SECURITY.md](SECURITY.md) | Security policy, vulnerability reporting, threat model, implemented controls, and secure deployment guidelines |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Development environment setup, testing guide, coding standards, and PR process |
| [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | Contributor Covenant code of conduct with responsible use policy for security tooling |
| [LICENSE](LICENSE) | MIT License with liability disclaimer and dependency notices |

<p align="right">(<a href="#table-of-contents">back to top</a>)</p>

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| **2.3.0** | 2026-03-20 | `--capture` extended to all operational modes. `--proto` added to tunnel mode (TLS-aware validation). |
| **2.2.0** | 2026-03-20 | Protocol-aware stop: stopping TCP no longer kills UDP on shared ports. `--proto` added to redirect mode. Full documentation restoration. |
| **2.1.0** | 2026-03-20 | Fixed terminal blocking (PID-file handoff). Fixed wrong PID tracking. Added `--dual-stack` to all modes. |
| **2.0.0** | 2026-03-20 | Session ID system (8-char hex). PGID tracking via `setsid`. Comprehensive stop sequence with port verification. |
| **1.0.0** | 2026-03-20 | Initial release. Six operational modes. PID-file tracking. Basic stop/status. |

See [CHANGELOG.md](CHANGELOG.md) for complete details on every change.

<p align="right">(<a href="#table-of-contents">back to top</a>)</p>

---

## Acknowledgments

- **[socat](http://www.dest-unreach.org/socat/)** by Gerhard Rieger — the powerful relay utility that this manager wraps
- **[OpenSSL](https://www.openssl.org/)** — TLS/SSL implementation used for tunnel mode certificate generation
- **[Contributor Covenant](https://www.contributor-covenant.org/)** — code of conduct framework
- **[Keep a Changelog](https://keepachangelog.com/)** — changelog format standard
- **[Semantic Versioning](https://semver.org/)** — versioning scheme
- **[Shields.io](https://shields.io/)** — badge generation service
- **OWASP** and **NIST** — security standards referenced throughout (OWASP Logging Cheat Sheet, NIST SP 800-92, CWE-20, CWE-22, CWE-78)

<p align="right">(<a href="#table-of-contents">back to top</a>)</p>

---

## License

Distributed under the MIT License. See [LICENSE](LICENSE) for full terms.

```
MIT License · Copyright (c) 2026 socat_manager Contributors
```

This software is intended for authorized network operations, security testing, research, and educational purposes only. Users are solely responsible for ensuring their use complies with all applicable laws and regulations.

<p align="right">(<a href="#table-of-contents">back to top</a>)</p>

---

## Support

<p align="center">
  ⭐ If this project helps you operationally, please consider giving it a star! ⭐
</p>

<p align="center">
  <a href="https://github.com/Sandler73/Socat-Network-Operations-Manager/issues/new?template=bug_report.md">Report Bug</a>
  ·
  <a href="https://github.com/Sandler73/Socat-Network-Operations-Manager/issues/new?template=feature_request.md">Request Feature</a>
</p>

<p align="center">
  <a href="https://github.com/sponsors/Sandler73">
    <img src="https://img.shields.io/badge/Sponsor-❤️-ea4aaa?style=for-the-badge&logo=githubsponsors&logoColor=white" alt="Sponsor">
  </a>
  <a href="https://ko-fi.com/Sandler73">
    <img src="https://img.shields.io/badge/Ko--fi-Buy%20Me%20a%20Coffee-FF5E5B?style=for-the-badge&logo=ko-fi&logoColor=white" alt="Ko-fi">
  </a>
</p>

<p align="right">(<a href="#table-of-contents">back to top</a>)</p>

