# Changelog

All notable changes to socat_manager.sh are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- **Interactive menu system**: Running with no arguments launches a full-featured
  menu-driven interface with guided input collection, validation at every prompt,
  and cancel/escape support (type `q` at any prompt to return to main menu).
  Also accessible via `socat-manager menu`.
- **ASCII art banner**: Stylized SOCAT block-letter banner in the interactive menu.
- **Dependency check menu**: Option 8 in the interactive menu checks all required
  and recommended dependencies with version info and status indicators.

### Security (Audit Remediation)
- **C-1**: Eliminated all `eval` calls — watchdog uses `bash -c` instead.
- **C-2**: New `validate_socat_opts()` — whitelist validation on `--socat-opts` input.
- **C-4**: New `validate_session_name()` — whitelist validation on `--name` input,
  wired into all four mode parsers (listen, forward, tunnel, redirect).
- **H-3**: `stop --pid` input validated as numeric-only before use.
- **H-4**: `session_read_field` uses `awk` exact-match instead of `grep` regex.
- **H-5**: All `DEFAULT_*` configuration variables marked `readonly`.
- **M-2**: Advisory file locking via `flock` for session directory operations.
- **M-4**: `MAX_SESSIONS=256` limit enforced at launch time.
- **M-5**: Capture log files created with `chmod 600` (all 9 code paths).
- **M-6**: IPv6 validation enhanced with length (2-39) and colon count (≤7) checks.
- **L-1**: Terminal detection — color codes disabled when stderr is not a terminal.
- **L-4**: Removed unused `DEFAULT_TIMEOUT`, `DEFAULT_MAX_CHILDREN`, `DEFAULT_BUFFER_SIZE`.

### Changed
- No-args behavior: shows interactive menu instead of help text.
- Session file format comment updated to v2.3.
- `_ensure_dirs` uses guard variable (called once, not per log write).
- **Makefile v2.0.0**: Added `test-smoke` target (menu launch, help, version, syntax — no BATS needed).
  `lint` now checks all bash files (stubs, helpers). `check-deps` checks `flock`. `dist` includes
  `wiki/` and `.github/`. `clean` removes test artifacts and lock files. `verify` tests menu launch.
- **Test suite**: 220 tests (up from 187). Added 33 tests covering `validate_socat_opts` (12),
  `validate_session_name` (11), IPv6 rejection (4), `session_read_field` awk behavior (3),
  `_session_lock` (3).
- `.shellcheckrc`: Documented SC2015 pattern and nameref usage.
- `.gitignore`: Added `sessions/.lock`.

---

## [2.3.0] - 2026-03-20

### Added

- **`--capture` flag on all operational modes**: Traffic capture via socat's `-v` verbose hex dump is now available on `listen`, `batch`, `forward`, `tunnel`, and `redirect` modes (previously only `redirect`). Each mode routes socat stderr to a per-session, per-protocol capture log file through the `launch_socat_session` stderr redirect parameter.
- **`--proto` flag on tunnel mode**: Tunnel mode now accepts `--proto` for CLI consistency. TCP variants (`tcp`, `tcp4`) are accepted silently. `tcp6` produces a warning with TCP4 fallback. UDP variants (`udp`, `udp4`, `udp6`) produce a clear error message with explicit guidance to use `forward --proto udp4` instead.
- **`--logfile` flag on forward and tunnel modes**: Custom capture log file path can now be specified for forward and tunnel modes when `--capture` is enabled.
- **Capture parameter on all command builders**: `build_socat_listen_cmd`, `build_socat_forward_cmd`, `build_socat_tunnel_cmd`, and `build_socat_redirect_cmd` all accept a capture boolean parameter that controls inclusion of the socat `-v` flag.
- **Capture log isolation for dual-stack**: When `--capture` and `--dual-stack` are combined, each protocol gets its own independent capture log file (e.g., `capture-tcp4-8443-...log` and `capture-udp4-8443-...log`).

### Changed

- Updated help text for all modes to document `--capture` in OPTIONS sections with examples.
- Updated help text for tunnel mode to document `--proto` with TLS-aware validation behavior.
- Updated main help to list `--capture` as a global option available on all modes.
- Updated script header description to note universal `--capture` availability.
- Version bumped from 2.2.0 to 2.3.0.

### Fixed

- **Tunnel `--proto` rejection**: Previously, `./socat_manager.sh tunnel --port 4443 --rhost host --rport 22 --proto tcp4` returned `"Unknown tunnel option: --proto"` because the tunnel argument parser lacked a `--proto` case entry. Now handled with TLS-aware validation logic.

---

## [2.2.0] - 2026-03-20

### Added

- **`--proto` flag on redirect mode**: Redirect mode now accepts `--proto` for individual TCP or UDP protocol selection. Previously, redirect hardcoded TCP4 regardless of user intent.
- **Protocol-aware stop operations**: The `_stop_session` function now reads the `PROTOCOL` field from the session file and scopes all port checks, port-based fallback kills, and port-freed verification to the session's own protocol only.
- **Protocol-scoped `_kill_by_port`**: The last-resort port-based kill function now accepts a protocol parameter and uses protocol-specific `ss` flags (`-tlnp` for TCP, `-ulnp` for UDP) instead of querying both protocols. The `lsof` fallback also uses `-iTCP` or `-iUDP` flags.
- **Protocol-scoped `check_port_freed`**: Port-freed verification now accepts a protocol parameter and only checks the specified protocol.
- **Full function documentation restoration**: All functions restored to comprehensive multi-line documentation blocks with Description, Parameters, Returns, Outputs, and inline code comments explaining socat options, validation logic, process group mechanics, and the PID-file handoff architecture.
- **Inline code comment restoration**: Restored explanatory comments throughout the codebase including socat address options (`reuseaddr`, `fork`, `backlog`, `keepalive`), command builder logic, validation rationale, and process lifecycle mechanics.
- **Session file protocol field in session names**: Redirect mode session names now include the protocol for disambiguation (e.g., `redir-tcp4-8443-example.com-443` instead of `redir-8443-example.com-443`).

### Changed

- Updated help text for all modes with full DESCRIPTION sections, comprehensive OPTIONS tables, and additional examples showing `--proto` and `--dual-stack` usage.
- Updated stop mode help to document protocol-aware stop behavior.
- Updated status detail view to show port status scoped to the session's protocol.
- Session file format version updated to v2.2.
- Version bumped from 2.1.0 to 2.2.0.

### Fixed

- **Cross-protocol kill on dual-stack stop** (critical): Stopping a TCP session on a shared port no longer kills the UDP session on the same port (and vice versa). Root cause was a three-step chain: (1) `_stop_session` checked `check_port_available` for both `tcp4` and `udp4` regardless of which session was being stopped; (2) `_kill_by_port` merged TCP and UDP PIDs into a single kill list; (3) `session_cleanup_dead` then swept the orphaned other-protocol session file. All three functions are now protocol-scoped.

---

## [2.1.0] - 2026-03-20

### Added

- **`--dual-stack` flag on all operational modes**: `listen`, `batch`, `forward`, `tunnel`, and `redirect` modes now support `--dual-stack` to launch both TCP and UDP sessions simultaneously on the same port. Each protocol receives its own independent Session ID for separate lifecycle management.
- **`get_alt_protocol` utility function**: Returns the alternate protocol for dual-stack operations (tcp4 to udp4, tcp6 to udp6, and vice versa).
- **Protocol-aware `build_socat_redirect_cmd`**: The redirect command builder now accepts a protocol parameter instead of hardcoding TCP4, enabling UDP redirectors.
- **Tunnel dual-stack advisory**: When `--dual-stack` is used with tunnel mode, a warning is logged that the UDP component is a plaintext forwarder (TLS is TCP-only).
- **PID-file handoff launch pattern**: Replaced the v2.0 `setsid cmd & ; $!` pattern with `setsid bash -c 'echo $$ > pidfile; exec socat ...'`. The inner bash writes its PID to a staging file before `exec` replaces it with socat (preserving the PID). The parent reads the real socat PID from this file.
- **`LAUNCH_SID` global variable**: Session IDs are now returned from `launch_socat_session` via a global variable instead of stdout, preventing `$()` subshell file descriptor inheritance.
- **`PID_FILE_WAIT_ITERS` constant**: Configurable timeout (default 20 iterations at 0.1s = 2 seconds) for waiting on the PID staging file.
- **Session error logs**: Non-capture mode stderr from socat processes is now captured to `logs/session-<SID>-error.log` for post-mortem debugging.

### Changed

- Stop grace period increased from 3 seconds to 5 seconds (`STOP_GRACE_SECONDS=5`).
- All mode functions updated to use `launch_socat_session` with the `LAUNCH_SID` global pattern instead of `$()` subshell capture.
- Version bumped from 2.0.0 to 2.1.0.

### Fixed

- **Terminal blocking on launch** (critical): Running `./socat_manager.sh redirect --lport 8443 ...` previously hung at "Starting Redirector" and required a second terminal for status/stop. Root cause: `sid="$(launch_socat_session ...)"` created a `$()` subshell that waited for all child processes holding its stdout file descriptor to close. The backgrounded socat process inherited this fd, keeping the pipe open indefinitely. Fixed by returning the session ID via `LAUNCH_SID` global variable and redirecting all socat stdout/stderr before `exec`.
- **Wrong PID tracked** (critical): The stored PID was the `setsid` wrapper process PID (which forks internally and exits immediately), not the actual socat PID. This caused SIGTERM during stop to target a dead process, falling through to SIGKILL every time. Fixed by the PID-file handoff pattern where socat's real PID (which equals its PGID under setsid) is captured from the staging file.
- **SIGTERM always falling through to SIGKILL**: Direct consequence of the wrong-PID bug. With the correct PID/PGID now stored, `kill -TERM -${PGID}` correctly targets the live socat process group, and graceful SIGTERM shutdown works as intended.

---

## [2.0.0] - 2026-03-20

### Added

- **Unique Session ID system**: Every launched socat process receives an 8-character hex Session ID generated from `/proc/sys/kernel/random/uuid` with collision checking against existing sessions.
- **Session file format (`.session`)**: Replaced v1.0 `.pid` files with comprehensive `.session` metadata files containing: SESSION_ID, SESSION_NAME, PID, PGID, MODE, PROTOCOL, LOCAL_PORT, REMOTE_HOST, REMOTE_PORT, SOCAT_CMD, STARTED, CORRELATION, LAUNCHER_PID.
- **Process group isolation via `setsid`**: All socat processes launched through `setsid` to create isolated process groups. PGID stored in session files for reliable tree kill.
- **`disown` after backgrounding**: Background processes disowned to prevent SIGHUP on script exit.
- **Comprehensive stop sequence**: 9-step stop process: read metadata, signal watchdog, SIGTERM process group, SIGTERM PID and children, wait grace period, SIGKILL if alive, port-based fallback kill, verify port freed, remove session file.
- **`session_detail` function**: Detailed view for individual sessions showing all metadata, process tree (via `pstree`), port binding status, socat command string, and associated log files.
- **Flexible status command**: `status` accepts optional positional argument matched against Session ID (8-char hex), session name, or port number. Port lookups return multiple sessions for dual-stack.
- **Flexible stop command**: `stop` accepts positional Session ID as first argument, plus `--all`, `--name`, `--port`, `--pid` flags for alternative selectors.
- **`session_find_by_name`**: Search sessions by human-readable name.
- **`session_find_by_port`**: Search sessions by local port number.
- **`session_find_by_pid`**: Search sessions by PID.
- **`session_cleanup_dead`**: Remove session files for dead processes (both PID and PGID confirmed dead).
- **`_cleanup_orphaned_socat`**: Detect socat processes not tracked by any session file and report them (does not auto-kill to prevent collateral damage).
- **`_kill_by_port` fallback**: Last-resort kill of socat processes on a port via `ss`/`lsof`. Only targets processes with comm name `socat` (verified via `ps`).
- **`check_port_freed` verification**: Post-stop verification that the port has been released, with configurable retry count and interval.
- **`validate_session_id` function**: Input validation for session IDs (8 lowercase hex characters).
- **Session directory permissions**: `sessions/` set to 700, individual `.session` files set to 600.
- **`STOP_GRACE_SECONDS` constant**: Configurable grace period before SIGKILL (default 3 seconds).
- **`STOP_VERIFY_RETRIES` and `STOP_VERIFY_INTERVAL` constants**: Configurable post-stop port verification timing.
- **Backward compatibility migration**: Automatic detection and migration of v1.0 `.pid` session files to v2.0 `.session` format on startup. Dead legacy sessions are cleaned up automatically.
- **Status table with PGID column**: Session list table now includes PGID alongside PID.

### Changed

- Session tracking moved from `.pid` files keyed by session name to `.session` files keyed by Session ID.
- Stop command no longer uses `pgrep -P ${SCRIPT_PID}` (which only worked within the same script invocation). Now uses session file metadata for cross-invocation reliability.
- Status command enhanced from simple list to support both overview and detail views.
- Help text for status and stop modes updated with new Session ID-based usage patterns and examples.
- Version bumped from 1.0.0 to 2.0.0.

### Removed

- Direct `pgrep -P ${SCRIPT_PID}` usage for stop --all (replaced by session file enumeration).
- Reliance on script PID for process ownership tracking (replaced by PGID-based process group tracking).

---

## [1.0.0] - 2026-03-20

### Added

- **Initial release** of socat_manager.sh with six operational modes.
- **`listen` mode**: Start a single TCP or UDP listener on a specified port with unidirectional data capture to log file. Options: `--port`, `--proto`, `--bind`, `--name`, `--logfile`, `--watchdog`, `--socat-opts`.
- **`batch` mode**: Start multiple listeners from comma-separated port lists (`--ports`), port ranges (`--range`), or config files (`--config`). Supports `--dual-stack` for TCP+UDP per port.
- **`forward` mode**: Bidirectional port forwarding between local and remote endpoints. Options: `--lport`, `--rhost`, `--rport`, `--proto`, `--remote-proto` for cross-protocol forwarding.
- **`tunnel` mode**: Encrypted TLS/SSL tunnel via socat + OpenSSL. Auto-generates self-signed certificates if `--cert`/`--key` not provided. Options: `--port`, `--rhost`, `--rport`, `--cert`, `--key`, `--cn`.
- **`redirect` mode**: Transparent traffic redirection/proxy with optional traffic capture (`--capture`) via socat `-v` hex dump. Options: `--lport`, `--rhost`, `--rport`, `--capture`, `--logfile`.
- **`status` mode**: Display all active managed sessions in formatted table with PID, mode, protocol, port, remote target, and alive/dead status.
- **`stop` mode**: Stop sessions by `--name`, `--port`, `--pid`, or `--all`. Sends SIGTERM with grace period, then SIGKILL. Cleans up session files.
- **Session tracking via PID files**: Each session registered in `sessions/` directory via `.pid` files containing PID, MODE, PROTOCOL, LOCAL_PORT, REMOTE_HOST, REMOTE_PORT, STARTED, CORRELATION, MASTER_PID.
- **Watchdog auto-restart**: `--watchdog` flag enables background monitoring with exponential backoff (1s, 2s, 4s, 8s, 16s, 32s, 60s cap) and configurable max restarts (default 10). Graceful stop via `.stop` signal file.
- **Structured logging infrastructure**: Dual output (console + file). Master execution log per invocation. Per-session log files. Structured format: `TIMESTAMP [LEVEL] [corr:ID] [component] message`. Color-coded console output with severity symbols.
- **Input validation suite**: Whitelist-based validation for ports (1-65535), port ranges (max 1000 span), port lists, hostnames (IPv4, IPv6, RFC 1123), protocols (tcp4, tcp6, udp4, udp6), and file paths (path traversal and injection prevention).
- **Port conflict detection**: Pre-launch check via `ss` (preferred) or `netstat` fallback to detect port conflicts before binding.
- **Socat command builders**: Separated command construction (`build_socat_listen_cmd`, `build_socat_forward_cmd`, `build_socat_tunnel_cmd`, `build_socat_redirect_cmd`) from execution for testability and audit logging.
- **Self-signed certificate generation**: OpenSSL-based RSA 2048-bit certificate generation for tunnel mode with restrictive private key permissions (600).
- **Signal handling**: Trap handlers for INT, TERM, HUP signals with graceful child process cleanup.
- **Dependency checking**: Socat availability verification with per-distribution install guidance.
- **Colored terminal output**: Severity-coded output with Unicode symbols.
- **Correlation ID**: Per-execution correlation ID (first 8 chars of UUID) for log correlation across sessions.
- **Context-sensitive help system**: Per-mode help accessible via `-h`/`--help` with synopsis, options, and examples.
- **Banner display**: Styled ASCII box header showing mode, version, and correlation ID.
- **Script metadata**: Version string (`--version`), script directory resolution, execution timestamp.
- **Directory auto-creation**: `logs/`, `sessions/`, `conf/`, `certs/` directories created automatically on first run.

### Dependencies

- **Required**: socat, bash 4.4+, coreutils
- **Optional**: openssl (tunnel mode), iproute2/ss (status/stop verification), net-tools/netstat (fallback), lsof (fallback), psmisc/pstree (status detail)

---

## Version Comparison

| Capability | v1.0.0 | v2.0.0 | v2.1.0 | v2.2.0 | v2.3.0 |
|------------|--------|--------|--------|--------|--------|
| Session tracking | .pid files by name | .session files by SID | .session + PID-file handoff | .session + protocol field | .session + protocol field |
| Process isolation | Background `&` | setsid + disown | setsid + exec + PID-file | setsid + exec + PID-file | setsid + exec + PID-file |
| Stop reliability | pgrep by script PID | PGID-based tree kill | Correct PID/PGID via pidfile | Protocol-scoped stop | Protocol-scoped stop |
| Terminal blocking | Yes (hangs) | Yes (hangs) | Fixed (non-blocking) | Fixed | Fixed |
| Dual-stack | batch only | batch only | All modes | All modes | All modes |
| --proto on redirect | No (hardcoded TCP4) | No (hardcoded TCP4) | No (hardcoded TCP4) | Yes | Yes |
| --proto on tunnel | No | No | No | No | Yes (TCP-aware validation) |
| --capture | redirect only | redirect only | redirect only | redirect only | All modes |
| Protocol-aware stop | No | No | No | Yes | Yes |
| Cross-protocol kill bug | N/A | N/A | Present | Fixed | Fixed |
| Session detail view | No | Yes | Yes | Yes (protocol-scoped) | Yes |
| Documentation density | Full | Full | Reduced (bug) | Restored | Full |
