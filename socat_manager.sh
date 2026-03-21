#!/usr/bin/env bash
#======================================================================
# SCRIPT     : socat_manager.sh
#======================================================================
# Name       : Socat Network Operations Manager
#
# Synopsis   : A comprehensive socat-based network listener, forwarder,
#              tunneler, and traffic redirector with reliability and
#              multi-session management.
#
# Description: Provides a unified interface for socat network operations
#              across six operational modes:
#
#              listen   - Start a single TCP/UDP listener on a port
#              batch    - Start multiple listeners from port list/range
#              forward  - Forward traffic between local↔remote endpoints
#              tunnel   - Create encrypted (OpenSSL) tunnels via socat
#              redirect - Redirect/proxy traffic transparently
#              status   - Display all active managed sessions
#              stop     - Stop sessions by ID, name, port, PID, or all
#
#              All modes include automatic session tracking via unique
#              session IDs, process group (PGID) management, per-session
#              logging, connection counting, and optional auto-restart
#              (watchdog) for reliability.
#
#              All operational modes support --proto to select TCP or UDP
#              individually, and --dual-stack to launch both TCP and UDP
#              sessions simultaneously on the same port.
#
#              All operational modes support --capture for verbose hex
#              dump traffic logging via socat -v.
#
# Notes      : - Requires socat installed and in PATH
#              - Root/sudo required for privileged ports (<1024)
#              - Sessions tracked in sessions/ directory via .session files
#              - Each session gets a unique 8-character hex Session ID
#              - Processes launched in isolated process groups (setsid)
#                with PID-file handoff for reliable cross-invocation
#                tracking, status, and stop
#              - Stop operations are protocol-aware: stopping a TCP session
#                on a shared port does not affect a UDP session on the same
#                port, and vice versa
#              - Per-execution and per-listener logs in logs/ directory
#              - Supports TCP4, TCP6, UDP4, UDP6 protocol families
#              - Auto-restart via --watchdog flag for crash recovery
#              - Batch mode accepts port lists, ranges, or config files
#              - Tunnel mode generates self-signed certs if none provided
#              - All socat PIDs and PGIDs tracked for clean shutdown
#              - Script returns to prompt immediately after launch
#                (no terminal blocking; status/stop from same terminal)
#
# Execution  : bash socat_manager.sh <MODE> [OPTIONS]
#
# Examples   :
#   # Single TCP listener on port 8080
#   bash socat_manager.sh listen --port 8080
#
#   # UDP-only listener on port 5353
#   bash socat_manager.sh listen --port 5353 --proto udp4
#
#   # Listener on both TCP and UDP
#   bash socat_manager.sh listen --port 8080 --dual-stack
#
#   # Batch listeners on common service ports (requires root)
#   sudo bash socat_manager.sh batch --ports "21,22,23,25,80,443"
#
#   # Port range batch with dual-stack
#   bash socat_manager.sh batch --range 8000-8010 --dual-stack
#
#   # Forward local:8080 to remote 192.168.1.10:80
#   bash socat_manager.sh forward --lport 8080 --rhost 192.168.1.10 --rport 80
#
#   # Forward UDP-only
#   bash socat_manager.sh forward --lport 5353 --rhost 10.0.0.1 --rport 53 --proto udp4
#
#   # Encrypted tunnel listener on 4443
#   bash socat_manager.sh tunnel --port 4443 --rhost 10.0.0.5 --rport 22
#
#   # Redirect TCP traffic (transparent proxy)
#   bash socat_manager.sh redirect --lport 8443 --rhost example.com --rport 443
#
#   # Redirect UDP-only (e.g., DNS proxy)
#   bash socat_manager.sh redirect --lport 5353 --rhost 8.8.8.8 --rport 53 --proto udp4
#
#   # Redirect both TCP and UDP with capture
#   bash socat_manager.sh redirect --lport 8443 --rhost example.com --rport 443 --dual-stack --capture
#
#   # Show all active sessions
#   bash socat_manager.sh status
#
#   # Show specific session details
#   bash socat_manager.sh status a1b2c3d4
#
#   # Stop a specific session by ID
#   bash socat_manager.sh stop a1b2c3d4
#
#   # Stop everything
#   bash socat_manager.sh stop --all
#
# Version    : 2.3.0
# Dependencies: socat, openssl (for tunnel mode), ss/netstat (for status)
#======================================================================

set -euo pipefail

#======================================================================
# CONSTANTS AND CONFIGURATION
#======================================================================

# Script metadata
readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}" .sh)"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_VERSION="2.3.0"
readonly SCRIPT_PID="$$"

# Directory structure
readonly LOG_DIR="${SCRIPT_DIR}/logs"
readonly SESSION_DIR="${SCRIPT_DIR}/sessions"
readonly CONF_DIR="${SCRIPT_DIR}/conf"
readonly CERT_DIR="${SCRIPT_DIR}/certs"

# Timestamp for this execution (used in log filenames)
readonly EXEC_TIMESTAMP="$(date '+%Y-%m-%dT%H-%M-%S')"

# Correlation ID for this execution (first 8 chars of a pseudo-UUID)
readonly CORRELATION_ID="$(cat /proc/sys/kernel/random/uuid 2>/dev/null | cut -c1-8 || date +%s%N | sha256sum | cut -c1-8)"

# Master log for this execution
readonly MASTER_LOG="${LOG_DIR}/${SCRIPT_NAME}-${EXEC_TIMESTAMP}.log"

# Default values
DEFAULT_PROTOCOL="tcp4"            # Default to IPv4 TCP
DEFAULT_BACKLOG=128                # socat listen backlog
DEFAULT_TIMEOUT=0                  # 0 = no timeout (persistent)
DEFAULT_MAX_CHILDREN=256           # Max concurrent forked connections
DEFAULT_WATCHDOG_INTERVAL=5        # Seconds between watchdog health checks
DEFAULT_WATCHDOG_MAX_RESTARTS=10   # Max auto-restarts before giving up
DEFAULT_BUFFER_SIZE=8192           # socat transfer buffer size (bytes)

# Stop timing constants
readonly STOP_GRACE_SECONDS=5      # Seconds to wait after SIGTERM before SIGKILL
readonly STOP_VERIFY_RETRIES=5     # Number of verification checks after stop
readonly STOP_VERIFY_INTERVAL=0.5  # Seconds between verification checks

# PID-file handoff timeout (iterations at 0.1s each)
readonly PID_FILE_WAIT_ITERS=20    # 2 seconds max wait for PID file

# Global variable for launch_socat_session to return session ID.
# Using a global avoids $() subshell capture which causes terminal
# blocking due to inherited stdout file descriptors. See the
# PROCESS LAUNCH WRAPPER section for detailed explanation.
LAUNCH_SID=""

# Color codes for terminal output
readonly CLR_RESET="\033[0m"
readonly CLR_BOLD="\033[1m"
readonly CLR_DIM="\033[2m"
readonly CLR_RED="\033[31m"
readonly CLR_GREEN="\033[32m"
readonly CLR_YELLOW="\033[33m"
readonly CLR_BLUE="\033[34m"
readonly CLR_CYAN="\033[36m"
readonly CLR_MAGENTA="\033[35m"
readonly CLR_WHITE="\033[37m"

# Status symbols
readonly SYM_OK="✓"
readonly SYM_FAIL="✗"
readonly SYM_WARN="!"
readonly SYM_INFO="i"
readonly SYM_ARROW="→"
readonly SYM_PLUS="+"
readonly SYM_LISTEN="◉"
readonly SYM_FORWARD="⇄"
readonly SYM_TUNNEL="⊙"
readonly SYM_SESSION="■"

#======================================================================
# LOGGING INFRASTRUCTURE
# Dual output: always to file, optionally to console
# Per-execution master log + per-listener individual logs
# Compliant with OWASP Logging Cheat Sheet / NIST SP 800-92
#======================================================================

VERBOSE_MODE=false  # Set by --verbose / -v flag

# Function: _ensure_dirs
# Description: Create required directory structure if missing.
#              Sets restrictive permissions on session directory
#              to protect PID/session metadata from unauthorized access.
_ensure_dirs() {
    mkdir -p "${LOG_DIR}" "${SESSION_DIR}" "${CONF_DIR}" "${CERT_DIR}" 2>/dev/null || true
    # Restrict session directory permissions (session files contain PIDs and commands)
    chmod 700 "${SESSION_DIR}" 2>/dev/null || true
}

# Function: _log_write
# Description: Core log writer - appends structured entry to master log
#              and optionally echoes to console with color coding.
#              Log format follows structured logging best practices:
#              TIMESTAMP [LEVEL] [corr:ID] [component] message
# Parameters:
#   $1 - Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
#   $2 - Message text
#   $3 - Optional: component/module name (default: "main")
_log_write() {
    local level="${1:-INFO}"
    local message="${2:-}"
    local component="${3:-main}"
    local timestamp
    timestamp="$(date '+%Y-%m-%dT%H:%M:%S.%3N')"

    # Structured log line for file output
    local log_line="${timestamp} [${level}] [corr:${CORRELATION_ID}] [${component}] ${message}"

    # Always write to master log file
    echo "${log_line}" >> "${MASTER_LOG}" 2>/dev/null || true

    # Console output: DEBUG only when verbose, all others always
    local console_output=false
    case "${level}" in
        DEBUG)    [[ "${VERBOSE_MODE}" == true ]] && console_output=true ;;
        INFO)     console_output=true ;;
        WARNING)  console_output=true ;;
        ERROR)    console_output=true ;;
        CRITICAL) console_output=true ;;
    esac

    if [[ "${console_output}" == true ]]; then
        local color="${CLR_WHITE}" symbol="${SYM_INFO}"
        case "${level}" in
            DEBUG)    color="${CLR_DIM}";     symbol="…" ;;
            INFO)     color="${CLR_CYAN}";    symbol="${SYM_INFO}" ;;
            WARNING)  color="${CLR_YELLOW}";  symbol="${SYM_WARN}" ;;
            ERROR)    color="${CLR_RED}";     symbol="${SYM_FAIL}" ;;
            CRITICAL) color="${CLR_RED}${CLR_BOLD}"; symbol="${SYM_FAIL}" ;;
        esac
        echo -e "  ${color}[${symbol}]${CLR_RESET} ${message}" >&2
    fi
}

# Convenience logging functions - wrap _log_write with preset levels
log_debug()    { _log_write "DEBUG"    "$1" "${2:-main}"; }
log_info()     { _log_write "INFO"     "$1" "${2:-main}"; }
log_success()  { echo -e "  ${CLR_GREEN}[${SYM_OK}]${CLR_RESET} $1" >&2; _log_write "INFO" "$1" "${2:-main}"; }
log_warning()  { _log_write "WARNING"  "$1" "${2:-main}"; }
log_error()    { _log_write "ERROR"    "$1" "${2:-main}"; }
log_critical() { _log_write "CRITICAL" "$1" "${2:-main}"; }

# Function: log_session
# Description: Write to a session-specific log file (per-listener/session).
#              These logs persist independently of the master execution log
#              and provide per-session audit trails.
# Parameters:
#   $1 - Session name/ID (used in filename)
#   $2 - Log level
#   $3 - Message
log_session() {
    local session="${1:-unknown}"
    local level="${2:-INFO}"
    local message="${3:-}"
    local session_log="${LOG_DIR}/session-${session}-${EXEC_TIMESTAMP}.log"
    local timestamp
    timestamp="$(date '+%Y-%m-%dT%H:%M:%S.%3N')"
    echo "${timestamp} [${level}] [corr:${CORRELATION_ID}] ${message}" >> "${session_log}" 2>/dev/null || true
}

#======================================================================
# DISPLAY UTILITIES
#======================================================================

# Function: print_banner
# Description: Display styled script header with mode information
# Parameters:
#   $1 - Mode name (e.g., "Listener", "Forwarder")
print_banner() {
    local mode="${1:-Manager}"
    echo -e "" >&2
    echo -e "  ${CLR_BOLD}${CLR_CYAN}╔══════════════════════════════════════════════╗${CLR_RESET}" >&2
    echo -e "  ${CLR_BOLD}${CLR_CYAN}║${CLR_RESET}  ${CLR_BOLD}socat ${mode}${CLR_RESET}  (v${SCRIPT_VERSION})$(printf '%*s' $((27 - ${#mode} - ${#SCRIPT_VERSION})) '')${CLR_BOLD}${CLR_CYAN}║${CLR_RESET}" >&2
    echo -e "  ${CLR_BOLD}${CLR_CYAN}║${CLR_RESET}  Correlation: ${CORRELATION_ID}                       ${CLR_BOLD}${CLR_CYAN}║${CLR_RESET}" >&2
    echo -e "  ${CLR_BOLD}${CLR_CYAN}╚══════════════════════════════════════════════╝${CLR_RESET}" >&2
    echo -e "" >&2
}

# Function: print_section
# Description: Print a visual section divider with title
# Parameters:
#   $1 - Section title
print_section() {
    echo -e "" >&2
    echo -e "  ${CLR_BOLD}─── ${1} ───${CLR_RESET}" >&2
}

# Function: print_kv
# Description: Print a key-value pair with consistent alignment
# Parameters:
#   $1 - Key label
#   $2 - Value
print_kv() {
    printf "  ${CLR_DIM}%-20s${CLR_RESET} %s\n" "${1}:" "${2}" >&2
}

#======================================================================
# INPUT VALIDATION
# Whitelist-based validation following OWASP/CWE-20 standards
# Validates ports, IPs, hostnames, protocols, file paths, and
# session IDs. All validators return 0 on success, 1 on failure.
#======================================================================

# Function: validate_port
# Description: Validate that a value is a valid port number (1-65535).
#              Warns if port is privileged (<1024) and not running as root.
# Parameters:
#   $1 - Port number to validate
# Returns: 0 on success, 1 on failure
validate_port() {
    local port="${1:-}"

    # Must be a positive integer
    if ! [[ "${port}" =~ ^[0-9]+$ ]]; then
        log_error "Invalid port '${port}': must be a number" "validation"
        return 1
    fi

    # Must be in valid range
    if (( port < 1 || port > 65535 )); then
        log_error "Port ${port} out of range (1-65535)" "validation"
        return 1
    fi

    # Warn if privileged port and not root
    if (( port < 1024 )) && [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        log_warning "Port ${port} is privileged (<1024); root/sudo required" "validation"
    fi

    return 0
}

# Function: validate_port_range
# Description: Validate a port range string (e.g., "8000-8010").
#              Echoes each port on a separate line for consumption.
#              Enforces a maximum span of 1000 ports to prevent
#              accidental resource exhaustion.
# Parameters:
#   $1 - Port range string (format: START-END)
# Outputs: One port number per line
# Returns: 0 on success, 1 on failure
validate_port_range() {
    local range="${1:-}"

    if ! [[ "${range}" =~ ^[0-9]+-[0-9]+$ ]]; then
        log_error "Invalid port range '${range}': use format START-END" "validation"
        return 1
    fi

    local start="${range%-*}"
    local end="${range#*-}"

    if ! validate_port "${start}" || ! validate_port "${end}"; then
        return 1
    fi

    if (( start >= end )); then
        log_error "Range start (${start}) must be less than end (${end})" "validation"
        return 1
    fi

    # Sanity check: don't allow absurdly large ranges
    local span=$(( end - start + 1 ))
    if (( span > 1000 )); then
        log_error "Port range too large (${span} ports). Max 1000." "validation"
        return 1
    fi

    for (( p = start; p <= end; p++ )); do
        echo "${p}"
    done
}

# Function: validate_port_list
# Description: Validate a comma-separated port list (e.g., "21,22,80,443").
#              Echoes each valid port on a separate line. Sanitizes input
#              by removing spaces and replacing semicolons with commas.
# Parameters:
#   $1 - Comma-separated port list
# Outputs: One valid port number per line
# Returns: 0 if at least one valid port found, 1 otherwise
validate_port_list() {
    local list="${1:-}"

    # Sanitize: remove spaces, replace semicolons with commas
    list="${list// /}"
    list="${list//;/,}"

    IFS=',' read -ra ports <<< "${list}"
    local valid_count=0

    for port in "${ports[@]}"; do
        [[ -z "${port}" ]] && continue
        if validate_port "${port}"; then
            echo "${port}"
            ((valid_count++)) || true
        fi
    done

    if (( valid_count == 0 )); then
        log_error "No valid ports found in list '${list}'" "validation"
        return 1
    fi
}

# Function: validate_hostname
# Description: Validate a hostname or IP address for use as a target.
#              Accepts IPv4, IPv6, or RFC 1123-compliant hostnames.
#              Blocks shell metacharacters to prevent command injection.
# Parameters:
#   $1 - Hostname or IP to validate
# Returns: 0 on success, 1 on failure
validate_hostname() {
    local host="${1:-}"

    # Empty check
    if [[ -z "${host}" ]]; then
        log_error "Empty hostname/IP provided" "validation"
        return 1
    fi

    # Sanitize: strip dangerous characters (command injection prevention)
    if [[ "${host}" =~ [\;\|\&\$\`\(\)\{\}\[\]\<\>\!\#] ]]; then
        log_error "Hostname contains forbidden characters: '${host}'" "validation"
        return 1
    fi

    # IPv4 validation (four octets, each 0-255)
    if [[ "${host}" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        IFS='.' read -ra octets <<< "${host}"
        for octet in "${octets[@]}"; do
            if (( octet > 255 )); then
                log_error "Invalid IPv4 address: ${host} (octet ${octet} > 255)" "validation"
                return 1
            fi
        done
        return 0
    fi

    # IPv6 validation (basic - accepts standard and compressed forms)
    if [[ "${host}" =~ ^[0-9a-fA-F:]+$ ]] && [[ "${host}" == *":"* ]]; then
        return 0
    fi

    # Hostname validation (RFC 1123: alphanumeric, hyphens, dots)
    if [[ "${host}" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        return 0
    fi

    log_error "Invalid hostname/IP: '${host}'" "validation"
    return 1
}

# Function: validate_protocol
# Description: Validate and normalize the protocol string.
#              Accepts shorthand (tcp, udp) and explicit forms (tcp4, tcp6, etc.).
#              Returns the normalized protocol string on stdout.
# Parameters:
#   $1 - Protocol string (tcp, tcp4, tcp6, udp, udp4, udp6)
# Outputs: Normalized protocol string (tcp4, tcp6, udp4, udp6)
# Returns: 0 on success, 1 on failure
validate_protocol() {
    local proto="${1:-tcp}"
    proto="${proto,,}"  # lowercase

    case "${proto}" in
        tcp|tcp4)   echo "tcp4" ;;
        tcp6)       echo "tcp6" ;;
        udp|udp4)   echo "udp4" ;;
        udp6)       echo "udp6" ;;
        *)
            log_error "Invalid protocol '${proto}'. Supported: tcp, tcp4, tcp6, udp, udp4, udp6" "validation"
            return 1
            ;;
    esac
}

# Function: validate_file_path
# Description: Validate a file path is safe. Blocks path traversal
#              (../) and shell metacharacters to prevent injection.
# Parameters:
#   $1 - File path to validate
# Returns: 0 on success, 1 on failure
validate_file_path() {
    local path="${1:-}"

    if [[ -z "${path}" ]]; then
        log_error "Empty file path" "validation"
        return 1
    fi

    # Block path traversal
    if [[ "${path}" == *".."* ]]; then
        log_error "Path traversal detected in '${path}'" "validation"
        return 1
    fi

    # Block command injection characters in paths
    if [[ "${path}" =~ [\;\|\&\$\`] ]]; then
        log_error "Forbidden characters in path '${path}'" "validation"
        return 1
    fi

    return 0
}

# Function: validate_session_id
# Description: Validate a session ID is a valid 8-character hex string.
#              Prevents injection via session ID parameters.
# Parameters:
#   $1 - Session ID to validate
# Returns: 0 if valid, 1 if invalid
validate_session_id() {
    local sid="${1:-}"

    if [[ -z "${sid}" ]]; then
        log_error "Empty session ID" "validation"
        return 1
    fi

    # Session IDs must be exactly 8 lowercase hex characters
    if ! [[ "${sid}" =~ ^[a-f0-9]{8}$ ]]; then
        log_error "Invalid session ID '${sid}': must be 8 hex characters" "validation"
        return 1
    fi

    return 0
}

#======================================================================
# SESSION ID GENERATION
# Generates unique 8-character hex session IDs using kernel entropy.
# Falls back to timestamp+PID hash if /proc/sys/kernel/random/uuid
# is unavailable. Checks for collisions against existing sessions.
#======================================================================

# Function: generate_session_id
# Description: Generate a unique 8-character hex session ID.
#              Uses /proc/sys/kernel/random/uuid as primary entropy source.
#              Falls back to timestamp+PID+RANDOM hash via sha256sum.
#              Verifies uniqueness against existing session files to
#              prevent collision (extremely unlikely but handled).
# Outputs: Echoes the 8-character hex session ID
# Returns: 0 on success, 1 if unable to generate unique ID
generate_session_id() {
    local sid=""
    local attempts=0
    local max_attempts=10

    while (( attempts < max_attempts )); do
        # Primary: kernel UUID (high entropy)
        if [[ -r /proc/sys/kernel/random/uuid ]]; then
            sid="$(cat /proc/sys/kernel/random/uuid 2>/dev/null | tr -d '-' | cut -c1-8)"
        fi

        # Fallback: timestamp + PID + random number hashed
        if [[ -z "${sid}" ]] || [[ ${#sid} -ne 8 ]]; then
            sid="$(echo "${RANDOM}${$}$(date +%s%N)" | sha256sum | cut -c1-8)"
        fi

        # Ensure lowercase hex only
        sid="${sid,,}"

        # Check for collision with existing session files
        if [[ ! -f "${SESSION_DIR}/${sid}.session" ]]; then
            echo "${sid}"
            return 0
        fi

        ((attempts++)) || true
        log_debug "Session ID collision on '${sid}', retrying (${attempts}/${max_attempts})" "session"
    done

    # Extremely unlikely: all attempts collided
    log_error "Failed to generate unique session ID after ${max_attempts} attempts" "session"
    return 1
}

#======================================================================
# SESSION MANAGEMENT v2.2
# Tracks all spawned socat processes via session files in sessions/.
# Each session file uses .session extension and contains comprehensive
# metadata including PID, PGID, command, protocol, timestamps, and
# session ID.
#
# Key design decisions:
#   - Unique 8-char hex session IDs for unambiguous identification
#   - Process Group ID (PGID) tracking via setsid for tree kill
#   - Full socat command stored for watchdog restart capability
#   - PROTOCOL field stored for protocol-aware stop operations
#   - Launcher PID tracked separately from socat PID
#   - Session files use .session extension (not .pid)
#   - Port-release verification on stop is protocol-scoped
#
# Session file format:
#   SESSION_ID=<8-char-hex>
#   SESSION_NAME=<human-readable-name>
#   PID=<socat-process-pid>
#   PGID=<process-group-id>
#   MODE=<listen|batch-listen|forward|tunnel|redirect|watchdog>
#   PROTOCOL=<tcp4|tcp6|udp4|udp6|tls>
#   LOCAL_PORT=<port>
#   REMOTE_HOST=<host>
#   REMOTE_PORT=<port>
#   SOCAT_CMD=<full-socat-command-string>
#   STARTED=<ISO-8601-timestamp>
#   CORRELATION=<execution-correlation-id>
#   LAUNCHER_PID=<original-script-pid>
#======================================================================

# Function: session_register
# Description: Register a new socat session by writing a session file
#              with comprehensive metadata. Uses the session ID as the
#              primary key. File permissions set to 600 to protect
#              command strings and PID information.
# Parameters:
#   $1  - Session ID (unique 8-char hex)
#   $2  - Session name (human-readable, e.g., "redir-8443-example.com-443")
#   $3  - PID of the socat process
#   $4  - Process Group ID (PGID) for tree kill
#   $5  - Mode (listen, forward, tunnel, redirect, batch-listen, watchdog)
#   $6  - Protocol (tcp4, udp4, tls, etc.)
#   $7  - Local port
#   $8  - Full socat command string (for restart/audit)
#   $9  - Optional: remote host
#   $10 - Optional: remote port
session_register() {
    local sid="${1:?Session ID required}"
    local name="${2:?Session name required}"
    local pid="${3:?PID required}"
    local pgid="${4:?PGID required}"
    local mode="${5:?Mode required}"
    local proto="${6:-tcp4}"
    local lport="${7:-0}"
    local socat_cmd="${8:-}"
    local rhost="${9:-}"
    local rport="${10:-}"

    local session_file="${SESSION_DIR}/${sid}.session"

    # Write structured session metadata using heredoc
    cat > "${session_file}" << EOF
# socat_manager session file v2.2
# Generated: $(date '+%Y-%m-%d %H:%M:%S')
SESSION_ID=${sid}
SESSION_NAME=${name}
PID=${pid}
PGID=${pgid}
MODE=${mode}
PROTOCOL=${proto}
LOCAL_PORT=${lport}
REMOTE_HOST=${rhost}
REMOTE_PORT=${rport}
SOCAT_CMD=${socat_cmd}
STARTED=$(date '+%Y-%m-%dT%H:%M:%S')
CORRELATION=${CORRELATION_ID}
LAUNCHER_PID=${SCRIPT_PID}
EOF

    # Restrict permissions - session files contain command strings and PIDs
    chmod 600 "${session_file}" 2>/dev/null || true

    log_debug "Session registered: ${sid} (${name}, PID ${pid}, PGID ${pgid})" "session"
    log_session "${sid}" "INFO" "Session registered: name=${name} pid=${pid} pgid=${pgid} mode=${mode} proto=${proto} port=${lport}"
}

# Function: session_unregister
# Description: Remove a session file and all associated signal files
#              (stop signals, PID staging files). Called after confirmed
#              process termination.
# Parameters:
#   $1 - Session ID
session_unregister() {
    local sid="${1:?Session ID required}"
    rm -f "${SESSION_DIR}/${sid}.session" \
          "${SESSION_DIR}/${sid}.stop" \
          "${SESSION_DIR}/${sid}.launching" 2>/dev/null || true
    log_debug "Session unregistered: ${sid}" "session"
    log_session "${sid}" "INFO" "Session unregistered"
}

# Function: session_read_field
# Description: Read a specific field from a session file.
#              Safe parser that handles missing fields gracefully.
#              Uses grep + cut for reliable KEY=VALUE parsing.
# Parameters:
#   $1 - Path to session file
#   $2 - Field name (e.g., "PID", "PGID", "MODE", "PROTOCOL")
# Outputs: Field value, or empty string if not found
session_read_field() {
    local session_file="${1:?Session file required}"
    local field="${2:?Field name required}"

    if [[ ! -f "${session_file}" ]]; then
        return 0
    fi

    # Extract field value; head -1 handles any duplicate entries safely
    grep "^${field}=" "${session_file}" 2>/dev/null | head -1 | cut -d= -f2-
}

# Function: session_find_by_name
# Description: Find session file(s) matching a session name (exact match).
#              Returns the session ID(s) for matching sessions.
# Parameters:
#   $1 - Session name to search for
# Outputs: Session IDs (one per line)
session_find_by_name() {
    local target_name="${1:?Session name required}"
    for sf in "${SESSION_DIR}"/*.session; do
        [[ ! -f "${sf}" ]] && continue
        local name
        name="$(session_read_field "${sf}" "SESSION_NAME")"
        if [[ "${name}" == "${target_name}" ]]; then
            session_read_field "${sf}" "SESSION_ID"
        fi
    done
}

# Function: session_find_by_port
# Description: Find session file(s) matching a local port.
# Parameters:
#   $1 - Port number to search for
# Outputs: Session IDs (one per line)
session_find_by_port() {
    local target_port="${1:?Port required}"
    for sf in "${SESSION_DIR}"/*.session; do
        [[ ! -f "${sf}" ]] && continue
        local port
        port="$(session_read_field "${sf}" "LOCAL_PORT")"
        if [[ "${port}" == "${target_port}" ]]; then
            session_read_field "${sf}" "SESSION_ID"
        fi
    done
}

# Function: session_find_by_pid
# Description: Find session file(s) matching a PID.
# Parameters:
#   $1 - PID to search for
# Outputs: Session IDs (one per line)
session_find_by_pid() {
    local target_pid="${1:?PID required}"
    for sf in "${SESSION_DIR}"/*.session; do
        [[ ! -f "${sf}" ]] && continue
        local pid
        pid="$(session_read_field "${sf}" "PID")"
        if [[ "${pid}" == "${target_pid}" ]]; then
            session_read_field "${sf}" "SESSION_ID"
        fi
    done
}

# Function: session_is_alive
# Description: Check if a registered session's process is still running.
#              Checks both the primary PID and the process group.
# Parameters:
#   $1 - Session ID
# Returns: 0 if alive, 1 if dead/missing
session_is_alive() {
    local sid="${1:?Session ID required}"
    local session_file="${SESSION_DIR}/${sid}.session"

    if [[ ! -f "${session_file}" ]]; then
        return 1
    fi

    local pid pgid
    pid="$(session_read_field "${session_file}" "PID")"
    pgid="$(session_read_field "${session_file}" "PGID")"

    # Check primary PID first
    if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
        return 0
    fi

    # Fallback: check if any process in the group is alive
    if [[ -n "${pgid}" ]] && [[ "${pgid}" != "0" ]]; then
        if kill -0 "-${pgid}" 2>/dev/null; then
            return 0
        fi
    fi

    return 1
}

# Function: session_get_all_ids
# Description: List all registered session IDs.
# Outputs: Session IDs (one per line), empty if none
session_get_all_ids() {
    for sf in "${SESSION_DIR}"/*.session; do
        [[ ! -f "${sf}" ]] && continue
        session_read_field "${sf}" "SESSION_ID"
    done
}

# Function: session_list
# Description: List all registered sessions with their status.
#              Displays a formatted table of sessions including
#              session ID, name, PID, PGID, mode, protocol, port,
#              remote target, and alive/dead status.
session_list() {
    local has_sessions=false

    # Check if any sessions exist
    for sf in "${SESSION_DIR}"/*.session; do
        if [[ -f "${sf}" ]]; then
            has_sessions=true
            break
        fi
    done

    if [[ "${has_sessions}" != true ]]; then
        log_info "No active sessions found"
        return 0
    fi

    print_section "Active Sessions"
    printf "\n" >&2

    # Table header
    printf "  ${CLR_BOLD}%-10s %-28s %-8s %-8s %-10s %-6s %-6s %-22s %-8s${CLR_RESET}\n" \
        "SID" "SESSION" "PID" "PGID" "MODE" "PROTO" "LPORT" "REMOTE" "STATUS" >&2
    printf "  %s\n" "$(printf '─%.0s' {1..112})" >&2

    local alive_count=0 dead_count=0

    for sf in "${SESSION_DIR}"/*.session; do
        [[ ! -f "${sf}" ]] && continue

        local sid name pid pgid mode proto lport rhost rport status status_color

        # Parse session file fields using safe reader
        sid="$(session_read_field "${sf}" "SESSION_ID")"
        name="$(session_read_field "${sf}" "SESSION_NAME")"
        pid="$(session_read_field "${sf}" "PID")"
        pgid="$(session_read_field "${sf}" "PGID")"
        mode="$(session_read_field "${sf}" "MODE")"
        proto="$(session_read_field "${sf}" "PROTOCOL")"
        lport="$(session_read_field "${sf}" "LOCAL_PORT")"
        rhost="$(session_read_field "${sf}" "REMOTE_HOST")"
        rport="$(session_read_field "${sf}" "REMOTE_PORT")"

        # Build remote display string
        local remote="-"
        if [[ -n "${rhost}" && -n "${rport}" ]]; then
            remote="${rhost}:${rport}"
        elif [[ -n "${rhost}" ]]; then
            remote="${rhost}"
        fi

        # Check process status (PID and PGID)
        if session_is_alive "${sid}"; then
            status="ALIVE"
            status_color="${CLR_GREEN}"
            ((alive_count++)) || true
        else
            status="DEAD"
            status_color="${CLR_RED}"
            ((dead_count++)) || true
        fi

        printf "  %-10s %-28s %-8s %-8s %-10s %-6s %-6s %-22s ${status_color}%-8s${CLR_RESET}\n" \
            "${sid}" "${name:0:28}" "${pid}" "${pgid}" "${mode}" "${proto}" "${lport}" "${remote:0:22}" "${status}" >&2
    done

    printf "\n" >&2
    log_info "Sessions: ${alive_count} alive, ${dead_count} dead, $((alive_count + dead_count)) total"
}

# Function: session_detail
# Description: Display detailed information about a specific session.
#              Shows all metadata fields, process tree, port status
#              (for the session's own protocol), and associated log files.
# Parameters:
#   $1 - Session ID
session_detail() {
    local sid="${1:?Session ID required}"
    local session_file="${SESSION_DIR}/${sid}.session"

    if [[ ! -f "${session_file}" ]]; then
        log_error "Session '${sid}' not found"
        return 1
    fi

    print_section "Session Detail: ${sid}"

    # Read all fields
    local name pid pgid mode proto lport rhost rport started socat_cmd correlation launcher_pid

    name="$(session_read_field "${session_file}" "SESSION_NAME")"
    pid="$(session_read_field "${session_file}" "PID")"
    pgid="$(session_read_field "${session_file}" "PGID")"
    mode="$(session_read_field "${session_file}" "MODE")"
    proto="$(session_read_field "${session_file}" "PROTOCOL")"
    lport="$(session_read_field "${session_file}" "LOCAL_PORT")"
    rhost="$(session_read_field "${session_file}" "REMOTE_HOST")"
    rport="$(session_read_field "${session_file}" "REMOTE_PORT")"
    started="$(session_read_field "${session_file}" "STARTED")"
    socat_cmd="$(session_read_field "${session_file}" "SOCAT_CMD")"
    correlation="$(session_read_field "${session_file}" "CORRELATION")"
    launcher_pid="$(session_read_field "${session_file}" "LAUNCHER_PID")"

    # Display session metadata
    print_kv "Session ID" "${sid}"
    print_kv "Session Name" "${name}"
    print_kv "Mode" "${mode}"
    print_kv "Protocol" "${proto}"
    print_kv "Local Port" "${lport}"
    [[ -n "${rhost}" ]] && print_kv "Remote Host" "${rhost}"
    [[ -n "${rport}" ]] && print_kv "Remote Port" "${rport}"
    print_kv "PID" "${pid}"
    print_kv "PGID" "${pgid}"
    print_kv "Started" "${started}"
    print_kv "Correlation ID" "${correlation}"
    print_kv "Launcher PID" "${launcher_pid}"

    # Process status
    echo "" >&2
    print_section "Process Status"

    if session_is_alive "${sid}"; then
        echo -e "  ${CLR_GREEN}[${SYM_OK}] Process is ALIVE${CLR_RESET}" >&2
    else
        echo -e "  ${CLR_RED}[${SYM_FAIL}] Process is DEAD${CLR_RESET}" >&2
    fi

    # Show process tree if alive
    if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
        echo "" >&2
        echo -e "  ${CLR_DIM}Process tree:${CLR_RESET}" >&2
        if command -v pstree &>/dev/null; then
            pstree -p "${pid}" 2>/dev/null | sed 's/^/    /' >&2 || true
        else
            # Fallback: show process info via ps
            ps --forest -o pid,ppid,comm,args -g "${pgid}" 2>/dev/null | sed 's/^/    /' >&2 || \
                ps -o pid,ppid,comm -p "${pid}" 2>/dev/null | sed 's/^/    /' >&2 || true
        fi
    fi

    # Port status (checks only this session's protocol)
    echo "" >&2
    print_section "Port Status"
    if [[ -n "${lport}" ]] && [[ "${lport}" != "0" ]]; then
        if command -v ss &>/dev/null; then
            # Check TCP
            if [[ "${proto}" == tcp* ]] || [[ "${proto}" == "tls" ]]; then
                local tcp_info
                tcp_info="$(ss -tlnp 2>/dev/null | grep ":${lport} " || true)"
                if [[ -n "${tcp_info}" ]]; then
                    echo -e "  ${CLR_GREEN}[${SYM_OK}] Port ${lport} is LISTENING (TCP)${CLR_RESET}" >&2
                    echo "    ${tcp_info}" >&2
                else
                    echo -e "  ${CLR_RED}[${SYM_FAIL}] Port ${lport} is NOT listening (TCP)${CLR_RESET}" >&2
                fi
            fi
            # Check UDP
            if [[ "${proto}" == udp* ]]; then
                local udp_info
                udp_info="$(ss -ulnp 2>/dev/null | grep ":${lport} " || true)"
                if [[ -n "${udp_info}" ]]; then
                    echo -e "  ${CLR_GREEN}[${SYM_OK}] Port ${lport} is LISTENING (UDP)${CLR_RESET}" >&2
                    echo "    ${udp_info}" >&2
                else
                    echo -e "  ${CLR_RED}[${SYM_FAIL}] Port ${lport} is NOT listening (UDP)${CLR_RESET}" >&2
                fi
            fi
        fi
    fi

    # Show socat command
    if [[ -n "${socat_cmd}" ]]; then
        echo "" >&2
        print_section "Socat Command"
        echo "    ${socat_cmd}" >&2
    fi

    # List associated log files
    echo "" >&2
    print_section "Associated Logs"
    local log_count=0
    for lf in "${LOG_DIR}"/session-"${sid}"-*.log "${LOG_DIR}"/session-"${sid}"-error.log \
              "${LOG_DIR}"/capture-*"${lport}"*.log; do
        if [[ -f "${lf}" ]]; then
            echo "    ${lf}" >&2
            ((log_count++)) || true
        fi
    done
    if (( log_count == 0 )); then
        echo "    (no session-specific logs found)" >&2
    fi
}

# Function: session_cleanup_dead
# Description: Remove session files for sessions whose processes have died.
#              Only removes if BOTH PID and PGID are confirmed dead to
#              prevent premature cleanup. This is critical for dual-stack:
#              killing one protocol must not cause cleanup of the other.
session_cleanup_dead() {
    local cleaned=0
    for sf in "${SESSION_DIR}"/*.session; do
        [[ ! -f "${sf}" ]] && continue

        local sid pid pgid
        sid="$(session_read_field "${sf}" "SESSION_ID")"
        pid="$(session_read_field "${sf}" "PID")"
        pgid="$(session_read_field "${sf}" "PGID")"

        # Only clean up if BOTH PID and PGID are confirmed dead
        local pid_alive=false pgid_alive=false

        if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
            pid_alive=true
        fi

        if [[ -n "${pgid}" ]] && [[ "${pgid}" != "0" ]] && kill -0 "-${pgid}" 2>/dev/null; then
            pgid_alive=true
        fi

        if [[ "${pid_alive}" == false && "${pgid_alive}" == false ]]; then
            rm -f "${sf}" "${SESSION_DIR}/${sid}.stop" "${SESSION_DIR}/${sid}.launching" 2>/dev/null
            ((cleaned++)) || true
            log_debug "Cleaned dead session: ${sid} (PID ${pid})" "session"
        fi
    done

    if (( cleaned > 0 )); then
        log_info "Cleaned ${cleaned} dead session(s)"
    fi
}

#======================================================================
# PROCESS LAUNCH WRAPPER (v2.1+ PID-file handoff)
#
# Architecture:
#   1. Generate session ID
#   2. Create a PID staging file path
#   3. Launch via: setsid bash -c 'echo $$ > pidfile; exec socat ...'
#      - setsid creates a new session + process group
#      - bash -c writes its own PID to the staging file
#      - exec replaces bash with socat (same PID preserved)
#      - All stdout/stderr redirected BEFORE exec (no fd leaks)
#   4. Parent reads the actual socat PID from the staging file
#   5. PGID == PID (because setsid made socat the group leader)
#   6. Register session with correct PID/PGID
#   7. Return session ID via LAUNCH_SID global (no $() subshell)
#
# Why not $() subshell?
#   Command substitution `sid="$(launch...)"` creates a subshell that
#   waits for ALL child processes holding its stdout fd to close. Even
#   with `&` and `disown`, setsid'd socat inherits the subshell's
#   stdout fd, keeping the pipe open. The subshell never completes,
#   and the terminal hangs at "Starting Redirector".
#
# Why PID-file handoff?
#   `setsid cmd &` followed by `$!` captures the PID of the setsid
#   wrapper process, which forks internally and exits immediately.
#   The actual socat runs under a different PID. By having the inner
#   bash write $$ before `exec socat`, we capture socat's real PID.
#   Under setsid, PID == PGID, so SIGTERM -PGID targets the correct
#   process tree including all fork children.
#======================================================================

# Function: launch_socat_session
# Description: Launch a socat command in an isolated process group and
#              register it as a managed session. Uses the PID-file handoff
#              pattern to capture the real socat PID. Returns the session
#              ID via the LAUNCH_SID global variable to avoid $() subshell
#              terminal blocking.
# Parameters:
#   $1 - Session name (human-readable identifier)
#   $2 - Mode (listen, forward, tunnel, redirect, batch-listen)
#   $3 - Protocol (tcp4, udp4, tls, etc.)
#   $4 - Local port
#   $5 - Full socat command string to execute
#   $6 - Optional: remote host
#   $7 - Optional: remote port
#   $8 - Optional: stderr redirect file (for capture mode)
# Returns: 0 on success (LAUNCH_SID set), 1 on failure
# Side effects: Sets LAUNCH_SID global variable
launch_socat_session() {
    local name="${1:?Session name required}"
    local mode="${2:?Mode required}"
    local proto="${3:?Protocol required}"
    local lport="${4:?Local port required}"
    local socat_cmd="${5:?Socat command required}"
    local rhost="${6:-}"
    local rport="${7:-}"
    local stderr_redirect="${8:-}"

    # Reset global return value
    LAUNCH_SID=""

    # Generate unique session ID
    local sid
    sid="$(generate_session_id)" || {
        log_error "Failed to generate session ID for '${name}'" "launch"
        return 1
    }

    log_debug "Launching session ${sid} (${name}): ${socat_cmd}" "launch"
    log_session "${sid}" "INFO" "Launching: ${socat_cmd}"

    # PID staging file: the launched process writes its PID here
    # before exec'ing into socat. This gives us the real socat PID.
    local pid_file="${SESSION_DIR}/${sid}.launching"
    rm -f "${pid_file}" 2>/dev/null || true

    # Session error log for non-capture mode stderr
    local error_log="${LOG_DIR}/session-${sid}-error.log"

    # Build the inner bash -c script:
    #   1. Write our PID to the staging file (bash's PID before exec)
    #   2. exec replaces bash with socat, preserving the same PID
    #   3. All fd redirections are set up before exec so socat inherits clean fds
    local inner_script=""
    if [[ -n "${stderr_redirect}" ]]; then
        # Capture mode: stderr → capture log file (for socat -v hex dumps)
        inner_script="echo \$\$ > '${pid_file}'; exec ${socat_cmd} >/dev/null 2>>'${stderr_redirect}'"
    else
        # Normal mode: stderr → session error log
        inner_script="echo \$\$ > '${pid_file}'; exec ${socat_cmd} >/dev/null 2>>'${error_log}'"
    fi

    # Launch via setsid for session/process group isolation.
    # &>/dev/null prevents any setsid-level output from reaching the terminal.
    # & backgrounds the setsid invocation so the script continues immediately.
    setsid bash -c "${inner_script}" &>/dev/null &

    # NOTE: We do NOT use $! here - that would give us the setsid wrapper PID
    # which exits immediately. Instead we read the real PID from pid_file.

    # Wait for the PID file to appear (inner bash writes it before exec)
    local wait_count=0
    while [[ ! -f "${pid_file}" ]] && (( wait_count < PID_FILE_WAIT_ITERS )); do
        sleep 0.1
        ((wait_count++)) || true
    done

    if [[ ! -f "${pid_file}" ]]; then
        log_error "Session ${sid} (${name}) failed to start - PID file not created within timeout" "launch"
        log_session "${sid}" "ERROR" "PID file not created within timeout"
        return 1
    fi

    # Read the actual socat PID from the staging file
    local socat_pid
    socat_pid="$(cat "${pid_file}" 2>/dev/null | tr -d '[:space:]')"
    rm -f "${pid_file}" 2>/dev/null || true

    if [[ -z "${socat_pid}" ]] || ! [[ "${socat_pid}" =~ ^[0-9]+$ ]]; then
        log_error "Session ${sid} (${name}) failed - invalid PID in staging file" "launch"
        return 1
    fi

    # Brief pause to verify socat bound the port and is stable
    sleep 0.3

    if ! kill -0 "${socat_pid}" 2>/dev/null; then
        log_error "Session ${sid} (${name}) failed - process ${socat_pid} died immediately" "launch"
        log_session "${sid}" "ERROR" "Process died immediately after launch (PID ${socat_pid})"
        return 1
    fi

    # Under setsid, the socat process IS the session leader and process
    # group leader. Therefore PGID == PID. This is what makes
    # `kill -TERM -${pgid}` reliable for stopping the entire tree.
    local pgid="${socat_pid}"

    # Register the session with the verified, correct PID and PGID
    session_register "${sid}" "${name}" "${socat_pid}" "${pgid}" \
        "${mode}" "${proto}" "${lport}" "${socat_cmd}" "${rhost}" "${rport}"

    log_session "${sid}" "INFO" "Session active: PID=${socat_pid} PGID=${pgid}"

    # Return session ID via global variable (avoids $() subshell blocking)
    LAUNCH_SID="${sid}"
    return 0
}

#======================================================================
# PORT UTILITIES
# Functions for checking port availability and protocol alternation.
# Port checks are protocol-aware to prevent cross-protocol interference
# during stop operations on dual-stack configurations.
#======================================================================

# Function: check_port_available
# Description: Check if a port is available for binding on a specific
#              protocol. Uses ss (preferred) or netstat to detect
#              existing listeners. Only checks the specified protocol,
#              not both TCP and UDP.
# Parameters:
#   $1 - Port number
#   $2 - Protocol (tcp4, udp4, etc.)
# Returns: 0 if available, 1 if in use
check_port_available() {
    local port="${1:?Port required}"
    local proto="${2:-tcp4}"

    # Determine if checking TCP or UDP
    local check_type="tcp"
    [[ "${proto}" == *"udp"* ]] && check_type="udp"

    # Try ss first (preferred, modern), fall back to netstat
    if command -v ss &>/dev/null; then
        local ss_flag="-tln"
        [[ "${check_type}" == "udp" ]] && ss_flag="-uln"

        if ss "${ss_flag}" 2>/dev/null | grep -qE ":${port}\b"; then
            return 1  # Port in use
        fi
    elif command -v netstat &>/dev/null; then
        # netstat: -t for TCP, -u for UDP
        local netstat_flag="-tln"
        [[ "${check_type}" == "udp" ]] && netstat_flag="-uln"

        if netstat "${netstat_flag}" 2>/dev/null | grep -qE ":${port}\b"; then
            return 1  # Port in use
        fi
    else
        # No tool available; warn and proceed
        log_warning "Neither ss nor netstat available; cannot check port ${port}" "port-check"
    fi

    return 0  # Port available
}

# Function: check_port_freed
# Description: Verify that a port has been released after stopping a session.
#              Retries multiple times with a delay to account for TIME_WAIT.
#              Protocol-aware: only checks the specified protocol.
# Parameters:
#   $1 - Port number
#   $2 - Protocol to check (tcp4, udp4, etc.)
#   $3 - Max retries (default: STOP_VERIFY_RETRIES)
# Returns: 0 if freed, 1 if still in use
check_port_freed() {
    local port="${1:?Port required}"
    local proto="${2:-tcp4}"
    local max_retries="${3:-${STOP_VERIFY_RETRIES}}"
    local attempt=0

    while (( attempt < max_retries )); do
        if check_port_available "${port}" "${proto}"; then
            return 0
        fi
        sleep "${STOP_VERIFY_INTERVAL}"
        ((attempt++)) || true
    done

    return 1  # Port still in use
}

# Function: get_alt_protocol
# Description: Return the alternate protocol for dual-stack operations.
#              Maps TCP→UDP and UDP→TCP within the same address family.
# Parameters:
#   $1 - Protocol (tcp4, tcp6, udp4, udp6)
# Outputs: The alternate protocol string
get_alt_protocol() {
    local proto="${1:?Protocol required}"
    case "${proto}" in
        tcp4) echo "udp4" ;;
        tcp6) echo "udp6" ;;
        udp4) echo "tcp4" ;;
        udp6) echo "tcp6" ;;
        *)    echo "" ;;
    esac
}

#======================================================================
# SOCAT COMMAND BUILDERS
# Constructs socat command strings for each operational mode.
# Separates command construction from execution for testability,
# dry-run support, and audit logging.
#======================================================================

# Function: build_socat_listen_cmd
# Description: Build a socat command string for a listener.
#              Constructs a unidirectional listener that captures
#              incoming data to a log file. When capture mode is enabled,
#              socat's -v flag is added for verbose hex dump output
#              on stderr (redirected to a capture log by the launcher).
# Parameters:
#   $1 - Protocol (tcp4, tcp6, udp4, udp6)
#   $2 - Port number
#   $3 - Log file path for captured data
#   $4 - Additional socat options (optional)
#   $5 - Capture mode enabled (true/false, default: false)
# Outputs: The constructed socat command string
build_socat_listen_cmd() {
    local proto="${1:?Protocol required}"
    local port="${2:?Port required}"
    local logfile="${3:?Log file required}"
    local extra_opts="${4:-}"
    local capture="${5:-false}"

    # Map protocol to socat address type (uppercase as socat expects)
    local socat_proto
    case "${proto}" in
        tcp4) socat_proto="TCP4-LISTEN" ;;
        tcp6) socat_proto="TCP6-LISTEN" ;;
        udp4) socat_proto="UDP4-LISTEN" ;;
        udp6) socat_proto="UDP6-LISTEN" ;;
    esac

    # Base listener options:
    #   reuseaddr  - Allow rebinding immediately after close (avoids TIME_WAIT)
    #   fork       - Fork a child process per connection (multi-session)
    local listen_opts="reuseaddr,fork"

    # TCP-specific options
    if [[ "${proto}" == tcp* ]]; then
        # backlog   - Connection queue depth
        # keepalive - Enable TCP keepalive probes
        listen_opts+=",backlog=${DEFAULT_BACKLOG},keepalive"
    fi

    # Append any extra user-provided socat address options
    if [[ -n "${extra_opts}" ]]; then
        listen_opts+=",${extra_opts}"
    fi

    # Capture mode: add -v for verbose hex dump output on stderr.
    # The launcher redirects stderr to a capture log file.
    local verbose_flag=""
    if [[ "${capture}" == true ]]; then
        verbose_flag="-v"
    fi

    # Build the command:
    #   -u        = Unidirectional (from left to right) for logging listeners
    #   -v        = Verbose hex dump (capture mode only, output on stderr)
    #   The listener captures incoming data to the log file
    #   creat     = Create file if it doesn't exist
    #   append    = Append to existing file (don't overwrite)
    echo "socat ${verbose_flag} -u ${socat_proto}:${port},${listen_opts} OPEN:${logfile},creat,append"
}

# Function: build_socat_forward_cmd
# Description: Build a socat command for port forwarding (bidirectional).
#              Creates a full-duplex proxy between a local listener and
#              a remote target. When capture mode is enabled, socat's -v
#              flag adds verbose hex dump output on stderr for both
#              directions of traffic.
# Parameters:
#   $1 - Listen protocol (tcp4, tcp6, udp4, udp6)
#   $2 - Local port to listen on
#   $3 - Remote host to forward to
#   $4 - Remote port to forward to
#   $5 - Remote protocol (optional, defaults to match listen)
#   $6 - Capture mode enabled (true/false, default: false)
# Outputs: The constructed socat command string
build_socat_forward_cmd() {
    local listen_proto="${1:?Listen protocol required}"
    local lport="${2:?Local port required}"
    local rhost="${3:?Remote host required}"
    local rport="${4:?Remote port required}"
    local remote_proto="${5:-${listen_proto}}"
    local capture="${6:-false}"

    # Map protocols to socat address types
    local socat_listen socat_remote
    case "${listen_proto}" in
        tcp4) socat_listen="TCP4-LISTEN" ;;
        tcp6) socat_listen="TCP6-LISTEN" ;;
        udp4) socat_listen="UDP4-LISTEN" ;;
        udp6) socat_listen="UDP6-LISTEN" ;;
    esac
    case "${remote_proto}" in
        tcp4) socat_remote="TCP4" ;;
        tcp6) socat_remote="TCP6" ;;
        udp4) socat_remote="UDP4" ;;
        udp6) socat_remote="UDP6" ;;
    esac

    # Capture mode: add -v for verbose hex dump on stderr
    local verbose_flag=""
    if [[ "${capture}" == true ]]; then
        verbose_flag="-v"
    fi

    # Forwarding is bidirectional (no -u flag):
    #   Left side:  Listener accepting connections
    #   Right side: Connector to remote target
    local listen_opts="reuseaddr,fork"
    if [[ "${listen_proto}" == tcp* ]]; then
        listen_opts+=",backlog=${DEFAULT_BACKLOG}"
    fi

    echo "socat ${verbose_flag} ${socat_listen}:${lport},${listen_opts} ${socat_remote}:${rhost}:${rport}"
}

# Function: build_socat_tunnel_cmd
# Description: Build a socat command for an encrypted (OpenSSL) tunnel.
#              Accepts TLS connections on a local port and forwards
#              plaintext traffic to a remote target. When capture mode
#              is enabled, socat's -v flag adds verbose hex dump output
#              on stderr showing the decrypted traffic in both directions.
# Parameters:
#   $1 - Local port to listen on (encrypted endpoint)
#   $2 - Remote host to tunnel to
#   $3 - Remote port to tunnel to
#   $4 - Certificate PEM file path
#   $5 - Key PEM file path
#   $6 - Capture mode enabled (true/false, default: false)
# Outputs: The constructed socat command string
build_socat_tunnel_cmd() {
    local lport="${1:?Local port required}"
    local rhost="${2:?Remote host required}"
    local rport="${3:?Remote port required}"
    local cert="${4:?Certificate required}"
    local key="${5:?Key required}"
    local capture="${6:-false}"

    # Capture mode: add -v for verbose hex dump on stderr
    # For tunnels, this captures the DECRYPTED traffic between
    # the TLS termination point and the remote target.
    local verbose_flag=""
    if [[ "${capture}" == true ]]; then
        verbose_flag="-v"
    fi

    # OpenSSL listener accepts encrypted connections and forwards
    # plaintext to the remote target:
    #   OPENSSL-LISTEN - Accept TLS/SSL connections
    #   cert/key       - Server certificate and private key
    #   verify=0       - Don't verify client certificates (server mode)
    #   fork           - Handle multiple connections
    #   reuseaddr      - Allow rebinding immediately after close
    echo "socat ${verbose_flag} OPENSSL-LISTEN:${lport},cert=${cert},key=${key},verify=0,reuseaddr,fork TCP4:${rhost}:${rport}"
}

# Function: build_socat_redirect_cmd
# Description: Build a socat command for transparent traffic redirection.
#              Bidirectional forwarding with optional traffic logging.
#              Protocol-aware: supports TCP and UDP independently.
# Parameters:
#   $1 - Protocol (tcp4, tcp6, udp4, udp6)
#   $2 - Local port to listen on
#   $3 - Remote host to redirect to
#   $4 - Remote port to redirect to
#   $5 - Enable capture mode (true/false)
# Outputs: The constructed socat command string
build_socat_redirect_cmd() {
    local proto="${1:?Protocol required}"
    local lport="${2:?Local port required}"
    local rhost="${3:?Remote host required}"
    local rport="${4:?Remote port required}"
    local capture="${5:-false}"

    # Map protocol to socat address types
    local socat_listen socat_remote
    case "${proto}" in
        tcp4) socat_listen="TCP4-LISTEN"; socat_remote="TCP4" ;;
        tcp6) socat_listen="TCP6-LISTEN"; socat_remote="TCP6" ;;
        udp4) socat_listen="UDP4-LISTEN"; socat_remote="UDP4" ;;
        udp6) socat_listen="UDP6-LISTEN"; socat_remote="UDP6" ;;
    esac

    # If capture is enabled, use socat's -v (verbose) mode to
    # capture traffic hex dumps to stderr (redirected to log by launcher)
    local verbose_flag=""
    if [[ "${capture}" == true ]]; then
        verbose_flag="-v"
    fi

    # Build listener options
    local listen_opts="reuseaddr,fork"
    if [[ "${proto}" == tcp* ]]; then
        listen_opts+=",backlog=${DEFAULT_BACKLOG}"
    fi

    echo "socat ${verbose_flag} ${socat_listen}:${lport},${listen_opts} ${socat_remote}:${rhost}:${rport}"
}

#======================================================================
# CERTIFICATE GENERATION
# Self-signed certificate generation for tunnel mode when no cert
# is provided. Uses OpenSSL to generate a temporary keypair.
#======================================================================

# Function: generate_self_signed_cert
# Description: Generate a self-signed certificate and key for TLS tunnels.
#              Files are placed in the certs/ directory with restrictive
#              permissions on the private key (600).
# Parameters:
#   $1 - Common Name for the certificate (default: localhost)
# Outputs: Echoes "CERT_PATH KEY_PATH" space-separated
# Returns: 0 on success, 1 on failure
generate_self_signed_cert() {
    local cn="${1:-localhost}"
    local cert_file="${CERT_DIR}/socat-tunnel-${EXEC_TIMESTAMP}.pem"
    local key_file="${CERT_DIR}/socat-tunnel-${EXEC_TIMESTAMP}.key"

    if ! command -v openssl &>/dev/null; then
        log_error "openssl not found. Required for tunnel mode." "cert"
        log_info "Install with: sudo apt-get install -y openssl" "cert"
        return 1
    fi

    log_info "Generating self-signed certificate (CN=${cn})..." "cert"

    # Generate RSA 2048-bit key and self-signed cert, valid 365 days
    # -nodes    = No passphrase on private key
    # -x509     = Output a self-signed certificate
    # -newkey   = Generate a new key pair
    # -keyout   = Private key output file
    # -out      = Certificate output file
    # -subj     = Certificate subject (avoids interactive prompts)
    if openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "${key_file}" \
        -out "${cert_file}" \
        -days 365 \
        -subj "/CN=${cn}/O=socat_manager/OU=tunnel" \
        2>/dev/null; then

        # Restrict permissions on key file (private key protection)
        chmod 600 "${key_file}" 2>/dev/null
        chmod 644 "${cert_file}" 2>/dev/null

        log_success "Certificate generated: ${cert_file}" "cert"
        log_debug "Key generated: ${key_file}" "cert"

        echo "${cert_file} ${key_file}"
        return 0
    else
        log_error "Certificate generation failed" "cert"
        return 1
    fi
}

#======================================================================
# WATCHDOG / AUTO-RESTART
# Monitors a socat process and restarts it if it crashes.
# Implements exponential backoff and max restart limits.
# Respects stop signals via .stop file for graceful shutdown.
#======================================================================

# Function: watchdog_loop
# Description: Monitor a socat process and restart on crash. Runs in
#              the background as a supervisor. Uses exponential backoff
#              (1s, 2s, 4s, 8s... capped at 60s) to prevent rapid
#              restart loops. Checks for a .stop file between restarts
#              to support graceful shutdown.
# Parameters:
#   $1 - Session ID
#   $2 - Session name
#   $3 - Full socat command to run
#   $4 - Max restarts (default: DEFAULT_WATCHDOG_MAX_RESTARTS)
#   $5 - Check interval in seconds (default: DEFAULT_WATCHDOG_INTERVAL)
watchdog_loop() {
    local session_id="${1:?Session ID required}"
    local session_name="${2:?Session name required}"
    local socat_cmd="${3:?Socat command required}"
    local max_restarts="${4:-${DEFAULT_WATCHDOG_MAX_RESTARTS}}"
    local interval="${5:-${DEFAULT_WATCHDOG_INTERVAL}}"

    local restart_count=0
    local backoff=1  # Initial backoff in seconds

    log_info "Watchdog started for '${session_name}' [${session_id}] (max ${max_restarts} restarts)" "watchdog"

    while (( restart_count <= max_restarts )); do
        # Launch the socat process
        eval "${socat_cmd}" &
        local pid=$!

        log_info "Process launched: PID ${pid} (restart #${restart_count})" "watchdog"
        log_session "${session_id}" "INFO" "Watchdog launched socat PID ${pid} (restart #${restart_count})"

        # Wait for the process to exit
        wait "${pid}" 2>/dev/null || true
        local exit_code=$?

        # Check if we were signaled to stop (graceful shutdown via .stop file)
        if [[ -f "${SESSION_DIR}/${session_id}.stop" ]]; then
            rm -f "${SESSION_DIR}/${session_id}.stop" 2>/dev/null
            log_info "Watchdog: graceful stop requested for '${session_name}' [${session_id}]" "watchdog"
            break
        fi

        ((restart_count++)) || true

        if (( restart_count > max_restarts )); then
            log_error "Watchdog: max restarts (${max_restarts}) reached for '${session_name}' [${session_id}]" "watchdog"
            break
        fi

        log_warning "Process exited (code ${exit_code}). Restarting in ${backoff}s... (${restart_count}/${max_restarts})" "watchdog"
        sleep "${backoff}"

        # Exponential backoff: 1, 2, 4, 8, 16... capped at 60 seconds
        backoff=$(( backoff * 2 ))
        (( backoff > 60 )) && backoff=60
    done

    session_unregister "${session_id}"
    log_info "Watchdog exiting for '${session_name}' [${session_id}]" "watchdog"
}

#======================================================================
# MODE: listen
# Start a single TCP or UDP listener on a specified port.
# Captures incoming data to a per-port log file.
# Supports --proto for protocol selection and --dual-stack for both.
# Supports --watchdog for auto-restart on crash.
#======================================================================

# Function: mode_listen
# Description: Parse listen-mode arguments and start a single listener.
#              Uses launch_socat_session for reliable process tracking.
#              When --dual-stack is specified, launches both TCP and UDP
#              listeners on the same port with independent session IDs.
# Parameters: All remaining CLI arguments after "listen"
mode_listen() {
    local port="" proto="${DEFAULT_PROTOCOL}" extra_opts=""
    local use_watchdog=false session_name="" logfile="" bind_addr=""
    local dual_stack=false capture=false capture_logfile=""

    # Parse listen-specific arguments
    while [[ $# -gt 0 ]]; do
        case "${1}" in
            -p|--port)       port="${2:?--port requires a value}"; shift 2 ;;
            --proto)         proto="${2:?--proto requires a value}"; shift 2 ;;
            --bind)          bind_addr="${2:?--bind requires a value}"; shift 2 ;;
            --name)          session_name="${2:?--name requires a value}"; shift 2 ;;
            --logfile)       logfile="${2:?--logfile requires a value}"; shift 2 ;;
            --capture)       capture=true; shift ;;
            --watchdog)      use_watchdog=true; shift ;;
            --dual-stack)    dual_stack=true; shift ;;
            --socat-opts)    extra_opts="${2:?--socat-opts requires a value}"; shift 2 ;;
            -v|--verbose)    VERBOSE_MODE=true; shift ;;
            -h|--help)       show_listen_help; exit 0 ;;
            *)               log_error "Unknown listen option: ${1}"; exit 1 ;;
        esac
    done

    # Validate required arguments
    if [[ -z "${port}" ]]; then
        log_error "Port is required. Use: ${SCRIPT_NAME} listen --port <PORT>"
        exit 1
    fi

    validate_port "${port}" || exit 1
    proto=$(validate_protocol "${proto}") || exit 1

    print_banner "Listener"

    # Check port availability for the primary protocol
    if ! check_port_available "${port}" "${proto}"; then
        log_error "Port ${port} (${proto}) is already in use"
        exit 1
    fi

    # Default session name: protocol-port
    [[ -z "${session_name}" ]] && session_name="${proto}-${port}"

    # Default log file: listener data capture
    [[ -z "${logfile}" ]] && logfile="${LOG_DIR}/listener-${proto}-${port}.log"

    # Construct bind address option if specified
    if [[ -n "${bind_addr}" ]]; then
        validate_hostname "${bind_addr}" || exit 1
        extra_opts="bind=${bind_addr}${extra_opts:+,${extra_opts}}"
    fi

    # Build the socat command
    local cmd
    cmd=$(build_socat_listen_cmd "${proto}" "${port}" "${logfile}" "${extra_opts}" "${capture}")

    # Display configuration
    print_section "Listener Configuration"
    print_kv "Port" "${port}"
    print_kv "Protocol" "${proto}${dual_stack:+ + $(get_alt_protocol "${proto}")}"
    print_kv "Session Name" "${session_name}"
    print_kv "Data Log" "${logfile}"
    print_kv "Traffic Capture" "${capture}"
    [[ "${capture}" == true ]] && print_kv "Capture Log" "${capture_logfile}"
    print_kv "Watchdog" "${use_watchdog}"
    print_kv "Dual-Stack" "${dual_stack}"
    [[ -n "${bind_addr}" ]] && print_kv "Bind Address" "${bind_addr}"
    log_debug "Command: ${cmd}" "listen"

    # Launch the listener
    print_section "Starting Listener"

    # Primary protocol listener
    # Determine stderr redirect for capture mode
    local stderr_file=""
    [[ "${capture}" == true && -n "${capture_logfile}" ]] && stderr_file="${capture_logfile}"

    launch_socat_session "${session_name}" "listen" "${proto}" "${port}" "${cmd}" "" "" "${stderr_file}" || exit 1
    local primary_sid="${LAUNCH_SID}"

    log_success "Listener active on ${proto}:${port} (SID ${primary_sid})"

    # Dual-stack: also launch alternate protocol listener
    if [[ "${dual_stack}" == true ]]; then
        local alt_proto
        alt_proto="$(get_alt_protocol "${proto}")"
        local alt_name="${alt_proto}-${port}"
        local alt_logfile="${LOG_DIR}/listener-${alt_proto}-${port}.log"
        local alt_cmd
        alt_cmd=$(build_socat_listen_cmd "${alt_proto}" "${port}" "${alt_logfile}" "${extra_opts}" "${capture}")

        if check_port_available "${port}" "${alt_proto}"; then
            local alt_capture_logfile=""
            [[ "${capture}" == true ]] && alt_capture_logfile="${LOG_DIR}/capture-${alt_proto}-${port}-${EXEC_TIMESTAMP}.log"
            local alt_stderr=""
            [[ "${capture}" == true && -n "${alt_capture_logfile}" ]] && alt_stderr="${alt_capture_logfile}"

            launch_socat_session "${alt_name}" "listen" "${alt_proto}" "${port}" "${alt_cmd}" "" "" "${alt_stderr}" || {
                log_warning "Dual-stack ${alt_proto} listener failed on port ${port}"
            }
            if [[ -n "${LAUNCH_SID}" ]]; then
                log_success "Listener active on ${alt_proto}:${port} (SID ${LAUNCH_SID})"
            fi
        else
            log_warning "Port ${port} (${alt_proto}) already in use - skipping dual-stack"
        fi
    fi

    log_info "Data captured to: ${logfile}"
    log_info "Stop with: ${SCRIPT_NAME} stop ${primary_sid}"
}

#======================================================================
# MODE: batch
# Start multiple listeners from a port list, range, or config file.
# Supports both TCP and UDP per port (dual-stack option).
# Each listener gets its own session ID for independent management.
#======================================================================

# Function: mode_batch
# Description: Parse batch-mode arguments and start multiple listeners.
#              Supports port lists, ranges, and config files. Each port
#              gets an independent session with unique session ID.
#              --dual-stack launches both TCP and UDP per port.
# Parameters: All remaining CLI arguments after "batch"
mode_batch() {
    local ports_arg="" range_arg="" config_arg="" proto="${DEFAULT_PROTOCOL}"
    local dual_stack=false use_watchdog=false capture=false

    # Parse batch-specific arguments
    while [[ $# -gt 0 ]]; do
        case "${1}" in
            --ports)         ports_arg="${2:?--ports requires a value}"; shift 2 ;;
            --range)         range_arg="${2:?--range requires a value}"; shift 2 ;;
            --config)        config_arg="${2:?--config requires a value}"; shift 2 ;;
            --proto)         proto="${2:?--proto requires a value}"; shift 2 ;;
            --dual-stack)    dual_stack=true; shift ;;
            --watchdog)      use_watchdog=true; shift ;;
            --capture)       capture=true; shift ;;
            -v|--verbose)    VERBOSE_MODE=true; shift ;;
            -h|--help)       show_batch_help; exit 0 ;;
            *)               log_error "Unknown batch option: ${1}"; exit 1 ;;
        esac
    done

    # At least one port source is required
    if [[ -z "${ports_arg}" && -z "${range_arg}" && -z "${config_arg}" ]]; then
        log_error "Specify ports with --ports, --range, or --config"
        exit 1
    fi

    proto=$(validate_protocol "${proto}") || exit 1

    print_banner "Batch Listener"

    # Collect all ports into an array from the three possible sources
    local -a all_ports=()

    # From comma-separated list
    if [[ -n "${ports_arg}" ]]; then
        while IFS= read -r p; do
            all_ports+=("${p}")
        done < <(validate_port_list "${ports_arg}")
    fi

    # From range
    if [[ -n "${range_arg}" ]]; then
        while IFS= read -r p; do
            all_ports+=("${p}")
        done < <(validate_port_range "${range_arg}")
    fi

    # From config file (one port per line, # comments, blank lines ignored)
    if [[ -n "${config_arg}" ]]; then
        validate_file_path "${config_arg}" || exit 1
        if [[ ! -f "${config_arg}" ]]; then
            log_error "Config file not found: ${config_arg}"; exit 1
        fi
        while IFS= read -r line; do
            # Strip comments and whitespace
            line="${line%%#*}"
            line="${line// /}"
            [[ -z "${line}" ]] && continue
            if validate_port "${line}" 2>/dev/null; then
                all_ports+=("${line}")
            fi
        done < "${config_arg}"
    fi

    # Deduplicate ports (preserve order)
    local -a unique_ports=()
    local -A seen_ports=()
    for p in "${all_ports[@]}"; do
        if [[ -z "${seen_ports[${p}]+x}" ]]; then
            unique_ports+=("${p}")
            seen_ports[${p}]=1
        fi
    done

    if (( ${#unique_ports[@]} == 0 )); then
        log_error "No valid ports to listen on"; exit 1
    fi

    print_section "Batch Configuration"
    print_kv "Port Count" "${#unique_ports[@]}"
    print_kv "Protocol" "${proto}${dual_stack:+ + $(get_alt_protocol "${proto}")}"
    print_kv "Traffic Capture" "${capture}"
    print_kv "Watchdog" "${use_watchdog}"
    print_kv "Ports" "$(echo "${unique_ports[*]}" | tr ' ' ',')"

    # Launch listeners
    print_section "Starting Listeners"

    local started=0 failed=0

    for port in "${unique_ports[@]}"; do
        # --- Primary protocol listener ---
        local session_name="${proto}-${port}"
        local logfile="${LOG_DIR}/listener-${proto}-${port}.log"

        # Skip if port is in use
        if ! check_port_available "${port}" "${proto}"; then
            log_warning "Port ${port} (${proto}) in use - skipping"
            ((failed++)) || true
            continue
        fi

        # Set up capture stderr redirect for this port
        local capture_logfile=""
        local stderr_file=""
        if [[ "${capture}" == true ]]; then
            capture_logfile="${LOG_DIR}/capture-${proto}-${port}-${EXEC_TIMESTAMP}.log"
            stderr_file="${capture_logfile}"
        fi

        local cmd
        cmd=$(build_socat_listen_cmd "${proto}" "${port}" "${logfile}" "" "${capture}")

        launch_socat_session "${session_name}" "batch-listen" "${proto}" "${port}" "${cmd}" "" "" "${stderr_file}" || {
            ((failed++)) || true
            continue
        }
        ((started++)) || true
        log_debug "Started ${proto}:${port} (SID ${LAUNCH_SID})" "batch"

        # --- Dual-stack: also start alternate protocol ---
        if [[ "${dual_stack}" == true ]]; then
            local alt_proto
            alt_proto="$(get_alt_protocol "${proto}")"
            local alt_session="${alt_proto}-${port}"
            local alt_logfile="${LOG_DIR}/listener-${alt_proto}-${port}.log"

            if check_port_available "${port}" "${alt_proto}"; then
                local alt_capture_logfile=""
                local alt_stderr=""
                if [[ "${capture}" == true ]]; then
                    alt_capture_logfile="${LOG_DIR}/capture-${alt_proto}-${port}-${EXEC_TIMESTAMP}.log"
                    alt_stderr="${alt_capture_logfile}"
                fi
                local alt_cmd
                alt_cmd=$(build_socat_listen_cmd "${alt_proto}" "${port}" "${alt_logfile}" "" "${capture}")
                launch_socat_session "${alt_session}" "batch-listen" "${alt_proto}" "${port}" "${alt_cmd}" "" "" "${alt_stderr}" || {
                    continue
                }
                ((started++)) || true
                log_debug "Started ${alt_proto}:${port} (SID ${LAUNCH_SID})" "batch"
            fi
        fi
    done

    # Brief settle time for binding
    sleep 0.3

    echo "" >&2
    log_success "Batch complete: ${started} listeners started, ${failed} skipped"
    log_info "Data logs in: ${LOG_DIR}/"
    log_info "Stop all with: ${SCRIPT_NAME} stop --all"
}

#======================================================================
# MODE: forward
# Forward connections from a local port to a remote host:port.
# Bidirectional by default (full proxy). Supports TCP and UDP.
# --proto selects individual protocol; --dual-stack launches both.
#======================================================================

# Function: mode_forward
# Description: Parse forward-mode arguments and set up port forwarding.
#              Uses launch_socat_session for reliable process tracking.
#              Supports --proto for individual protocol and --dual-stack
#              for both TCP and UDP simultaneously.
# Parameters: All remaining CLI arguments after "forward"
mode_forward() {
    local lport="" rhost="" rport="" proto="${DEFAULT_PROTOCOL}" remote_proto=""
    local use_watchdog=false session_name="" dual_stack=false
    local capture=false capture_logfile=""

    # Parse forward-specific arguments
    while [[ $# -gt 0 ]]; do
        case "${1}" in
            --lport)         lport="${2:?--lport requires a value}"; shift 2 ;;
            --rhost)         rhost="${2:?--rhost requires a value}"; shift 2 ;;
            --rport)         rport="${2:?--rport requires a value}"; shift 2 ;;
            --proto)         proto="${2:?--proto requires a value}"; shift 2 ;;
            --remote-proto)  remote_proto="${2:?--remote-proto requires a value}"; shift 2 ;;
            --name)          session_name="${2:?--name requires a value}"; shift 2 ;;
            --watchdog)      use_watchdog=true; shift ;;
            --dual-stack)    dual_stack=true; shift ;;
            --capture)       capture=true; shift ;;
            --logfile)       logfile="${2:?--logfile requires a value}"; shift 2 ;;
            -v|--verbose)    VERBOSE_MODE=true; shift ;;
            -h|--help)       show_forward_help; exit 0 ;;
            *)               log_error "Unknown forward option: ${1}"; exit 1 ;;
        esac
    done

    # Validate required arguments
    [[ -z "${lport}" ]] && { log_error "--lport is required"; exit 1; }
    [[ -z "${rhost}" ]] && { log_error "--rhost is required"; exit 1; }
    [[ -z "${rport}" ]] && { log_error "--rport is required"; exit 1; }

    validate_port "${lport}" || exit 1
    validate_port "${rport}" || exit 1
    validate_hostname "${rhost}" || exit 1
    proto=$(validate_protocol "${proto}") || exit 1

    # Default remote protocol matches listen protocol
    if [[ -n "${remote_proto}" ]]; then
        remote_proto=$(validate_protocol "${remote_proto}") || exit 1
    else
        remote_proto="${proto}"
    fi

    print_banner "Forwarder"

    # Check port availability for primary protocol
    if ! check_port_available "${lport}" "${proto}"; then
        log_error "Local port ${lport} (${proto}) is already in use"
        exit 1
    fi

    # Default session name
    [[ -z "${session_name}" ]] && session_name="fwd-${lport}-${rhost}-${rport}"

    # Build command
    local cmd
    cmd=$(build_socat_forward_cmd "${proto}" "${lport}" "${rhost}" "${rport}" "${remote_proto}" "${capture}")

    # Set up capture log if --capture is enabled
    if [[ "${capture}" == true ]]; then
        capture_logfile="${LOG_DIR}/capture-${proto}-${lport}-${rhost}-${rport}-${EXEC_TIMESTAMP}.log"
    fi

    # Display configuration
    print_section "Forward Configuration"
    print_kv "Local Port" "${lport} (${proto})"
    print_kv "Remote Target" "${rhost}:${rport} (${remote_proto})"
    print_kv "Direction" "Bidirectional"
    print_kv "Session Name" "${session_name}"
    print_kv "Traffic Capture" "${capture}"
    [[ "${capture}" == true ]] && print_kv "Capture Log" "${capture_logfile}"
    print_kv "Dual-Stack" "${dual_stack}"
    print_kv "Watchdog" "${use_watchdog}"
    log_debug "Command: ${cmd}" "forward"

    # Launch
    print_section "Starting Forwarder"

    # Determine stderr redirect for capture mode
    local stderr_file=""
    [[ "${capture}" == true && -n "${capture_logfile}" ]] && stderr_file="${capture_logfile}"

    launch_socat_session "${session_name}" "forward" "${proto}" "${lport}" \
        "${cmd}" "${rhost}" "${rport}" "${stderr_file}" || exit 1
    local primary_sid="${LAUNCH_SID}"

    log_success "Forwarder active: ${proto}:${lport} ${SYM_FORWARD} ${rhost}:${rport} (SID ${primary_sid})"

    # Dual-stack: also launch alternate protocol forwarder
    if [[ "${dual_stack}" == true ]]; then
        local alt_proto alt_remote_proto
        alt_proto="$(get_alt_protocol "${proto}")"
        alt_remote_proto="$(get_alt_protocol "${remote_proto}")"
        local alt_name="fwd-${alt_proto}-${lport}-${rhost}-${rport}"
        local alt_cmd
        alt_cmd=$(build_socat_forward_cmd "${alt_proto}" "${lport}" "${rhost}" "${rport}" "${alt_remote_proto}" "${capture}")
            local alt_capture_logfile=""
            local alt_stderr=""
            if [[ "${capture}" == true ]]; then
                alt_capture_logfile="${LOG_DIR}/capture-${alt_proto}-${lport}-${rhost}-${rport}-${EXEC_TIMESTAMP}.log"
                alt_stderr="${alt_capture_logfile}"
            fi

        if check_port_available "${lport}" "${alt_proto}"; then
            launch_socat_session "${alt_name}" "forward" "${alt_proto}" "${lport}" \
                "${alt_cmd}" "${rhost}" "${rport}" "${alt_stderr}" || {
                log_warning "Dual-stack ${alt_proto} forwarder failed on port ${lport}"
            }
            if [[ -n "${LAUNCH_SID}" ]]; then
                log_success "Forwarder active: ${alt_proto}:${lport} ${SYM_FORWARD} ${rhost}:${rport} (SID ${LAUNCH_SID})"
            fi
        else
            log_warning "Port ${lport} (${alt_proto}) already in use - skipping dual-stack"
        fi
    fi

    log_info "Stop with: ${SCRIPT_NAME} stop ${primary_sid}"
}

#======================================================================
# MODE: tunnel
# Create an encrypted (OpenSSL/TLS) tunnel via socat.
# Accepts TLS connections on a local port and forwards plaintext
# to a remote target. Auto-generates self-signed certs if needed.
# --dual-stack adds a plaintext UDP forwarder (TLS is TCP-only).
#======================================================================

# Function: mode_tunnel
# Description: Parse tunnel-mode arguments and create an encrypted tunnel.
#              Uses launch_socat_session for reliable process tracking.
#              TLS tunnels are inherently TCP-only. When --dual-stack is
#              specified, a plaintext UDP forwarder is added on the same
#              port with a warning that UDP traffic is NOT encrypted.
# Parameters: All remaining CLI arguments after "tunnel"
mode_tunnel() {
    local lport="" rhost="" rport="" cert="" key=""
    local use_watchdog=false session_name="" cn="localhost" dual_stack=false
    local capture=false capture_logfile=""

    # Parse tunnel-specific arguments
    while [[ $# -gt 0 ]]; do
        case "${1}" in
            -p|--port)       lport="${2:?--port requires a value}"; shift 2 ;;
            --rhost)         rhost="${2:?--rhost requires a value}"; shift 2 ;;
            --rport)         rport="${2:?--rport requires a value}"; shift 2 ;;
            --cert)          cert="${2:?--cert requires a value}"; shift 2 ;;
            --key)           key="${2:?--key requires a value}"; shift 2 ;;
            --cn)            cn="${2:?--cn requires a value}"; shift 2 ;;
            --name)          session_name="${2:?--name requires a value}"; shift 2 ;;
            --watchdog)      use_watchdog=true; shift ;;
            --dual-stack)    dual_stack=true; shift ;;
            --proto)         
                # TLS tunnels are TCP-only. Accept --proto for consistency
                # but only allow TCP variants. Reject UDP with guidance.
                local tunnel_proto="${2:?--proto requires a value}"
                tunnel_proto="${tunnel_proto,,}"
                case "${tunnel_proto}" in
                    tcp|tcp4) log_debug "Tunnel using default TCP4" "tunnel" ;;
                    tcp6)     log_warning "TCP6 TLS tunnels not currently supported; using TCP4" "tunnel" ;;
                    udp|udp4|udp6)
                        log_error "TLS tunnels require TCP. UDP is not supported for encrypted tunnels."
                        log_info "For UDP forwarding, use: ${SCRIPT_NAME} forward --proto udp4 --lport <PORT> --rhost <HOST> --rport <PORT>"
                        exit 1
                        ;;
                    *) log_error "Invalid protocol: ${tunnel_proto}"; exit 1 ;;
                esac
                shift 2 ;;
            --capture)       capture=true; shift ;;
            --logfile)       capture_logfile="${2:?--logfile requires a value}"; shift 2 ;;
            -v|--verbose)    VERBOSE_MODE=true; shift ;;
            -h|--help)       show_tunnel_help; exit 0 ;;
            *)               log_error "Unknown tunnel option: ${1}"; exit 1 ;;
        esac
    done

    # Validate required arguments
    [[ -z "${lport}" ]] && { log_error "--port is required"; exit 1; }
    [[ -z "${rhost}" ]] && { log_error "--rhost is required"; exit 1; }
    [[ -z "${rport}" ]] && { log_error "--rport is required"; exit 1; }

    validate_port "${lport}" || exit 1
    validate_port "${rport}" || exit 1
    validate_hostname "${rhost}" || exit 1

    # Dual-stack advisory: TLS/OpenSSL tunnels are TCP-only by design
    if [[ "${dual_stack}" == true ]]; then
        log_warning "TLS tunnels use TCP only. --dual-stack will add a plaintext UDP forwarder (unencrypted) on the same port." "tunnel"
    fi

    print_banner "Encrypted Tunnel"

    # Generate self-signed cert if none provided
    if [[ -z "${cert}" || -z "${key}" ]]; then
        log_info "No certificate provided; generating self-signed cert..." "tunnel"
        local cert_pair
        cert_pair=$(generate_self_signed_cert "${cn}") || exit 1
        cert="${cert_pair%% *}"
        key="${cert_pair##* }"
    else
        # Validate provided cert/key paths
        validate_file_path "${cert}" || exit 1
        validate_file_path "${key}" || exit 1
        [[ ! -f "${cert}" ]] && { log_error "Certificate not found: ${cert}"; exit 1; }
        [[ ! -f "${key}" ]] && { log_error "Key not found: ${key}"; exit 1; }
    fi

    # Check port availability
    if ! check_port_available "${lport}" "tcp4"; then
        log_error "Local port ${lport} (tcp4) is already in use"
        exit 1
    fi

    # Default session name
    [[ -z "${session_name}" ]] && session_name="tunnel-${lport}-${rhost}-${rport}"

    # Build command
    local cmd
    cmd=$(build_socat_tunnel_cmd "${lport}" "${rhost}" "${rport}" "${cert}" "${key}" "${capture}")

    # Set up capture log if --capture is enabled
    if [[ "${capture}" == true ]]; then
        [[ -z "${capture_logfile}" ]] && capture_logfile="${LOG_DIR}/capture-tls-${lport}-${rhost}-${rport}-${EXEC_TIMESTAMP}.log"
    fi

    # Display configuration
    print_section "Tunnel Configuration"
    print_kv "Listen Port" "${lport} (TLS/SSL)"
    print_kv "Remote Target" "${rhost}:${rport} (plaintext)"
    print_kv "Certificate" "${cert}"
    print_kv "Key" "${key}"
    print_kv "Session Name" "${session_name}"
    print_kv "Traffic Capture" "${capture}"
    [[ "${capture}" == true ]] && print_kv "Capture Log" "${capture_logfile}"
    print_kv "Dual-Stack" "${dual_stack}"
    print_kv "Watchdog" "${use_watchdog}"
    log_debug "Command: ${cmd}" "tunnel"

    # Launch
    print_section "Starting Tunnel"

    # Determine stderr redirect for capture mode
    local stderr_file=""
    [[ "${capture}" == true && -n "${capture_logfile}" ]] && stderr_file="${capture_logfile}"

    launch_socat_session "${session_name}" "tunnel" "tls" "${lport}" \
        "${cmd}" "${rhost}" "${rport}" "${stderr_file}" || exit 1
    local primary_sid="${LAUNCH_SID}"

    log_success "Tunnel active: TLS:${lport} ${SYM_TUNNEL} ${rhost}:${rport} (SID ${primary_sid})"

    # Dual-stack: add plaintext UDP forwarder on same port
    if [[ "${dual_stack}" == true ]]; then
        if check_port_available "${lport}" "udp4"; then
            local udp_name="fwd-udp4-${lport}-${rhost}-${rport}"
            local udp_cmd
            udp_cmd=$(build_socat_forward_cmd "udp4" "${lport}" "${rhost}" "${rport}" "udp4" "${capture}")

            local udp_capture_logfile=""
            local udp_stderr=""
            if [[ "${capture}" == true ]]; then
                udp_capture_logfile="${LOG_DIR}/capture-udp4-${lport}-${rhost}-${rport}-${EXEC_TIMESTAMP}.log"
                udp_stderr="${udp_capture_logfile}"
            fi

            launch_socat_session "${udp_name}" "tunnel-udp" "udp4" "${lport}" \
                "${udp_cmd}" "${rhost}" "${rport}" "${udp_stderr}" || {
                log_warning "Dual-stack UDP forwarder failed on port ${lport}"
            }
            if [[ -n "${LAUNCH_SID}" ]]; then
                log_success "UDP forwarder active: udp4:${lport} ${SYM_FORWARD} ${rhost}:${rport} (SID ${LAUNCH_SID})"
            fi
        else
            log_warning "Port ${lport} (udp4) already in use - skipping dual-stack"
        fi
    fi

    log_info "Connect with: socat - OPENSSL:localhost:${lport},verify=0"
    log_info "Stop with: ${SCRIPT_NAME} stop ${primary_sid}"
}

#======================================================================
# MODE: redirect
# Redirect/proxy traffic transparently between endpoints.
# Optionally captures bidirectional traffic dumps for inspection.
# Supports --proto for individual TCP/UDP selection and --dual-stack
# for both protocols simultaneously.
#======================================================================

# Function: mode_redirect
# Description: Parse redirect-mode arguments and set up traffic redirection.
#              Uses launch_socat_session for reliable process tracking.
#              Protocol-aware: --proto selects TCP or UDP individually;
#              --dual-stack launches both. Capture mode uses stderr
#              redirection handled cleanly by the launcher.
# Parameters: All remaining CLI arguments after "redirect"
mode_redirect() {
    local lport="" rhost="" rport="" logfile="" proto="${DEFAULT_PROTOCOL}"
    local use_watchdog=false session_name="" capture=false dual_stack=false

    # Parse redirect-specific arguments
    while [[ $# -gt 0 ]]; do
        case "${1}" in
            --lport)         lport="${2:?--lport requires a value}"; shift 2 ;;
            --rhost)         rhost="${2:?--rhost requires a value}"; shift 2 ;;
            --rport)         rport="${2:?--rport requires a value}"; shift 2 ;;
            --proto)         proto="${2:?--proto requires a value}"; shift 2 ;;
            --capture)       capture=true; shift ;;
            --logfile)       logfile="${2:?--logfile requires a value}"; shift 2 ;;
            --name)          session_name="${2:?--name requires a value}"; shift 2 ;;
            --watchdog)      use_watchdog=true; shift ;;
            --dual-stack)    dual_stack=true; shift ;;
            -v|--verbose)    VERBOSE_MODE=true; shift ;;
            -h|--help)       show_redirect_help; exit 0 ;;
            *)               log_error "Unknown redirect option: ${1}"; exit 1 ;;
        esac
    done

    # Validate required arguments
    [[ -z "${lport}" ]] && { log_error "--lport is required"; exit 1; }
    [[ -z "${rhost}" ]] && { log_error "--rhost is required"; exit 1; }
    [[ -z "${rport}" ]] && { log_error "--rport is required"; exit 1; }

    validate_port "${lport}" || exit 1
    validate_port "${rport}" || exit 1
    validate_hostname "${rhost}" || exit 1
    proto=$(validate_protocol "${proto}") || exit 1

    print_banner "Redirector"

    # Check port availability for primary protocol
    if ! check_port_available "${lport}" "${proto}"; then
        log_error "Local port ${lport} (${proto}) is already in use"
        exit 1
    fi

    # Default session name includes protocol for disambiguation
    [[ -z "${session_name}" ]] && session_name="redir-${proto}-${lport}-${rhost}-${rport}"

    # Set up capture log if requested
    if [[ "${capture}" == true ]]; then
        [[ -z "${logfile}" ]] && logfile="${LOG_DIR}/capture-${proto}-${lport}-${rhost}-${rport}-${EXEC_TIMESTAMP}.log"
    fi

    # Build command using protocol-aware builder
    local cmd
    cmd=$(build_socat_redirect_cmd "${proto}" "${lport}" "${rhost}" "${rport}" "${capture}")

    # Display configuration
    print_section "Redirect Configuration"
    print_kv "Listen Port" "${lport}"
    print_kv "Protocol" "${proto}${dual_stack:+ + $(get_alt_protocol "${proto}")}"
    print_kv "Remote Target" "${rhost}:${rport}"
    print_kv "Traffic Capture" "${capture}"
    [[ "${capture}" == true ]] && print_kv "Capture Log" "${logfile}"
    print_kv "Session Name" "${session_name}"
    print_kv "Dual-Stack" "${dual_stack}"
    print_kv "Watchdog" "${use_watchdog}"
    log_debug "Command: ${cmd}" "redirect"

    # Launch - stderr_redirect parameter handles capture mode cleanly
    print_section "Starting Redirector"

    local stderr_file=""
    [[ "${capture}" == true && -n "${logfile}" ]] && stderr_file="${logfile}"

    launch_socat_session "${session_name}" "redirect" "${proto}" "${lport}" \
        "${cmd}" "${rhost}" "${rport}" "${stderr_file}" || exit 1
    local primary_sid="${LAUNCH_SID}"

    log_success "Redirector active: ${proto}:${lport} ${SYM_ARROW} ${rhost}:${rport} (SID ${primary_sid})"

    # Dual-stack: also launch alternate protocol redirector
    if [[ "${dual_stack}" == true ]]; then
        local alt_proto
        alt_proto="$(get_alt_protocol "${proto}")"

        if check_port_available "${lport}" "${alt_proto}"; then
            local alt_name="redir-${alt_proto}-${lport}-${rhost}-${rport}"
            local alt_logfile=""
            if [[ "${capture}" == true ]]; then
                alt_logfile="${LOG_DIR}/capture-${alt_proto}-${lport}-${rhost}-${rport}-${EXEC_TIMESTAMP}.log"
            fi
            local alt_cmd
            alt_cmd=$(build_socat_redirect_cmd "${alt_proto}" "${lport}" "${rhost}" "${rport}" "${capture}")
            local alt_stderr=""
            [[ "${capture}" == true && -n "${alt_logfile}" ]] && alt_stderr="${alt_logfile}"

            launch_socat_session "${alt_name}" "redirect" "${alt_proto}" "${lport}" \
                "${alt_cmd}" "${rhost}" "${rport}" "${alt_stderr}" || {
                log_warning "Dual-stack ${alt_proto} redirector failed on port ${lport}"
            }
            if [[ -n "${LAUNCH_SID}" ]]; then
                log_success "Redirector active: ${alt_proto}:${lport} ${SYM_ARROW} ${rhost}:${rport} (SID ${LAUNCH_SID})"
            fi
        else
            log_warning "Port ${lport} (${alt_proto}) already in use - skipping dual-stack"
        fi
    fi

    log_info "Stop with: ${SCRIPT_NAME} stop ${primary_sid}"
}

#======================================================================
# MODE: status
# Display all active managed sessions with their health status.
# Supports optional session ID argument for detailed view.
#
# Usage:
#   socat_manager.sh status              - List all sessions
#   socat_manager.sh status <SID>        - Detail for specific session
#   socat_manager.sh status <NAME>       - Detail by session name
#   socat_manager.sh status <PORT>       - Detail by port number
#   socat_manager.sh status --cleanup    - Remove dead session files
#   socat_manager.sh status --verbose    - Include system listener info
#======================================================================

# Function: mode_status
# Description: Show all registered sessions with process status.
#              Accepts an optional positional argument to show detailed
#              information for a specific session. The argument is
#              matched against session IDs (8-char hex), session names,
#              and port numbers in that order.
# Parameters: Optional session identifier and flags
mode_status() {
    local target_sid="" do_cleanup=false

    # Parse arguments - first non-flag argument is treated as session identifier
    while [[ $# -gt 0 ]]; do
        case "${1}" in
            -v|--verbose) VERBOSE_MODE=true; shift ;;
            --cleanup)    do_cleanup=true; shift ;;
            -h|--help)    show_status_help; exit 0 ;;
            -*)           shift ;;  # Skip unknown flags gracefully
            *)
                # First positional argument: session ID, name, or port
                if [[ -z "${target_sid}" ]]; then
                    target_sid="${1}"
                fi
                shift
                ;;
        esac
    done

    # Run cleanup if requested
    if [[ "${do_cleanup}" == true ]]; then
        session_cleanup_dead
    fi

    # If a specific session identifier was provided, show detailed view
    if [[ -n "${target_sid}" ]]; then
        print_banner "Session Status"

        # Try as session ID first (8-char hex)
        if [[ "${target_sid}" =~ ^[a-f0-9]{8}$ ]] && \
           [[ -f "${SESSION_DIR}/${target_sid}.session" ]]; then
            session_detail "${target_sid}"
            return 0
        fi

        # Try as session name (search all session files)
        local found_sid
        found_sid="$(session_find_by_name "${target_sid}" | head -1)"
        if [[ -n "${found_sid}" ]]; then
            session_detail "${found_sid}"
            return 0
        fi

        # Try as port number (may match multiple sessions for dual-stack)
        if [[ "${target_sid}" =~ ^[0-9]+$ ]]; then
            local port_sids
            port_sids="$(session_find_by_port "${target_sid}")"
            if [[ -n "${port_sids}" ]]; then
                while IFS= read -r psid; do
                    session_detail "${psid}"
                    echo "" >&2
                done <<< "${port_sids}"
                return 0
            fi
        fi

        log_error "Session '${target_sid}' not found (searched by ID, name, and port)"
        log_info "Run '${SCRIPT_NAME} status' to see all sessions"
        return 1
    fi

    # No specific session: show overview of all sessions
    print_banner "Session Status"
    session_list

    # Show listening ports via ss if verbose
    if [[ "${VERBOSE_MODE}" == true ]]; then
        print_section "System Listeners (socat)"
        if command -v ss &>/dev/null; then
            ss -tlnp 2>/dev/null | grep -i socat || echo "  (no socat TCP listeners detected via ss)" >&2
            echo "" >&2
            ss -ulnp 2>/dev/null | grep -i socat || echo "  (no socat UDP listeners detected via ss)" >&2
        elif command -v netstat &>/dev/null; then
            netstat -tulnp 2>/dev/null | grep -i socat || echo "  (no socat listeners detected)" >&2
        fi
    fi
}

#======================================================================
# MODE: stop
# Stop one or more sessions by session ID, name, port, PID, or all.
# Protocol-aware: stopping a TCP session on a shared port does NOT
# affect a UDP session on the same port, and vice versa.
#
# Usage:
#   socat_manager.sh stop <SID>          - Stop specific session by ID
#   socat_manager.sh stop --all          - Stop all sessions
#   socat_manager.sh stop --name <n>  - Stop by session name
#   socat_manager.sh stop --port <PORT>  - Stop all on port (all protocols)
#   socat_manager.sh stop --pid <PID>    - Stop by PID
#
# Stop process (per session):
#   1. Read session metadata including PROTOCOL
#   2. Signal watchdog to stop
#   3. SIGTERM the entire process group (-PGID)
#   4. SIGTERM specific PID + children
#   5. Wait grace period (5 seconds)
#   6. SIGKILL if still alive
#   7. Fallback: kill socat by port (protocol-scoped)
#   8. Verify port freed (protocol-scoped)
#   9. Remove session file after confirmed dead
#======================================================================

# Function: mode_stop
# Description: Stop sessions by various selectors.
#              First positional argument is treated as session ID.
# Parameters: All remaining CLI arguments after "stop"
mode_stop() {
    local stop_all=false stop_name="" stop_port="" stop_pid=""
    local target_sid=""

    while [[ $# -gt 0 ]]; do
        case "${1}" in
            --all)           stop_all=true; shift ;;
            --name)          stop_name="${2:?--name requires a value}"; shift 2 ;;
            --port)          stop_port="${2:?--port requires a value}"; shift 2 ;;
            --pid)           stop_pid="${2:?--pid requires a value}"; shift 2 ;;
            -v|--verbose)    VERBOSE_MODE=true; shift ;;
            -h|--help)       show_stop_help; exit 0 ;;
            -*)              log_error "Unknown stop option: ${1}"; exit 1 ;;
            *)
                # First positional argument: session ID or name
                if [[ -z "${target_sid}" ]]; then
                    target_sid="${1}"
                fi
                shift
                ;;
        esac
    done

    # Require at least one selector
    if [[ "${stop_all}" != true && -z "${stop_name}" && -z "${stop_port}" && \
          -z "${stop_pid}" && -z "${target_sid}" ]]; then
        log_error "Specify what to stop: <session-id>, --all, --name, --port, or --pid"
        log_info "Run '${SCRIPT_NAME} status' to see active sessions"
        exit 1
    fi

    print_banner "Session Stop"
    local stopped=0 failed=0

    if [[ "${stop_all}" == true ]]; then
        # ─── Stop all registered sessions ───
        print_section "Stopping All Sessions"

        local all_sids
        all_sids="$(session_get_all_ids)"

        if [[ -z "${all_sids}" ]]; then
            log_info "No sessions to stop"
        else
            while IFS= read -r sid; do
                [[ -z "${sid}" ]] && continue
                if _stop_session "${sid}"; then
                    ((stopped++)) || true
                else
                    ((failed++)) || true
                fi
            done <<< "${all_sids}"
        fi

        # Safety net: report any orphaned socat processes
        _cleanup_orphaned_socat

    elif [[ -n "${target_sid}" ]]; then
        # ─── Stop by session ID (positional argument) ───
        # Try as session ID first (8-char hex)
        if [[ "${target_sid}" =~ ^[a-f0-9]{8}$ ]] && \
           [[ -f "${SESSION_DIR}/${target_sid}.session" ]]; then
            if _stop_session "${target_sid}"; then
                ((stopped++)) || true
            else
                ((failed++)) || true
            fi
        else
            # Try as session name
            local found_sids
            found_sids="$(session_find_by_name "${target_sid}")"
            if [[ -n "${found_sids}" ]]; then
                while IFS= read -r sid; do
                    [[ -z "${sid}" ]] && continue
                    if _stop_session "${sid}"; then
                        ((stopped++)) || true
                    else
                        ((failed++)) || true
                    fi
                done <<< "${found_sids}"
            else
                log_warning "Session '${target_sid}' not found"
                ((failed++)) || true
            fi
        fi

    elif [[ -n "${stop_name}" ]]; then
        # ─── Stop by session name ───
        local name_sids
        name_sids="$(session_find_by_name "${stop_name}")"

        if [[ -z "${name_sids}" ]]; then
            log_warning "No sessions found with name '${stop_name}'"
            ((failed++)) || true
        else
            while IFS= read -r sid; do
                [[ -z "${sid}" ]] && continue
                if _stop_session "${sid}"; then
                    ((stopped++)) || true
                else
                    ((failed++)) || true
                fi
            done <<< "${name_sids}"
        fi

    elif [[ -n "${stop_port}" ]]; then
        # ─── Stop all sessions on a specific port (all protocols) ───
        validate_port "${stop_port}" || exit 1

        local port_sids
        port_sids="$(session_find_by_port "${stop_port}")"

        if [[ -z "${port_sids}" ]]; then
            log_warning "No sessions found on port ${stop_port}"
            ((failed++)) || true
        else
            while IFS= read -r sid; do
                [[ -z "${sid}" ]] && continue
                if _stop_session "${sid}"; then
                    ((stopped++)) || true
                else
                    ((failed++)) || true
                fi
            done <<< "${port_sids}"
        fi

    elif [[ -n "${stop_pid}" ]]; then
        # ─── Stop by PID ───
        local pid_sids
        pid_sids="$(session_find_by_pid "${stop_pid}")"

        if [[ -z "${pid_sids}" ]]; then
            log_warning "No sessions found with PID ${stop_pid}"
            ((failed++)) || true
        else
            while IFS= read -r sid; do
                [[ -z "${sid}" ]] && continue
                if _stop_session "${sid}"; then
                    ((stopped++)) || true
                else
                    ((failed++)) || true
                fi
            done <<< "${pid_sids}"
        fi
    fi

    echo "" >&2
    log_info "Stop summary: ${stopped} stopped, ${failed} failed"

    # Clean up any remaining dead session files
    session_cleanup_dead
}

# Function: _stop_session
# Description: Stop a single session by its session ID. Implements a
#              comprehensive, protocol-aware stop sequence:
#
#              1. Read session metadata including PROTOCOL
#              2. Signal watchdog to stop (if applicable)
#              3. SIGTERM the entire process group (-PGID)
#              4. SIGTERM the specific PID + direct children
#              5. Wait grace period (STOP_GRACE_SECONDS)
#              6. SIGKILL if still alive
#              7. Fallback: kill socat by port (ONLY this session's protocol)
#              8. Verify port freed (ONLY this session's protocol)
#              9. Remove session file after confirmed dead
#
#              CRITICAL: Steps 7 and 8 are protocol-scoped. Stopping a TCP
#              session will NOT check/kill UDP on the same port, and vice
#              versa. This prevents cross-protocol interference in
#              dual-stack configurations.
#
# Parameters:
#   $1 - Session ID
# Returns: 0 on success, 1 on failure
_stop_session() {
    local sid="${1:?Session ID required}"
    local session_file="${SESSION_DIR}/${sid}.session"

    if [[ ! -f "${session_file}" ]]; then
        log_warning "Session file not found for '${sid}'"
        return 1
    fi

    # Read session metadata - PROTOCOL is critical for scoped port checks
    local name pid pgid lport mode proto
    name="$(session_read_field "${session_file}" "SESSION_NAME")"
    pid="$(session_read_field "${session_file}" "PID")"
    pgid="$(session_read_field "${session_file}" "PGID")"
    lport="$(session_read_field "${session_file}" "LOCAL_PORT")"
    mode="$(session_read_field "${session_file}" "MODE")"
    proto="$(session_read_field "${session_file}" "PROTOCOL")"

    # Default protocol if not recorded (legacy sessions)
    [[ -z "${proto}" ]] && proto="tcp4"

    log_info "Stopping session ${sid} (${name}, PID ${pid}, PGID ${pgid}, ${proto})..." "stop"
    log_session "${sid}" "INFO" "Stop requested for ${proto} session"

    # Step 1: Signal watchdog to stop gracefully (if applicable)
    touch "${SESSION_DIR}/${sid}.stop" 2>/dev/null || true

    # Step 2: SIGTERM the entire process group (most reliable method)
    # Under setsid, PGID == PID of the socat parent. Killing -PGID
    # terminates socat AND all its forked children in one operation.
    if [[ -n "${pgid}" ]] && [[ "${pgid}" != "0" ]]; then
        if kill -0 "-${pgid}" 2>/dev/null; then
            log_debug "Sending SIGTERM to process group -${pgid}" "stop"
            kill -TERM "-${pgid}" 2>/dev/null || true
        fi
    fi

    # Step 3: Also SIGTERM the specific PID + direct children (belt and suspenders)
    if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
        log_debug "Sending SIGTERM to PID ${pid}" "stop"
        kill -TERM "${pid}" 2>/dev/null || true
        # Kill any direct children that may have been forked by socat
        pkill -TERM -P "${pid}" 2>/dev/null || true
    fi

    # Step 4: Wait grace period for clean shutdown
    local waited=0 is_dead=false
    while (( waited < STOP_GRACE_SECONDS * 2 )); do
        local pid_alive=false pgid_alive=false

        if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
            pid_alive=true
        fi

        if [[ -n "${pgid}" ]] && [[ "${pgid}" != "0" ]] && kill -0 "-${pgid}" 2>/dev/null; then
            pgid_alive=true
        fi

        if [[ "${pid_alive}" == false && "${pgid_alive}" == false ]]; then
            is_dead=true
            break
        fi

        sleep 0.5
        ((waited++)) || true
    done

    # Step 5: Force kill if still alive
    if [[ "${is_dead}" == false ]]; then
        log_warning "Session ${sid} still alive after grace period, sending SIGKILL..." "stop"

        # SIGKILL the process group
        if [[ -n "${pgid}" ]] && [[ "${pgid}" != "0" ]]; then
            kill -KILL "-${pgid}" 2>/dev/null || true
        fi

        # SIGKILL the specific PID and its children
        if [[ -n "${pid}" ]]; then
            kill -KILL "${pid}" 2>/dev/null || true
            pkill -KILL -P "${pid}" 2>/dev/null || true
        fi

        sleep 0.5
    fi

    # Step 6: Verify PID is truly dead
    local final_check=false
    if [[ -n "${pid}" ]] && ! kill -0 "${pid}" 2>/dev/null; then
        final_check=true
    elif [[ -z "${pid}" ]]; then
        final_check=true
    fi

    # Step 7: Fallback - if port still in use FOR THIS PROTOCOL, kill by port
    # CRITICAL: Only check the session's own protocol. This prevents
    # cross-protocol interference when dual-stack sessions share a port.
    if [[ -n "${lport}" ]] && [[ "${lport}" != "0" ]]; then
        if ! check_port_available "${lport}" "${proto}"; then
            log_warning "Port ${lport} (${proto}) still in use after kill, attempting port-based cleanup..." "stop"
            _kill_by_port "${lport}" "${proto}"
            sleep 0.5
        fi
    fi

    # Step 8: Final port verification (protocol-scoped)
    if [[ -n "${lport}" ]] && [[ "${lport}" != "0" ]]; then
        if ! check_port_freed "${lport}" "${proto}" 3; then
            log_warning "Port ${lport} (${proto}) may still be in TIME_WAIT state" "stop"
        fi
    fi

    # Step 9: Remove session file and associated signal files
    rm -f "${session_file}" "${SESSION_DIR}/${sid}.stop" "${SESSION_DIR}/${sid}.launching" 2>/dev/null

    if [[ "${final_check}" == true ]]; then
        log_success "Stopped: ${sid} (${name}, ${proto})" "stop"
        log_session "${sid}" "INFO" "Session stopped successfully"
    else
        log_warning "Session ${sid} (${name}) may not be fully stopped - manual verification recommended" "stop"
        log_session "${sid}" "WARNING" "Session stop may be incomplete"
    fi

    return 0
}

# Function: _kill_by_port
# Description: Last-resort function to kill socat processes listening on
#              a specific port and protocol. Uses ss or lsof to find PIDs
#              bound to the port. Only targets socat processes to avoid
#              killing unrelated services. Protocol-aware: only queries
#              the specified protocol (TCP or UDP), not both.
# Parameters:
#   $1 - Port number
#   $2 - Protocol (tcp4, udp4, etc.) - determines which ss flag to use
_kill_by_port() {
    local port="${1:?Port required}"
    local proto="${2:-tcp4}"

    # Determine ss flag based on protocol
    local ss_flag="-tlnp"
    if [[ "${proto}" == *"udp"* ]]; then
        ss_flag="-ulnp"
    fi

    # Try ss first to find PIDs on this port for this protocol only
    if command -v ss &>/dev/null; then
        local pids
        pids="$(ss ${ss_flag} 2>/dev/null | grep ":${port} " | \
                grep -oP 'pid=\K[0-9]+' | sort -u || true)"

        if [[ -n "${pids}" ]]; then
            while IFS= read -r p; do
                [[ -z "${p}" ]] && continue
                # Safety check: only kill socat processes
                local proc_name
                proc_name="$(ps -o comm= -p "${p}" 2>/dev/null || true)"
                if [[ "${proc_name}" == "socat" ]]; then
                    log_debug "Killing socat PID ${p} on ${proto}:${port}" "stop"
                    kill -KILL "${p}" 2>/dev/null || true
                else
                    log_debug "Skipping non-socat PID ${p} (${proc_name}) on ${proto}:${port}" "stop"
                fi
            done <<< "${pids}"
        fi
    fi

    # Try lsof as fallback (lsof is not protocol-scoped, so verify manually)
    if command -v lsof &>/dev/null; then
        local lsof_proto_flag=""
        if [[ "${proto}" == *"tcp"* ]]; then
            lsof_proto_flag="-iTCP"
        elif [[ "${proto}" == *"udp"* ]]; then
            lsof_proto_flag="-iUDP"
        fi

        local lsof_pids
        lsof_pids="$(lsof ${lsof_proto_flag} -ti ":${port}" 2>/dev/null || true)"
        if [[ -n "${lsof_pids}" ]]; then
            while IFS= read -r p; do
                [[ -z "${p}" ]] && continue
                local proc_name
                proc_name="$(ps -o comm= -p "${p}" 2>/dev/null || true)"
                if [[ "${proc_name}" == "socat" ]]; then
                    log_debug "Killing socat PID ${p} on ${proto}:${port} (via lsof)" "stop"
                    kill -KILL "${p}" 2>/dev/null || true
                fi
            done <<< "${lsof_pids}"
        fi
    fi
}

# Function: _cleanup_orphaned_socat
# Description: Find socat processes that are not tracked by any session file
#              and report them. Does NOT auto-kill to prevent collateral damage
#              to socat processes managed by other tools or users. Provides
#              commands for manual cleanup.
_cleanup_orphaned_socat() {
    # Collect all PIDs from session files
    local -A tracked_pids=()
    for sf in "${SESSION_DIR}"/*.session; do
        [[ ! -f "${sf}" ]] && continue
        local p
        p="$(session_read_field "${sf}" "PID")"
        [[ -n "${p}" ]] && tracked_pids[${p}]=1
    done

    # Find all running socat processes
    local socat_pids
    socat_pids="$(pgrep -x socat 2>/dev/null || true)"

    if [[ -z "${socat_pids}" ]]; then
        return 0
    fi

    local orphan_count=0
    while IFS= read -r p; do
        [[ -z "${p}" ]] && continue
        if [[ -z "${tracked_pids[${p}]+x}" ]]; then
            ((orphan_count++)) || true
            if (( orphan_count == 1 )); then
                echo "" >&2
                print_section "Orphaned socat Processes (not tracked)"
            fi
            local proc_info
            proc_info="$(ps -o pid,ppid,start,args -p "${p}" 2>/dev/null | tail -1 || true)"
            echo "    ${proc_info}" >&2
        fi
    done <<< "${socat_pids}"

    if (( orphan_count > 0 )); then
        log_warning "${orphan_count} orphaned socat process(es) found (not managed by this tool)"
        log_info "To kill manually: kill <PID> or kill -9 <PID>"
    fi
}

#======================================================================
# SIGNAL HANDLING / CLEANUP
# Ensures graceful shutdown when interrupted (Ctrl+C, SIGTERM, etc.)
# Only affects child processes of THIS script invocation.
# setsid-launched sessions survive script exit by design.
#======================================================================

# Function: cleanup_handler
# Description: Trap handler for graceful shutdown. Stops all child
#              processes of THIS script invocation only. Sessions
#              launched via setsid are unaffected (they survive in
#              their own process groups).
# Parameters:
#   $1 - Signal name (set by trap)
cleanup_handler() {
    local sig="${1:-UNKNOWN}"
    echo "" >&2
    log_warning "Caught signal ${sig} - shutting down..." "signal"

    # Kill all child processes of THIS script invocation only
    local children
    children=$(jobs -pr 2>/dev/null || true)
    if [[ -n "${children}" ]]; then
        log_info "Terminating child processes: ${children// /, }..." "signal"
        echo "${children}" | xargs kill -TERM 2>/dev/null || true
        sleep 0.5
        echo "${children}" | xargs kill -KILL 2>/dev/null || true
    fi

    log_info "Cleanup complete. Log: ${MASTER_LOG}" "signal"
    exit 0
}

# Register signal traps for clean shutdown
trap 'cleanup_handler INT' INT
trap 'cleanup_handler TERM' TERM
trap 'cleanup_handler HUP' HUP

#======================================================================
# DEPENDENCY CHECK
# Verify that socat is installed before attempting any operations
#======================================================================

# Function: check_socat
# Description: Verify socat is available in PATH and provide install
#              guidance if missing. Called before all operational modes
#              (listen, batch, forward, tunnel, redirect) but skipped
#              for status and stop modes which only need session files.
check_socat() {
    if ! command -v socat &>/dev/null; then
        log_critical "socat is not installed or not in PATH"
        echo "" >&2
        echo -e "  ${CLR_BOLD}Install socat:${CLR_RESET}" >&2
        echo -e "    ${CLR_CYAN}sudo apt-get update && sudo apt-get install -y socat${CLR_RESET}" >&2
        echo -e "    ${CLR_CYAN}# or: sudo yum install -y socat${CLR_RESET}" >&2
        echo -e "    ${CLR_CYAN}# or: sudo pacman -S socat${CLR_RESET}" >&2
        echo "" >&2
        exit 1
    fi

    log_debug "socat found: $(command -v socat) ($(socat -V 2>/dev/null | head -2 | tail -1 | xargs))" "deps"
}

#======================================================================
# HELP SYSTEM
# Per-mode help documentation accessible via -h/--help
# Each mode provides usage synopsis, options, and examples
#======================================================================

show_main_help() {
    cat << 'HELPEOF'
NAME
    socat_manager.sh - Comprehensive socat network operations manager

SYNOPSIS
    socat_manager.sh <MODE> [OPTIONS]

MODES
    listen      Start a single TCP/UDP listener on a port
    batch       Start multiple listeners (port list, range, or config)
    forward     Forward local port to remote host:port (bidirectional)
    tunnel      Create encrypted (TLS/SSL) tunnel via socat + OpenSSL
    redirect    Redirect/proxy traffic with optional capture
    status      Display all active managed sessions
    stop        Stop sessions (by ID, name, port, PID, or all)

GLOBAL OPTIONS
    --proto <PROTOCOL>   Select protocol: tcp, tcp4, tcp6, udp, udp4, udp6
    --dual-stack         Launch both TCP and UDP sessions simultaneously
    --capture            Enable traffic capture (hex dump) for any mode
    -v, --verbose        Enable debug-level console output
    -h, --help           Show help (context-sensitive per mode)

EXAMPLES
    # Start a TCP listener on port 8080
    bash socat_manager.sh listen --port 8080

    # Start a UDP-only listener
    bash socat_manager.sh listen --port 5353 --proto udp4

    # Listener on both TCP and UDP
    bash socat_manager.sh listen --port 8080 --dual-stack

    # Batch listeners on common ports (requires root for <1024)
    sudo bash socat_manager.sh batch --ports "21,22,23,25,80,443"

    # Batch from a port range with dual-stack
    bash socat_manager.sh batch --range 8000-8010 --dual-stack

    # Forward local:8080 to 192.168.1.10:80
    bash socat_manager.sh forward --lport 8080 --rhost 192.168.1.10 --rport 80

    # Forward UDP-only
    bash socat_manager.sh forward --lport 5353 --rhost 10.0.0.1 --rport 53 --proto udp4

    # Encrypted tunnel: TLS:4443 → 10.0.0.5:22
    bash socat_manager.sh tunnel --port 4443 --rhost 10.0.0.5 --rport 22

    # Redirect with traffic capture
    bash socat_manager.sh redirect --lport 8443 --rhost example.com --rport 443 --capture

    # Forward with traffic capture
    bash socat_manager.sh forward --lport 8080 --rhost 192.168.1.10 --rport 80 --capture

    # Listener with traffic capture
    bash socat_manager.sh listen --port 8080 --capture

    # Redirect UDP-only (e.g., DNS proxy)
    bash socat_manager.sh redirect --lport 5353 --rhost 8.8.8.8 --rport 53 --proto udp4

    # Redirect both TCP and UDP with capture
    bash socat_manager.sh redirect --lport 8443 --rhost example.com --rport 443 --dual-stack --capture

    # Check all session status
    bash socat_manager.sh status

    # Check specific session (by ID, name, or port)
    bash socat_manager.sh status a1b2c3d4
    bash socat_manager.sh status redir-tcp4-8443-example.com-443
    bash socat_manager.sh status 8443

    # Stop specific session by ID
    bash socat_manager.sh stop a1b2c3d4

    # Stop everything
    bash socat_manager.sh stop --all

SESSION MANAGEMENT
    Each socat process is assigned a unique 8-character hex Session ID.
    Sessions are tracked in sessions/ via .session metadata files.
    Each session records: Session ID, PID, PGID, mode, protocol, ports,
    full socat command, start time, and correlation ID.

    Processes are launched in isolated process groups (via setsid) with
    PID-file handoff for reliable cross-invocation tracking and stop.
    The script returns to the prompt immediately after launching sessions.

PROTOCOL SELECTION
    --proto <PROTOCOL>   Select a single protocol (tcp4, tcp6, udp4, udp6).
                         Default: tcp4. Available on listen, batch, forward,
                         redirect modes. Tunnel mode is TLS/TCP-only.

    --dual-stack         Launch sessions on BOTH TCP and UDP simultaneously.
                         Each protocol gets its own session ID for independent
                         management. Stop operations are protocol-aware: stopping
                         a TCP session does NOT affect a UDP session on the same
                         port, and vice versa.

RELIABILITY
    --watchdog flag enables auto-restart with exponential backoff.
    Max 10 restarts before giving up. Backoff: 1s, 2s, 4s... 60s cap.

LOGGING
    Master execution log:  logs/socat_manager-<timestamp>.log
    Per-listener data:     logs/listener-<proto>-<port>.log
    Session-specific:      logs/session-<sid>-<timestamp>.log
    Session errors:        logs/session-<sid>-error.log
    Traffic capture:       logs/capture-<proto>-<ports>-<timestamp>.log

DEPENDENCIES
    Required:     socat
    Optional:     openssl (tunnel mode), ss/netstat (status)
    Install:      sudo apt-get install -y socat openssl

VERSION
    2.3.0
HELPEOF
}

show_listen_help() {
    cat << 'HELPEOF'
NAME
    socat_manager.sh listen - Start a single network listener

SYNOPSIS
    socat_manager.sh listen --port <PORT> [OPTIONS]

DESCRIPTION
    Start a single TCP or UDP listener that captures incoming data
    to a log file. The listener forks per connection for concurrent
    client handling. Use --proto to select UDP or a specific address
    family, and --dual-stack to listen on both TCP and UDP.

OPTIONS
    -p, --port <PORT>        Port number to listen on (required)
    --proto <PROTOCOL>       Protocol: tcp, tcp4, tcp6, udp, udp4, udp6
                             (default: tcp4)
    --dual-stack             Also start listener on alternate protocol
                             (e.g., tcp4 primary → also starts udp4)
    --bind <ADDRESS>         Bind to specific IP address
    --name <n>            Custom session name
    --logfile <PATH>         Custom log file for captured data
    --capture                Enable traffic capture (verbose hex dump)
    --watchdog               Enable auto-restart on crash
    --socat-opts <OPTS>      Additional socat address options
    -v, --verbose            Debug output
    -h, --help               Show this help

EXAMPLES
    bash socat_manager.sh listen --port 8080
    bash socat_manager.sh listen --port 5353 --proto udp4
    bash socat_manager.sh listen --port 8080 --dual-stack
    bash socat_manager.sh listen --port 8080 --capture
    bash socat_manager.sh listen --port 4443 --proto tcp6
    bash socat_manager.sh listen --port 80 --watchdog --bind 0.0.0.0
HELPEOF
}

show_batch_help() {
    cat << 'HELPEOF'
NAME
    socat_manager.sh batch - Start multiple listeners

SYNOPSIS
    socat_manager.sh batch --ports <LIST> | --range <START-END> | --config <FILE>

DESCRIPTION
    Start listeners on multiple ports simultaneously. Accepts port lists,
    ranges, or config files. Each port gets an independent session with
    a unique session ID. --dual-stack launches both TCP and UDP per port.

OPTIONS
    --ports <LIST>           Comma-separated port list (e.g., "21,22,80,443")
    --range <START-END>      Port range (e.g., "8000-8010")
    --config <FILE>          Config file (one port per line, # comments)
    --proto <PROTOCOL>       Protocol for all listeners (default: tcp4)
    --dual-stack             Start both TCP and UDP per port
    --capture                Enable traffic capture (verbose hex dump)
    --watchdog               Enable auto-restart for all listeners
    -v, --verbose            Debug output
    -h, --help               Show this help

EXAMPLES
    sudo bash socat_manager.sh batch --ports "21,22,23,25,80,443,445"
    bash socat_manager.sh batch --ports "80,443" --capture
    bash socat_manager.sh batch --range 8000-8010 --dual-stack
    bash socat_manager.sh batch --range 8000-8005 --proto udp4
    bash socat_manager.sh batch --config ./ports.conf --watchdog
HELPEOF
}

show_forward_help() {
    cat << 'HELPEOF'
NAME
    socat_manager.sh forward - Forward connections to a remote target

SYNOPSIS
    socat_manager.sh forward --lport <PORT> --rhost <HOST> --rport <PORT>

DESCRIPTION
    Create a bidirectional port forwarder. Local connections are proxied
    to a remote target. Use --proto to select UDP or a specific address
    family, and --dual-stack to forward both TCP and UDP.

OPTIONS
    --lport <PORT>           Local port to listen on (required)
    --rhost <HOST>           Remote host to forward to (required)
    --rport <PORT>           Remote port to forward to (required)
    --proto <PROTOCOL>       Listen protocol (default: tcp4)
    --remote-proto <PROTO>   Remote protocol (default: matches --proto)
    --dual-stack             Also start forwarder on alternate protocol
    --capture                Enable traffic capture (verbose hex dump)
    --logfile <PATH>         Custom capture log file
    --name <n>            Custom session name
    --watchdog               Enable auto-restart
    -v, --verbose            Debug output
    -h, --help               Show this help

EXAMPLES
    bash socat_manager.sh forward --lport 8080 --rhost 192.168.1.10 --rport 80
    bash socat_manager.sh forward --lport 5353 --rhost 10.0.0.1 --rport 53 --proto udp4
    bash socat_manager.sh forward --lport 8080 --rhost 192.168.1.10 --rport 80 --dual-stack
    bash socat_manager.sh forward --lport 5433 --rhost db.internal --rport 5432 --watchdog
HELPEOF
}

show_tunnel_help() {
    cat << 'HELPEOF'
NAME
    socat_manager.sh tunnel - Create an encrypted TLS tunnel

SYNOPSIS
    socat_manager.sh tunnel --port <PORT> --rhost <HOST> --rport <PORT>

DESCRIPTION
    Accepts TLS/SSL connections on the local port and forwards
    plaintext traffic to the remote target. Auto-generates a
    self-signed certificate if --cert/--key are not provided.
    TLS tunnels are TCP-only. --dual-stack adds a plaintext UDP
    forwarder on the same port (with a warning that UDP is unencrypted).

OPTIONS
    -p, --port <PORT>        Local TLS listen port (required)
    --rhost <HOST>           Remote target host (required)
    --rport <PORT>           Remote target port (required)
    --cert <PATH>            Path to PEM certificate file
    --key <PATH>             Path to PEM private key file
    --cn <CN>                Common Name for self-signed cert
    --dual-stack             Also start plaintext UDP forwarder on same port
    --proto <PROTOCOL>       Validate protocol (tcp/tcp4 accepted; udp rejected
                             with guidance to use forward mode instead)
    --capture                Enable traffic capture (verbose hex dump of
                             decrypted traffic between TLS endpoint and target)
    --logfile <PATH>         Custom capture log file
    --name <n>            Custom session name
    --watchdog               Enable auto-restart
    -v, --verbose            Debug output
    -h, --help               Show this help

EXAMPLES
    bash socat_manager.sh tunnel --port 4443 --rhost 10.0.0.5 --rport 22
    bash socat_manager.sh tunnel --port 4443 --rhost 10.0.0.5 --rport 22 --dual-stack
    bash socat_manager.sh tunnel --port 4443 --rhost 10.0.0.5 --rport 22 --capture
    bash socat_manager.sh tunnel --port 8443 --rhost db.internal --rport 5432 \
        --cert /etc/ssl/cert.pem --key /etc/ssl/key.pem
HELPEOF
}

show_redirect_help() {
    cat << 'HELPEOF'
NAME
    socat_manager.sh redirect - Redirect/proxy traffic

SYNOPSIS
    socat_manager.sh redirect --lport <PORT> --rhost <HOST> --rport <PORT>

DESCRIPTION
    Redirect traffic transparently between a local port and a remote
    target. Optionally captures bidirectional traffic hex dumps for
    inspection. Use --proto to select UDP or a specific address family,
    and --dual-stack to redirect both TCP and UDP.

OPTIONS
    --lport <PORT>           Local listen port (required)
    --rhost <HOST>           Remote target host (required)
    --rport <PORT>           Remote target port (required)
    --proto <PROTOCOL>       Protocol: tcp, tcp4, tcp6, udp, udp4, udp6
                             (default: tcp4)
    --dual-stack             Also start redirector on alternate protocol
    --capture                Enable traffic capture (hex dump)
    --logfile <PATH>         Custom capture log file
    --name <n>            Custom session name
    --watchdog               Enable auto-restart
    -v, --verbose            Debug output
    -h, --help               Show this help

EXAMPLES
    bash socat_manager.sh redirect --lport 8443 --rhost example.com --rport 443
    bash socat_manager.sh redirect --lport 5353 --rhost 8.8.8.8 --rport 53 --proto udp4
    bash socat_manager.sh redirect --lport 8443 --rhost example.com --rport 443 --dual-stack
    bash socat_manager.sh redirect --lport 3307 --rhost db.local --rport 3306 --capture
    bash socat_manager.sh redirect --lport 8443 --rhost example.com --rport 443 --dual-stack --capture
HELPEOF
}

show_stop_help() {
    cat << 'HELPEOF'
NAME
    socat_manager.sh stop - Stop managed sessions

SYNOPSIS
    socat_manager.sh stop <SESSION_ID>
    socat_manager.sh stop --all | --name <n> | --port <PORT> | --pid <PID>

DESCRIPTION
    Stop one or more managed socat sessions. The first positional
    argument is treated as a session ID. Alternatively, use named
    flags to stop by other selectors.

    The stop process terminates the entire process group (PGID),
    verifies the port is freed, and removes the session file only
    after confirming all processes are dead.

    Stop operations are protocol-aware: stopping a TCP session on
    a shared port does NOT affect a UDP session on the same port,
    and vice versa. This is critical for dual-stack configurations
    where TCP and UDP run independently on the same port.

OPTIONS
    <SESSION_ID>             Stop session by its 8-char hex ID (positional)
    --all                    Stop all managed sessions
    --name <n>            Stop session by name
    --port <PORT>            Stop all sessions on a port (all protocols)
    --pid <PID>              Stop session by PID
    -v, --verbose            Debug output
    -h, --help               Show this help

EXAMPLES
    bash socat_manager.sh stop a1b2c3d4
    bash socat_manager.sh stop --all
    bash socat_manager.sh stop --name redir-tcp4-8443-example.com-443
    bash socat_manager.sh stop --port 8443
HELPEOF
}

show_status_help() {
    cat << 'HELPEOF'
NAME
    socat_manager.sh status - Show active session status

SYNOPSIS
    socat_manager.sh status [SESSION_ID | SESSION_NAME | PORT] [OPTIONS]

DESCRIPTION
    Without arguments, displays a summary table of all managed sessions.
    With a positional argument, shows detailed information for the
    matching session including process tree, port status, and logs.

    The argument is matched against session IDs (8-char hex), session
    names (e.g., redir-tcp4-8443-example.com-443), and port numbers.
    Port lookups may return multiple sessions when dual-stack is active.

OPTIONS
    <SESSION_ID>             Show detail for a specific session (positional)
    --cleanup                Remove dead session files
    -v, --verbose            Show system-level listener info
    -h, --help               Show this help

EXAMPLES
    bash socat_manager.sh status
    bash socat_manager.sh status a1b2c3d4
    bash socat_manager.sh status redir-tcp4-8443-example.com-443
    bash socat_manager.sh status 8443
    bash socat_manager.sh status --cleanup
    bash socat_manager.sh status --verbose
HELPEOF
}

#======================================================================
# BACKWARD COMPATIBILITY
# Migrate v1 (.pid) and v2.0 session files on startup.
# Detects legacy session files and converts them to v2.2 format.
# Dead legacy sessions are cleaned up automatically.
#======================================================================

# Function: migrate_legacy_sessions
# Description: Detect and migrate v1 .pid session files to v2.2 .session
#              format. Preserves original metadata and adds new v2.2 fields
#              where possible. Dead sessions are removed automatically.
migrate_legacy_sessions() {
    local migrated=0

    for old_file in "${SESSION_DIR}"/*.pid; do
        [[ ! -f "${old_file}" ]] && continue

        local old_name pid mode proto lport rhost rport

        old_name="$(basename "${old_file}" .pid)"
        pid=$(grep '^PID=' "${old_file}" 2>/dev/null | cut -d= -f2)
        mode=$(grep '^MODE=' "${old_file}" 2>/dev/null | cut -d= -f2)
        proto=$(grep '^PROTOCOL=' "${old_file}" 2>/dev/null | cut -d= -f2)
        lport=$(grep '^LOCAL_PORT=' "${old_file}" 2>/dev/null | cut -d= -f2)
        rhost=$(grep '^REMOTE_HOST=' "${old_file}" 2>/dev/null | cut -d= -f2)
        rport=$(grep '^REMOTE_PORT=' "${old_file}" 2>/dev/null | cut -d= -f2)

        # Skip if PID is not valid/alive (dead session from old version)
        if [[ -z "${pid}" ]] || ! kill -0 "${pid}" 2>/dev/null; then
            rm -f "${old_file}" 2>/dev/null
            log_debug "Removed dead legacy session: ${old_name}" "migrate"
            continue
        fi

        # Generate session ID for this legacy session
        local sid
        sid="$(generate_session_id)" || continue

        # Derive PGID from the running process
        local pgid
        pgid="$(ps -o pgid= -p "${pid}" 2>/dev/null | tr -d ' ')" || pgid="${pid}"

        # Create v2.2 session file
        session_register "${sid}" "${old_name}" "${pid}" "${pgid}" \
            "${mode:-unknown}" "${proto:-tcp4}" "${lport:-0}" "" "${rhost:-}" "${rport:-}"

        # Remove old v1 file
        rm -f "${old_file}" 2>/dev/null
        ((migrated++)) || true
        log_info "Migrated legacy session '${old_name}' → SID ${sid}" "migrate"
    done

    if (( migrated > 0 )); then
        log_info "Migrated ${migrated} legacy session(s) to v2.2 format"
    fi
}

#======================================================================
# MAIN DISPATCHER
# Routes the first positional argument (mode) to the appropriate
# handler function, passing all remaining arguments through.
#======================================================================

main() {
    # Ensure directory structure exists
    _ensure_dirs

    # Must have at least a mode argument
    if [[ $# -lt 1 ]]; then
        show_main_help
        exit 0
    fi

    local mode="${1}"
    shift  # Remove mode from argument list

    # Handle global help before mode dispatch
    case "${mode}" in
        -h|--help|help)
            show_main_help
            exit 0
            ;;
        --version)
            echo "socat_manager.sh v${SCRIPT_VERSION}"
            exit 0
            ;;
    esac

    # Initialize master log
    log_info "=== socat_manager v${SCRIPT_VERSION} started (mode: ${mode}) ===" "main"
    log_debug "PID: ${SCRIPT_PID}, User: $(whoami), PWD: $(pwd)" "main"

    # Migrate legacy session files if any exist
    migrate_legacy_sessions

    # Check for socat (required for all modes except status/stop/help)
    # Skip socat check if user is just asking for help (-h/--help in args)
    local needs_socat=true
    case "${mode}" in
        status|stop) needs_socat=false ;;
    esac
    for arg in "$@"; do
        [[ "${arg}" == "-h" || "${arg}" == "--help" ]] && needs_socat=false
    done
    [[ "${needs_socat}" == true ]] && check_socat

    # Dispatch to mode handler
    case "${mode}" in
        listen)   mode_listen "$@" ;;
        batch)    mode_batch "$@" ;;
        forward)  mode_forward "$@" ;;
        tunnel)   mode_tunnel "$@" ;;
        redirect) mode_redirect "$@" ;;
        status)   mode_status "$@" ;;
        stop)     mode_stop "$@" ;;
        *)
            log_error "Unknown mode '${mode}'"
            echo "" >&2
            echo -e "  Valid modes: listen, batch, forward, tunnel, redirect, status, stop" >&2
            echo -e "  Run '${SCRIPT_NAME} --help' for full usage." >&2
            exit 1
            ;;
    esac
}

# Entry point
# Guard allows sourcing without execution (used by test framework).
# When executed directly (./socat_manager.sh), BASH_SOURCE[0] == $0 → runs main.
# When sourced (source socat_manager.sh), BASH_SOURCE[0] != $0 → functions loaded only.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
