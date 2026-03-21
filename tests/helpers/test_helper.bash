#!/usr/bin/env bash
#======================================================================
# FILE       : tests/helpers/test_helper.bash
#======================================================================
# Synopsis   : Shared setup/teardown helper for all BATS test files.
#
# Description: Provides the test infrastructure that every .bats file
#              loads via `load '../helpers/test_helper'`. Handles:
#
#              1. Per-test temporary directory creation and cleanup
#              2. Symlink-based script sourcing that redirects all
#                 runtime paths (SESSION_DIR, LOG_DIR, etc.) into the
#                 temp directory for full isolation
#              3. Stub executable injection (socat, ss, openssl) via
#                 PATH prepending so tests run without real network
#              4. Utility functions for common test operations
#              5. Process cleanup to prevent leaked background jobs
#
# Usage      : In any .bats file, add at the top:
#                  setup() {
#                      load '../helpers/test_helper'
#                      helper_setup
#                  }
#                  teardown() {
#                      helper_teardown
#                  }
#
# Notes      : - BATS runs each @test in its own subshell, so readonly
#                variables from one test do not conflict with the next
#              - The script's source guard (`[[ BASH_SOURCE == $0 ]]`)
#                prevents main() from executing when sourced
#              - Stubs are prepended to PATH so they shadow real binaries
#              - All temp directories are cleaned up in teardown, even
#                if the test fails
#
# Version    : 1.0.0
#======================================================================

# =====================================================================
# RESOLVE PROJECT ROOT
# Find the project root directory relative to this helper file.
# This works regardless of where BATS is invoked from.
# =====================================================================

# This helper lives at tests/helpers/test_helper.bash
# Project root is two directories up
_HELPER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${_HELPER_DIR}/../.." && pwd)"

# Path to the real script in the project root
SCRIPT_PATH="${PROJECT_ROOT}/socat_manager.sh"

# Path to the stubs directory
STUBS_DIR="${PROJECT_ROOT}/tests/stubs"
export STUBS_DIR

# Path to the fixtures directory
FIXTURES_DIR="${PROJECT_ROOT}/tests/fixtures"

# =====================================================================
# HELPER_SETUP
# Called from setup() in each .bats file. Creates an isolated test
# environment with its own temp directory, runtime paths, and stubs.
#
# Architecture:
#   1. Create temp directory for this test
#   2. Symlink the script into the temp directory
#      → SCRIPT_DIR resolves to temp dir when sourced
#      → LOG_DIR, SESSION_DIR, etc. automatically point into temp
#   3. Prepend stubs directory to PATH
#      → Mock socat/ss/openssl shadow real binaries
#   4. Source the script (functions loaded, main() skipped via guard)
#   5. Call _ensure_dirs to create runtime directories in temp
# =====================================================================

helper_setup() {
    # Create a unique temp directory for this test.
    # BATS_TEST_TMPDIR is available in BATS 1.5+.
    # Fall back to mktemp for older BATS versions.
    if [[ -n "${BATS_TEST_TMPDIR:-}" ]]; then
        TEST_TMPDIR="${BATS_TEST_TMPDIR}"
    else
        TEST_TMPDIR="$(mktemp -d /tmp/socat-manager-test-XXXXXX)"
    fi

    # Export for use in stubs (stubs need to know where to write state files)
    export TEST_TMPDIR

    # Symlink the script into the temp directory.
    # When sourced from here, BASH_SOURCE[0] resolves to the temp path,
    # so SCRIPT_DIR (derived from dirname of BASH_SOURCE[0]) points to
    # the temp directory. All runtime paths (LOG_DIR, SESSION_DIR, etc.)
    # are derived from SCRIPT_DIR, so they automatically isolate into temp.
    ln -sf "${SCRIPT_PATH}" "${TEST_TMPDIR}/socat_manager.sh"

    # Prepend stubs directory to PATH so mock binaries are found first.
    # This shadows real socat, ss, and openssl with test stubs.
    export PATH="${STUBS_DIR}:${PATH}"

    # Clear bash's command hash table. Bash caches the full path of
    # previously resolved commands. On CI runners, ss/socat/openssl may
    # already be cached at /usr/sbin/ss etc. from the system environment.
    # Without this, bash reuses the cached real binary path even though
    # the stubs directory is now first in PATH.
    hash -r

    # Disable set -e for test context (BATS handles assertions differently).
    # The script sets `set -euo pipefail` at the top level. When sourced
    # in BATS, this would cause tests to fail on the first non-zero exit
    # instead of letting BATS handle assertion logic.
    set +e
    set +u
    set +o pipefail

    # Source the script from the symlink location.
    # The source guard prevents main() from executing.
    # All functions, constants, and variables are now available.
    # shellcheck disable=SC1090
    source "${TEST_TMPDIR}/socat_manager.sh"

    # Override external commands with bash functions that delegate to stubs.
    #
    # WHY: PATH prepending + hash -r is insufficient on CI runners.
    # GitHub Actions runners have real ss/socat/openssl installed at
    # /usr/sbin/ or /usr/bin/. Despite stubs being first on PATH,
    # bash may still resolve to the real binary through mechanisms
    # that survive hash -r (e.g., BATS subshell inheritance, cached
    # lookups in command substitutions, or OS-level command caching).
    #
    # SOLUTION: Bash function lookup has STRICTLY HIGHER priority than
    # PATH-based external command lookup. By defining ss/socat/openssl
    # as functions, every call within the test shell — including calls
    # from sourced script functions like check_port_available — will
    # route to the stub scripts. This cannot be bypassed.
    #
    # NOTE: export -f exports the functions to child bash processes
    # (e.g., setsid bash -c '...'). For exec'd commands (exec socat),
    # bash falls back to PATH lookup, which still finds the stub.
    # shellcheck disable=SC2032
    ss() { "${STUBS_DIR}/ss" "$@"; }
    export -f ss

    socat() { "${STUBS_DIR}/socat" "$@"; }
    export -f socat

    openssl() { "${STUBS_DIR}/openssl" "$@"; }
    export -f openssl

    # Create runtime directories in the temp location.
    # _ensure_dirs is defined in the script and creates sessions/, logs/,
    # conf/, and certs/ relative to SCRIPT_DIR (which is now temp).
    _ensure_dirs
}

# =====================================================================
# HELPER_TEARDOWN
# Called from teardown() in each .bats file. Cleans up all test
# artifacts: temp directories, background processes, and state files.
# Runs even if the test fails (BATS guarantees teardown execution).
# =====================================================================

helper_teardown() {
    # Kill any background processes spawned during this test.
    local children
    children="$(jobs -pr 2>/dev/null || true)"
    if [[ -n "${children}" ]]; then
        echo "${children}" | xargs kill -KILL 2>/dev/null || true
    fi

    # Kill all setsid-spawned processes tracked in session files.
    # These are in separate process groups and not visible to `jobs`.
    if [[ -d "${TEST_TMPDIR:-}/sessions" ]]; then
        local _sf_list
        _sf_list="$(ls "${TEST_TMPDIR}"/sessions/*.session 2>/dev/null || true)"
        if [[ -n "${_sf_list}" ]]; then
            local sf pid
            for sf in ${_sf_list}; do
                [[ ! -f "${sf}" ]] && continue
                pid="$(grep '^PID=' "${sf}" 2>/dev/null | cut -d= -f2)"
                if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
                    # Kill the process group (setsid: PGID == PID)
                    kill -KILL "-${pid}" 2>/dev/null || true
                    kill -KILL "${pid}" 2>/dev/null || true
                fi
            done
        fi
    fi

    # Final sweep: kill any remaining socat stubs that wrote to our log
    if [[ -f "${TEST_TMPDIR:-}/.socat_stub.log" ]]; then
        local stub_pids
        stub_pids="$(grep -oP 'PID=\K[0-9]+' "${TEST_TMPDIR}/.socat_stub.log" 2>/dev/null || true)"
        if [[ -n "${stub_pids}" ]]; then
            local p
            for p in ${stub_pids}; do
                kill -KILL "-${p}" 2>/dev/null || true
                kill -KILL "${p}" 2>/dev/null || true
            done
        fi
    fi

    # Brief wait for processes to die
    sleep 0.1 2>/dev/null || true

    # Remove temp directory and all contents.
    if [[ -n "${TEST_TMPDIR:-}" ]] && [[ "${TEST_TMPDIR}" == /tmp/* ]]; then
        rm -rf "${TEST_TMPDIR}" 2>/dev/null || true
    fi
}

# =====================================================================
# UTILITY FUNCTIONS
# Common operations used across multiple test files.
# =====================================================================

# Function: create_mock_session
# Description: Create a mock session file in the test's SESSION_DIR
#              with specified metadata. Useful for testing session
#              lookup, status, and stop operations without launching
#              a real (or stubbed) socat process.
# Parameters:
#   $1 - Session ID (8-char hex)
#   $2 - Session name
#   $3 - PID (use a real PID like $$ or a fake one)
#   $4 - Mode (listen, forward, redirect, tunnel, batch-listen)
#   $5 - Protocol (tcp4, udp4, etc.)
#   $6 - Local port
#   $7 - Optional: remote host
#   $8 - Optional: remote port
create_mock_session() {
    local sid="${1:?Session ID required}"
    local name="${2:?Session name required}"
    local pid="${3:?PID required}"
    local mode="${4:-redirect}"
    local proto="${5:-tcp4}"
    local lport="${6:-8080}"
    local rhost="${7:-}"
    local rport="${8:-}"

    local session_file="${SESSION_DIR}/${sid}.session"

    cat > "${session_file}" << EOF
# socat_manager session file v2.2 (test fixture)
SESSION_ID=${sid}
SESSION_NAME=${name}
PID=${pid}
PGID=${pid}
MODE=${mode}
PROTOCOL=${proto}
LOCAL_PORT=${lport}
REMOTE_HOST=${rhost}
REMOTE_PORT=${rport}
SOCAT_CMD=socat TCP4-LISTEN:${lport},reuseaddr,fork TCP4:${rhost}:${rport}
STARTED=$(date '+%Y-%m-%dT%H:%M:%S')
CORRELATION=testcorr
LAUNCHER_PID=$$
EOF

    chmod 600 "${session_file}" 2>/dev/null || true
}

# Function: count_session_files
# Description: Count the number of .session files in SESSION_DIR.
#              Useful for verifying that stop/cleanup operations
#              remove the correct number of sessions.
# Outputs: Integer count on stdout
count_session_files() {
    local count=0
    for sf in "${SESSION_DIR}"/*.session; do
        [[ -f "${sf}" ]] && ((count++)) || true
    done
    echo "${count}"
}

# Function: get_stub_log
# Description: Read the socat stub's argument log. The stub writes
#              each invocation's arguments to a log file in TEST_TMPDIR
#              so tests can verify the correct command was built.
# Outputs: Contents of the stub log, or empty if no invocations
get_stub_log() {
    local stub_log="${TEST_TMPDIR}/.socat_stub.log"
    if [[ -f "${stub_log}" ]]; then
        cat "${stub_log}"
    fi
}

# Function: set_ss_state
# Description: Configure the ss stub to report specific ports as
#              listening. The stub reads this state file to determine
#              its output. Format: one entry per line as "port:proto"
#              (e.g., "8080:tcp" or "5353:udp").
# Parameters:
#   $@ - Port:proto entries (e.g., "8080:tcp" "5353:udp")
set_ss_state() {
    local state_file="${TEST_TMPDIR}/.ss_state"
    : > "${state_file}"  # Truncate
    for entry in "$@"; do
        echo "${entry}" >> "${state_file}"
    done
}

# Function: clear_ss_state
# Description: Clear all ss stub state so all ports appear available.
clear_ss_state() {
    rm -f "${TEST_TMPDIR}/.ss_state" 2>/dev/null || true
}

# Function: wait_for_session_file
# Description: Wait for a session file to appear in SESSION_DIR.
#              Used in integration tests after launch_socat_session
#              which runs asynchronously via setsid.
# Parameters:
#   $1 - Session ID to wait for
#   $2 - Max wait in seconds (default: 3)
# Returns: 0 if found, 1 if timeout
wait_for_session_file() {
    local sid="${1:?Session ID required}"
    local max_wait="${2:-3}"
    local waited=0
    while [[ ! -f "${SESSION_DIR}/${sid}.session" ]] && (( waited < max_wait * 10 )); do
        sleep 0.1
        ((waited++)) || true
    done
    [[ -f "${SESSION_DIR}/${sid}.session" ]]
}
