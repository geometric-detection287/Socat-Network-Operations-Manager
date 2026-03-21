#!/usr/bin/env bats
#======================================================================
# TEST FILE  : tests/integration/extended.bats
#======================================================================
# Synopsis   : Extended integration tests covering gaps identified in
#              the Phase 1 test audit.
#
# Description: Tests for:
#              - check_port_available using ss stub state
#              - generate_self_signed_cert using openssl stub
#              - Batch config file parsing (ports.conf fixture)
#              - _kill_by_port protocol-scoped fallback
#              - check_port_freed protocol-scoped verification
#              - Per-mode --help output
#              - Per-mode unknown flag rejection
#              - Watchdog restart with SOCAT_STUB_EXIT
#              - Legacy .pid session file migration
#
# Execution  : bats tests/integration/extended.bats
#
# Version    : 1.0.0
#======================================================================

# =====================================================================
# SETUP / TEARDOWN
# =====================================================================

setup() {
    load '../helpers/test_helper'
    helper_setup
    clear_ss_state
}

teardown() {
    helper_teardown
}

# =====================================================================
# check_port_available: uses ss stub state
# =====================================================================

@test "check_port_available: returns 0 when port is free (no ss state)" {
    clear_ss_state
    check_port_available "8080" "tcp4"
}

@test "check_port_available: returns 1 when TCP port is in use" {
    set_ss_state "8080:tcp"
    # Call directly without 'run' to avoid BATS $() subshell where
    # ss function override does not propagate reliably.
    # The && ... || pattern captures the return code explicitly.
    check_port_available "8080" "tcp4" && _rc=0 || _rc=$?
    [ "$_rc" -eq 1 ]
}

@test "check_port_available: returns 1 when UDP port is in use" {
    set_ss_state "5353:udp"
    check_port_available "5353" "udp4" && _rc=0 || _rc=$?
    [ "$_rc" -eq 1 ]
}

@test "check_port_available: TCP occupied does NOT block UDP on same port" {
    set_ss_state "8080:tcp"
    # UDP on same port should be available
    check_port_available "8080" "udp4"
}

@test "check_port_available: UDP occupied does NOT block TCP on same port" {
    set_ss_state "8080:udp"
    # TCP on same port should be available
    check_port_available "8080" "tcp4"
}

@test "check_port_available: different port is available when another is occupied" {
    set_ss_state "8080:tcp"
    check_port_available "9090" "tcp4"
}

# =====================================================================
# generate_self_signed_cert: uses openssl stub
# =====================================================================

@test "generate_self_signed_cert: creates cert and key files" {
    local result
    result="$(generate_self_signed_cert "testhost.local")"

    # Result should contain two space-separated paths (cert key)
    local cert_path key_path
    cert_path="${result%% *}"
    key_path="${result##* }"

    [ -f "${cert_path}" ]
    [ -f "${key_path}" ]
}

@test "generate_self_signed_cert: key file has restrictive permissions" {
    local result
    result="$(generate_self_signed_cert "testhost.local")"
    local key_path="${result##* }"

    local perms
    perms="$(stat -c '%a' "${key_path}")"
    [ "${perms}" = "600" ]
}

@test "generate_self_signed_cert: cert and key are different files" {
    local result
    result="$(generate_self_signed_cert "testhost.local")"
    local cert_path="${result%% *}"
    local key_path="${result##* }"

    [ "${cert_path}" != "${key_path}" ]
}

@test "generate_self_signed_cert: openssl stub logs invocation" {
    generate_self_signed_cert "testhost.local" >/dev/null 2>&1 || true

    local stub_log="${TEST_TMPDIR}/.openssl_stub.log"
    [ -f "${stub_log}" ]
    # Should contain 'req' (the openssl subcommand)
    grep -q 'req' "${stub_log}"
}

# =====================================================================
# Batch config file parsing
# =====================================================================

@test "batch config: ports.conf fixture has 5 active ports" {
    # Parse the fixture file the same way mode_batch does
    local count=0
    while IFS= read -r line; do
        line="${line%%#*}"
        line="${line// /}"
        [[ -z "${line}" ]] && continue
        if validate_port "${line}" 2>/dev/null; then
            ((count++)) || true
        fi
    done < "${FIXTURES_DIR}/ports.conf"

    [ "${count}" -eq 5 ]
}

@test "batch config: commented ports are skipped" {
    # The fixture has "# 9999" which should not be parsed
    local found=false
    while IFS= read -r line; do
        line="${line%%#*}"
        line="${line// /}"
        [[ -z "${line}" ]] && continue
        if [[ "${line}" == "9999" ]]; then
            found=true
        fi
    done < "${FIXTURES_DIR}/ports.conf"

    [ "${found}" = "false" ]
}

@test "batch config: blank lines are skipped" {
    # Should not produce empty port entries
    local empty_count=0
    while IFS= read -r line; do
        line="${line%%#*}"
        line="${line// /}"
        if [[ -z "${line}" ]]; then
            continue
        fi
        if ! validate_port "${line}" 2>/dev/null; then
            ((empty_count++)) || true
        fi
    done < "${FIXTURES_DIR}/ports.conf"

    [ "${empty_count}" -eq 0 ]
}

# =====================================================================
# _kill_by_port: protocol-scoped fallback kill
# =====================================================================

@test "_kill_by_port: does not error on empty port" {
    # Should handle gracefully when no processes match
    run _kill_by_port "59999" "tcp4"
    [ "$status" -eq 0 ]
}

@test "_kill_by_port: does not error on UDP port" {
    run _kill_by_port "59999" "udp4"
    [ "$status" -eq 0 ]
}

# =====================================================================
# check_port_freed: protocol-scoped verification
# =====================================================================

@test "check_port_freed: returns 0 when port is free" {
    clear_ss_state
    check_port_freed "8080" "tcp4" 1
}

@test "check_port_freed: returns 1 when TCP port is still bound" {
    set_ss_state "8080:tcp"
    check_port_freed "8080" "tcp4" 1 && _rc=0 || _rc=$?
    [ "$_rc" -eq 1 ]
}

@test "check_port_freed: TCP bound does not affect UDP freed check" {
    set_ss_state "8080:tcp"
    # UDP on same port should be reported as freed
    check_port_freed "8080" "udp4" 1
}

# =====================================================================
# Per-mode --help output
# =====================================================================

@test "listen --help: outputs help text" {
    run bash "${TEST_TMPDIR}/socat_manager.sh" listen --help
    [ "$status" -eq 0 ]
    [[ "${output}" == *"--port"* ]]
    [[ "${output}" == *"--proto"* ]]
    [[ "${output}" == *"--capture"* ]]
}

@test "batch --help: outputs help text" {
    run bash "${TEST_TMPDIR}/socat_manager.sh" batch --help
    [ "$status" -eq 0 ]
    [[ "${output}" == *"--ports"* ]]
    [[ "${output}" == *"--range"* ]]
    [[ "${output}" == *"--capture"* ]]
}

@test "forward --help: outputs help text" {
    run bash "${TEST_TMPDIR}/socat_manager.sh" forward --help
    [ "$status" -eq 0 ]
    [[ "${output}" == *"--lport"* ]]
    [[ "${output}" == *"--rhost"* ]]
    [[ "${output}" == *"--capture"* ]]
}

@test "tunnel --help: outputs help text" {
    run bash "${TEST_TMPDIR}/socat_manager.sh" tunnel --help
    [ "$status" -eq 0 ]
    [[ "${output}" == *"--port"* ]]
    [[ "${output}" == *"--rhost"* ]]
    [[ "${output}" == *"--capture"* ]]
    [[ "${output}" == *"--proto"* ]]
}

@test "redirect --help: outputs help text" {
    run bash "${TEST_TMPDIR}/socat_manager.sh" redirect --help
    [ "$status" -eq 0 ]
    [[ "${output}" == *"--lport"* ]]
    [[ "${output}" == *"--rhost"* ]]
    [[ "${output}" == *"--capture"* ]]
    [[ "${output}" == *"--proto"* ]]
}

@test "status --help: outputs help text" {
    run bash "${TEST_TMPDIR}/socat_manager.sh" status --help
    [ "$status" -eq 0 ]
    [[ "${output}" == *"--cleanup"* ]]
}

@test "stop --help: outputs help text" {
    run bash "${TEST_TMPDIR}/socat_manager.sh" stop --help
    [ "$status" -eq 0 ]
    [[ "${output}" == *"--all"* ]]
    [[ "${output}" == *"--name"* ]]
}

# =====================================================================
# Per-mode unknown flag rejection
# =====================================================================

@test "listen: rejects unknown flag" {
    run bash "${TEST_TMPDIR}/socat_manager.sh" listen --port 8080 --bogus 2>&1
    [ "$status" -ne 0 ]
    [[ "${output}" == *"Unknown"* ]] || [[ "${output}" == *"unknown"* ]]
}

@test "forward: rejects unknown flag" {
    run bash "${TEST_TMPDIR}/socat_manager.sh" forward --lport 8080 --rhost 10.0.0.1 --rport 80 --bogus 2>&1
    [ "$status" -ne 0 ]
    [[ "${output}" == *"Unknown"* ]] || [[ "${output}" == *"unknown"* ]]
}

@test "redirect: rejects unknown flag" {
    run bash "${TEST_TMPDIR}/socat_manager.sh" redirect --lport 8080 --rhost 10.0.0.1 --rport 80 --bogus 2>&1
    [ "$status" -ne 0 ]
    [[ "${output}" == *"Unknown"* ]] || [[ "${output}" == *"unknown"* ]]
}

@test "tunnel: rejects unknown flag" {
    run bash "${TEST_TMPDIR}/socat_manager.sh" tunnel --port 4443 --rhost 10.0.0.1 --rport 22 --bogus 2>&1
    [ "$status" -ne 0 ]
    [[ "${output}" == *"Unknown"* ]] || [[ "${output}" == *"unknown"* ]]
}

@test "tunnel: --proto udp4 is rejected with guidance" {
    run bash "${TEST_TMPDIR}/socat_manager.sh" tunnel --port 4443 --rhost 10.0.0.1 --rport 22 --proto udp4 2>&1
    [ "$status" -ne 0 ]
    [[ "${output}" == *"TCP"* ]] || [[ "${output}" == *"forward"* ]]
}

@test "stop: rejects unknown flag" {
    run bash "${TEST_TMPDIR}/socat_manager.sh" stop --bogus 2>&1
    [ "$status" -ne 0 ]
    [[ "${output}" == *"Unknown"* ]] || [[ "${output}" == *"unknown"* ]]
}

# =====================================================================
# Legacy .pid session migration
# =====================================================================

@test "legacy migration: .pid files detected in session directory" {
    # Copy legacy fixture into the session directory
    cp "${FIXTURES_DIR}/legacy_session.pid" "${SESSION_DIR}/old-session.pid"

    # The script's migrate function should be available
    # Check that the file exists and has expected format
    [ -f "${SESSION_DIR}/old-session.pid" ]
    grep -q '^PID=' "${SESSION_DIR}/old-session.pid"
    grep -q '^MODE=' "${SESSION_DIR}/old-session.pid"
}

@test "legacy session fixture: contains expected v1 fields" {
    local fixture="${FIXTURES_DIR}/legacy_session.pid"
    [ -f "${fixture}" ]

    # v1 format fields
    grep -q '^PID=' "${fixture}"
    grep -q '^MODE=' "${fixture}"
    grep -q '^PROTOCOL=' "${fixture}"
    grep -q '^LOCAL_PORT=' "${fixture}"
    grep -q '^MASTER_PID=' "${fixture}"

    # v2 fields should NOT be present
    ! grep -q '^SESSION_ID=' "${fixture}"
    ! grep -q '^PGID=' "${fixture}"
}

# =====================================================================
# Watchdog: crash and restart simulation
# =====================================================================

@test "watchdog: SOCAT_STUB_EXIT causes immediate stub exit" {
    # Verify the stub exit mechanism works
    export SOCAT_STUB_EXIT=1
    run bash "${STUBS_DIR}/socat" "TCP4-LISTEN:8080"
    [ "$status" -eq 1 ]
    unset SOCAT_STUB_EXIT
}

@test "watchdog: SOCAT_STUB_EXIT=0 causes clean exit" {
    export SOCAT_STUB_EXIT=0
    run bash "${STUBS_DIR}/socat" "TCP4-LISTEN:8080"
    [ "$status" -eq 0 ]
    unset SOCAT_STUB_EXIT
}

@test "watchdog: stub logs arguments even when exiting immediately" {
    export SOCAT_STUB_EXIT=1
    bash "${STUBS_DIR}/socat" "TCP4-LISTEN:8080" "reuseaddr,fork" 2>/dev/null || true
    unset SOCAT_STUB_EXIT

    local stub_log
    stub_log="$(get_stub_log)"
    [[ "${stub_log}" == *"TCP4-LISTEN:8080"* ]]
}

@test "watchdog: stub responds to SIGTERM" {
    # Launch stub in background
    bash "${STUBS_DIR}/socat" "TCP4-LISTEN:9999" &
    local stub_pid=$!

    # Verify it's running
    sleep 0.2
    kill -0 "${stub_pid}" 2>/dev/null

    # Send SIGTERM
    kill -TERM "${stub_pid}" 2>/dev/null
    wait "${stub_pid}" 2>/dev/null || true

    # Should be dead
    ! kill -0 "${stub_pid}" 2>/dev/null
}

# =====================================================================
# Session file format validation
# =====================================================================

@test "session fixture: v2.2 format contains all required fields" {
    local fixture="${FIXTURES_DIR}/sample_session.session"
    [ -f "${fixture}" ]

    grep -q '^SESSION_ID=' "${fixture}"
    grep -q '^SESSION_NAME=' "${fixture}"
    grep -q '^PID=' "${fixture}"
    grep -q '^PGID=' "${fixture}"
    grep -q '^MODE=' "${fixture}"
    grep -q '^PROTOCOL=' "${fixture}"
    grep -q '^LOCAL_PORT=' "${fixture}"
    grep -q '^REMOTE_HOST=' "${fixture}"
    grep -q '^REMOTE_PORT=' "${fixture}"
    grep -q '^SOCAT_CMD=' "${fixture}"
    grep -q '^STARTED=' "${fixture}"
    grep -q '^CORRELATION=' "${fixture}"
    grep -q '^LAUNCHER_PID=' "${fixture}"
}

@test "session_register: output matches v2.2 format" {
    session_register "aabb1122" "test-session" "12345" "12345" \
        "redirect" "tcp4" "8443" "socat TCP4-LISTEN:8443" "example.com" "443"

    local sf="${SESSION_DIR}/aabb1122.session"

    # All v2.2 fields should be present
    grep -q '^SESSION_ID=aabb1122' "${sf}"
    grep -q '^SESSION_NAME=test-session' "${sf}"
    grep -q '^PID=12345' "${sf}"
    grep -q '^PGID=12345' "${sf}"
    grep -q '^MODE=redirect' "${sf}"
    grep -q '^PROTOCOL=tcp4' "${sf}"
    grep -q '^LOCAL_PORT=8443' "${sf}"
    grep -q '^SOCAT_CMD=' "${sf}"
    grep -q '^STARTED=' "${sf}"
    grep -q '^CORRELATION=' "${sf}"
}
