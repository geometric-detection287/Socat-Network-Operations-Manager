#!/usr/bin/env bats
#======================================================================
# TEST FILE  : tests/integration/lifecycle.bats
#======================================================================
# Synopsis   : Integration tests for the full session lifecycle:
#              launch → status → stop.
#
# Description: Tests the launch_socat_session function with the mock
#              socat stub, verifying PID-file handoff, session file
#              creation, LAUNCH_SID global variable, non-blocking
#              behavior, process group isolation, and clean shutdown.
#              Also tests --version, --help, and error handling.
#
# Execution  : bats tests/integration/lifecycle.bats
#
# Notes      : - Uses stubbed socat (tests/stubs/socat) — no real
#                network operations occur
#              - Uses stubbed ss (tests/stubs/ss) — no real port
#                checks against the kernel
#              - Each test gets its own temp directory for isolation
#
# Version    : 1.0.0
#======================================================================

# =====================================================================
# SETUP / TEARDOWN
# =====================================================================

setup() {
    load '../helpers/test_helper'
    helper_setup

    # Clear ss state so all ports appear available by default
    clear_ss_state
}

teardown() {
    helper_teardown
}

# =====================================================================
# launch_socat_session: PID-file handoff and session registration
# =====================================================================

@test "launch_socat_session: creates session file with correct SID" {
    launch_socat_session "test-listen" "listen" "tcp4" "8080" \
        "socat TCP4-LISTEN:8080,reuseaddr,fork OPEN:/dev/null,creat,append"

    [ -n "${LAUNCH_SID}" ]
    [ -f "${SESSION_DIR}/${LAUNCH_SID}.session" ]
}

@test "launch_socat_session: sets LAUNCH_SID global variable" {
    launch_socat_session "test-listen" "listen" "tcp4" "8080" \
        "socat TCP4-LISTEN:8080,reuseaddr,fork OPEN:/dev/null,creat,append"

    # LAUNCH_SID should be an 8-char hex string
    [[ "${LAUNCH_SID}" =~ ^[a-f0-9]{8}$ ]]
}

@test "launch_socat_session: session file contains correct PID" {
    launch_socat_session "test-listen" "listen" "tcp4" "8080" \
        "socat TCP4-LISTEN:8080,reuseaddr,fork OPEN:/dev/null,creat,append"

    local pid
    pid="$(session_read_field "${SESSION_DIR}/${LAUNCH_SID}.session" "PID")"

    # PID should be a valid number
    [[ "${pid}" =~ ^[0-9]+$ ]]

    # PID should be a running process (the socat stub sleeping)
    kill -0 "${pid}" 2>/dev/null
}

@test "launch_socat_session: PGID equals PID (setsid isolation)" {
    launch_socat_session "test-listen" "listen" "tcp4" "8080" \
        "socat TCP4-LISTEN:8080,reuseaddr,fork OPEN:/dev/null,creat,append"

    local pid pgid
    pid="$(session_read_field "${SESSION_DIR}/${LAUNCH_SID}.session" "PID")"
    pgid="$(session_read_field "${SESSION_DIR}/${LAUNCH_SID}.session" "PGID")"

    # Under setsid, PGID should equal PID (process is its own group leader)
    [ "${pid}" = "${pgid}" ]
}

@test "launch_socat_session: records protocol in session file" {
    launch_socat_session "test-listen" "listen" "udp4" "5353" \
        "socat UDP4-LISTEN:5353,reuseaddr,fork OPEN:/dev/null,creat,append"

    local proto
    proto="$(session_read_field "${SESSION_DIR}/${LAUNCH_SID}.session" "PROTOCOL")"
    [ "${proto}" = "udp4" ]
}

@test "launch_socat_session: records mode in session file" {
    launch_socat_session "test-fwd" "forward" "tcp4" "8080" \
        "socat TCP4-LISTEN:8080,reuseaddr,fork TCP4:10.0.0.1:80"

    local mode
    mode="$(session_read_field "${SESSION_DIR}/${LAUNCH_SID}.session" "MODE")"
    [ "${mode}" = "forward" ]
}

@test "launch_socat_session: records remote host and port" {
    launch_socat_session "test-redir" "redirect" "tcp4" "8443" \
        "socat TCP4-LISTEN:8443,reuseaddr,fork TCP4:example.com:443" \
        "example.com" "443"

    local rhost rport
    rhost="$(session_read_field "${SESSION_DIR}/${LAUNCH_SID}.session" "REMOTE_HOST")"
    rport="$(session_read_field "${SESSION_DIR}/${LAUNCH_SID}.session" "REMOTE_PORT")"
    [ "${rhost}" = "example.com" ]
    [ "${rport}" = "443" ]
}

@test "launch_socat_session: PID staging file is cleaned up" {
    launch_socat_session "test-listen" "listen" "tcp4" "8080" \
        "socat TCP4-LISTEN:8080,reuseaddr,fork OPEN:/dev/null,creat,append"

    # The .launching file should be removed after PID is read
    [ ! -f "${SESSION_DIR}/${LAUNCH_SID}.launching" ]
}

@test "launch_socat_session: stub socat logs its arguments" {
    launch_socat_session "test-listen" "listen" "tcp4" "8080" \
        "socat TCP4-LISTEN:8080,reuseaddr,fork OPEN:/dev/null,creat,append"

    local stub_log
    stub_log="$(get_stub_log)"

    # The stub should have logged the socat arguments
    [[ "${stub_log}" == *"TCP4-LISTEN:8080"* ]]
}

# =====================================================================
# _stop_session: clean shutdown
# =====================================================================

@test "_stop_session: kills process and removes session file" {
    launch_socat_session "test-listen" "listen" "tcp4" "8080" \
        "socat TCP4-LISTEN:8080,reuseaddr,fork OPEN:/dev/null,creat,append"

    local sid="${LAUNCH_SID}"
    local pid
    pid="$(session_read_field "${SESSION_DIR}/${sid}.session" "PID")"

    # Session file should exist before stop
    [ -f "${SESSION_DIR}/${sid}.session" ]

    # Stop the session
    _stop_session "${sid}"

    # Session file should be removed
    [ ! -f "${SESSION_DIR}/${sid}.session" ]

    # Process should be dead
    ! kill -0 "${pid}" 2>/dev/null
}

@test "_stop_session: handles already-dead process gracefully" {
    create_mock_session "aabb1122" "dead-session" "99999" "listen" "tcp4" "8080"

    run _stop_session "aabb1122"
    [ "$status" -eq 0 ]

    # Session file should be removed even for dead processes
    [ ! -f "${SESSION_DIR}/aabb1122.session" ]
}

@test "_stop_session: removes stop signal file" {
    launch_socat_session "test-listen" "listen" "tcp4" "8080" \
        "socat TCP4-LISTEN:8080,reuseaddr,fork OPEN:/dev/null,creat,append"

    local sid="${LAUNCH_SID}"
    _stop_session "${sid}"

    # .stop file should be cleaned up
    [ ! -f "${SESSION_DIR}/${sid}.stop" ]
}

# =====================================================================
# Non-blocking launch verification
# =====================================================================

@test "launch_socat_session: returns within 3 seconds (non-blocking)" {
    local start_time end_time elapsed

    start_time="$(date +%s)"

    launch_socat_session "test-listen" "listen" "tcp4" "8080" \
        "socat TCP4-LISTEN:8080,reuseaddr,fork OPEN:/dev/null,creat,append"

    end_time="$(date +%s)"
    elapsed=$(( end_time - start_time ))

    # Launch should complete in under 3 seconds (generous for CI)
    [ "${elapsed}" -lt 3 ]
}

# =====================================================================
# Multiple concurrent sessions
# =====================================================================

@test "launch: multiple sessions on different ports coexist" {
    launch_socat_session "listen-8080" "listen" "tcp4" "8080" \
        "socat TCP4-LISTEN:8080,reuseaddr,fork OPEN:/dev/null,creat,append"
    local sid1="${LAUNCH_SID}"

    launch_socat_session "listen-9090" "listen" "tcp4" "9090" \
        "socat TCP4-LISTEN:9090,reuseaddr,fork OPEN:/dev/null,creat,append"
    local sid2="${LAUNCH_SID}"

    # Both sessions should exist
    [ -f "${SESSION_DIR}/${sid1}.session" ]
    [ -f "${SESSION_DIR}/${sid2}.session" ]

    # Both should have different SIDs
    [ "${sid1}" != "${sid2}" ]

    # Both processes should be alive
    local pid1 pid2
    pid1="$(session_read_field "${SESSION_DIR}/${sid1}.session" "PID")"
    pid2="$(session_read_field "${SESSION_DIR}/${sid2}.session" "PID")"
    kill -0 "${pid1}" 2>/dev/null
    kill -0 "${pid2}" 2>/dev/null
}

@test "stop: stopping one session preserves others" {
    launch_socat_session "listen-8080" "listen" "tcp4" "8080" \
        "socat TCP4-LISTEN:8080,reuseaddr,fork OPEN:/dev/null,creat,append"
    local sid1="${LAUNCH_SID}"

    launch_socat_session "listen-9090" "listen" "tcp4" "9090" \
        "socat TCP4-LISTEN:9090,reuseaddr,fork OPEN:/dev/null,creat,append"
    local sid2="${LAUNCH_SID}"

    # Stop only the first session
    _stop_session "${sid1}"

    # First session removed
    [ ! -f "${SESSION_DIR}/${sid1}.session" ]

    # Second session still exists and is alive
    [ -f "${SESSION_DIR}/${sid2}.session" ]
    local pid2
    pid2="$(session_read_field "${SESSION_DIR}/${sid2}.session" "PID")"
    kill -0 "${pid2}" 2>/dev/null
}

# =====================================================================
# --version and --help output
# =====================================================================

@test "--version: outputs version string" {
    run bash "${TEST_TMPDIR}/socat_manager.sh" --version
    [ "$status" -eq 0 ]
    [[ "${output}" == *"v2.3.0"* ]]
}

@test "--help: outputs help text" {
    run bash "${TEST_TMPDIR}/socat_manager.sh" --help
    [ "$status" -eq 0 ]
    [[ "${output}" == *"SYNOPSIS"* ]]
    [[ "${output}" == *"MODES"* ]]
}

@test "unknown mode: produces error" {
    run bash "${TEST_TMPDIR}/socat_manager.sh" invalidmode 2>&1
    [ "$status" -eq 1 ]
}

# =====================================================================
# Command builder verification
# =====================================================================

@test "build_socat_listen_cmd: produces correct command structure" {
    local cmd
    cmd="$(build_socat_listen_cmd "tcp4" "8080" "/tmp/test.log" "" "false")"

    [[ "${cmd}" == *"TCP4-LISTEN:8080"* ]]
    [[ "${cmd}" == *"reuseaddr,fork"* ]]
    [[ "${cmd}" == *"OPEN:/tmp/test.log"* ]]
}

@test "build_socat_forward_cmd: produces correct command structure" {
    local cmd
    cmd="$(build_socat_forward_cmd "tcp4" "8080" "10.0.0.1" "80" "tcp4" "false")"

    [[ "${cmd}" == *"TCP4-LISTEN:8080"* ]]
    [[ "${cmd}" == *"TCP4:10.0.0.1:80"* ]]
}

@test "build_socat_redirect_cmd: produces correct command structure" {
    local cmd
    cmd="$(build_socat_redirect_cmd "tcp4" "8443" "example.com" "443" "false")"

    [[ "${cmd}" == *"TCP4-LISTEN:8443"* ]]
    [[ "${cmd}" == *"TCP4:example.com:443"* ]]
}

@test "build_socat_redirect_cmd: uses UDP for udp4 protocol" {
    local cmd
    cmd="$(build_socat_redirect_cmd "udp4" "5353" "8.8.8.8" "53" "false")"

    [[ "${cmd}" == *"UDP4-LISTEN:5353"* ]]
    [[ "${cmd}" == *"UDP4:8.8.8.8:53"* ]]
}

@test "build_socat_tunnel_cmd: produces correct command structure" {
    local cmd
    cmd="$(build_socat_tunnel_cmd "4443" "10.0.0.5" "22" "/tmp/cert.pem" "/tmp/key.pem" "false")"

    [[ "${cmd}" == *"OPENSSL-LISTEN:4443"* ]]
    [[ "${cmd}" == *"cert=/tmp/cert.pem"* ]]
    [[ "${cmd}" == *"TCP4:10.0.0.5:22"* ]]
}
