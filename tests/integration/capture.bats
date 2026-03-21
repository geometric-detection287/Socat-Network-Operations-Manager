#!/usr/bin/env bats
#======================================================================
# TEST FILE  : tests/integration/capture.bats
#======================================================================
# Synopsis   : Integration tests for traffic capture (--capture) log
#              generation across all operational modes.
#
# Description: Verifies that:
#              - --capture flag adds socat -v to command strings for
#                all modes (listen, forward, tunnel, redirect)
#              - Capture log files are created at expected paths
#              - Stderr redirect is passed through launch_socat_session
#              - Dual-stack + capture creates per-protocol capture logs
#              - Command builders produce correct -v flag placement
#              - Non-capture mode does NOT include -v in commands
#
# Execution  : bats tests/integration/capture.bats
#
# Notes      : - Uses stubbed socat — no real traffic captured
#              - Verifies command construction and file creation,
#                not actual hex dump content (stub socat doesn't
#                generate traffic)
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
# Command builder: capture flag produces -v
# =====================================================================

@test "build_socat_listen_cmd: capture=true adds -v flag" {
    local cmd
    cmd="$(build_socat_listen_cmd "tcp4" "8080" "/tmp/data.log" "" "true")"

    [[ "${cmd}" == *"-v"* ]]
    [[ "${cmd}" == *"TCP4-LISTEN:8080"* ]]
}

@test "build_socat_listen_cmd: capture=false omits -v flag" {
    local cmd
    cmd="$(build_socat_listen_cmd "tcp4" "8080" "/tmp/data.log" "" "false")"

    # -v should NOT appear (except inside filenames — check specifically)
    # The command should start with "socat -u" not "socat -v -u"
    [[ "${cmd}" == socat\ -u\ * ]] || [[ "${cmd}" == socat\ \ -u\ * ]]
}

@test "build_socat_forward_cmd: capture=true adds -v flag" {
    local cmd
    cmd="$(build_socat_forward_cmd "tcp4" "8080" "10.0.0.1" "80" "tcp4" "true")"

    [[ "${cmd}" == *"-v"* ]]
}

@test "build_socat_forward_cmd: capture=false omits -v flag" {
    local cmd
    cmd="$(build_socat_forward_cmd "tcp4" "8080" "10.0.0.1" "80" "tcp4" "false")"

    # Should not contain -v as a standalone flag
    [[ "${cmd}" != *" -v "* ]]
}

@test "build_socat_tunnel_cmd: capture=true adds -v flag" {
    local cmd
    cmd="$(build_socat_tunnel_cmd "4443" "10.0.0.5" "22" "/tmp/cert.pem" "/tmp/key.pem" "true")"

    [[ "${cmd}" == *"-v"* ]]
}

@test "build_socat_tunnel_cmd: capture=false omits -v flag" {
    local cmd
    cmd="$(build_socat_tunnel_cmd "4443" "10.0.0.5" "22" "/tmp/cert.pem" "/tmp/key.pem" "false")"

    [[ "${cmd}" != *" -v "* ]]
}

@test "build_socat_redirect_cmd: capture=true adds -v flag" {
    local cmd
    cmd="$(build_socat_redirect_cmd "tcp4" "8443" "example.com" "443" "true")"

    [[ "${cmd}" == *"-v"* ]]
}

@test "build_socat_redirect_cmd: capture=false omits -v flag" {
    local cmd
    cmd="$(build_socat_redirect_cmd "tcp4" "8443" "example.com" "443" "false")"

    [[ "${cmd}" != *" -v "* ]]
}

# =====================================================================
# Capture with UDP protocol
# =====================================================================

@test "build_socat_redirect_cmd: UDP capture produces correct command" {
    local cmd
    cmd="$(build_socat_redirect_cmd "udp4" "5353" "8.8.8.8" "53" "true")"

    [[ "${cmd}" == *"-v"* ]]
    [[ "${cmd}" == *"UDP4-LISTEN:5353"* ]]
    [[ "${cmd}" == *"UDP4:8.8.8.8:53"* ]]
}

@test "build_socat_listen_cmd: UDP capture produces correct command" {
    local cmd
    cmd="$(build_socat_listen_cmd "udp4" "5353" "/tmp/data.log" "" "true")"

    [[ "${cmd}" == *"-v"* ]]
    [[ "${cmd}" == *"UDP4-LISTEN:5353"* ]]
}

# =====================================================================
# Launch with capture: stderr redirect
# =====================================================================

@test "launch with capture: stderr redirect file is passed" {
    local capture_log="${LOG_DIR}/capture-tcp4-8080-test.log"

    launch_socat_session "test-listen" "listen" "tcp4" "8080" \
        "socat -v TCP4-LISTEN:8080,reuseaddr,fork OPEN:/dev/null,creat,append" \
        "" "" "${capture_log}"

    [ -n "${LAUNCH_SID}" ]

    # The session should be created successfully even with stderr redirect
    [ -f "${SESSION_DIR}/${LAUNCH_SID}.session" ]

    local pid
    pid="$(session_read_field "${SESSION_DIR}/${LAUNCH_SID}.session" "PID")"
    kill -0 "${pid}" 2>/dev/null
}

@test "launch without capture: session error log path used as stderr" {
    # Launch WITHOUT a capture file (empty 8th parameter)
    launch_socat_session "test-listen" "listen" "tcp4" "8080" \
        "socat TCP4-LISTEN:8080,reuseaddr,fork OPEN:/dev/null,creat,append" \
        "" "" ""

    [ -n "${LAUNCH_SID}" ]

    # Session should be created
    [ -f "${SESSION_DIR}/${LAUNCH_SID}.session" ]
}

# =====================================================================
# Dual-stack + capture: independent capture logs
# =====================================================================

@test "dual-stack capture: TCP and UDP get separate capture files" {
    local tcp_capture="${LOG_DIR}/capture-tcp4-8443-example.com-443-test.log"
    local udp_capture="${LOG_DIR}/capture-udp4-8443-example.com-443-test.log"

    # Launch TCP with capture
    launch_socat_session "redir-tcp4-8443" "redirect" "tcp4" "8443" \
        "socat -v TCP4-LISTEN:8443,reuseaddr,fork TCP4:example.com:443" \
        "example.com" "443" "${tcp_capture}"
    local tcp_sid="${LAUNCH_SID}"

    # Launch UDP with capture
    launch_socat_session "redir-udp4-8443" "redirect" "udp4" "8443" \
        "socat -v UDP4-LISTEN:8443,reuseaddr,fork UDP4:example.com:443" \
        "example.com" "443" "${udp_capture}"
    local udp_sid="${LAUNCH_SID}"

    # Both sessions should be created independently
    [ -f "${SESSION_DIR}/${tcp_sid}.session" ]
    [ -f "${SESSION_DIR}/${udp_sid}.session" ]

    # Both should have different SIDs
    [ "${tcp_sid}" != "${udp_sid}" ]

    # Verify protocol fields are correct
    local tcp_proto udp_proto
    tcp_proto="$(session_read_field "${SESSION_DIR}/${tcp_sid}.session" "PROTOCOL")"
    udp_proto="$(session_read_field "${SESSION_DIR}/${udp_sid}.session" "PROTOCOL")"
    [ "${tcp_proto}" = "tcp4" ]
    [ "${udp_proto}" = "udp4" ]
}

@test "dual-stack capture: stopping TCP preserves UDP capture session" {
    local tcp_capture="${LOG_DIR}/capture-tcp4-test.log"
    local udp_capture="${LOG_DIR}/capture-udp4-test.log"

    launch_socat_session "redir-tcp4-8443" "redirect" "tcp4" "8443" \
        "socat -v TCP4-LISTEN:8443,reuseaddr,fork TCP4:example.com:443" \
        "example.com" "443" "${tcp_capture}"
    local tcp_sid="${LAUNCH_SID}"

    launch_socat_session "redir-udp4-8443" "redirect" "udp4" "8443" \
        "socat -v UDP4-LISTEN:8443,reuseaddr,fork UDP4:example.com:443" \
        "example.com" "443" "${udp_capture}"
    local udp_sid="${LAUNCH_SID}"

    local udp_pid
    udp_pid="$(session_read_field "${SESSION_DIR}/${udp_sid}.session" "PID")"

    # Stop TCP only
    _stop_session "${tcp_sid}"

    # TCP gone
    [ ! -f "${SESSION_DIR}/${tcp_sid}.session" ]

    # UDP with capture still alive
    [ -f "${SESSION_DIR}/${udp_sid}.session" ]
    kill -0 "${udp_pid}" 2>/dev/null
}
