#!/usr/bin/env bats
#======================================================================
# TEST FILE  : tests/unit/session.bats
#======================================================================
# Synopsis   : Unit tests for session management functions in
#              socat_manager.sh.
#
# Description: Tests session_register, session_unregister,
#              session_read_field, session_find_by_name,
#              session_find_by_port, session_find_by_pid,
#              session_is_alive, session_get_all_ids,
#              session_cleanup_dead, and the create_mock_session
#              test helper utility.
#
# Execution  : bats tests/unit/session.bats
#
# Notes      : - Uses mock sessions created by create_mock_session
#                (from test_helper) — no real processes spawned
#              - Uses $$ (current shell PID) as a "living" PID and
#                99999 as a "dead" PID for alive/dead checks
#
# Version    : 1.0.0
#======================================================================

# =====================================================================
# SETUP / TEARDOWN
# =====================================================================

setup() {
    load '../helpers/test_helper'
    helper_setup
}

teardown() {
    helper_teardown
}

# =====================================================================
# session_register
# =====================================================================

@test "session_register: creates session file with correct name" {
    session_register "aabb1122" "test-session" "12345" "12345" \
        "listen" "tcp4" "8080" "socat TCP4-LISTEN:8080" "" ""

    [ -f "${SESSION_DIR}/aabb1122.session" ]
}

@test "session_register: writes all required fields" {
    session_register "aabb1122" "test-session" "12345" "12345" \
        "redirect" "tcp4" "8443" "socat TCP4-LISTEN:8443" "example.com" "443"

    local sf="${SESSION_DIR}/aabb1122.session"

    # Verify each field is present and correct
    [ "$(grep '^SESSION_ID=' "${sf}" | cut -d= -f2)" = "aabb1122" ]
    [ "$(grep '^SESSION_NAME=' "${sf}" | cut -d= -f2)" = "test-session" ]
    [ "$(grep '^PID=' "${sf}" | cut -d= -f2)" = "12345" ]
    [ "$(grep '^PGID=' "${sf}" | cut -d= -f2)" = "12345" ]
    [ "$(grep '^MODE=' "${sf}" | cut -d= -f2)" = "redirect" ]
    [ "$(grep '^PROTOCOL=' "${sf}" | cut -d= -f2)" = "tcp4" ]
    [ "$(grep '^LOCAL_PORT=' "${sf}" | cut -d= -f2)" = "8443" ]
    [ "$(grep '^REMOTE_HOST=' "${sf}" | cut -d= -f2-)" = "example.com" ]
    [ "$(grep '^REMOTE_PORT=' "${sf}" | cut -d= -f2)" = "443" ]
}

@test "session_register: sets restrictive file permissions (600)" {
    session_register "aabb1122" "test-session" "12345" "12345" \
        "listen" "tcp4" "8080" "socat TCP4-LISTEN:8080" "" ""

    local perms
    perms="$(stat -c '%a' "${SESSION_DIR}/aabb1122.session")"
    [ "${perms}" = "600" ]
}

# =====================================================================
# session_unregister
# =====================================================================

@test "session_unregister: removes session file" {
    create_mock_session "aabb1122" "test-session" "99999"
    [ -f "${SESSION_DIR}/aabb1122.session" ]

    session_unregister "aabb1122"
    [ ! -f "${SESSION_DIR}/aabb1122.session" ]
}

@test "session_unregister: removes associated stop and launching files" {
    create_mock_session "aabb1122" "test-session" "99999"
    touch "${SESSION_DIR}/aabb1122.stop"
    touch "${SESSION_DIR}/aabb1122.launching"

    session_unregister "aabb1122"

    [ ! -f "${SESSION_DIR}/aabb1122.session" ]
    [ ! -f "${SESSION_DIR}/aabb1122.stop" ]
    [ ! -f "${SESSION_DIR}/aabb1122.launching" ]
}

@test "session_unregister: does not error on non-existent session" {
    run session_unregister "nonexist"
    [ "$status" -eq 0 ]
}

# =====================================================================
# session_read_field
# =====================================================================

@test "session_read_field: reads existing field correctly" {
    create_mock_session "aabb1122" "test-redirect" "99999" "redirect" "tcp4" "8443" "example.com" "443"

    local result
    result="$(session_read_field "${SESSION_DIR}/aabb1122.session" "SESSION_NAME")"
    [ "${result}" = "test-redirect" ]
}

@test "session_read_field: reads PROTOCOL field" {
    create_mock_session "aabb1122" "test-redirect" "99999" "redirect" "udp4" "5353"

    local result
    result="$(session_read_field "${SESSION_DIR}/aabb1122.session" "PROTOCOL")"
    [ "${result}" = "udp4" ]
}

@test "session_read_field: reads REMOTE_HOST with dots" {
    create_mock_session "aabb1122" "test-redirect" "99999" "redirect" "tcp4" "8443" "example.com" "443"

    local result
    result="$(session_read_field "${SESSION_DIR}/aabb1122.session" "REMOTE_HOST")"
    [ "${result}" = "example.com" ]
}

@test "session_read_field: returns empty for missing field" {
    create_mock_session "aabb1122" "test-redirect" "99999"

    local result
    result="$(session_read_field "${SESSION_DIR}/aabb1122.session" "NONEXISTENT_FIELD" || true)"
    [ -z "${result}" ]
}

@test "session_read_field: returns empty for missing file" {
    local result
    result="$(session_read_field "${SESSION_DIR}/nonexistent.session" "PID")"
    [ -z "${result}" ]
}

# =====================================================================
# session_find_by_name
# =====================================================================

@test "session_find_by_name: finds matching session" {
    create_mock_session "aabb1122" "redir-tcp4-8443" "99999"

    local result
    result="$(session_find_by_name "redir-tcp4-8443")"
    [ "${result}" = "aabb1122" ]
}

@test "session_find_by_name: returns empty for no match" {
    create_mock_session "aabb1122" "redir-tcp4-8443" "99999"

    local result
    result="$(session_find_by_name "nonexistent-name")"
    [ -z "${result}" ]
}

@test "session_find_by_name: finds multiple sessions with same name" {
    create_mock_session "aabb1122" "batch-tcp4-8080" "99999"
    create_mock_session "ccdd3344" "batch-tcp4-8080" "99998"

    local result
    result="$(session_find_by_name "batch-tcp4-8080")"
    local count
    count="$(echo "${result}" | wc -l)"
    [ "${count}" -eq 2 ]
}

# =====================================================================
# session_find_by_port
# =====================================================================

@test "session_find_by_port: finds session on port" {
    create_mock_session "aabb1122" "test-session" "99999" "listen" "tcp4" "8080"

    local result
    result="$(session_find_by_port "8080")"
    [ "${result}" = "aabb1122" ]
}

@test "session_find_by_port: finds both protocols on same port (dual-stack)" {
    create_mock_session "aabb1122" "redir-tcp4-8443" "99999" "redirect" "tcp4" "8443"
    create_mock_session "ccdd3344" "redir-udp4-8443" "99998" "redirect" "udp4" "8443"

    local result
    result="$(session_find_by_port "8443")"
    local count
    count="$(echo "${result}" | wc -l)"
    [ "${count}" -eq 2 ]
}

@test "session_find_by_port: returns empty for no match" {
    create_mock_session "aabb1122" "test-session" "99999" "listen" "tcp4" "8080"

    local result
    result="$(session_find_by_port "9999")"
    [ -z "${result}" ]
}

# =====================================================================
# session_find_by_pid
# =====================================================================

@test "session_find_by_pid: finds session by PID" {
    create_mock_session "aabb1122" "test-session" "55555"

    local result
    result="$(session_find_by_pid "55555")"
    [ "${result}" = "aabb1122" ]
}

@test "session_find_by_pid: returns empty for no match" {
    create_mock_session "aabb1122" "test-session" "55555"

    local result
    result="$(session_find_by_pid "00000")"
    [ -z "${result}" ]
}

# =====================================================================
# session_is_alive
# =====================================================================

@test "session_is_alive: returns 0 for living PID" {
    # Spawn a real background process so we have a guaranteed-alive PID
    # that teardown can safely kill without destroying BATS itself.
    sleep 300 &
    local alive_pid=$!

    create_mock_session "aabb1122" "test-session" "${alive_pid}"

    session_is_alive "aabb1122"

    # Cleanup
    kill "${alive_pid}" 2>/dev/null || true
}

@test "session_is_alive: returns 1 for dead PID" {
    # PID 99999 almost certainly doesn't exist
    create_mock_session "aabb1122" "test-session" "99999"

    run session_is_alive "aabb1122"
    [ "$status" -eq 1 ]
}

@test "session_is_alive: returns 1 for non-existent session" {
    run session_is_alive "nonexist"
    [ "$status" -eq 1 ]
}

# =====================================================================
# session_get_all_ids
# =====================================================================

@test "session_get_all_ids: returns all registered IDs" {
    create_mock_session "aabb1122" "session-1" "99999"
    create_mock_session "ccdd3344" "session-2" "99998"
    create_mock_session "eeff5566" "session-3" "99997"

    local result
    result="$(session_get_all_ids)"
    local count
    count="$(echo "${result}" | wc -l)"
    [ "${count}" -eq 3 ]
}

@test "session_get_all_ids: returns empty when no sessions exist" {
    local result
    result="$(session_get_all_ids)"
    [ -z "${result}" ]
}

# =====================================================================
# session_cleanup_dead
# =====================================================================

@test "session_cleanup_dead: removes sessions with dead PIDs" {
    # Create a session with a dead PID
    create_mock_session "aabb1122" "dead-session" "99999"

    session_cleanup_dead

    [ ! -f "${SESSION_DIR}/aabb1122.session" ]
}

@test "session_cleanup_dead: preserves sessions with living PIDs" {
    # Spawn a real process for a living PID
    sleep 300 &
    local alive_pid=$!

    create_mock_session "aabb1122" "alive-session" "${alive_pid}"

    session_cleanup_dead

    [ -f "${SESSION_DIR}/aabb1122.session" ]

    kill "${alive_pid}" 2>/dev/null || true
}

@test "session_cleanup_dead: handles mixed alive and dead sessions" {
    # Spawn a real process for a living PID
    sleep 300 &
    local alive_pid=$!

    create_mock_session "aabb1122" "alive-session" "${alive_pid}"
    create_mock_session "ccdd3344" "dead-session" "99999"

    session_cleanup_dead

    # Alive session preserved
    [ -f "${SESSION_DIR}/aabb1122.session" ]
    # Dead session removed
    [ ! -f "${SESSION_DIR}/ccdd3344.session" ]

    kill "${alive_pid}" 2>/dev/null || true
}

# =====================================================================
# create_mock_session (test helper verification)
# =====================================================================

@test "create_mock_session: helper creates valid session file" {
    create_mock_session "aabb1122" "test-session" "99999" "redirect" "tcp4" "8443" "example.com" "443"

    [ -f "${SESSION_DIR}/aabb1122.session" ]

    # Verify it's parseable by session_read_field
    local sid
    sid="$(session_read_field "${SESSION_DIR}/aabb1122.session" "SESSION_ID")"
    [ "${sid}" = "aabb1122" ]
}

@test "count_session_files: returns correct count" {
    create_mock_session "aabb1122" "session-1" "99999"
    create_mock_session "ccdd3344" "session-2" "99998"

    local count
    count="$(count_session_files)"
    [ "${count}" -eq 2 ]
}

@test "count_session_files: returns 0 when empty" {
    local count
    count="$(count_session_files)"
    [ "${count}" -eq 0 ]
}

# =====================================================================
# session_read_field: awk exact-match (H-4 audit remediation)
# Ensures field lookup uses exact key match, not regex
# =====================================================================

@test "session_read_field: reads value containing equals sign" {
    create_mock_session "aabb1122" "test-session" "99999"
    # Add a field whose value contains equals signs (tests awk substr extraction)
    echo "CUSTOM_DATA=key1=val1,key2=val2,key3=val3" >> "${SESSION_DIR}/aabb1122.session"

    local result
    result="$(session_read_field "${SESSION_DIR}/aabb1122.session" "CUSTOM_DATA")"
    [ "${result}" = "key1=val1,key2=val2,key3=val3" ]
}

@test "session_read_field: does not match partial field names" {
    create_mock_session "aabb1122" "test-session" "99999"
    # PID field exists; LAUNCHER_PID also exists - make sure reading PID doesn't match LAUNCHER_PID
    echo "LAUNCHER_PID=88888" >> "${SESSION_DIR}/aabb1122.session"

    local result
    result="$(session_read_field "${SESSION_DIR}/aabb1122.session" "PID")"
    # Should get the PID value (99999), not LAUNCHER_PID (88888)
    [ "${result}" = "99999" ]
}

@test "session_read_field: handles field with dots in value" {
    create_mock_session "aabb1122" "test-session" "99999" "redirect" "tcp4" "8443" "192.168.1.100" "443"

    local result
    result="$(session_read_field "${SESSION_DIR}/aabb1122.session" "REMOTE_HOST")"
    [ "${result}" = "192.168.1.100" ]
}

# =====================================================================
# _session_lock / _session_unlock (M-2 audit remediation)
# Advisory file locking via flock
# =====================================================================

@test "_session_lock: acquires lock successfully" {
    run _session_lock
    [ "$status" -eq 0 ]
    # Clean up
    _session_unlock 2>/dev/null || true
}

@test "_session_unlock: releases lock without error" {
    _session_lock || true
    run _session_unlock
    [ "$status" -eq 0 ]
}

@test "_session_lock: lock file is created in session directory" {
    _session_lock || true
    [ -f "${SESSION_DIR}/.lock" ]
    _session_unlock 2>/dev/null || true
}
