# Contributing to Socat Network Operations Manager

Thank you for your interest in contributing. This document provides everything
you need to set up a development environment, run tests, follow coding
standards, and submit changes.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
  - [Development Prerequisites](#development-prerequisites)
  - [Setting Up the Development Environment](#setting-up-the-development-environment)
  - [Project Structure](#project-structure)
- [Running Tests](#running-tests)
  - [Full Test Suite](#full-test-suite)
  - [Unit Tests Only](#unit-tests-only)
  - [Integration Tests Only](#integration-tests-only)
  - [Running Specific Tests](#running-specific-tests)
  - [Linting](#linting)
- [Writing Tests](#writing-tests)
  - [Test Architecture](#test-architecture)
  - [Adding Unit Tests](#adding-unit-tests)
  - [Adding Integration Tests](#adding-integration-tests)
  - [Using Stubs](#using-stubs)
- [Coding Standards](#coding-standards)
  - [Script Structure](#script-structure)
  - [Function Documentation](#function-documentation)
  - [Input Validation](#input-validation)
  - [Error Handling](#error-handling)
  - [CLI Flag Checklist](#cli-flag-checklist)
- [Submitting Changes](#submitting-changes)
  - [Branch Naming](#branch-naming)
  - [Commit Messages](#commit-messages)
  - [Pull Request Process](#pull-request-process)
- [Reporting Bugs](#reporting-bugs)
- [Security Vulnerabilities](#security-vulnerabilities)

---

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).
By participating, you are expected to uphold this code. This includes the
**Responsible Use** section — all contributions must be consistent with
authorized, lawful use of security tooling.

---

## Getting Started

### Development Prerequisites

| Tool | Version | Purpose | Install |
|------|---------|---------|---------|
| **bash** | 4.4+ | Script execution | Pre-installed on most Linux |
| **socat** | any | Runtime dependency (optional for tests) | `sudo apt-get install -y socat` |
| **BATS** | 1.5+ | Test framework | [GitHub](https://github.com/bats-core/bats-core) |
| **ShellCheck** | 0.8+ | Static analysis | `sudo apt-get install -y shellcheck` |
| **GNU Make** | 3.81+ | Build automation | Pre-installed on most Linux |
| **Git** | 2.0+ | Version control | `sudo apt-get install -y git` |

**Install BATS from source** (recommended for latest version):

```bash
git clone --depth 1 https://github.com/bats-core/bats-core.git /tmp/bats-core
sudo /tmp/bats-core/install.sh /usr/local
bats --version
```

**Verify all prerequisites at once:**

```bash
make check-deps
```

### Setting Up the Development Environment

```bash
# Clone the repository
git clone https://github.com/<your-org>/socat-manager.git
cd socat-manager

# Verify prerequisites
make check-deps

# Run the full test suite to confirm everything works
make test

# You should see: "✓ All tests passed" with 143 tests passing
```

### Project Structure

```
socat-manager/
├── socat_manager.sh            # Main script (3,400+ lines)
├── Makefile                    # Build, test, install, package
├── bin/
│   └── socat-manager           # System-wide wrapper script
├── templates/
│   └── activate.sh             # Virtual environment activation template
├── tests/
│   ├── helpers/
│   │   └── test_helper.bash    # Shared setup/teardown for all tests
│   ├── stubs/
│   │   ├── socat               # Mock socat (logs args, sleeps)
│   │   ├── ss                  # Mock ss (canned port data)
│   │   └── openssl             # Mock openssl (dummy certs)
│   ├── fixtures/
│   │   ├── sample_session.session  # v2.2 format session file
│   │   ├── legacy_session.pid      # v1.0 format (migration testing)
│   │   └── ports.conf              # Sample batch port config
│   ├── unit/
│   │   ├── validation.bats     # Input validation function tests
│   │   └── session.bats        # Session management function tests
│   └── integration/
│       ├── lifecycle.bats      # Launch → status → stop tests
│       ├── dual_stack.bats     # Protocol-scoped stop tests
│       └── capture.bats        # Traffic capture tests
├── .shellcheckrc               # ShellCheck configuration
├── .gitignore                  # Git ignore rules
├── README.md                   # Project overview and reference
├── USAGE_GUIDE.md              # Detailed usage and deployment
├── CHANGELOG.md                # Version history
├── SECURITY.md                 # Security policy and threat model
├── CODE_OF_CONDUCT.md          # Contributor code of conduct
├── CONTRIBUTING.md             # This file
└── LICENSE                     # MIT License
```

---

## Running Tests

### Full Test Suite

```bash
make test
```

This runs ShellCheck linting, then all unit tests, then all integration tests.
All 143 tests must pass before submitting a PR.

### Unit Tests Only

```bash
make test-unit
```

Fast (~2 seconds). Tests validation functions and session management functions
in isolation. No stubs or background processes involved.

### Integration Tests Only

```bash
make test-integration
```

Tests the full session lifecycle (launch → status → stop) using stubbed socat,
ss, and openssl. Verifies PID-file handoff, process group isolation,
protocol-scoped stop, and capture log generation.

### Running Specific Tests

```bash
# Run a single test file
bats tests/unit/validation.bats

# Run a specific test by name (partial match)
bats tests/integration/dual_stack.bats --filter "stopping TCP preserves UDP"

# Run all tests matching a pattern
bats --recursive tests/ --filter "validate_port"
```

### Linting

```bash
make lint
```

Runs ShellCheck with the project's `.shellcheckrc` configuration. Any warnings
at severity `warning` or above will fail the check.

---

## Writing Tests

### Test Architecture

Tests use [BATS](https://github.com/bats-core/bats-core) (Bash Automated
Testing System). Key concepts:

- Each `@test` block runs in its **own subshell** (test isolation is automatic)
- `setup()` runs before each test, `teardown()` runs after (even on failure)
- `run <command>` captures stdout in `$output` and exit code in `$status`
- Assertions use standard `[ ]` test expressions

The test helper (`tests/helpers/test_helper.bash`) provides:

- **Temp directory isolation**: Each test gets its own temp dir. All runtime
  paths (`SESSION_DIR`, `LOG_DIR`, etc.) point into the temp dir via symlink.
- **Stub injection**: Mock socat/ss/openssl are prepended to `PATH`.
- **Utility functions**: `create_mock_session`, `count_session_files`,
  `get_stub_log`, `set_ss_state`, `wait_for_session_file`.

### Adding Unit Tests

Unit tests go in `tests/unit/`. They test individual functions directly:

```bash
#!/usr/bin/env bats

setup() {
    load '../helpers/test_helper'
    helper_setup
}

teardown() {
    helper_teardown
}

@test "my_function: accepts valid input" {
    run my_function "valid_input"
    [ "$status" -eq 0 ]
}

@test "my_function: rejects invalid input" {
    run my_function "invalid;input"
    [ "$status" -eq 1 ]
}
```

### Adding Integration Tests

Integration tests go in `tests/integration/`. They test multi-function flows
with the stubbed socat:

```bash
@test "launch and stop: full lifecycle" {
    # Launch a session (uses stubbed socat)
    launch_socat_session "test-listen" "listen" "tcp4" "8080" \
        "socat TCP4-LISTEN:8080,reuseaddr,fork OPEN:/dev/null,creat,append"
    local sid="${LAUNCH_SID}"

    # Verify session exists
    [ -f "${SESSION_DIR}/${sid}.session" ]

    # Stop the session
    _stop_session "${sid}"

    # Verify cleanup
    [ ! -f "${SESSION_DIR}/${sid}.session" ]
}
```

### Using Stubs

**socat stub**: Logs its arguments to `${TEST_TMPDIR}/.socat_stub.log` and
sleeps. Set `SOCAT_STUB_EXIT=1` to simulate a crash (for watchdog testing).

**ss stub**: Reads `${TEST_TMPDIR}/.ss_state` to determine which ports are
"listening". Use `set_ss_state "8080:tcp" "5353:udp"` to configure, and
`clear_ss_state` to reset.

**openssl stub**: Creates dummy cert/key files at the paths specified by
`-out` and `-keyout` arguments.

---

## Coding Standards

### Script Structure

The script follows a consistent pattern:

1. **Header comment block** with synopsis, description, notes, examples, version
2. **Constants and configuration** (readonly where appropriate)
3. **Utility functions** (logging, colors, formatting)
4. **Validation functions** (all `validate_*` functions)
5. **Session management functions** (register, read, find, cleanup)
6. **Command builders** (one per mode: `build_socat_*_cmd`)
7. **Launch infrastructure** (`launch_socat_session`, watchdog)
8. **Mode handlers** (one per mode: `mode_listen`, `mode_batch`, etc.)
9. **Help system** (one per mode: `show_*_help`)
10. **Signal handling and entry point**

New functions should be placed in the appropriate section.

### Function Documentation

Every non-trivial function must have a documentation header:

```bash
# Function: function_name
# Description: What this function does. Multi-line descriptions
#              should be aligned like this.
# Parameters:
#   $1 - Description of first parameter
#   $2 - Description of second parameter (optional, default: value)
# Returns: 0 on success, 1 on failure
# Outputs: What it writes to stdout (if anything)
function_name() {
    ...
}
```

### Input Validation

All user-supplied inputs **must** pass through validation before use:

- Ports → `validate_port`
- Hostnames/IPs → `validate_hostname`
- Protocols → `validate_protocol`
- File paths → `validate_file_path`
- Session IDs → `validate_session_id`

Never interpolate raw user input into socat command strings, file paths, or
session file names without validation.

### Error Handling

- Use `set -euo pipefail` (already set at script top)
- Arithmetic increments must use `((count++)) || true` under `set -e`
- Functions that can legitimately fail should be called with `|| true` or
  have their return value explicitly checked
- Never use `$()` subshell capture for functions that launch background
  processes (use global variables like `LAUNCH_SID` instead)

### CLI Flag Checklist

When adding a new CLI flag, ensure **all** of these are updated:

- [ ] Mode argument parser (`case` block in `mode_*` function)
- [ ] Command builder function (if the flag affects the socat command)
- [ ] Help function (`show_*_help`)
- [ ] Main help (`show_main_help`) if the flag is global
- [ ] README.md options table for the relevant mode
- [ ] USAGE_GUIDE.md if the flag is significant
- [ ] CHANGELOG.md under `[Unreleased]`
- [ ] At least one BATS test covering the new flag

---

## Submitting Changes

### Branch Naming

Use descriptive branch names with a category prefix:

```
feature/add-rate-limiting
fix/cross-protocol-kill-on-stop
docs/update-tunnel-examples
test/add-watchdog-restart-tests
```

### Commit Messages

Use conventional commit format:

```
Add: --rate-limit flag for listen and forward modes

Implements per-port connection rate limiting using socat's
max-children option. Adds --rate-limit <N> to listen, batch,
and forward mode parsers. Updates help text and adds 4 BATS tests.

Closes #42
```

Prefixes: `Add:`, `Fix:`, `Change:`, `Remove:`, `Docs:`, `Test:`, `Refactor:`

### Pull Request Process

1. **Fork and branch**: Create a feature branch from `main`
2. **Implement**: Make your changes following the coding standards above
3. **Test**: Run `make test` — all 143+ tests must pass
4. **Lint**: Run `make lint` — no warnings
5. **Document**: Update CHANGELOG.md, help text, and README/USAGE_GUIDE as needed
6. **Commit**: Clear, descriptive commit messages
7. **Push**: Push your branch to your fork
8. **PR**: Open a Pull Request with:
   - Description of what changed and why
   - How it was tested
   - Reference to any related issues
   - Confirmation that `make test` passes

The PR template will pre-populate a checklist. All items must be checked before
merge.

---

## Reporting Bugs

Use the repository's **Issues** tab with the **Bug Report** template. Include:

- socat_manager.sh version (`socat-manager --version`)
- Operating system and version
- Bash version (`bash --version`)
- Steps to reproduce
- Expected vs actual behavior
- Relevant log output (from `logs/` directory)

---

## Security Vulnerabilities

**Do not open a public issue for security vulnerabilities.**

See [SECURITY.md](SECURITY.md) for private reporting instructions.
