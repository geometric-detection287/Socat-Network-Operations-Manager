# Security Policy

This document describes the security policy for the socat_manager.sh project,
including how to report vulnerabilities, what security measures are implemented,
the project's threat model, and guidance for secure deployment.

---

## Table of Contents

- [Supported Versions](#supported-versions)
- [Reporting a Vulnerability](#reporting-a-vulnerability)
- [Vulnerability Disclosure Policy](#vulnerability-disclosure-policy)
- [Security Response Process](#security-response-process)
- [Security Design Overview](#security-design-overview)
- [Threat Model](#threat-model)
- [Implemented Security Controls](#implemented-security-controls)
- [Known Limitations and Accepted Risks](#known-limitations-and-accepted-risks)
- [Secure Deployment Guidelines](#secure-deployment-guidelines)
- [Dependency Security](#dependency-security)
- [Security-Related Configuration](#security-related-configuration)
- [Security Changelog](#security-changelog)

---

## Supported Versions

Security updates are provided for the following versions:

| Version | Supported          | Notes                                    |
|---------|--------------------|------------------------------------------|
| 2.3.x   | :white_check_mark: | Current release. Actively maintained.   |
| 2.2.x   | :white_check_mark: | Security fixes backported on request.   |
| 2.1.x   | :warning:          | Known bugs (cross-protocol kill). Upgrade recommended. |
| 2.0.x   | :warning:          | Known bugs (terminal blocking, wrong PID). Upgrade recommended. |
| 1.0.x   | :x:                | End of life. No security fixes. Upgrade required. |

Users running versions marked with :warning: or :x: should upgrade to the
latest release. Critical vulnerabilities discovered in end-of-life versions
will be documented but not patched.

---

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

If you discover a security vulnerability in socat_manager.sh, please report it
responsibly through one of the following channels:

### Preferred: Private Vulnerability Report

If the project is hosted on GitHub, use the **Security Advisories** feature:

1. Navigate to the repository's **Security** tab.
2. Click **Report a vulnerability**.
3. Provide the details described below.

### Alternative: Encrypted Email

If private vulnerability reporting is not available through the hosting
platform, send an encrypted email to the project maintainers. Contact
information is available in the repository's profile or maintainer list.

### What to Include in Your Report

Please provide as much of the following information as possible to help us
understand and reproduce the issue:

1. **Description**: Clear, concise description of the vulnerability.
2. **Affected versions**: Which version(s) of socat_manager.sh are affected.
3. **Attack vector**: How the vulnerability can be exploited (local, remote,
   requires authentication, requires specific configuration, etc.).
4. **Impact assessment**: What an attacker could achieve by exploiting this
   vulnerability (e.g., arbitrary command execution, information disclosure,
   denial of service, privilege escalation).
5. **Reproduction steps**: Step-by-step instructions to reproduce the issue,
   including the exact command(s) used, operating system and version, bash
   version, and socat version.
6. **Proof of concept**: If available, a minimal proof-of-concept script or
   command sequence that demonstrates the vulnerability.
7. **Suggested fix**: If you have a proposed fix, please include it or
   reference a branch/commit.
8. **Severity estimate**: Your assessment of severity using the CVSS v3.1
   framework or a qualitative rating (Critical, High, Medium, Low).

### What to Expect

- **Acknowledgment**: We will acknowledge receipt of your report within
  **48 hours**.
- **Initial assessment**: We will provide an initial severity assessment and
  estimated timeline within **7 days**.
- **Status updates**: We will provide status updates at least every **14 days**
  until the issue is resolved.
- **Resolution**: We aim to resolve confirmed vulnerabilities within **30 days**
  for Critical/High severity and **90 days** for Medium/Low severity.
- **Credit**: With your permission, we will credit you in the security
  changelog and release notes.

---

## Vulnerability Disclosure Policy

This project follows a **coordinated disclosure** model:

1. **Reporter** submits vulnerability details privately (see above).
2. **Maintainers** acknowledge receipt, assess severity, and develop a fix.
3. **Maintainers** coordinate a disclosure timeline with the reporter.
4. **Fix** is developed, tested, and merged into supported branches.
5. **Advisory** is published simultaneously with the patched release.
6. **Reporter** may publish their own analysis after the advisory is live.

### Disclosure Timeline

- **0 days**: Vulnerability reported privately.
- **≤7 days**: Maintainers acknowledge and provide initial assessment.
- **≤30 days** (Critical/High): Patch developed and released.
- **≤90 days** (Medium/Low): Patch developed and released.
- **Release day**: Security advisory published. Reporter credited (if desired).
- **Release + 30 days**: Full technical details may be published by reporter.

If we are unable to meet these timelines, we will communicate the delay and
revised timeline to the reporter. If the maintainers are unresponsive for more
than 30 days after the initial report, the reporter may proceed with public
disclosure at their discretion, preferably with a 7-day advance notice.

---

## Security Response Process

When a vulnerability is reported, the following process is followed:

### 1. Triage

- Verify the report is valid and reproducible.
- Determine affected versions.
- Assess severity using CVSS v3.1 scoring or qualitative assessment.
- Assign a tracking identifier.

### 2. Classification

| Severity | CVSS Score | Description | Response Target |
|----------|------------|-------------|-----------------|
| Critical | 9.0 - 10.0 | Remote code execution, privilege escalation, credential theft | Fix within 7 days |
| High     | 7.0 - 8.9  | Command injection, path traversal, session hijacking | Fix within 14 days |
| Medium   | 4.0 - 6.9  | Information disclosure, denial of service, input validation bypass | Fix within 30 days |
| Low      | 0.1 - 3.9  | Minor information leak, defense-in-depth gap, hardening improvement | Fix within 90 days |

### 3. Remediation

- Develop fix on a private branch.
- Conduct security-focused code review of the fix.
- Test fix against the reproduction steps from the report.
- Verify no regressions introduced.
- Backport to supported versions as applicable.

### 4. Release and Disclosure

- Merge fix and tag a new release.
- Publish security advisory with: affected versions, attack vector, impact,
  fix version, mitigation steps for users who cannot upgrade immediately.
- Notify the reporter and provide credit if authorized.

---

## Security Design Overview

socat_manager.sh is a bash script that manages socat processes for network
operations. Its security design addresses the following areas:

### Input Boundary

All user-supplied inputs pass through whitelist-based validation before any
use in commands, file paths, or session metadata:

- **Ports**: Integer validation, range check (1-65535).
- **Hostnames/IPs**: IPv4 octet validation, IPv6 pattern matching, RFC 1123
  hostname validation. Shell metacharacters explicitly blocked.
- **Protocols**: Validated against a fixed whitelist (tcp4, tcp6, udp4, udp6).
- **File paths**: Path traversal (`..`) blocked. Shell injection characters
  blocked.
- **Session IDs**: Validated as exactly 8 lowercase hexadecimal characters.

### Process Isolation

- Socat processes are launched via `setsid` in isolated process groups.
- PID-file handoff ensures the correct PID is tracked (not a wrapper PID).
- Stop operations use process group kill (`kill -TERM -${PGID}`) for
  complete tree termination.
- Stop operations are protocol-scoped to prevent cross-session interference.

### File System Security

- Session directory permissions: 700 (owner read/write/execute only).
- Session file permissions: 600 (owner read/write only).
- Private key file permissions: 600 (owner read/write only).
- Certificate file permissions: 644 (world-readable, as is standard for
  public certificates).
- PID staging files are removed immediately after reading.

### Logging Security

- Structured log format with correlation IDs for forensic reconstruction.
- Sensitive data (private key contents, password material) is never written
  to logs by the script itself.
- Capture logs may contain sensitive traffic data (see Known Limitations).

---

## Threat Model

### In Scope

The following threats are considered within the project's threat model and
are addressed by implemented controls:

| Threat | Category | Mitigation |
|--------|----------|------------|
| Command injection via hostname/port/path parameters | Input validation (CWE-78) | Whitelist validation, metacharacter blocking |
| Path traversal via file path parameters | Input validation (CWE-22) | `..` detection, injection character blocking |
| Orphaned socat processes after failed stop | Process management | PGID-based tree kill, port-based fallback, dead session cleanup |
| Cross-session interference during stop | Process isolation | Protocol-scoped stop operations, per-session PGID |
| Session file tampering | File integrity | Restrictive permissions (600), session directory (700) |
| Private key exposure | Credential protection | Restrictive permissions (600), keys excluded from .gitignore |
| Stale session data after external process kill | State consistency | `session_cleanup_dead`, `--cleanup` flag |
| Process tracking evasion (wrong PID) | Process management | PID-file handoff via `setsid` + `exec` pattern |
| Terminal blocking as denial of service | Availability | `LAUNCH_SID` global variable (no `$()` subshell capture) |

### Out of Scope

The following threats are explicitly **not** addressed by socat_manager.sh
and must be mitigated through external controls:

| Threat | Why Out of Scope | Recommended External Control |
|--------|------------------|------------------------------|
| Network-level attacks against socat listeners | socat_manager manages processes, not network security | Firewall rules (iptables/nftables), network segmentation |
| Unauthorized connections to forwarded/redirected ports | No authentication layer in socat TCP/UDP modes | Application-level authentication, VPN, firewall ACLs |
| Traffic interception by third parties | No encryption (except tunnel mode TLS) | Use tunnel mode, VPN, or application-layer TLS |
| Self-signed certificate trust | Auto-generated certs are not CA-signed | Provide CA-signed certs via `--cert`/`--key`, certificate pinning |
| Capture log data exposure | Capture logs contain raw traffic including potentially sensitive data | File system permissions, encryption at rest, access controls, log rotation |
| Privilege escalation from socat process | socat runs with invoking user's privileges | Principle of least privilege, dedicated service accounts, SELinux/AppArmor |
| Resource exhaustion (too many sessions/forks) | No built-in rate limiting or connection caps | OS-level ulimits, cgroups, connection rate limiting at firewall |
| Modification of the script itself | Script integrity not verified at runtime | File integrity monitoring (AIDE, OSSEC), read-only filesystem mount |
| Supply chain attacks on socat/openssl | Dependency management is OS-level | Package manager signature verification, pinned package versions |
| Local privilege escalation via session directory | Requires local access to session directory | File system permissions (already 700), disk encryption |

---

## Implemented Security Controls

### Input Validation (CWE-20)

All functions that accept external input validate before processing:

| Function | Validates | Blocks |
|----------|-----------|--------|
| `validate_port` | Integer type, range 1-65535, privileged port warning | Non-integer, out-of-range, negative values |
| `validate_port_range` | Format START-END, both ends valid, max span 1000 | Malformed ranges, excessively large spans |
| `validate_port_list` | Comma-separated integers, each in valid range | Empty lists, non-integer entries |
| `validate_hostname` | IPv4 (octet ≤ 255), IPv6 (hex+colon), RFC 1123 hostname | Shell metacharacters `;` `\|` `&` `$` `` ` `` `(` `)` `{` `}` `[` `]` `<` `>` `!` `#` |
| `validate_protocol` | Whitelist: tcp, tcp4, tcp6, udp, udp4, udp6 | Arbitrary strings, injection attempts |
| `validate_file_path` | Non-empty, no path traversal, no injection characters | `..` sequences, `;` `\|` `&` `$` `` ` `` |
| `validate_session_id` | Exactly 8 lowercase hex characters | Non-hex, wrong length, uppercase, injection characters |

### Command Injection Prevention (CWE-78)

- Hostnames, ports, and protocols are validated before interpolation into socat
  command strings.
- The `build_socat_*_cmd` functions construct commands from validated components
  only.
- No user-supplied strings are passed to `eval` without prior validation.
- Session file parsing uses `grep` + `cut` (not `source` or `eval`) to prevent
  code execution from tampered session files.

### Path Traversal Prevention (CWE-22)

- All file path parameters checked for `..` sequences.
- Log file paths are constructed from validated components (protocol, port,
  timestamp) rather than raw user input.
- Session files are read by validated Session ID (8 hex chars) which cannot
  contain path separators.

### Process Management Safety

- `_kill_by_port` verifies process name is `socat` via `ps -o comm=` before
  sending any kill signal.
- Stop operations target only the session's own protocol to prevent
  cross-session interference in dual-stack configurations.
- `session_cleanup_dead` requires both PID and PGID to be confirmed dead
  before removing a session file.
- `_cleanup_orphaned_socat` reports untracked socat processes but does not
  auto-kill them to prevent collateral damage to processes managed by other
  tools.

---

## Known Limitations and Accepted Risks

### 1. `eval` Usage for Command Execution

The script uses `eval` to execute constructed socat command strings. While all
interpolated values pass through input validation, `eval` inherently carries
risk if validation is bypassed or a new code path introduces unvalidated input.

**Mitigation**: All inputs validated before command string construction.
Validation functions are called at the mode handler level before the builder
functions. The `--socat-opts` parameter (listen mode) is the highest-risk
input as it passes arbitrary socat address options; users should exercise
caution with this parameter.

**Future improvement**: Consider replacing `eval` with array-based command
execution (`"${cmd_array[@]}"`) for defense in depth.

### 2. Capture Logs Contain Sensitive Data

When `--capture` is enabled, socat's `-v` mode writes raw traffic hex dumps
to log files. This may include passwords, authentication tokens, session
cookies, personal data, or other sensitive information in plaintext.

**Mitigation**: Capture log files inherit the umask of the invoking user.
The `.gitignore` excludes all log files from version control.

**Recommended**: Apply restrictive file permissions to the `logs/` directory.
Encrypt the filesystem or `logs/` directory at rest. Implement log rotation
with secure deletion. Limit access to capture logs to authorized personnel
only. Comply with applicable data protection regulations (GDPR, HIPAA, etc.)
when capturing traffic.

### 3. Self-Signed Certificates (Tunnel Mode)

When no certificate is provided to tunnel mode, a self-signed certificate is
auto-generated. This certificate is not trusted by clients and is vulnerable
to man-in-the-middle attacks if an attacker can intercept the initial
connection.

**Mitigation**: Private key files are generated with 600 permissions.

**Recommended**: Provide CA-signed certificates via `--cert`/`--key` for
production deployments. Implement certificate pinning on the client side.

### 4. No Authentication on Listeners/Forwarders/Redirectors

Socat TCP/UDP listeners do not implement any authentication. Anyone with
network access to the listening port can connect.

**Mitigation**: None at the application level.

**Recommended**: Use firewall rules (iptables, nftables, security groups) to
restrict source addresses. Deploy within a VPN or isolated network segment.
Use tunnel mode for encrypted connections.

### 5. Race Condition Window During Launch

Between the moment socat binds a port and the session file is written, there
is a brief window (~0.3-0.5 seconds) where the process is running but not
yet tracked. If the script is killed during this window, the socat process
becomes orphaned.

**Mitigation**: `_cleanup_orphaned_socat` detects and reports untracked socat
processes. The PID staging file provides a partial tracking mechanism during
this window.

### 6. Session File as Source of Truth

Session files are the sole record of managed processes. If session files are
deleted or corrupted externally, the corresponding socat processes become
unmanaged orphans.

**Mitigation**: Session directory permissions (700) restrict access. The
`status --verbose` flag shows system-level socat listeners via `ss` regardless
of session file state, enabling discovery of untracked processes.

---

## Secure Deployment Guidelines

### 1. Principle of Least Privilege

Run socat_manager.sh with the minimum necessary privileges:

```bash
# For unprivileged ports (≥1024): run as a regular user
./socat_manager.sh listen --port 8080

# For privileged ports (<1024): use sudo only when needed
sudo ./socat_manager.sh listen --port 443

# Consider a dedicated service account for production deployments
sudo -u socat_service ./socat_manager.sh listen --port 8080
```

### 2. File System Hardening

```bash
# Restrict the project directory
chmod 750 /opt/tools/socat-manager/
chown root:socat_group /opt/tools/socat-manager/

# Restrict the script itself (read+execute only)
chmod 550 /opt/tools/socat-manager/socat_manager.sh

# Ensure runtime directories have correct permissions (auto-set by script)
# sessions/ → 700, session files → 600, private keys → 600
```

### 3. Network Segmentation

- Deploy listeners and redirectors behind a firewall.
- Restrict source addresses that can connect to forwarded/redirected ports.
- Use network namespaces or VLANs to isolate socat sessions from production
  traffic.

### 4. Log Protection

```bash
# Restrict log directory
chmod 750 /opt/tools/socat-manager/logs/

# Encrypt at rest (if filesystem supports it)
# Or use encrypted directories via fscrypt, eCryptfs, or LUKS

# Implement log rotation with secure deletion
cat > /etc/logrotate.d/socat-manager << 'EOF'
/opt/tools/socat-manager/logs/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 640 root socat_group
    shred
    shredcycles 3
}
EOF
```

### 5. Monitoring and Alerting

- Monitor for unexpected socat processes: `pgrep -a socat`
- Monitor for unexpected listening ports: `ss -tlnp` / `ss -ulnp`
- Set up file integrity monitoring on the script and session directory
- Alert on session files created outside expected operational windows

### 6. Mandatory Access Control

For high-security environments, consider SELinux or AppArmor profiles to
restrict what socat processes can access:

```bash
# Example AppArmor profile skeleton (customize for your deployment)
# /etc/apparmor.d/usr.bin.socat
/usr/bin/socat {
    # Network access
    network tcp,
    network udp,

    # File access (restrict to socat_manager directories)
    /opt/tools/socat-manager/logs/** rw,
    /opt/tools/socat-manager/certs/** r,

    # Deny everything else
    deny /etc/** w,
    deny /home/** rwx,
}
```

---

## Dependency Security

### socat

socat is the core dependency. Security considerations:

- **Keep socat updated**: Security fixes are released periodically. Monitor
  your distribution's security advisories.
- **Verify package integrity**: Use your package manager's signature
  verification (`apt-get` and `yum` do this automatically).
- **Check version**: `socat -V | head -5`

Known socat CVEs should be tracked via:
- [NVD search for socat](https://nvd.nist.gov/vuln/search/results?query=socat)
- Your distribution's security tracker (e.g., Debian Security Tracker,
  Ubuntu CVE Tracker, Red Hat CVE Database)

### OpenSSL

OpenSSL is used for certificate generation in tunnel mode:

- **Keep OpenSSL updated**: OpenSSL vulnerabilities can affect tunnel mode
  security.
- **Verify version**: `openssl version`
- **Monitor advisories**: [OpenSSL Security Advisories](https://www.openssl.org/news/secadv/)

### Bash

Bash is the script interpreter:

- **Minimum version**: 4.4+ required.
- **Keep bash updated**: Critical bash vulnerabilities (e.g., Shellshock,
  CVE-2014-6271) have been discovered historically.
- **Verify version**: `bash --version`

---

## Security-Related Configuration

### Configurable Constants

The following constants in the script can be adjusted for security tuning:

| Constant | Default | Description | Security Relevance |
|----------|---------|-------------|-------------------|
| `STOP_GRACE_SECONDS` | 5 | Seconds to wait after SIGTERM before SIGKILL | Longer grace periods allow more time for clean shutdown but delay forced termination |
| `STOP_VERIFY_RETRIES` | 5 | Number of port-freed verification checks | More retries increase confidence that the port is truly released |
| `STOP_VERIFY_INTERVAL` | 0.5 | Seconds between verification checks | Shorter intervals provide faster verification |
| `PID_FILE_WAIT_ITERS` | 20 | Iterations (×0.1s) waiting for PID file | Longer timeout handles slow systems but increases launch window |
| `DEFAULT_BACKLOG` | 128 | TCP connection backlog depth | Higher values handle burst connections but consume more kernel memory |
| `DEFAULT_WATCHDOG_MAX_RESTARTS` | 10 | Maximum auto-restarts before giving up | Limits resource consumption from crash loops |

### Environment Hardening

```bash
# Restrict umask for the socat_manager process
umask 0077
./socat_manager.sh listen --port 8080

# Limit resource usage via ulimits
ulimit -n 1024    # Max open file descriptors
ulimit -u 256     # Max user processes
./socat_manager.sh batch --range 8000-8010
```

---

## Security Changelog

Security-relevant changes across versions:

| Version | Change | Security Impact |
|---------|--------|-----------------|
| 2.3.0 | `--proto` on tunnel mode rejects UDP with clear error | Prevents accidental unencrypted tunnel configuration |
| 2.2.0 | Protocol-scoped stop operations | Prevents cross-protocol interference (session integrity) |
| 2.2.0 | `_kill_by_port` protocol-scoped | Prevents killing unrelated sessions on shared ports |
| 2.2.0 | Session names include protocol | Prevents session name collision on dual-stack |
| 2.1.0 | PID-file handoff via `setsid` + `exec` | Correct PID tracking prevents targeting wrong processes |
| 2.1.0 | `LAUNCH_SID` global (no `$()` subshell) | Eliminates terminal blocking (availability) |
| 2.1.0 | Session error logs | Enables post-mortem analysis of socat failures |
| 2.0.0 | Session file permissions 600 | Restricts session metadata to owner only |
| 2.0.0 | Session directory permissions 700 | Restricts session directory to owner only |
| 2.0.0 | `_kill_by_port` verifies process name is `socat` | Prevents killing non-socat processes |
| 2.0.0 | Session ID validation (8 hex chars) | Prevents injection via session ID parameters |
| 2.0.0 | PGID-based tree kill | Ensures complete process termination including fork children |
| 1.0.0 | Whitelist-based input validation | Prevents command injection via ports, hostnames, paths |
| 1.0.0 | Metacharacter blocking on hostnames | Prevents shell injection via hostname parameters |
| 1.0.0 | Path traversal detection | Prevents file access outside intended directories |
| 1.0.0 | Private key permissions 600 | Restricts TLS private keys to owner only |
| 1.0.0 | Structured logging with correlation IDs | Enables forensic reconstruction of operations |
