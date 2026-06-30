---
tags: [endpoint-security]
---

# Linux Syslog and Auth Logs

## TCM Exam Objectives

Before taking the PSAA exam, you must be able to:

- Compare traditional Antivirus (AV) with Endpoint Detection and Response (EDR) capabilities
- Configure and interpret Application Allowlisting using AppLocker and WDAC
- Create and analyze host-based firewall rules (Windows Defender Firewall)
- Examine file system and registry artifacts for forensic evidence of compromise
- Analyze Linux syslog and auth logs for SSH brute force and privilege escalation
- Investigate process and service information to detect malware and persistence
- Query Windows Event Logs (System, Security, Application) for incident detection
- Correlate endpoint telemetry with network evidence for comprehensive incident response

Linux logging is the foundation of endpoint monitoring in Linux environments. The syslog system aggregates kernel, authentication, service, and application events into centralized log files. Authentication logs are the primary source for detecting SSH brute force, sudo abuse, and user account compromise.

- Syslog architecture: rsyslog, syslog-ng, and log locations
- Auth log (`/var/log/auth.log`): SSH logins, sudo, PAM events
- Syslog messages: facility, severity, and message format
- Log analysis for incident detection


## Syslog Architecture

### The Syslog Message Format

```
Mar 21 15:30:45 webserver sshd[12345]: Failed password for root from 185.220.101.45 port 54321 ssh2
```

| Field | Example | Meaning |
|-------|---------|---------|
| Timestamp | Mar 21 15:30:45 | Month Day HH:MM:SS (no year by default) |
| Hostname | webserver | Source host (useful for centralized logging) |
| Process[PID] | sshd[12345] | Process name and PID generating the log |
| Message | Failed password... | Actual log content |

### Syslog Facilities and Severities

| Facility Code | Facility Name | Typical Use |
|---------------|---------------|-------------|
| 0 | kern | Kernel messages |
| 1 | user | User-level messages |
| 2 | mail | Mail system |
| 3 | daemon | System daemons (sshd, httpd) |
| 4 | auth | Authentication (security/authorization) |
| 5 | syslog | Syslogd itself |
| 8 | cron | Cron daemon |

| Severity Code | Severity | Meaning |
|---------------|----------|---------|
| 0 | emerg | System is unusable |
| 1 | alert | Immediate action required |
| 2 | crit | Critical condition |
| 3 | err | Error condition |
| 4 | warning | Warning condition |
| 5 | notice | Normal but significant |
| 6 | info | Informational |
| 7 | debug | Debug-level messages |

## Key Log Files

| Log File | Contents | PSAA Relevance |
|----------|----------|----------------|
| `/var/log/auth.log` | Authentication (SSH, sudo, PAM, login) | Primary for SSHD attacks, sudo abuse |
| `/var/log/syslog` | General system messages | Application, service, kernel events |
| `/var/log/kern.log` | Kernel messages | Kernel exploits, driver issues |
| `/var/log/dpkg.log` | Package installation logs | Attacker installed tools |
| `/var/log/messages` | Boot and general messages | System startup, daemon status |
| `/var/log/boot.log` | Boot sequence messages | Early boot compromise |
| `/var/log/secure` | Red Hat/CentOS equivalent of auth.log | RHEL-based distros |

## Auth Log Analysis

### SSH Login Detection

```bash
grep "Accepted password\|Accepted publickey" /var/log/auth.log

grep "Failed password" /var/log/auth.log

grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr

grep "185.220.101.45" /var/log/auth.log | grep "sshd"
```

### Sudo Detection

```bash
grep "sudo:" /var/log/auth.log

grep "sudo:.*authentication failure" /var/log/auth.log

grep "sudo:.*COMMAND=" /var/log/auth.log
```

### User Account Detection

```bash
grep "new user" /var/log/auth.log

grep "password changed" /var/log/auth.log

grep "delete user" /var/log/auth.log

grep "added to group\|removed from group" /var/log/auth.log
```

### SSH Brute Force Analysis

```bash
awk '/Failed password/{ip[$(NF-3)]++} END{for (i in ip) print ip[i], i}' /var/log/auth.log | sort -nr | head -10

grep "Failed password" /var/log/auth.log | awk '{print $(NF-5)}' | sort | uniq -c | sort -nr

grep "Failed password" /var/log/auth.log | awk '{print $1, $2}' | sort | uniq -c
```

## journalctl (Systemd)

Modern Linux systems use `journald` for log collection. Logs are viewable with `journalctl`. This is the primary log access method on Ubuntu 18.04+, RHEL 7+, and all modern systemd-based distros.

```bash
# View logs for a specific unit
journalctl -u sshd

# Filter for failed passwords
journalctl -u sshd | grep "Failed password"

# Show sudo commands
journalctl -u sudo | grep "COMMAND"

# Time-based filtering
journalctl --since "2024-03-21 15:00:00" --until "2024-03-21 16:00:00"

# Follow (real-time tail)
journalctl -u sshd -f

# Export to file for analysis
journalctl -u sshd > sshd_export.log

# Kernel messages
journalctl -k

# All authentication events
journalctl _TRANSPORT=audit

# JSON output for machine parsing
journalctl -u sshd -o json

# Show only the last 50 lines with priority error or higher
journalctl -u sshd -p err -n 50

# Show boot-specific logs
journalctl -b -1  # previous boot logs

# Disk usage and rotation
journalctl --disk-usage
journalctl --vacuum-time=2weeks
```

> **Note:** journald does not write to `/var/log/auth.log` by default on all distros. On Ubuntu 18.04+, the `systemd-journald` service stores logs in `/var/log/journal/`. The traditional syslog files exist only if `rsyslog` is installed and configured. Always use `journalctl` first.

## auditd for Enhanced Monitoring

Beyond syslog, `auditd` provides granular file, process, and system call auditing:

```bash
# Check if auditd is running
systemctl status auditd

# Search for sudo execution events
ausearch -m USER_CMD

# Search for file access to /etc/shadow
ausearch -f /etc/shadow

# Search for system call events from a specific PID
ausearch -p 12345

# Generate a report of all events in time range
aureport --start 2024-03-21 15:00 --end 2024-03-21 16:00

# Watch a specific path for access
auditctl -w /etc/passwd -p wa -k passwd_changes
```

> **Exam Tip:** Always check `journalctl` before `/var/log/auth.log`. On modern systemd-based distros (Ubuntu 18.04+, RHEL 7+), `rsyslogd` may not be installed, meaning `/var/log/auth.log` won't exist. Run `journalctl -u sshd` as the primary auth log source.

> **Exam Tip:** The absence of log entries is itself evidence. If /var/log/auth.log has no entries for a known compromise time window, check if `auditd` or `rsyslog` was stopped. Run `journalctl -u rsyslog --since "2024-01-01"` to check for service interruptions that may indicate log tampering.

> **Exam Tip:** SSH brute force detection isn't just about failed passwords. Also check for `Connection closed by authenticating user` messages — these indicate the attacker disconnected after a failed attempt, which may mean they moved to another target or source IP.


## PSAA Investigation Workflow

### Scenario: SSH Brute Force

1. **Check auth.log for failed password events:**
```
grep "Failed password" /var/log/auth.log | head -20
```

2. **Identify top attacking IPs:**
```
awk '/Failed password/{ip[$(NF-3)]++} END{for (i in ip) print ip[i], i}' /var/log/auth.log | sort -nr
```

3. **Check if any succeeded:**
```
grep "Accepted password\|Accepted publickey" /var/log/auth.log
```

4. **If success found, check subsequent activity:**
```
grep "192.168.1.105" /var/log/auth.log | grep "sudo:.*COMMAND="
```
This reveals what the attacker did after logging in.

5. **Check for post-exploitation tool installation:**
```
grep "install\|wget\|curl\|git clone" /var/log/syslog
grep "install" /var/log/dpkg.log
```

### Scenario: Privilege Escalation

1. **Failed sudo attempts:**
```
grep "sudo:.*authentication failure" /var/log/auth.log
```

2. **Successful sudo escalation:**
```
grep "sudo:.*COMMAND=" /var/log/auth.log
```

3. **Check for sudoers modifications:**
```
grep "sudoers" /var/log/auth.log
```

## Syslog-ng and Centralized Logging

In enterprise environments, logs are forwarded to a SIEM:

```bash
destination d_siem {
    syslog("192.168.1.100" port(514) transport("tcp"));
};
log {
    source(s_sys);
    destination(d_siem);
};
```

## Suspicious Auth Log Patterns

| Pattern | Interpretation |
|---------|----------------|
| Many `Failed password` from one IP | SSH brute force |
| `Failed password` for root then other users | First root, then user enumeration |
| `Accepted password` from known-bad IP | Successful compromise |
| `sudo: COMMAND` for unusual commands (`wget`, `curl`, `base64`) | Post-exploitation tool download |
| `new user` created | Backdoor account |
| `su:` to root from non-admin user | Privilege escalation |
| `authentication failure` for `PAM` modules | PAM backdoor or misconfiguration |

## PSAA Exam Traps

- **auth.log vs secure:** Debian/Ubuntu use `/var/log/auth.log`; RHEL/CentOS use `/var/log/secure`. Know which distro.
- **journalctl is the new standard.** On systemd systems, `/var/log/auth.log` may not exist unless `rsyslog` is installed. Always check with `journalctl` first.
- **Timestamps lack year.** Add `--since` flag to journalctl or parse syslog timestamps with knowledge of log rotation dates.
- **IPTables logging goes to kern.log or syslog**, not auth.log. `grep "IN=" /var/log/kern.log` for firewall drops.


```mermaid
flowchart LR
    LINUX[Linux Host] --> AUTH[/var/log/auth.log]
    LINUX --> SYS[/var/log/syslog]
    LINUX --> KERN[/var/log/kern.log]
    AUTH --> SSH[SSH Logins]
    AUTH --> SUDO[sudo Commands]
    AUTH --> USER[User Changes]
    SSH --> FAIL[Failed Password - Brute Force]
    SSH --> ACCEPT[Accepted - Compromise?]
    SUDO --> PRIVESC[Privilege Escalation]
    FAIL --> BLOCK[Block Source IP]
    ACCEPT --> INVESTIGATE[Full Investigation]
```

```mermaid
flowchart TD
    HOSTS[Linux Hosts] --> RSYSLOG[rsyslog / syslog-ng]
    RSYSLOG --> AUTH[/var/log/auth.log\nSSH, sudo, PAM events]
    RSYSLOG --> SYS[/var/log/syslog\nSystem & daemon messages]
    RSYSLOG --> KERN[/var/log/kern.log\nKernel messages]
    RSYSLOG --> DPKG[/var/log/dpkg.log\nPackage installs]
    AUTH --> CENTRAL[Central Log Collector\nsyslog TCP/514]
    SYS --> CENTRAL
    KERN --> CENTRAL
    DPKG --> CENTRAL
    CENTRAL --> SIEM[SIEM / SOC]
    SIEM --> ALERT[Alert on Suspicious Patterns\nSSH brute force, sudo abuse\nPrivilege escalation]
```

## Recap

- `/var/log/auth.log` (or `/var/log/secure`) is the primary log for authentication events
- Syslog format: Timestamp, Hostname, Process[PID], Message
- Key auth events: SSH logins (Accepted/Failed), sudo commands, user account changes
- `journalctl` replaces traditional syslog on systemd-based systems
- Brute force detection: count `Failed password` entries by source IP and username
- Post-exploitation analysis: correlate successful logins with subsequent sudo and installation events