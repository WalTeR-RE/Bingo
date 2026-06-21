---
tool_name: wpscan
category: scanning
tags: [wordpress, cms, plugins, themes, users, brute-force, cve]
used_by_agents: [recon_agent, discovery_agent, brute_force_agent]
---

# WPScan — WordPress Security Scanner

## What It Does
Dedicated WordPress vulnerability scanner. Enumerates users, plugins, themes, and their versions, then checks against a vulnerability database for known CVEs. Can also brute force WordPress login. Essential since WordPress powers ~40% of all websites.

## CRITICAL: Use `--no-banner` to reduce output noise. Use `-f json` for parseable output.

---

## Basic Scanning

```bash
# Default scan
wpscan --url http://target.com --no-banner

# Skip SSL verification
wpscan --url https://target.com --no-banner --disable-tls-checks
```

---

## Enumeration

### Users
```bash
wpscan --url http://target.com -e u --no-banner
wpscan --url http://target.com -e u1-100 --no-banner
```

### Plugins (all, vulnerable, popular)
```bash
# All plugins
wpscan --url http://target.com -e ap --no-banner

# Only vulnerable plugins
wpscan --url http://target.com -e vp --no-banner

# Popular plugins
wpscan --url http://target.com -e p --no-banner
```

### Themes
```bash
# All themes
wpscan --url http://target.com -e at --no-banner

# Vulnerable themes
wpscan --url http://target.com -e vt --no-banner
```

### Full enumeration (everything)
```bash
wpscan --url http://target.com -e ap,at,u,dbe --no-banner
```

### Enumerate with aggressive detection
```bash
wpscan --url http://target.com -e ap --plugins-detection aggressive --no-banner
```

---

## Vulnerability Database (API Token)

```bash
# With API token (required for vulnerability data)
wpscan --url http://target.com -e vp --api-token YOUR_TOKEN --no-banner

# Without token: enumerates versions but won't show CVE details
```

---

## Password Brute Force

```bash
# Single user
wpscan --url http://target.com -U admin -P /usr/share/wordlists/rockyou.txt --no-banner

# Multiple users
wpscan --url http://target.com -U users.txt -P passwords.txt --no-banner

# With max threads
wpscan --url http://target.com -U admin -P rockyou.txt -t 20 --no-banner

# Password attack via XML-RPC (faster, multi-call)
wpscan --url http://target.com -U admin -P rockyou.txt --password-attack xmlrpc-multicall --no-banner
```

---

## Detection Modes

```bash
# Passive (minimal requests)
wpscan --url http://target.com --detection-mode passive --no-banner

# Aggressive (more requests, better coverage)
wpscan --url http://target.com --detection-mode aggressive --no-banner

# Mixed (default)
wpscan --url http://target.com --detection-mode mixed --no-banner
```

---

## Headers & Authentication

```bash
# Custom cookies
wpscan --url http://target.com --cookie-string "session=abc123" --no-banner

# Custom headers
wpscan --url http://target.com --headers "Authorization: Bearer TOKEN" --no-banner

# HTTP basic auth (not WP login)
wpscan --url http://target.com --http-auth admin:password --no-banner

# Custom User-Agent
wpscan --url http://target.com --user-agent "Mozilla/5.0" --no-banner
```

---

## Proxy & Performance

```bash
# Through proxy
wpscan --url http://target.com --proxy http://127.0.0.1:8080 --no-banner

# Threads
wpscan --url http://target.com -t 10 --no-banner

# Request throttle (milliseconds)
wpscan --url http://target.com --throttle 500 --no-banner
```

---

## Output

```bash
# JSON output (best for parsing)
wpscan --url http://target.com -e vp -f json -o results.json --no-banner

# CLI table format (default)
wpscan --url http://target.com -f cli --no-banner

# CLI with no color
wpscan --url http://target.com -f cli-no-color --no-banner
```

---

## Output Interpretation

### WordPress detected:
```
[+] URL: http://target.com/
[+] WordPress version 5.9.3 identified (Insecure, released on 2022-04-05)
[+] WordPress theme in use: flavor
 | Version: 1.2 (Latest: 3.1)
```

### Users found:
```
[i] User(s) Identified:
[+] admin
 | Found By: Author Id Brute Forcing
[+] editor
 | Found By: Wp Json Api
```

### Vulnerable plugin found:
```
[+] flavor
 | Location: http://target.com/wp-content/plugins/flavor/
 | Last Updated: 2021-08-15
 | [!] The version is out of date, the latest version is 3.1
 |
 | [!] 2 vulnerabilities identified:
 |
 | [!] Title: Flavor < 2.0 - SQL Injection
 |     Fixed in: 2.0
 |     Reference: https://wpscan.com/vulnerability/xxxx
 |
 | [!] Title: Flavor < 2.5 - Stored XSS
 |     Fixed in: 2.5
```

### Password found:
```
[+] Performing password attack on Wp Login against 1 user/s
[SUCCESS] - admin / password123
```

### Nothing notable:
```
[+] Finished scanning, no vulnerabilities were identified.
```

**Success indicators**: `[!]` lines (vulnerabilities), `[SUCCESS]` (cracked password), `Insecure` version tag.
**Failure indicators**: `no vulnerabilities were identified`, `No WPScan API Token given` (limited results).

---

## Common Flags Reference

| Flag | Purpose |
|------|---------|
| `--url` | Target WordPress URL |
| `-e` | Enumeration options (u, ap, vp, at, vt, dbe) |
| `-U` | Username(s) or file for brute force |
| `-P` | Password wordlist for brute force |
| `--api-token` | WPScan API token for vulnerability data |
| `--detection-mode` | passive, mixed, aggressive |
| `--plugins-detection` | Plugin detection mode (passive, mixed, aggressive) |
| `--password-attack` | Attack type (wp-login, xmlrpc, xmlrpc-multicall) |
| `-t` | Max threads |
| `--throttle` | Delay between requests (ms) |
| `--cookie-string` | Cookie string |
| `--headers` | Custom headers |
| `--http-auth` | HTTP basic auth (user:pass) |
| `--proxy` | Proxy URL |
| `-f` | Output format (json, cli, cli-no-color) |
| `-o` | Output file |
| `--no-banner` | Suppress banner |
| `--disable-tls-checks` | Skip SSL cert validation |
| `--user-agent` | Custom User-Agent |
