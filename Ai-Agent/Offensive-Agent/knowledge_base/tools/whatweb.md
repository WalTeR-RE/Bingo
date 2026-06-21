---
tool_name: whatweb
category: reconnaissance
tags: [fingerprinting, technology-detection, cms-detection, web-server]
used_by_agents: [recon_agent]
---

# WhatWeb — Web Technology Fingerprinter

## What It Does
Identifies technologies used by a website: web servers, CMS platforms, JavaScript frameworks, analytics tools, programming languages, and more. Uses 1800+ plugins. Essential for the recon phase to understand the target stack before testing.

---

## Basic Usage

```bash
whatweb http://target.com
whatweb https://target.com
whatweb 192.168.1.100
whatweb http://target.com https://other-target.com
```

---

## Aggression Levels

```bash
# Stealthy (default) — one request
whatweb -a 1 http://target.com

# Aggressive — multiple requests, more plugins
whatweb -a 3 http://target.com

# Heavy — try all plugins, lots of requests
whatweb -a 4 http://target.com
```

---

## Input & Batch Scanning

```bash
whatweb -i targets.txt
whatweb --no-errors http://target.com
```

---

## Headers & Authentication

```bash
whatweb --cookie "session=abc123" http://target.com
whatweb --header "Authorization: Bearer TOKEN" http://target.com
whatweb --user admin:password http://target.com
whatweb --proxy 127.0.0.1:8080 http://target.com
```

---

## Output

```bash
# Verbose
whatweb -v http://target.com

# Quiet (brief)
whatweb --quiet http://target.com

# JSON (best for parsing)
whatweb --log-json=output.json http://target.com

# XML
whatweb --log-xml=output.xml http://target.com

# Brief text
whatweb --log-brief=output.txt http://target.com
```

---

## Plugin Control

```bash
# List all available plugins
whatweb -l

# Run specific plugin
whatweb -p wp-enum http://target.com

# Exclude a plugin
whatweb -p -wordpress http://target.com
```

---

## Performance

```bash
whatweb --max-threads 100 -i targets.txt
```

---

## Output Interpretation

### Standard output:
```
http://target.com [200 OK] Apache[2.4.49], Country[US][United States], HTML5, 
HTTPServer[Apache/2.4.49 (Debian)], IP[192.168.1.100], JQuery[3.5.1], PHP[7.4.33], 
Title[DVWA - Damn Vulnerable Web Application], X-Powered-By[PHP/7.4.33]
```
**Format**: `URL [Status] Technology[Version], Technology[Version], ...`

### Key technologies to look for:
- **Web server**: Apache, Nginx, IIS, LiteSpeed
- **Language**: PHP, Python, Java, ASP.NET
- **CMS**: WordPress, Joomla, Drupal
- **Frameworks**: jQuery, React, Angular, Django, Laravel
- **Security headers**: X-Frame-Options, CSP, HSTS
- **Server info**: X-Powered-By, Server header leaks

### Verbose output (`-v`):
```
WhatWeb report for http://target.com
Status    : 200 OK
Title     : DVWA - Damn Vulnerable Web Application
IP        : 192.168.1.100
Country   : US, United States

Summary   : Apache[2.4.49], PHP[7.4.33], JQuery[3.5.1], HTML5

Detected Plugins:
[ Apache ]
        Version: 2.4.49
[ PHP ]
        Version: 7.4.33
        Evidence: X-Powered-By: PHP/7.4.33
```

**Success indicators**: Any output with technologies detected.
**Failure indicators**: Connection errors or empty output.

---

## Common Flags Reference

| Flag | Purpose |
|------|---------|
| `-a` | Aggression level (1=stealthy, 3=aggressive, 4=heavy) |
| `-i` | Input file with target URLs |
| `-v` | Verbose output |
| `-q`, `--quiet` | Brief output |
| `--log-json` | JSON output file |
| `--log-xml` | XML output file |
| `--log-brief` | Brief text output file |
| `--cookie` | Cookie string |
| `--header` | Custom header |
| `--user` | Basic auth (user:password) |
| `--proxy` | Proxy URL |
| `-p` | Plugin selection (or `-plugin` to exclude) |
| `-l` | List all plugins |
| `--max-threads` | Concurrent threads (default 25) |
| `--no-errors` | Suppress error messages |
