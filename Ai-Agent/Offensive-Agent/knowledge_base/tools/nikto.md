---
tool_name: nikto
category: scanning
tags: [web-scanner, misconfiguration, outdated-software, default-files, security-headers]
used_by_agents: [recon_agent]
---

# Nikto — Web Server Scanner

## What It Does
Scans web servers for dangerous files, outdated software, misconfigurations, and known vulnerabilities. Checks 6700+ potentially dangerous files/programs. Good for initial recon to find low-hanging fruit before targeted testing.

---

## Basic Scanning

```bash
nikto -h http://target.com
nikto -h https://target.com
nikto -h 192.168.1.100
nikto -h http://target.com:8080
nikto -h http://target.com -p 80,8080,8443
```

---

## SSL/HTTPS

```bash
nikto -h https://target.com -ssl
nikto -h target.com -p 443 -ssl
```

---

## Scan Tuning (Focus on Specific Tests)

```bash
# 1 = Interesting File / Default files
# 2 = Misconfiguration / Default file
# 3 = Information Disclosure
# 4 = Injection (XSS/Script/HTML)
# 5 = Remote File Retrieval (Inside Web Root)
# 6 = Denial of Service
# 7 = Remote File Retrieval (Server Wide)
# 8 = Command Execution / Remote Shell
# 9 = SQL Injection
# 0 = File Upload

nikto -h http://target.com -Tuning 123       # files + misconfig + info disclosure
nikto -h http://target.com -Tuning 4589       # injection + file retrieval + rce + sqli
nikto -h http://target.com -Tuning x          # reverse tuning (exclude type x)
```

---

## Evasion Techniques

```bash
# 1 = Random URI encoding
# 2 = Directory self-reference (/./)
# 3 = Premature URL ending
# 4 = Prepend long random string
# 5 = Fake parameter
# 6 = TAB as request spacer
# 7 = Change URL case
# 8 = Use Windows directory separator (\)

nikto -h http://target.com -evasion 1
nikto -h http://target.com -evasion 1234
```

---

## Authentication & Headers

```bash
# Basic auth
nikto -h http://target.com -id admin:password

# Cookies
nikto -h http://target.com -C "session=abc123;security=low"

# Custom User-Agent
nikto -h http://target.com -useragent "Mozilla/5.0 (Windows NT 10.0)"

# Virtual host
nikto -h http://192.168.1.100 -vhost target.com
```

---

## Plugins

```bash
# List available plugins
nikto -h http://target.com -list-plugins

# Run specific plugin
nikto -h http://target.com -Plugins "headers"
nikto -h http://target.com -Plugins "shellshock"
nikto -h http://target.com -Plugins "cgi"
nikto -h http://target.com -Plugins "put_del_test"
```

---

## Proxy

```bash
nikto -h http://target.com -useproxy http://127.0.0.1:8080
```

---

## Performance

```bash
# Timeout per request (seconds)
nikto -h http://target.com -timeout 10

# Pause between requests (seconds)
nikto -h http://target.com -Pause 1

# Max scan time (seconds)
nikto -h http://target.com -maxtime 300
```

---

## Output

```bash
nikto -h http://target.com -o output.txt -Format txt
nikto -h http://target.com -o output.json -Format json
nikto -h http://target.com -o output.xml -Format xml
nikto -h http://target.com -o output.html -Format htm
nikto -h http://target.com -o output.csv -Format csv

# Display options: V=verbose, 1=show redirects, 2=show cookies, E=HTTP errors, P=progress
nikto -h http://target.com -Display V
```

---

## Batch Scanning

```bash
nikto -h targets.txt -o batch_results.json -Format json
```

---

## Output Interpretation

### Findings:
```
+ Server: Apache/2.4.49 (Debian)
+ /: The anti-clickjacking X-Frame-Options header is not present.
+ /: The X-Content-Type-Options header is not set.
+ /icons/README: Apache default file found.
+ /config.php.bak: PHP config backup found, may contain credentials.
+ /phpinfo.php: PHP info page found. Output reveals detailed server info.
+ /admin/: Admin directory found.
+ /test/: Test directory with listing enabled.
```
**Each line**: `+ <path>: <finding description>`

Lines starting with `+` are findings. The path tells you where, the description tells you what.

### Summary:
```
+ 7 host(s) tested
+ 15 item(s) reported on remote host
```

### Nothing notable:
```
+ 0 item(s) reported on remote host
```

**Success indicators**: `+` prefixed lines with findings, `item(s) reported` count > 0.
**Failure indicators**: `0 item(s) reported`, connection errors.

---

## Common Flags Reference

| Flag | Purpose |
|------|---------|
| `-h` | Target host (URL, IP, or file) |
| `-p` | Port(s) to scan |
| `-ssl` | Force SSL mode |
| `-Tuning` | Scan test types to include (1-9, 0) |
| `-evasion` | IDS evasion technique(s) (1-8) |
| `-id` | Basic auth credentials |
| `-C` | Cookie string |
| `-useragent` | Custom User-Agent |
| `-vhost` | Virtual host header |
| `-Plugins` | Specific plugin(s) to run |
| `-useproxy` | Proxy URL |
| `-timeout` | Request timeout (seconds) |
| `-Pause` | Pause between requests |
| `-maxtime` | Max scan duration (seconds) |
| `-o` | Output file |
| `-Format` | Output format (txt, json, xml, htm, csv) |
| `-Display` | Display options (V, 1, 2, E, P) |
