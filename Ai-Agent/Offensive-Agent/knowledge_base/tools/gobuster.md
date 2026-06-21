---
tool_name: gobuster
category: discovery
tags: [directory-discovery, dns-enumeration, vhost-discovery, brute-force]
used_by_agents: [recon_agent]
---

# gobuster — Directory, DNS & VHost Brute Forcer

## What It Does
Fast brute-force tool for discovering directories/files, DNS subdomains, and virtual hosts. Written in Go — very fast. Complements ffuf (gobuster is better for pure dir/dns brute force, ffuf is better for parameter fuzzing).

---

## Directory & File Discovery (dir mode)

```bash
# Basic directory scan
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt

# With file extensions
gobuster dir -u http://target.com -w wordlist.txt -x php,html,txt,bak,zip,config

# Filter status codes
gobuster dir -u http://target.com -w wordlist.txt -s 200,301,302,403
gobuster dir -u http://target.com -w wordlist.txt -b 404,500

# Print full URLs
gobuster dir -u http://target.com -w wordlist.txt -e

# Follow redirects
gobuster dir -u http://target.com -w wordlist.txt -r

# Show response body length
gobuster dir -u http://target.com -w wordlist.txt -l
```

---

## DNS Subdomain Enumeration (dns mode)

```bash
gobuster dns -d target.com -w /usr/share/wordlists/subdomains-top1million-5000.txt
gobuster dns -d target.com -w wordlist.txt --show-ips
gobuster dns -d target.com -w wordlist.txt -r 8.8.8.8
```

---

## Virtual Host Enumeration (vhost mode)

```bash
gobuster vhost -u http://target.com -w wordlist.txt --append-domain
gobuster vhost -u http://target.com -w wordlist.txt --exclude-length 250
```

---

## Authentication & Headers

```bash
# Basic auth
gobuster dir -u http://target.com -w wordlist.txt -U admin -P password

# Cookie-based session
gobuster dir -u http://target.com -w wordlist.txt -c "session=abc123;security=low"

# Custom headers
gobuster dir -u http://target.com -w wordlist.txt -H "Authorization: Bearer TOKEN"
```

---

## Performance

```bash
# Threads (default 10)
gobuster dir -u http://target.com -w wordlist.txt -t 50

# Throttle (delay between requests)
gobuster dir -u http://target.com -w wordlist.txt --delay 500ms

# HTTPS without cert validation
gobuster dir -u https://target.com -w wordlist.txt -k
```

---

## Proxy & Output

```bash
gobuster dir -u http://target.com -w wordlist.txt --proxy http://127.0.0.1:8080
gobuster dir -u http://target.com -w wordlist.txt -o results.txt
gobuster dir -u http://target.com -w wordlist.txt -q  # quiet (results only)
```

---

## Output Interpretation

### Directories/files found:
```
/admin                (Status: 301) [Size: 314]
/config.php.bak       (Status: 200) [Size: 2847]
/uploads              (Status: 403) [Size: 277]
/robots.txt           (Status: 200) [Size: 45]
```
**Each line**: `/<path> (Status: <code>) [Size: <bytes>]`

### DNS subdomains found:
```
Found: admin.target.com [IP: 192.168.1.10]
Found: dev.target.com [IP: 192.168.1.11]
```

### Nothing found:
Only progress bar output, no result lines.

**Success indicators**: Lines starting with `/` (dir mode) or `Found:` (dns mode).
**Failure indicators**: No result lines, only progress output.

---

## Common Flags Reference

| Flag | Purpose |
|------|---------|
| `-u` | Target URL (dir/vhost modes) |
| `-d` | Target domain (dns mode) |
| `-w` | Wordlist path |
| `-x` | File extensions to test (comma-separated) |
| `-s` | Show only these status codes |
| `-b` | Hide these status codes |
| `-t` | Threads (default 10) |
| `-o` | Output file |
| `-k` | Skip TLS cert validation |
| `-c` | Cookie string |
| `-H` | Custom header |
| `-U` | Basic auth username |
| `-P` | Basic auth password |
| `-e` | Print full URLs |
| `-r` | Follow redirects |
| `-l` | Show response body length |
| `-q` | Quiet mode (no banner/progress) |
| `--proxy` | HTTP/SOCKS proxy |
| `--delay` | Delay between requests |
| `--show-ips` | Show resolved IPs (dns mode) |
| `--append-domain` | Append base domain to vhost wordlist |
| `--exclude-length` | Exclude responses by body length (vhost mode) |
