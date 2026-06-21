---
tool_name: httpx
category: reconnaissance
tags: [http-probing, tech-detection, status-codes, live-hosts, web-fingerprinting]
used_by_agents: [recon_agent, discovery_agent]
---

# httpx — HTTP Probing & Fingerprinting

## What It Does
Fast HTTP toolkit from ProjectDiscovery. Probes hosts/URLs to check if they're alive, extracts status codes, titles, technologies, content lengths, and more. Designed for large-scale recon — takes lists of hosts/IPs and quickly identifies live web services. The glue between subdomain discovery and vulnerability scanning.

---

## Basic Usage

```bash
# Probe a single URL
echo "http://target.com" | httpx

# Probe list of hosts
httpx -l hosts.txt

# Probe with URL path
httpx -l hosts.txt -path "/admin"

# Probe from stdin (pipe from subfinder, etc.)
subfinder -d target.com -silent | httpx
cat ips.txt | httpx
```

---

## Information Extraction

```bash
# Status code
httpx -l hosts.txt -status-code

# Page title
httpx -l hosts.txt -title

# Content length
httpx -l hosts.txt -content-length

# Technology detection
httpx -l hosts.txt -tech-detect

# Web server
httpx -l hosts.txt -web-server

# IP address
httpx -l hosts.txt -ip

# Response time
httpx -l hosts.txt -rt

# All the above combined
httpx -l hosts.txt -status-code -title -tech-detect -web-server -ip -content-length

# Extract specific response header
httpx -l hosts.txt -include-response-header "X-Powered-By,Server"

# Follow redirects and show final URL
httpx -l hosts.txt -follow-redirects -location
```

---

## Filtering

```bash
# Only show specific status codes
httpx -l hosts.txt -mc 200,301,302,403

# Filter out status codes
httpx -l hosts.txt -fc 404,502,503

# Filter by content length
httpx -l hosts.txt -ml 100   # minimum length
httpx -l hosts.txt -cl 5000  # exact content length

# Match response body content
httpx -l hosts.txt -match-string "login"
httpx -l hosts.txt -match-regex "wordpress|joomla|drupal"

# Filter response body content
httpx -l hosts.txt -filter-string "404 Not Found"
```

---

## Screenshot & Hash

```bash
# Take screenshots of live hosts
httpx -l hosts.txt -screenshot

# Response body hash (detect unique pages)
httpx -l hosts.txt -hash md5
```

---

## Headers & Authentication

```bash
# Custom headers
httpx -l hosts.txt -H "Cookie: session=abc123"
httpx -l hosts.txt -H "Authorization: Bearer TOKEN"

# Custom HTTP method
httpx -l hosts.txt -x POST

# Request body
httpx -l hosts.txt -body '{"test": "value"}'

# Custom User-Agent
httpx -l hosts.txt -random-agent
```

---

## Performance

```bash
# Threads (default 50)
httpx -l hosts.txt -threads 100

# Rate limit
httpx -l hosts.txt -rl 50   # requests per second

# Timeout (seconds)
httpx -l hosts.txt -timeout 10

# Retries
httpx -l hosts.txt -retries 2
```

---

## Proxy

```bash
httpx -l hosts.txt -http-proxy http://127.0.0.1:8080
```

---

## Output

```bash
# JSON output (best for parsing)
httpx -l hosts.txt -j -o results.json

# Plain text
httpx -l hosts.txt -o results.txt

# Silent (only URLs, no stats)
httpx -l hosts.txt -silent

# No color
httpx -l hosts.txt -nc

# CSV output
httpx -l hosts.txt -csv -o results.csv
```

---

## Useful One-Liners

```bash
# Full recon probe with all info
subfinder -d target.com -silent | httpx -status-code -title -tech-detect -web-server -silent

# Find login pages
httpx -l hosts.txt -path "/login,/admin,/wp-login.php,/user/login" -mc 200 -silent

# Find hosts running specific tech
httpx -l hosts.txt -tech-detect -match-string "PHP" -silent

# Probe all ports for web services
httpx -l hosts.txt -ports 80,443,8080,8443,8000,3000,9090 -silent
```

---

## Output Interpretation

### Standard output:
```
http://target.com [200] [My Website] [Apache/2.4.49] [PHP,jQuery,Bootstrap]
https://api.target.com [403] [Forbidden]
http://dev.target.com [301] [Moved] -> https://dev.target.com
http://admin.target.com [200] [Admin Panel] [Nginx] [WordPress]
```
**Format**: `URL [status] [title] [server] [technologies]`

### JSON output (with `-j`):
```json
{
  "url": "http://target.com",
  "status_code": 200,
  "title": "My Website",
  "webserver": "Apache/2.4.49",
  "technologies": ["PHP", "jQuery", "Bootstrap"],
  "content_length": 15234,
  "host": "192.168.1.100"
}
```

### No live hosts:
Empty output or all hosts filtered out.

**High-value indicators**: 200 on `/admin`, `/wp-login.php`, `/phpmyadmin`; outdated server versions; exposed technologies.

---

## Common Flags Reference

| Flag | Purpose |
|------|---------|
| `-l` | Input file with hosts/URLs |
| `-u` | Single target URL |
| `-path` | Path(s) to append to each host |
| `-ports` | Ports to probe (comma-separated) |
| `-status-code` | Show HTTP status code |
| `-title` | Show page title |
| `-tech-detect` | Detect technologies |
| `-web-server` | Show web server |
| `-ip` | Show IP address |
| `-content-length` | Show content length |
| `-rt` | Show response time |
| `-mc` | Match status codes |
| `-fc` | Filter status codes |
| `-match-string` | Match response body text |
| `-match-regex` | Match response body regex |
| `-follow-redirects` | Follow HTTP redirects |
| `-H` | Custom header |
| `-x` | HTTP method |
| `-random-agent` | Random User-Agent |
| `-threads` | Concurrent threads |
| `-rl` | Rate limit (req/sec) |
| `-timeout` | Request timeout (seconds) |
| `-http-proxy` | Proxy URL |
| `-j` | JSON output |
| `-csv` | CSV output |
| `-o` | Output file |
| `-silent` | Results only |
| `-nc` | No color |
| `-screenshot` | Capture screenshots |
