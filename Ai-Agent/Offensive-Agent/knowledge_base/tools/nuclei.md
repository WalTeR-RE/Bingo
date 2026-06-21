---
tool_name: nuclei
category: scanning
tags: [vulnerability-scanner, templates, cve, misconfig, exposed-panels, recon]
used_by_agents: [recon_agent, discovery_agent]
---

# nuclei — Template-Based Vulnerability Scanner

## What It Does
Fast, template-driven scanner from ProjectDiscovery. Uses YAML templates to detect CVEs, misconfigurations, exposed panels, default credentials, and more. Thousands of community templates available. Ideal for automated recon and known-vuln detection.

## CRITICAL: Use `-silent` or `-nc` to suppress banners. Use `-j` for JSON output for agent parsing.

---

## Basic Scanning

### Scan a single target
```bash
nuclei -u http://target.com -nc
```

### Scan a list of targets
```bash
nuclei -l targets.txt -nc
```

### Scan with JSON output (best for parsing)
```bash
nuclei -u http://target.com -j -o results.json -nc
```

---

## Template Filtering

### By severity
```bash
nuclei -u http://target.com -severity critical,high -nc
nuclei -u http://target.com -severity medium,low,info -nc
```

### By template tags
```bash
nuclei -u http://target.com -tags sqli,xss,rce -nc
nuclei -u http://target.com -tags cve -nc
nuclei -u http://target.com -tags default-login -nc
nuclei -u http://target.com -tags exposed-panels -nc
nuclei -u http://target.com -tags misconfig -nc
nuclei -u http://target.com -tags tech -nc
```

### By template ID
```bash
nuclei -u http://target.com -t cves/2021/CVE-2021-44228.yaml -nc
nuclei -u http://target.com -t http/misconfiguration/ -nc
```

### Exclude templates
```bash
nuclei -u http://target.com -exclude-tags dos,fuzz -nc
nuclei -u http://target.com -exclude-severity info -nc
```

### By protocol
```bash
nuclei -u http://target.com -type http -nc
nuclei -u target.com -type dns -nc
```

---

## Authentication & Headers

```bash
# Custom headers
nuclei -u http://target.com -H "Cookie: session=abc123" -nc
nuclei -u http://target.com -H "Authorization: Bearer TOKEN" -nc

# Follow redirects
nuclei -u http://target.com -fr -nc

# Custom User-Agent
nuclei -u http://target.com -H "User-Agent: Mozilla/5.0" -nc
```

---

## Performance & Rate Limiting

```bash
# Concurrent templates (default 25)
nuclei -u http://target.com -c 50 -nc

# Rate limit (requests per second)
nuclei -u http://target.com -rl 100 -nc
nuclei -u http://target.com -rl 10 -nc  # slow/stealthy

# Bulk size (hosts processed in parallel)
nuclei -l targets.txt -bs 50 -nc

# Timeout per request
nuclei -u http://target.com -timeout 10 -nc

# Retries
nuclei -u http://target.com -retries 3 -nc
```

---

## Proxy

```bash
nuclei -u http://target.com -proxy http://127.0.0.1:8080 -nc
nuclei -u http://target.com -proxy socks5://127.0.0.1:1080 -nc
```

---

## Output

```bash
# JSON lines output (best for agent parsing)
nuclei -u http://target.com -j -o results.jsonl -nc

# Plain text
nuclei -u http://target.com -o results.txt -nc

# Markdown report
nuclei -u http://target.com -me report_dir -nc

# Silent mode (only results, no progress)
nuclei -u http://target.com -silent
```

---

## Useful One-Liners

```bash
# Quick critical/high vuln scan
nuclei -u http://target.com -severity critical,high -nc -silent

# Detect tech stack + exposed panels
nuclei -u http://target.com -tags tech,exposed-panels -nc

# Known CVE scan
nuclei -u http://target.com -tags cve -severity critical,high -nc

# Default credentials check
nuclei -u http://target.com -tags default-login -nc

# Misconfigurations only
nuclei -u http://target.com -tags misconfig -nc

# Full scan, JSON output, exclude DoS
nuclei -u http://target.com -exclude-tags dos -j -o full_scan.jsonl -nc
```

---

## Template Updates

```bash
# Update templates to latest
nuclei -update-templates

# List available templates
nuclei -tl
```

---

## Output Interpretation

### Vulnerability found:
```
[2024-01-15 10:30:45] [CVE-2021-44228] [http] [critical] http://target.com/api
[2024-01-15 10:30:46] [apache-detect] [http] [info] http://target.com [Apache/2.4.49]
[2024-01-15 10:30:47] [wordpress-login] [http] [info] http://target.com/wp-login.php
[2024-01-15 10:30:48] [phpmyadmin-panel] [http] [medium] http://target.com/phpmyadmin/
```
**Format**: `[template-id] [protocol] [severity] URL [extracted-data]`

### JSON output (with `-j`):
```json
{
  "template-id": "CVE-2021-44228",
  "info": {"name": "Apache Log4j RCE", "severity": "critical"},
  "type": "http",
  "host": "http://target.com",
  "matched-at": "http://target.com/api",
  "extracted-results": ["..."],
  "timestamp": "2024-01-15T10:30:45Z"
}
```

### No findings:
No output lines = no matches. nuclei only prints when a template matches.

**Success indicators**: Any output line with `[critical]`, `[high]`, `[medium]`, or specific CVE/template IDs.
**Failure/clean indicators**: Empty output or only `[info]` level tech detection results.

---

## Common Flags Reference

| Flag | Purpose |
|------|---------|
| `-u` | Target URL |
| `-l` | File with list of target URLs |
| `-t` | Path to specific template(s) or directory |
| `-tags` | Filter templates by tags (comma-separated) |
| `-severity` | Filter by severity: info, low, medium, high, critical |
| `-exclude-tags` | Exclude templates matching these tags |
| `-exclude-severity` | Exclude templates matching these severities |
| `-type` | Protocol type filter (http, dns, tcp, etc.) |
| `-H` | Custom header(s) to include |
| `-fr` | Follow HTTP redirects |
| `-j` | JSON Lines output (best for automated parsing) |
| `-o` | Output file path |
| `-silent` | Only show results, no banner or progress |
| `-nc` | No color (cleaner for log parsing) |
| `-c` | Number of concurrent templates to run (default 25) |
| `-rl` | Rate limit — max requests per second |
| `-bs` | Number of hosts to process in parallel |
| `-timeout` | Timeout per request in seconds |
| `-retries` | Number of retries on failure |
| `-proxy` | HTTP/SOCKS proxy URL |
| `-update-templates` | Download latest community templates |
