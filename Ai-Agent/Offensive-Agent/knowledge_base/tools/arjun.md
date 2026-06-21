---
tool_name: arjun
category: discovery
tags: [parameter-discovery, hidden-parameters, recon, api]
used_by_agents: [recon_agent, discovery_agent]
---

# Arjun — Hidden HTTP Parameter Discovery

## What It Does
Discovers hidden/undocumented GET and POST parameters on web endpoints. Sends requests with large batches of common parameter names and detects which ones the server responds to differently. Useful for finding attack surfaces not visible in the HTML source.

---

## Basic Usage

```bash
# GET parameters
arjun -u https://target.com/endpoint

# POST parameters
arjun -u https://target.com/endpoint -m POST

# JSON body parameters
arjun -u https://target.com/api/endpoint -m JSON

# XML parameters
arjun -u https://target.com/api/endpoint -m XML
```

---

## Multi-Target

```bash
arjun -i targets.txt
arjun -i targets.txt -m POST
```

---

## Custom Wordlist

```bash
arjun -u https://target.com/endpoint -w /path/to/custom/wordlist.txt
```

---

## Headers & Authentication

```bash
arjun -u https://target.com/endpoint -H "Authorization: Bearer TOKEN"
arjun -u https://target.com/endpoint -H "Cookie: session=abc123"
```

---

## Performance

```bash
# Concurrent threads (default 2)
arjun -u https://target.com/endpoint -t 10

# Delay between requests
arjun -u https://target.com/endpoint -d 2
```

---

## Output

```bash
# JSON output
arjun -u https://target.com/endpoint -oJ results.json

# Text output
arjun -u https://target.com/endpoint -oT results.txt

# Passive mode (no requests sent — collects from public sources)
arjun -u https://target.com/endpoint --passive
```

---

## Output Interpretation

### Parameters found:
```
[*] Probing the target for stability
[*] Analysing HTTP response for anomalies
[*] Performing 25000 requests
[+] Parameters found: id, debug, admin, test
```
**Success indicators**: `[+] Parameters found:` followed by parameter names.

### No parameters found:
```
[*] Probing the target for stability
[*] Analysing HTTP response for anomalies
[-] No parameters were discovered
```
**Failure indicators**: `[-] No parameters were discovered`

---

## Common Flags Reference

| Flag | Purpose |
|------|---------|
| `-u` | Target URL |
| `-i` | Input file with target URLs |
| `-m` | HTTP method (GET, POST, JSON, XML) |
| `-w` | Custom wordlist path |
| `-H` | Custom header |
| `-t` | Concurrent threads (default 2) |
| `-d` | Delay between requests (seconds) |
| `-oJ` | JSON output file |
| `-oT` | Text output file |
| `--passive` | Collect params from public sources only |
