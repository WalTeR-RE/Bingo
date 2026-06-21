---
tool_name: ffuf
category: discovery
tags: [fuzzing, directory-discovery, parameter-fuzzing, vhost, brute-force, content-discovery]
used_by_agents: [recon_agent, planner_agent]
---

# ffuf — Fuzz Faster U Fool

## What It Does
High-performance web fuzzer. Replaces the `FUZZ` keyword in any part of the request (URL, headers, body, cookies) with wordlist entries. Used for directory discovery, parameter fuzzing, subdomain/vhost enumeration, and brute forcing.

---

## Directory & File Discovery

```bash
ffuf -u http://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt
ffuf -u http://target.com/FUZZ -w wordlist.txt -e .php,.html,.txt,.bak,.zip -mc 200,301,302,403
ffuf -u http://target.com/FUZZ -w wordlist.txt -recursion -recursion-depth 2
```

---

## Parameter Fuzzing

### GET parameter names
```bash
ffuf -u "http://target.com/page.php?FUZZ=test" -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt -mc 200 -fs 1234
```

### GET parameter values
```bash
ffuf -u "http://target.com/page.php?id=FUZZ" -w wordlist.txt -mc 200
```

### POST parameter fuzzing
```bash
ffuf -u http://target.com/login -X POST -d "username=admin&password=FUZZ" -w wordlist.txt -H "Content-Type: application/x-www-form-urlencoded" -fc 401
```

---

## Multi-Wordlist (Clusterbomb)

```bash
# Fuzz two positions simultaneously
ffuf -u "http://target.com/FUZZ/FUZ2Z" -w dirs.txt:FUZZ -w files.txt:FUZ2Z

# Brute force login (username + password)
ffuf -u http://target.com/login -X POST \
  -d "user=FUZZ&pass=FUZ2Z" \
  -w users.txt:FUZZ -w passwords.txt:FUZ2Z \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -fc 401
```

---

## Virtual Host / Subdomain Enumeration

```bash
ffuf -u http://target.com -w subdomains.txt -H "Host: FUZZ.target.com" -fs 1234
ffuf -u http://IP_ADDRESS -w subdomains.txt -H "Host: FUZZ.target.com" -mc 200
```

---

## Headers & Authentication

```bash
# With cookies
ffuf -u http://target.com/FUZZ -w wordlist.txt -b "session=abc123;security=low"

# Custom header
ffuf -u http://target.com/FUZZ -w wordlist.txt -H "Authorization: Bearer TOKEN"

# Header fuzzing (403 bypass)
ffuf -u http://target.com/admin -w headers.txt -H "FUZZ" -mc 200,301,302
```

---

## Filtering & Matching

```bash
# Match specific status codes only
ffuf -u http://target.com/FUZZ -w wordlist.txt -mc 200,301,302

# Filter out status codes
ffuf -u http://target.com/FUZZ -w wordlist.txt -fc 404,500

# Filter by response size (hide default pages)
ffuf -u http://target.com/FUZZ -w wordlist.txt -fs 1234

# Filter by word count
ffuf -u http://target.com/FUZZ -w wordlist.txt -fw 10

# Filter by line count
ffuf -u http://target.com/FUZZ -w wordlist.txt -fl 5

# Match/filter by regex in response body
ffuf -u http://target.com/FUZZ -w wordlist.txt -mr "admin panel"
ffuf -u http://target.com/FUZZ -w wordlist.txt -fr "not found"

# Auto-calibrate filtering (detect and hide default response)
ffuf -u http://target.com/FUZZ -w wordlist.txt -ac
```

---

## Performance

```bash
# Threads (default 40)
ffuf -u http://target.com/FUZZ -w wordlist.txt -t 100

# Rate limit (requests per second)
ffuf -u http://target.com/FUZZ -w wordlist.txt -rate 50

# Delay between requests
ffuf -u http://target.com/FUZZ -w wordlist.txt -p 0.5

# Timeout per request
ffuf -u http://target.com/FUZZ -w wordlist.txt -timeout 10
```

---

## Proxy & Output

```bash
# Through proxy
ffuf -u http://target.com/FUZZ -w wordlist.txt -x http://127.0.0.1:8080

# Output to file
ffuf -u http://target.com/FUZZ -w wordlist.txt -o results.json -of json
ffuf -u http://target.com/FUZZ -w wordlist.txt -o results.csv -of csv

# Silent mode
ffuf -u http://target.com/FUZZ -w wordlist.txt -s
```

---

## Output Interpretation

### Directories/files found:
```
admin                   [Status: 301, Size: 314, Words: 20, Lines: 10, Duration: 32ms]
config.php.bak          [Status: 200, Size: 2847, Words: 145, Lines: 50, Duration: 28ms]
uploads                 [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 25ms]
```
**Each line**: `<wordlist-entry> [Status: <code>, Size: <bytes>, Words: <count>, Lines: <count>]`

### Parameter found (valid parameter name):
Responses that differ from baseline (different size/code) indicate a valid parameter.

### No results:
```
:: Progress: [4614/4614] :: Job [1/1] :: 0 req/sec :: Duration: [0:01:30] :: Errors: 0 ::
```
No result lines before the progress summary = nothing found.

**Success indicators**: Result lines with Status codes (200, 301, 302, 403).
**Failure indicators**: Only the progress bar summary, no result lines.

---

## Common Flags Reference

| Flag | Purpose |
|------|---------|
| `-u` | Target URL with FUZZ keyword |
| `-w` | Wordlist (supports named keywords: `wordlist.txt:FUZZ`) |
| `-X` | HTTP method |
| `-d` | POST data body |
| `-H` | Custom header |
| `-b` | Cookie data |
| `-e` | File extensions to append (comma-separated) |
| `-mc` | Match HTTP status codes |
| `-fc` | Filter (hide) HTTP status codes |
| `-fs` | Filter by response size |
| `-fw` | Filter by word count |
| `-fl` | Filter by line count |
| `-mr` | Match regex in response body |
| `-fr` | Filter regex in response body |
| `-ac` | Auto-calibrate filtering |
| `-t` | Threads (default 40) |
| `-rate` | Requests per second limit |
| `-p` | Delay between requests (seconds) |
| `-timeout` | Request timeout (seconds) |
| `-recursion` | Recurse into discovered directories |
| `-recursion-depth` | Max recursion depth |
| `-x` | Proxy URL |
| `-o` | Output file |
| `-of` | Output format (json, csv, html, md) |
| `-s` | Silent mode (results only) |
| `-v` | Verbose (show full URLs and redirects) |
