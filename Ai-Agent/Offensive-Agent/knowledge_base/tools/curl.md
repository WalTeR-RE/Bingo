---
tool_name: curl
category: utility
tags: [http, requests, headers, cookies, upload, download, api]
used_by_agents: [all_agents, exploit_agents, planner_agent, validator]
---

# curl — HTTP Request Swiss Army Knife

## What It Does
Sends HTTP requests from the command line. The universal tool for testing web endpoints — every agent uses it for probing, submitting payloads, verifying responses, and interacting with web forms.

---

## HTTP Methods

```bash
curl -X GET http://target.com/page
curl -X POST http://target.com/page
curl -X PUT http://target.com/api/resource
curl -X DELETE http://target.com/api/resource/1
curl -X OPTIONS http://target.com -i
```

---

## Sending Data

### URL-encoded form data (POST)
```bash
curl -X POST http://target.com/login -d "username=admin&password=test"
```

### JSON body
```bash
curl -X POST http://target.com/api -H "Content-Type: application/json" -d '{"user":"admin","pass":"test"}'
```

### File upload (multipart)
```bash
curl -X POST http://target.com/upload -F "file=@shell.php;type=image/jpeg" -F "Submit=Upload"
```

### Data from stdin or file
```bash
curl -X POST http://target.com/api -d @payload.json -H "Content-Type: application/json"
```

---

## Headers & Cookies

```bash
# Custom header
curl -H "Authorization: Bearer TOKEN" http://target.com/api

# Cookie string
curl -b "PHPSESSID=abc123;security=low" http://target.com/page

# Save cookies to file
curl -c cookies.txt http://target.com/login -d "user=admin&pass=password"

# Load cookies from file
curl -b cookies.txt http://target.com/dashboard

# Referer header
curl -e "http://target.com/allowed-page" http://target.com/protected

# User-Agent
curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" http://target.com
```

---

## Authentication

```bash
# Basic auth
curl -u admin:password http://target.com/protected

# Bearer token
curl -H "Authorization: Bearer eyJhbGc..." http://target.com/api

# NTLM
curl --ntlm -u domain\\user:pass http://target.com
```

---

## Response Inspection

```bash
# Show response headers + body
curl -i http://target.com

# Verbose mode (full request + response headers)
curl -v http://target.com

# Only response headers
curl -I http://target.com

# Silent mode (suppress progress)
curl -s http://target.com

# Write response timing
curl -w "\nHTTP_CODE:%{http_code}\nTIME:%{time_total}s\nSIZE:%{size_download}\n" -s -o /dev/null http://target.com
```

---

## Redirects & SSL

```bash
# Follow redirects
curl -L http://target.com/redirect

# Ignore SSL certificate errors
curl -k https://target.com

# Specify client certificate
curl --cert client.pem https://target.com
```

---

## Proxy

```bash
curl -x http://127.0.0.1:8080 http://target.com
curl -x socks5://127.0.0.1:1080 http://target.com
```

---

## Path Traversal & Special

```bash
# Prevent curl from normalizing ../ in URL (crucial for LFI testing)
curl --path-as-is "http://target.com/../../etc/passwd"

# Rate limit download
curl --limit-rate 100K http://target.com/large-file
```

---

## Output Interpretation

### Checking if payload is reflected (XSS verification):
```bash
curl -s "http://target.com/search?q=<script>alert(1)</script>" -b "session=abc" | grep -i "<script>alert"
```
**Vulnerable**: grep matches — payload appears unescaped in response body.
**Not vulnerable**: no match — payload was sanitized or encoded.

### Checking HTTP status codes:
```bash
curl -s -o /dev/null -w "%{http_code}" http://target.com/admin
```
- `200` — accessible
- `301/302` — redirect (follow with `-L`)
- `401` — requires authentication
- `403` — forbidden (try bypass techniques)
- `404` — not found
- `500` — server error (may indicate injection worked)

### Checking response for SQL errors:
```bash
curl -s "http://target.com/page?id=1'" -b "session=abc" | grep -iE "sql syntax|mysql|warning|error in your"
```
**Vulnerable**: error messages about SQL syntax appear in response.

### Checking CSRF — state change without token:
```bash
curl -s "http://target.com/change_pass?new=hacked&confirm=hacked" -b "session=abc" -w "%{http_code}"
```
**Vulnerable**: returns 200 and password actually changed.

---

## Common Flags Reference

| Flag | Purpose |
|------|---------|
| `-X` | HTTP method (GET, POST, PUT, DELETE) |
| `-d` | Send data in request body (sets POST by default) |
| `-H` | Add custom header |
| `-b` | Send cookies (string or file) |
| `-c` | Save received cookies to file |
| `-F` | Multipart form data (file upload) |
| `-u` | Basic authentication (user:password) |
| `-A` | User-Agent string |
| `-e` | Referer header |
| `-i` | Include response headers in output |
| `-I` | HEAD request — headers only |
| `-v` | Verbose (full request/response details) |
| `-s` | Silent mode (no progress bar) |
| `-o` | Write response body to file |
| `-w` | Custom output format (status code, timing, etc.) |
| `-L` | Follow redirects |
| `-k` | Allow insecure SSL connections |
| `-x` | Proxy URL |
| `--path-as-is` | Don't normalize `../` in URL path |
| `--limit-rate` | Throttle transfer speed |
