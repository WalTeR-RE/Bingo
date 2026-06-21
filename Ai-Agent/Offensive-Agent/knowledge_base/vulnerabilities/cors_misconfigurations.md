---
vuln_type: cors
severity: medium
cwe: [CWE-346]
owasp: A05:2021-Security-Misconfiguration
related_tools: [curl]
exploit_agent: cors_misconfiguration_agent
tags: [cors, security-misconfiguration, web-security, origin-bypass]
---

# Cross-Origin Resource Sharing (CORS) Misconfiguration

## Overview
Cross-Origin Resource Sharing (CORS) is a browser security feature that restricts web pages from making requests to a different domain than the one that served the web page. A misconfigured CORS policy can allow malicious websites to make unauthorized requests to a vulnerable application, potentially leading to data exfiltration, CSRF, or other attacks.

---

## How CORS Works

When a browser makes a cross-origin HTTP request, it often sends an "origin" header. The server then responds with an `Access-Control-Allow-Origin` header, indicating which origins are permitted to access its resources. If the origin is allowed, the browser proceeds with the request; otherwise, it blocks it.

### Simple Request
- GET, HEAD, POST methods
- Content-Type: `application/x-www-form-urlencoded`, `multipart/form-data`, or `text/plain`
- No custom headers

### Preflight Request
- For other methods (PUT, DELETE, CONNECT, OPTIONS, TRACE, PATCH) or custom headers
- Browser sends an OPTIONS request with `Access-Control-Request-Method` and `Access-Control-Request-Headers`
- Server responds with allowed methods and headers

---

## Common Misconfigurations

### 1. Wildcard Origin (`Access-Control-Allow-Origin: *`)
- Allows any domain to access resources.
- **Severity**: High if sensitive data is involved, as it bypasses same-origin policy completely.

### 2. Reflected Origin
- Server reflects the `Origin` header back as `Access-Control-Allow-Origin` without proper validation.
- **Vulnerable if**: `Origin` header is not strictly validated against a whitelist.
- **Example**: If `Origin: evil.com` results in `Access-Control-Allow-Origin: evil.com`.

### 3. Null Origin
- Some applications allow `null` origin, which can be exploited by sandboxed iframes or local files.
- **Example**: `Access-Control-Allow-Origin: null`.

### 4. Whitelist Bypass
- Insecure regex or partial matching in the whitelist.
- **Example**: Whitelist `example.com` but allows `evil.com.example.com` or `example.com.evil.com`.

### 5. Internal Network Exposure
- CORS policy allows internal IP addresses or domains, exposing internal resources to external attackers if combined with other vulnerabilities.

---

## Detection Techniques

### Step 1: Identify CORS headers
- Use browser developer tools or `curl` to inspect `Access-Control-Allow-Origin` and other CORS headers.

### Step 2: Test with various origins
- Try sending requests with different `Origin` headers, including malicious domains, `null`, and subdomains.

```bash
# Test with a malicious origin
curl -H "Origin: http://evil.com" -I http://target.com/api/data

# Test with null origin
curl -H "Origin: null" -I http://target.com/api/data

# Test with a subdomain of a whitelisted domain (if applicable )
curl -H "Origin: http://evil.example.com" -I http://target.com/api/data
