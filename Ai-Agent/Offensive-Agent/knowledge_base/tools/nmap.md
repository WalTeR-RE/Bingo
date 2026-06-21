---
tool_name: nmap
category: reconnaissance
tags: [port-scanning, service-detection, os-detection, nse-scripts, network]
used_by_agents: [recon_agent]
---

# nmap — Network Mapper

## What It Does
Network scanner for host discovery, port scanning, service/version detection, and OS fingerprinting. NSE scripts extend it to detect web vulnerabilities, default credentials, and misconfigurations. Essential for the recon phase.

---

## Host Discovery

```bash
# Ping sweep (no port scan)
nmap -sn 192.168.1.0/24
nmap -sn 10.0.0.1-50

# Skip discovery, scan directly (when host is known to be up)
nmap -Pn target.com
```

---

## Port Scanning

```bash
# Default scan (top 1000 ports)
nmap target.com

# Specific ports
nmap -p 80,443,8080,8443 target.com

# All ports
nmap -p- target.com

# Top N ports
nmap --top-ports 100 target.com

# Fast scan (top 100)
nmap -F target.com

# Scan types
nmap -sS target.com     # SYN scan (default, stealthy)
nmap -sT target.com     # TCP connect (when SYN not possible)
nmap -sU target.com     # UDP scan
```

---

## Service & Version Detection

```bash
# Version detection
nmap -sV target.com
nmap -sV -p 80,443 target.com

# Aggressive detection (version + OS + scripts + traceroute)
nmap -A target.com

# Version intensity (0-9, higher = more probes)
nmap -sV --version-intensity 9 target.com
```

---

## OS Detection

```bash
nmap -O target.com
nmap -O --osscan-guess target.com
```

---

## NSE Scripts (Web-Relevant)

### General web enumeration
```bash
nmap -p 80,443 --script=http-enum target.com
nmap -p 80,443 --script=http-title target.com
nmap -p 80,443 --script=http-headers target.com
nmap -p 80,443 --script=http-methods target.com
```

### Vulnerability detection
```bash
nmap -p 80,443 --script=vuln target.com
nmap -p 80,443 --script=http-sql-injection target.com
nmap -p 80,443 --script=http-shellshock target.com
nmap -p 443 --script=ssl-heartbleed target.com
nmap -p 443 --script=ssl-poodle target.com
nmap -p 443 --script=ssl-enum-ciphers target.com
```

### Brute force / auth
```bash
nmap -p 80 --script=http-brute --script-args=http-brute.path=/admin target.com
nmap -p 22 --script=ssh-brute --script-args=userdb=users.txt,passdb=passwords.txt target.com
nmap -p 21 --script=ftp-anon target.com
```

### CMS detection
```bash
nmap -p 80,443 --script=http-wordpress-enum target.com
```

### Run safe + default scripts
```bash
nmap --script=default,safe target.com
```

---

## Performance & Evasion

```bash
# Timing templates (0=paranoid, 5=insane)
nmap -T4 target.com          # aggressive but reliable
nmap -T2 target.com          # polite (slower, less detection)

# Rate limit
nmap --max-rate 100 target.com
nmap --min-rate 50 target.com

# Fragment packets (basic IDS evasion)
nmap -f target.com

# Decoy scan
nmap -D RND:5 target.com
```

---

## Output

```bash
# Normal text
nmap target.com -oN results.txt

# XML (for parsing)
nmap target.com -oX results.xml

# Grepable
nmap target.com -oG results.gnmap

# All formats at once
nmap target.com -oA results

# Verbose
nmap -v target.com
nmap -vv target.com
```

---

## Output Interpretation

### Open ports found:
```
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 7.9p1
80/tcp   open  http     Apache httpd 2.4.38
443/tcp  open  ssl/http Apache httpd 2.4.38
3306/tcp open  mysql    MySQL 5.7.33
```
**Each line**: `PORT STATE SERVICE VERSION`

### Port states:
- `open` — accepting connections (service running)
- `closed` — accessible but no service listening
- `filtered` — firewall blocking (can't determine open/closed)

### NSE script findings:
```
| http-enum:
|   /admin/: Possible admin folder
|   /robots.txt: Robots file
|   /phpinfo.php: PHP info page
|_  /config.php.bak: Backup config file

| http-sql-injection:
|   Possible sqli in parameter id (GET)
```
**Vulnerability indicators**: NSE output lines with `|` prefix showing discovered paths, injection points, or vulnerabilities.

### No results:
```
All 1000 scanned ports on target.com are filtered
```
Or all ports show as `closed`.

---

## Common Flags Reference

| Flag | Purpose |
|------|---------|
| `-sS` | SYN scan (default, stealthy) |
| `-sT` | TCP connect scan |
| `-sU` | UDP scan |
| `-sV` | Service/version detection |
| `-sn` | Ping sweep only (no port scan) |
| `-O` | OS detection |
| `-A` | Aggressive (version + OS + scripts + traceroute) |
| `-Pn` | Skip host discovery (assume host is up) |
| `-p` | Port specification |
| `-F` | Fast scan (top 100 ports) |
| `--top-ports` | Scan N most common ports |
| `--script` | NSE script(s) to run |
| `--script-args` | Arguments for NSE scripts |
| `-T` | Timing template (0-5) |
| `-v` | Verbose |
| `-oN` | Normal output to file |
| `-oX` | XML output to file |
| `-oG` | Grepable output to file |
| `-oA` | All output formats |
| `-f` | Fragment packets |
| `-D` | Decoy scan |
| `--max-rate` | Max packets per second |
