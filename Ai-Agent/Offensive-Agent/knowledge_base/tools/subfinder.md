---
tool_name: subfinder
category: reconnaissance
tags: [subdomain-enumeration, passive-recon, dns, attack-surface, osint]
used_by_agents: [recon_agent]
---

# subfinder — Passive Subdomain Discovery

## What It Does
Fast passive subdomain enumeration tool from ProjectDiscovery. Discovers subdomains using passive sources (search engines, certificate transparency logs, DNS datasets, APIs) — **no direct requests to target**. Essential for mapping the full attack surface before active testing.

---

## Basic Usage

```bash
# Enumerate subdomains
subfinder -d target.com

# Silent mode (results only, no banner)
subfinder -d target.com -silent

# Multiple domains
subfinder -d target.com -d other.com
subfinder -dL domains.txt
```

---

## Source Control

```bash
# Use all sources
subfinder -d target.com -all

# Specific sources only
subfinder -d target.com -sources shodan,censys,virustotal

# List available sources
subfinder -ls

# Exclude sources
subfinder -d target.com -es google,bing
```

---

## Output

```bash
# Save to file
subfinder -d target.com -o subdomains.txt

# JSON output (includes source info)
subfinder -d target.com -oJ -o subdomains.json

# Show source for each subdomain
subfinder -d target.com -v

# Only show unique results
subfinder -d target.com -silent | sort -u
```

---

## API Configuration

```bash
# Config file location: $HOME/.config/subfinder/provider-config.yaml
# Add API keys for better results:
# shodan: [YOUR_KEY]
# censys: [YOUR_ID:YOUR_SECRET]
# virustotal: [YOUR_KEY]
# securitytrails: [YOUR_KEY]
# chaos: [YOUR_KEY]
```

---

## Performance

```bash
# Threads
subfinder -d target.com -t 50

# Timeout (seconds)
subfinder -d target.com -timeout 30

# Max enumeration time (minutes)
subfinder -d target.com -max-time 5
```

---

## Piping to Other Tools

```bash
# Pipe to httpx for live host detection
subfinder -d target.com -silent | httpx -silent

# Pipe to nmap for port scanning
subfinder -d target.com -silent | nmap -iL - -sV -p 80,443

# Pipe to nuclei for vulnerability scanning
subfinder -d target.com -silent | httpx -silent | nuclei -severity critical,high

# Full recon chain
subfinder -d target.com -silent | httpx -silent -title -status-code -tech-detect | tee recon.txt
```

---

## Recursive Enumeration

```bash
# Recursive (find sub-subdomains like dev.api.target.com)
subfinder -d target.com -recursive

# With depth limit
subfinder -d target.com -recursive -max-depth 3
```

---

## Output Interpretation

### Subdomains found:
```
api.target.com
dev.target.com
staging.target.com
mail.target.com
admin.target.com
blog.target.com
vpn.target.com
```
Each line is a discovered subdomain. More subdomains = larger attack surface.

### JSON output (with `-oJ`):
```json
{"host": "api.target.com", "source": "crtsh"}
{"host": "dev.target.com", "source": "virustotal"}
```

### No results:
Empty output or only the domain itself returned.

**High-value subdomains to flag**: `admin`, `dev`, `staging`, `test`, `api`, `internal`, `vpn`, `jenkins`, `git`, `backup`

---

## Common Flags Reference

| Flag | Purpose |
|------|---------|
| `-d` | Target domain |
| `-dL` | File with list of domains |
| `-all` | Use all available sources |
| `-sources` | Specific sources to use |
| `-es` | Exclude specific sources |
| `-ls` | List available sources |
| `-o` | Output file |
| `-oJ` | JSON Lines output |
| `-v` | Verbose (show source per result) |
| `-silent` | Results only, no banner/info |
| `-t` | Number of threads |
| `-timeout` | Request timeout (seconds) |
| `-max-time` | Max enumeration time (minutes) |
| `-recursive` | Recursive subdomain enumeration |
| `-max-depth` | Max recursion depth |
