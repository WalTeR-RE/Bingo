---
tool_name: gau
category: reconnaissance
tags: [historical-urls, passive-recon, wayback, attack-surface]
used_by_agents: [recon_agent, planner_agent]
---

# gau — Get All URLs (Historical Attack Surface)

## What It Does
Fetches known URLs from passive sources including Wayback Machine, Common Crawl, URLScan, and AlienVault OTX. Reveals the "Ghost" attack surface — old endpoints, forgotten paths, legacy parameters, and deprecated APIs that may still be live or expose sensitive data. No requests are sent to the target directly.

## CRITICAL: Output can be massive for large domains. Always pipe to a file or use `--o`.

---
 
## Basic Usage
 
```bash
# Fetch all historical URLs for a domain
gau target.com
 
# Save output to file
gau target.com --o urls.txt
 
# Include subdomains
gau --subs target.com
 
# Pipe into httpx to check which are still alive
gau target.com | httpx -silent
```
 
---
 
## Filtering
 
```bash
# Filter by file extension (only JS files)
gau target.com --ft js
 
# Exclude noise (images, fonts)
gau target.com --blacklist png,jpg,gif,svg,woff,ttf,eot,css
 
# Filter by status codes via httpx
gau target.com | httpx -mc 200,301,302
```
 
---
 
## Sources
 
```bash
# Use specific providers only
gau target.com --providers wayback,commoncrawl
 
# Available: wayback, commoncrawl, otx, urlscan
gau target.com --providers urlscan,otx
```
 
---
 
## Performance
 
```bash
# Set number of threads
gau target.com --threads 5
 
# Set retry count on failure
gau target.com --retries 3
```
 
---
 
## Proxy
 
```bash
gau target.com --proxy http://127.0.0.1:8080
```
 
---
 
## Common Pipelines
 
```bash
# Find old endpoints with parameters (potential injection points)
gau target.com | grep "=" | qsreplace "FUZZ"
 
# Find historically exposed JS files
gau target.com --ft js | tee js_files.txt
 
# Extract unique parameters from historical URLs
gau target.com | grep "?" | unfurl keys | sort -u
 
# Combine with httpx to find live ghost URLs
gau target.com | httpx -silent -mc 200 -o alive_ghost.txt
```
 
---
 
## Output Interpretation
 
### Standard output:
```
https://target.com/old-admin/login.php
https://target.com/api/v1/users?id=1
https://target.com/backup/config.bak
https://target.com/.git/HEAD
```
**High-value finds**: backup files, `.git` paths, old API versions, admin panels, config files, endpoints with parameters.
 
### No results:
```
(empty output)
```
**Failure indicators**: No output returned — domain may have no indexed history or provider returned no results.
 
---
 
## Common Flags Reference
 
| Flag | Purpose |
|------|---------|
| (domain) | Target domain to fetch URLs for |
| `--subs` | Include subdomains in results |
| `--o` | Output file path |
| `--ft` | Filter by file type/extension |
| `--blacklist` | Comma-separated extensions to exclude |
| `--providers` | Passive sources: wayback, commoncrawl, otx, urlscan |
| `--threads` | Number of concurrent threads |
| `--retries` | Number of retries on failure |
| `--proxy` | Proxy URL |

