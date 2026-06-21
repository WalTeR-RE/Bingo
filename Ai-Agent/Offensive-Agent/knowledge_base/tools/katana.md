---
tool_name: katana
category: discovery
tags: [crawling, spidering, headless, endpoint-discovery]
used_by_agents: [recon_agent, discovery_agent]
---

# Katana — Next-generation Web Crawling

## What It Does
A high-performance crawler that uses headless browsing to discover endpoints. Unlike basic spiders, it can execute JavaScript, making it essential for modern Single Page Applications (SPAs) like React or Angular.

## CRITICAL: Always use `-jsonl` for structured output and `-silent` to suppress logs.

---

## Basic Usage
 
```bash
# Crawl a single URL
katana -u https://target.com
 
# Save output to file
katana -u https://target.com -o endpoints.txt
 
# Crawl with depth limit
katana -u https://target.com -d 3
 
# Crawl multiple URLs from file
katana -list urls.txt -o endpoints.txt
```
 
---
 
## Headless / JS Rendering
 
```bash
# Enable headless browser (discovers JS-rendered content)
katana -u https://target.com -headless
 
# Use system-installed Chrome
katana -u https://target.com -headless -system-chrome
```
 
---
 
## Scope Control
 
```bash
# Stay within same domain only
katana -u https://target.com -d 3
 
# Include subdomains in scope
katana -u https://target.com -fs dn
 
# Exclude static file extensions
katana -u https://target.com -ef png,jpg,gif,svg,woff,css,ico
```
 
---
 
## Filtering & Output
 
```bash
# Show only URLs matching a regex pattern
katana -u https://target.com -mr "api|admin|login"
 
# Output in JSON Lines format (recommended for pipelines)
katana -u https://target.com -jsonl -o results.jsonl
 
# Silent mode (URLs only, no banner)
katana -u https://target.com -silent
```
 
---
 
## Performance
 
```bash
# Set concurrency (parallel goroutines)
katana -u https://target.com -c 10
 
# Set parallelism (URLs processed in parallel)
katana -u https://target.com -p 10
 
# Set rate limit (requests per second)
katana -u https://target.com -rl 50
 
# Set timeout per request (seconds)
katana -u https://target.com -timeout 10
```
 
---
 
## Authentication
 
```bash
# With session cookie
katana -u https://target.com -H "Cookie: session=abc123"
 
# With Bearer token
katana -u https://target.com -H "Authorization: Bearer TOKEN"
```
 
---
 
## Proxy
 
```bash
katana -u https://target.com -proxy http://127.0.0.1:8080
```
 
---
 
## Common Pipelines
 
```bash
# Crawl and pipe endpoints into nuclei
katana -u https://target.com -silent | nuclei -t templates/
 
# Find all endpoints with parameters
katana -u https://target.com -silent | grep "="
 
# Headless crawl + filter JS files only
katana -u https://target.com -headless -ef css,png,jpg | grep "\.js"
 
# Validate live endpoints with httpx
katana -u https://target.com -silent | httpx -silent -mc 200
```
 
---
 
## Output Interpretation
 
### Standard output:
```
https://target.com/
https://target.com/login
https://target.com/api/v2/users
https://target.com/admin/dashboard
https://target.com/assets/app.js
```
**High-value finds**: API paths, admin panels, login pages, JS files, forms with parameters.
 
### No results:
```
(empty output or only base URL)
```
**Failure indicators**: No endpoints beyond the root — JS rendering may be needed (`-headless`) or the site may block crawlers.
 
---
 
## Common Flags Reference
 
| Flag | Purpose |
|------|---------|
| `-u` | Target URL |
| `-list` | File containing list of target URLs |
| `-d` | Crawl depth (default: 2) |
| `-o` | Output file path |
| `-jsonl` | Output in JSON Lines format |
| `-headless` | Enable headless browser crawling |
| `-system-chrome` | Use installed Chrome for headless mode |
| `-fs` | Field scope: `dn` (domain), `rdn` (root domain) |
| `-ef` | Extensions to exclude from crawl |
| `-mr` | Match regex filter on discovered URLs |
| `-c` | Concurrency (parallel goroutines) |
| `-p` | Parallelism (URLs processed in parallel) |
| `-rl` | Rate limit (requests/second) |
| `-timeout` | Request timeout in seconds |
| `-H` | Custom header (repeatable) |
| `-proxy` | Proxy URL |
| `-silent` | Suppress banner, output URLs only |
