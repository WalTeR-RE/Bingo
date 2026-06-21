---
tool_name: jsluice
category: analysis
tags: [javascript, secret-extraction, endpoint-discovery, js-analysis, api-keys]
used_by_agents: [recon_agent, analysis_agent, planner_agent]
---

# jsluice — JavaScript Secret & Endpoint Extractor

## What It Does
Parses and analyzes JavaScript files to reveal the "Hidden" logic — API endpoints, hardcoded secrets, access tokens, cloud keys, and internal paths embedded in JS source code. Built for large-scale JS analysis pipelines. Operates entirely offline on JS content passed via file or stdin.

## CRITICAL: Always use the specific subcommand (`urls` or `secrets`) based on the objective.

---

## Basic Usage
 
```bash
# Extract endpoints/URLs from a local JS file
jsluice urls file.js
 
# Extract secrets from a local JS file
jsluice secrets file.js
 
# Extract secrets from a remote JS file (via curl)
curl -s https://target.com/app.js | jsluice secrets -
 
# Extract endpoints from a remote JS file
curl -s https://target.com/bundle.js | jsluice urls -
```
 
---
 
## Output Modes
 
```bash
# Output as JSON (recommended for pipelines)
jsluice secrets -o json app.js
 
# Output as plain text (default)
jsluice secrets -o text app.js
 
# URLs mode with JSON output
jsluice urls -o json app.js
```
 
---
 
## Bulk Analysis
 
```bash
# Analyze all JS files from a list (sequential)
cat js_files.txt | while read url; do
  curl -s "$url" | jsluice secrets -
done
 
# Parallel execution with xargs (5 workers)
cat js_files.txt | xargs -P 5 -I {} sh -c 'curl -s "{}" | jsluice secrets -'
```
 
---
 
## Common Pipelines
 
```bash
# Full pipeline: crawl → extract JS → analyze secrets
katana -u https://target.com -ef css,png,jpg -silent \
  | grep "\.js$" \
  | xargs -I {} sh -c 'curl -s "{}" | jsluice secrets -'
 
# Crawl → extract hidden endpoints from JS
katana -u https://target.com -silent \
  | grep "\.js$" \
  | xargs -I {} sh -c 'curl -s "{}" | jsluice urls -'
 
# Historical JS analysis (gau → jsluice)
gau target.com --ft js \
  | xargs -I {} sh -c 'curl -s "{}" | jsluice secrets -'
 
# Filter only high-severity secrets from JSON output
jsluice secrets -o json app.js | jq '.[] | select(.severity=="high")'
```
 
---
 
## Output Interpretation
 
### Secrets found (JSON):
```json
{
  "kind": "AWSAccessKey",
  "data": {
    "key": "AKIAIOSFODNN7EXAMPLE",
    "secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  },
  "severity": "high",
  "filename": "app.js",
  "line": 142
}
```
**Success indicators**: `"severity": "high"`, recognized `kind` values (AWSAccessKey, GoogleAPIKey, SlackToken, etc.)
 
### Endpoints found (JSON):
```json
{
  "url": "/api/v1/internal/users",
  "type": "endpoint",
  "filename": "bundle.js",
  "line": 87
}
```
**High-value finds**: `/internal/`, `/admin/`, versioned API paths not visible in the HTML source.
 
### No secrets found:
```
(empty output)
```
**Failure indicators**: No output — JS file may be minified beyond recognition, or contain no hardcoded secrets.
 
---
 
## Common Secret Types Detected
 
| Secret Type | Pattern Example |
|-------------|----------------|
| AWS Access Key | `AKIA...` |
| AWS Secret Key | 40-char alphanumeric after `aws_secret` |
| Google API Key | `AIza...` |
| Stripe Live Key | `sk_live_...` / `pk_live_...` |
| Slack Token | `xoxb-...` / `xoxp-...` |
| JWT Token | `eyJ...` (base64-encoded header) |
| Generic API Key | `api_key`, `apikey`, `access_token` assignments |
| Internal Endpoints | `/api/internal/`, `/v[0-9]/admin/` |
 
---
 
## Common Flags Reference
 
| Flag | Purpose |
|------|---------|
| `urls` | Mode: extract URLs and endpoints from JS |
| `secrets` | Mode: extract hardcoded secrets and keys |
| `-` | Read JS content from stdin |
| `-o json` | Output results in JSON format |
| `-o text` | Output results in plain text (default) |
