---
vuln_type: file_upload
severity: high
cwe: [CWE-434, CWE-23]
owasp: A01:2021-Broken-Access-Control, A05:2021-Security-Misconfiguration
related_tools: [burpsuite, exiftool, webshells]
exploit_agent: file_upload_exploitation_agent
tags: [file-upload, rce, webshell, bypass, content-type-bypass, extension-bypass]
---

# Unrestricted File Upload Vulnerabilities

## Overview
Unrestricted file upload vulnerabilities occur when a web application allows users to upload files to the server without properly validating their content, type, or size. This can lead to various severe consequences, including Remote Code Execution (RCE) if an attacker uploads a malicious script (e.g., a webshell) that the server then executes.

---

## How File Upload Vulnerabilities Work

When an application allows file uploads, it typically performs checks to ensure the uploaded file is legitimate and safe. If these checks are insufficient or can be bypassed, an attacker can upload a file that serves a malicious purpose. The severity often depends on the server's ability to execute the uploaded file.

### Common Vulnerable Scenarios
- **Insufficient File Type Validation**: Only checks the `Content-Type` header, which is easily spoofed.
- **Insufficient File Extension Validation**: Allows dangerous extensions (e.g., `.php`, `.jsp`, `.asp`, `.exe`).
- **Bypass of Renaming/Randomization**: Predictable file naming or storage locations.
- **Lack of Content Validation**: Does not inspect the actual content of the file for malicious code.
- **Directory Traversal**: Uploading files to arbitrary locations on the server.
- **Client-Side Validation Only**: Validation performed only in the browser, easily bypassed.

---

## Detection Techniques

### Step 1: Identify Upload Functionality
- Look for any feature that allows users to upload files (e.g., profile pictures, document attachments, media uploads).

### Step 2: Test File Type Validation (MIME Type Bypass)
- Upload a legitimate file (e.g., `image.jpg`).
- Intercept the request (e.g., with Burp Suite) and change the `Content-Type` header to a malicious type (e.g., `application/x-php`).
- Try uploading a webshell (e.g., `shell.php`) with a legitimate `Content-Type` (e.g., `image/jpeg`).

```bash
# Example: Uploading a PHP webshell with spoofed MIME type
# 1. Create a simple PHP webshell (e.g., shell.php with <?php system($_GET["cmd"]); ?>)
# 2. Use curl to send the file, spoofing the Content-Type
curl -X POST -F "file=@shell.php;type=image/jpeg" http://target.com/upload.php
```

### Step 3: Test File Extension Validation Bypass
- **Double Extension**: `shell.php.jpg`, `shell.jpg.php`
- **Null Byte Bypass**: `shell.php%00.jpg` (often works on older PHP versions)
- **Case Manipulation**: `shell.PhP`, `shell.aSpX`
- **Alternate Extensions**: Try less common but executable extensions (e.g., `.phtml`, `.phar`, `.jspx`, `.asa`, `.cer`, `.aspx`)
- **HTACCESS Bypass**: If `.htaccess` files are allowed, upload one to change how other files are interpreted (e.g., `AddType application/x-httpd-php .jpg`)

### Step 4: Test for Content Validation Bypass (Polyglot Files)
- Embed malicious code within a seemingly legitimate file (e.g., PHP code in EXIF data of a JPG image).
- Use tools like `exiftool` to inject code into image metadata.

### Step 5: Identify Upload Directory and Access
- After uploading, try to locate the file. Common directories: `/uploads/`, `/images/`, `/files/`, `/static/`.
- Attempt to access the uploaded file directly in the browser. If it's a webshell, try executing commands.

---

## Exploitation Scenarios

### 1. Remote Code Execution (RCE)
- Upload a webshell (e.g., PHP, ASP, JSP) and execute arbitrary commands on the server.
- **Example Webshell**: `<?php system($_GET["cmd"]); ?>`

### 2. Defacement
- Upload an HTML file to replace legitimate web pages.

### 3. Client-Side Attacks
- Upload malicious HTML/JS files for XSS attacks if the uploaded file is served from the same domain and can be executed in the browser.

### 4. Data Exfiltration
- Upload a script that reads sensitive files from the server and sends them to an attacker-controlled server.

---

## Remediation

- **Strict Whitelisting**: Only allow a predefined list of safe file extensions and MIME types. Blacklisting is insufficient.
- **Server-Side Validation**: Always perform validation on the server-side. Never rely solely on client-side checks.
- **Content Inspection**: Use libraries or tools to inspect the actual content of the file (e.g., magic bytes, image parsing) to ensure it matches the declared type and is not malicious.
- **Rename Files**: Rename uploaded files to a unique, non-predictable name (e.g., UUID) to prevent directory traversal and make guessing harder.
- **Store Outside Web Root**: Store uploaded files in a directory outside the web server's document root, if possible, to prevent direct execution.
- **Restrict Permissions**: Set strict file system permissions on upload directories to prevent execution.
- **Scan for Malware**: Integrate antivirus/antimalware scanning for uploaded files.
- **Limit File Size**: Enforce strict limits on file size to prevent DoS attacks.
- **Serve Files with `Content-Disposition: attachment`**: Force browsers to download files instead of rendering them, mitigating client-side attacks.

---

## References

[1] OWASP: Unrestricted File Upload - https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload
[2] PortSwigger: File upload vulnerabilities - https://portswigger.net/web-security/file-upload
[3] OWASP: File Upload Cheat Sheet - https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
