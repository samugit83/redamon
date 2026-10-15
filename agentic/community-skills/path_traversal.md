# Path Traversal Attack Skill

Directory-traversal and arbitrary-file-access workflow: find parameters that resolve to a filesystem path, confirm traversal above the intended directory, and escalate through encoding and filter bypasses to read sensitive files, abuse PHP and other URL-scheme wrappers, and reach file-write or inclusion sinks (LFI-to-RCE via log poisoning, session files, or upload chaining). Use this skill when attacker input influences a file path the server opens, includes, downloads, or serves.

## When to Classify Here

Pick this skill when the task is to escape an intended directory or read/write arbitrary files via a path parameter, including:

- "Test the `file`/`download` parameter for path traversal."
- "Read /etc/passwd through this document viewer."
- "Bypass the filter that strips `../` from the template parameter."
- "The include uses a user-controlled filename, chain LFI to RCE."
- "Use php://filter to exfiltrate the app source."
- "The export path parameter looks like it writes a file, test for arbitrary write."

Keywords: path traversal, directory traversal, LFI, local file inclusion, arbitrary file read, arbitrary file write, dot-dot-slash, `../`, `..%2f`, `..%5c`, `%2e%2e`, double encoding, null byte, php://filter, php://input, data://, expect://, zip://, phar://, log poisoning, /etc/passwd, web.config, download endpoint, file parameter, template parameter, RFI.

### Disjoint from neighbouring skills

- vs. `insecure_file_uploads` (community, @samugit83): that skill is about uploading a malicious file (web shell, SVG XSS, zip slip on extraction). This skill is about reading or writing files through a path parameter. They chain (an upload plus an include yields RCE), but the entry primitive differs: upload form versus path parameter.
- vs. `ssrf_exploitation` (community): `file://` reached through a URL-fetching parameter is SSRF scheme-smuggling; a filesystem path parameter opened directly by the app is path traversal. If the parameter is a URL, classify to `ssrf_exploitation`; if it is a path or filename, stay HERE.
- vs. `ssti` (community): SSTI evaluates a template engine; path traversal opens a file. A template-name parameter that selects a file is traversal/LFI; one whose contents are evaluated as template syntax is SSTI.
- vs. `xxe` (community): XXE reads files via XML external entities; this skill reads them via a path parameter. If the input is XML, classify to `xxe`.
- vs. `cve_exploit` (built-in): a named traversal/LFI CVE in a specific product belongs to `cve_exploit` when the user gives the CVE ID.

## Tools

- `query_graph` to inventory Endpoints and Parameters whose names suggest a path or file (file, path, filename, page, template, doc, download, view, include, dir, folder, lang, theme).
- `execute_httpx` to fingerprint the stack (OS and language decide the target files and wrapper availability).
- `execute_arjun` for hidden path/file parameters on candidate endpoints.
- `execute_curl` for single-shot traversal probes and the final proof requests.
- `execute_code` for encoding sweeps, depth iteration (`../` x N), wrapper payload construction, and LFI-to-RCE chaining loops.
- `execute_ffuf` for LFI wordlist fuzzing of the path parameter (common sensitive-file lists).
- `kali_shell` for `interactsh-client` (to confirm an RFI or log-poisoning callback) and `jq`.

### Captured-traffic workflow (proxy_brain tools)

When HTTP Traffic Capture is enabled, source candidates from recorded history. `redamon.params()` flags parameters whose observed values look like paths or filenames; `redamon.fuzz(<txn_id>, "<param>", ["../../../../etc/passwd","....//....//etc/passwd","%2e%2e%2fetc%2fpasswd"])` sprays traversal and encoding variants over one captured query parameter (50 payloads max, origin host only) and reports per-payload status and length, which is exactly the differential oracle traversal needs. `redamon.grep("root:.*:0:0")` scans response bodies for a successful `/etc/passwd` read. Where the proxy stops: path-segment file parameters and wrapper payloads (`php://filter`) that need body or header placement run through iterated `redamon.replay`, and LFI-to-RCE chaining runs through `execute_code`.

## Workflow

Three phases. Phase 1 is non-destructive: find path parameters and confirm traversal with a benign, known-safe file read. Phase 2 escalates to sensitive-file read, wrapper abuse, and inclusion-to-RCE. Phase 3 scopes impact. If out-of-band callbacks are forbidden, confine RFI and log-poisoning checks to inline evidence and note the limitation.

### Phase 1: Discovery and Confirmation (Informational)

1. **Inventory path sinks via `query_graph`**: ask "list Endpoints and Parameters for the target host whose name or sample value looks like a file path, filename, or template name". High-yield features: document/report viewers, file download endpoints, avatar/image servers, language and theme selectors, and template loaders.

2. **Fingerprint the stack with `execute_httpx`**: OS (Linux versus Windows) decides target files (`/etc/passwd` versus `C:\Windows\win.ini`) and path separators; language (PHP, Java, Node, .NET) decides wrapper availability and inclusion behavior.

3. **Discover hidden path parameters** with `execute_arjun` on candidate endpoints.

4. **Confirm traversal with a benign, reversible read**. Establish the baseline (the intended file), then step above the directory toward a known-safe, universally present file and diff the responses:
   ```
   execute_curl> -s "https://target.tld/download?file=../../../../etc/passwd"
   ```
   A response containing `root:x:0:0:` confirms traversal. On Windows, target `..\..\..\..\Windows\win.ini`. If `../` is stripped or the response is unchanged, move to the encoding ladder in Phase 2.A.

5. **Characterize the filter and sink**: note whether the app strips `../`, enforces a prefix or extension, appends an extension, or decodes once. Determine the sink type: read (download/view), include (code execution if the content is interpreted), or write (export/save). This decides the Phase 2 track.

Once a path parameter is confirmed to resolve above its intended directory (via a known-safe file read) and the filter and sink type are characterized, **request transition to exploitation phase**.

### Phase 2: Exploitation

Pick the track matching the Phase 1 sink, lowest impact first. Every track ends with a Validation step.

#### 2.A Encoding and filter-bypass ladder

Escalate through bypasses when plain `../` is filtered, using `execute_code` to sweep:
- URL-encoded and double-encoded: `..%2f`, `%2e%2e%2f`, `..%252f`.
- Non-recursive-strip bypass: `....//`, `..../\`, `..;/` (Tomcat).
- Backslash and mixed separators on Windows/Tomcat: `..%5c`, `..\`.
- Nested and overlong UTF-8: `%c0%ae%c0%ae/`.
- Null byte and extension-append defeat (legacy stacks): `file=../../../../etc/passwd%00.png`.
- Absolute-path and prefix defeat: supply a full path, or prepend the expected prefix then traverse out.
- Validation: the known-safe file reads through despite the filter.

#### 2.B Sensitive-file read

Once traversal works, enumerate high-value files for the fingerprinted stack with `execute_ffuf` or a targeted list:
- Linux: `/etc/passwd`, `/etc/hosts`, `/proc/self/environ`, `/proc/self/cmdline`, app config (`.env`, `config.php`, `application.properties`), SSH keys (only with authorization).
- Windows: `C:\Windows\win.ini`, `web.config`, `C:\inetpub\logs\...`, app config.
- Validation: a sensitive config value or credential read (redact in the report).

#### 2.C PHP and scheme wrappers (PHP stacks)

When the sink is a PHP `include`/`require` or a wrapper-aware reader:
- Source exfiltration without execution: `php://filter/convert.base64-encode/resource=index.php`, then base64-decode the response.
- Direct execution via input: `php://input` with the PHP payload in the POST body (when `allow_url_include` is on).
- `data://text/plain;base64,<payload>` for inline code (when `allow_url_include` is on).
- `phar://` or `zip://` to reach code inside an uploaded archive (chains with `insecure_file_uploads`).
- Validation: app source returned, or a controlled command output for an execution wrapper.

#### 2.D LFI to RCE

When a read sink actually includes/executes the file content:
- Log poisoning: inject PHP into a header (User-Agent) that the server logs, then include the log file (`/var/log/apache2/access.log`, `/var/log/nginx/access.log`).
- Session-file inclusion: control a session value, then include the session file under `/var/lib/php/sessions/`.
- `/proc/self/environ` poisoning (older stacks).
- Upload-then-include: pair with `insecure_file_uploads` to drop a file and include it.
- Validation: a controlled command output (for example a unique marker from `id`), tied to a unique token; use `interactsh-client` for a blind callback if output is suppressed.

### Phase 3: Post-Exploitation

Scope the compromise reversibly.

1. **With file read**: collect configuration, credentials, and keys that define blast radius; prove reach with a redacted sample, not bulk exfiltration.
2. **With RCE**: capture process identity (`id`, `whoami`) and container context, then hand foothold stabilization to the `rce` built-in.
3. **With file write**: demonstrate a single controlled, reversible write (a uniquely named marker file) and remove it; do not overwrite production files.
4. **Validation**: tie each proof to a unique marker and clean up anything created (poisoned log entries are hard to remove, so note them explicitly in the report).

## Reporting Guidelines

Each finding must include:

- **Class**: arbitrary file read, wrapper-based source disclosure, LFI-to-RCE, or arbitrary file write.
- **Sink**: parameter name, method, endpoint, and sink type (download/view/include/write).
- **Confirmation**: the benign known-safe read that proved traversal (with the response excerpt), plus the bypass used if any.
- **Working exploit**: the exact copy-paste request reproducing the read/execution/write.
- **Evidence**: the sensitive file read (redacted), the decoded source, or the command output with a unique marker.
- **Impact**: source/secret disclosure, remote code execution, or arbitrary write.
- **CVSS**: 9.x when it reaches RCE or credentials, lower for constrained reads.
- **Remediation**: canonicalize and validate the resolved path against an allowlisted base directory, reject traversal sequences after decoding, avoid passing user input to include/require, and disable dangerous PHP wrappers (`allow_url_include` off).
- **References**: PortSwigger path traversal and file inclusion labs, PayloadsAllTheThings Directory Traversal and File Inclusion, HackTricks LFI/RFI.

## Important Notes

- **Confirm with a known-safe file first.** Prove traversal against a universally present, non-sensitive file (`/etc/passwd`, `win.ini`) before reaching for secrets, so a false positive does not send you down a wrong bypass path.
- **Engagement scope and secret handling.** Read the minimum needed to prove impact; never bulk-exfiltrate key material, and redact live secrets in the report body (show the request, mask the value).
- **Log poisoning is noisy and hard to undo.** It writes attacker content into shared log files. Use it only with authorization, keep the payload minimal and marked, and document exactly which log you touched.
- **File writes are destructive by nature.** Only demonstrate a single reversible, uniquely named write, and remove it; never overwrite existing files to prove the bug.
- **OOB-blocked environments.** If interactsh is unreachable, confine RFI and blind-LFI-to-RCE checks to inline output and note the limitation.
- **Chain handoff.** Upload-plus-include goes to `insecure_file_uploads`; a stabilized shell goes to the `rce` built-in; a `file://` reached via a URL parameter is `ssrf_exploitation`.
- **CVE handoff.** A named traversal/LFI CVE in a specific product belongs to `cve_exploit` when the user gives the CVE ID.
- **No em dashes** anywhere in artifacts that flow into the report. Use hyphens.
