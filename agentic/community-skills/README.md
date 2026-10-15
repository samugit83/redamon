# Community Skills

Ready-to-use attack skill workflows contributed by the community. Download any `.md` file and upload it via **Global Settings > Agent Skills** to activate it for your user.

## Skills

| Skill | Author | Description |
|-------|--------|-------------|
| [ade_scoper.md](ade_scoper.md) | [@NikolasBielski](https://github.com/NikolasBielski), [@Koifman](https://github.com/Koifman) | Purple-team emulation planning, SIEM detection-gap analysis, rule-hardening recommendations |
| [api_testing.md](api_testing.md) | [@Shafranpackeer](https://github.com/Shafranpackeer) | API auth and authz: JWT (alg confusion, kid/jku/x5u, secret cracking, claim tampering), GraphQL (introspection recovery, IDOR, batching), REST 401/403 bypass, BOLA and version drift |
| [xss_exploitation.md](xss_exploitation.md) | [@Shafranpackeer](https://github.com/Shafranpackeer) | Reflected, stored, DOM-based and blind XSS: context analysis, CSP and WAF bypass, mutation XSS against sanitizers, browser-confirmed DOM sinks |
| [sqli_exploitation.md](sqli_exploitation.md) | [@Shafranpackeer](https://github.com/Shafranpackeer) | Advanced SQL injection beyond sqlmap: manual DBMS fingerprinting, boolean/time/error/UNION extraction, OOB exfiltration, WAF and filter evasion, second-order sinks |
| [auth_session_attacks.md](auth_session_attacks.md) | [@Shafranpackeer](https://github.com/Shafranpackeer) | OAuth/OIDC flow abuse (redirect_uri, state/PKCE, token leakage), session fixation and invalidation, cookie-flag gaps, MFA bypass |
| [request_smuggling.md](request_smuggling.md) | [@Shafranpackeer](https://github.com/Shafranpackeer) | HTTP request smuggling and connection desync: CL.TE/TE.CL/TE.TE, HTTP/2 downgrade (H2.CL/H2.TE), response queue poisoning, cache poisoning, control bypass |
| [broken_access_control.md](broken_access_control.md) | [@Shafranpackeer](https://github.com/Shafranpackeer) | Structured access-control audit: privilege-boundary mapping, vertical/horizontal escalation, forced browsing, workflow-state bypass, client-side enforcement; routes to the object/function/mass-assignment skills |
| [ssrf_exploitation.md](ssrf_exploitation.md) | [@Shafranpackeer](https://github.com/Shafranpackeer) | Server-Side Request Forgery: OOB confirmation, cloud metadata theft (AWS/GCP/Azure), internal port scanning, filter and allowlist bypass, gopher/dict/file scheme smuggling |
| [path_traversal.md](path_traversal.md) | [@Shafranpackeer](https://github.com/Shafranpackeer) | Path traversal and LFI: encoding and filter bypass, sensitive-file read, PHP scheme wrappers, LFI-to-RCE via log/session poisoning, arbitrary file write |
| [ssti.md](ssti.md) | [@samugit83](https://github.com/samugit83) | Server-Side Template Injection: engine fingerprinting and sandbox-escape to RCE across Jinja2, Twig, Freemarker, Velocity, EJS, Thymeleaf, Smarty, Mako, Pebble, Handlebars, Pug |
| [xxe.md](xxe.md) | [@samugit83](https://github.com/samugit83) | XML External Entity: file disclosure, SSRF, OOB DTD, XInclude, XSLT, SVG/OOXML uploads |
| [bfla_exploitation.md](bfla_exploitation.md) | [@samugit83](https://github.com/samugit83) | Broken Function Level Authorization: vertical privilege escalation, transport drift, gateway header trust, job replay |
| [insecure_deserialization.md](insecure_deserialization.md) | [@samugit83](https://github.com/samugit83) | Java/PHP/Python/.NET/Ruby gadget chains via ysoserial, phpggc, pickle, BinaryFormatter, Marshal |
| [idor_bola_exploitation.md](idor_bola_exploitation.md) | [@samugit83](https://github.com/samugit83) | Object-level authz (IDOR, BOLA, cross-tenant) with two-identity swap across REST/GraphQL/batch/job/storage |
| [mass_assignment.md](mass_assignment.md) | [@samugit83](https://github.com/samugit83) | Privileged-field injection, ownership takeover, feature-gate and billing tampering across REST, GraphQL, JSON Patch, batch writes |
| [subdomain_takeover.md](subdomain_takeover.md) | [@samugit83](https://github.com/samugit83) | Dangling CNAME / orphaned NS / unverified provider claim across S3, GitHub Pages, Heroku, Azure, CloudFront, Fastly and ~80 more |
| [insecure_file_uploads.md](insecure_file_uploads.md) | [@samugit83](https://github.com/samugit83) | Web shells, SVG/HTML stored XSS, magic-byte and config-drop bypass, ImageMagick/Ghostscript/ExifTool abuse, zip slip, presigned-URL tampering, processing-race AV bypass |

## Contributing

1. Create your `.md` skill file following the [Writing a Skill File](https://github.com/samugit83/redamon/wiki/Agent-Skills#writing-a-skill-file) format
2. Test it in your RedAmon instance by uploading via Global Settings
3. Fork the repo, add your `.md` file to this folder, and update this table with your GitHub username
4. Open a Pull Request
