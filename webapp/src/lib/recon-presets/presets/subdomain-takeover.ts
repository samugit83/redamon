import type { ReconPreset } from '../types'

export const SUBDOMAIN_TAKEOVER: ReconPreset = {
  id: 'subdomain-takeover',
  name: 'Subdomain Takeover Hunter',
  icon: '',
  image: '/preset-capture.svg',
  shortDescription: 'Maximum-aggression takeover hunt. Widest subdomain net feeds Subjack (all DNS checks), Nuclei takeover templates, and BadDNS. Lowered confidence threshold surfaces manual-review candidates.',
  fullDescription: `### Pipeline Goal
Discover every subdomain that exists and squeeze every possible takeover finding out of them. This is the one-preset-to-rule-them-all for subdomain takeover hunting: maximum discovery breadth + maximum detection depth + lowest feasible confidence threshold.

### Who is this for?
- Bug bounty hunters chasing the full spectrum of takeover primitives (CNAME, NS, stale A, SPF/MX).
- DNS hygiene audits during M&A, org restructures, or cloud migrations where dangling records are common.
- Asset inventory teams auditing DNS across large domain estates.

### What it enables -- Discovery layer
- **All 5 subdomain tools at 10000 max**: crt.sh, HackerTarget, Knockpy, Subfinder, Amass -- every passive source + brute force.
- **Amass active mode** + brute-force for deeper enumeration than pure passive sources.
- **Puredns** for DNS-based resolution and wildcard filtering.
- **Bruteforce wordlist** (jhaddix-all.txt) for fuzz-discovery of subdomains.
- **WHOIS** + **DNS** lookups for ownership and record context.
- **GAU** historical URL mining from Wayback/CommonCrawl/OTX/URLScan archives -- catches subdomains that existed in the past but not in live DNS today.

### What it enables -- Takeover detection layer
- **httpx** with CNAME, status code, title, IP, tech-detect, TLS-info probes -- the alive-URL list feeds the Nuclei takeover pass.
- **BadDNS (AGPL-3.0 isolated sidecar)** with 7 modules:
  - \`cname\`, \`ns\`, \`mx\`, \`txt\`, \`spf\` (same coverage as Subjack, different detection logic -- runs both for belt-and-suspenders)
  - \`dmarc\` (missing / misconfigured DMARC)
  - \`wildcard\` (wildcard DNS enabling broad takeovers)
  - Runs in its own Docker image (\`redamon-baddns:latest\`), zero license contagion.
- **Subjack with EVERY optional check**:
  - Default CNAME takeover
  - \`-a\` probe every URL, not just identified CNAMEs
  - \`-ns\` NS takeover (expired nameservers, dangling cloud DNS delegations)
  - \`-ar\` stale A records (dead cloud IPs, manual-review candidates)
  - \`-mail\` SPF include + MX takeover (email-vector attacks)
  - \`-ssl\` force HTTPS for accuracy
  - 20 threads, 30s timeout, 30-min hard cap
- **Nuclei takeover templates** (\`-t http/takeovers/ -t dns/\`) across all 4 severity levels (critical/high/medium/low).
- **Confidence threshold 40** (default is 60) -- more candidates surface as \`likely\` or \`confirmed\`.
- **Auto-publish manual-review findings** -- stale-A and uncertain-fingerprint candidates are promoted from \`severity: info\` to \`severity: medium\` so they appear in the main Vulnerability table instead of being hidden.
- **Rate limit 100 req/s** (default 50) for faster Nuclei pass.

### What it disables
- **Full Nuclei scan** -- the dedicated takeover module already runs Nuclei with takeover-only templates. Running the full scanner in addition would duplicate work without adding coverage.
- Port scanning (Naabu, Nmap, Masscan) -- irrelevant to takeover detection.
- Web crawlers (Katana, Hakrawler) and directory fuzzing (ffuf, Kiterunner, Arjun, ParamSpider) -- not on the takeover path.
- JS analysis (jsluice, JS Recon) -- not relevant.
- Wappalyzer, banner grabbing, heavy httpx probes (JARM, favicon, ASN, CDN, response body) -- unnecessary overhead.
- CVE lookup, MITRE enrichment -- focus stays on takeover.
- SecurityChecks -- no header/TLS/WAF noise mixed in.
- OSINT enrichment providers -- would duplicate subdomain work with worse signal-to-noise.
- GraphQL scan -- unrelated.

### How the layered scanner works
1. **Subdomain discovery** fans out across 5 parallel sources + active Amass + brute-force + Puredns filtering + GAU historical mining.
2. **DNS resolution** builds the full subdomain → IP map.
3. **httpx** identifies alive URLs.
4. **GROUP 6 Phase A** runs Subjack + Nuclei takeover templates in parallel on the alive set.
   - Subjack inspects CNAME/NS/MX chains against its built-in fingerprint database.
   - Nuclei fires only \`http/takeovers/\` and \`dns/\` templates against httpx-alive URLs.
5. **Dedup** merges findings by \`(hostname, provider, method)\`; findings confirmed by both tools get a higher \`confirmation_count\` and therefore a higher \`confidence\` score.
6. **Scoring** at threshold 40 classifies: \`confirmed\` (>=50), \`likely\` (>=40), \`manual_review\` (<40).
7. **Auto-publish** elevates manual-review findings from severity \`info\` to \`medium\` so they surface in the findings table.
8. **Graph write**: every finding becomes a \`Vulnerability\` node with \`source="takeover_scan"\`, linked to its Subdomain via \`HAS_VULNERABILITY\`.

### What to watch out for
- **\`subjackCheckAr\`** (stale A record detection) probes cloud IP ranges and historically needed root/ICMP. RedAmon's recon container runs with the right privileges so this is fine, but expect some false positives -- those are exactly the findings the manual-review queue is for.
- **High discovery breadth** can produce thousands of subdomains on large targets. Puredns filters wildcards but the downstream Nuclei pass can still take 30+ minutes. Run timeouts are set to 30 min (Subjack) and 40 min (Nuclei takeover pass).
- **Manual-review noise**: auto-publish is ON, so stale-A and low-confidence findings appear as \`severity: medium\`. Filter by \`verdict\` in the Findings table to triage -- \`confirmed\` first, then \`likely\`, then \`manual_review\`.`,
  parameters: {
    // Pipeline modules: discovery + http_probe + resource_enum (for GAU only) + vuln_scan.
    // resource_enum is present so GAU runs; all other resource_enum tools are
    // explicitly disabled below.
    scanModules: ['domain_discovery', 'http_probe', 'resource_enum', 'vuln_scan'],

    stealthMode: false,
    useTorForRecon: false,

    // ============================================================
    // DISCOVERY LAYER -- maximum breadth
    // ============================================================
    subdomainDiscoveryEnabled: true,
    crtshEnabled: true,
    crtshMaxResults: 10000,
    hackerTargetEnabled: true,
    hackerTargetMaxResults: 10000,
    knockpyReconEnabled: true,
    knockpyReconMaxResults: 10000,
    subfinderEnabled: true,
    subfinderMaxResults: 10000,
    amassEnabled: true,
    amassActive: true,           // Active queries on top of passive sources
    amassBrute: true,            // Brute-force subdomain wordlist
    amassMaxResults: 10000,
    amassTimeout: 15,
    purednsEnabled: true,        // Wildcard filtering
    useBruteforceForSubdomains: true,

    whoisEnabled: true,
    dnsEnabled: true,

    // --- GAU: historical URL mining adds subdomains not in live DNS ---
    gauEnabled: true,
    gauProviders: ['wayback', 'commoncrawl', 'otx', 'urlscan'],
    gauMaxUrls: 5000,
    gauVerifyUrls: false,

    // ============================================================
    // HTTP PROBE -- required inputs for Nuclei takeover pass
    // ============================================================
    httpxEnabled: true,
    httpxFollowRedirects: true,
    httpxProbeStatusCode: true,
    httpxProbeTitle: true,
    httpxProbeIp: true,
    httpxProbeCname: true,        // Critical for dangling-CNAME detection
    httpxProbeTechDetect: true,
    httpxProbeTlsInfo: true,
    // Heavy probes off
    httpxProbeJarm: false,
    httpxProbeFavicon: false,
    httpxProbeAsn: false,
    httpxProbeCdn: false,
    httpxIncludeResponse: false,
    httpxIncludeResponseHeaders: false,
    httpxProbeWordCount: false,
    httpxProbeLineCount: false,
    httpxProbeTlsGrab: false,

    wappalyzerEnabled: false,
    bannerGrabEnabled: false,

    // ============================================================
    // OFF: port scanning, crawlers, fuzzers, parameter discovery, JS analysis
    // ============================================================
    naabuEnabled: false,
    nmapEnabled: false,
    masscanEnabled: false,
    katanaEnabled: false,
    hakrawlerEnabled: false,
    paramspiderEnabled: false,
    jsluiceEnabled: false,
    jsReconEnabled: false,
    ffufEnabled: false,
    kiterunnerEnabled: false,
    arjunEnabled: false,

    // ============================================================
    // NUCLEI full scanner: DISABLED
    // The dedicated takeover module below runs its own Nuclei pass with
    // http/takeovers/ + dns/ templates. Running the full scanner in addition
    // would duplicate takeover template execution without new coverage.
    // ============================================================
    nucleiEnabled: false,

    // ============================================================
    // TAKEOVER DETECTION LAYER -- every layer, every check, lowest threshold
    // ============================================================
    subdomainTakeoverEnabled: true,
    subjackEnabled: true,
    subjackSsl: true,
    subjackAll: true,             // Probe every URL, not just identified CNAMEs
    subjackCheckNs: true,         // NS takeovers (expired nameservers / dangling cloud DNS)
    subjackCheckAr: true,         // Stale A records (dead cloud IPs -- manual-review candidates)
    subjackCheckMail: true,       // SPF include + MX takeovers (email-vector attacks)
    subjackThreads: 20,           // Aggressive -- DNS is cheap
    subjackTimeout: 30,
    subjackRunTimeout: 1800,      // 30 min hard cap
    nucleiTakeoversEnabled: true,
    nucleiTakeoverRunTimeout: 2400,            // 40 min hard cap
    takeoverSeverity: ['critical', 'high', 'medium', 'low'],
    takeoverConfidenceThreshold: 40,           // Lower than default 60 -- surface more candidates
    takeoverRateLimit: 100,                    // Higher than default 50 -- faster Nuclei pass
    takeoverManualReviewAutoPublish: true,     // Elevate manual_review findings to severity: medium

    // BadDNS AGPL-3.0 sidecar -- deep DNS coverage across all high-value modules.
    // Runs in its own Docker image (redamon-baddns:latest); no license contagion
    // since RedAmon never imports baddns and communicates over stdout only.
    // MTA-STS is intentionally omitted (upstream CLI validator rejects it).
    baddnsEnabled: true,
    baddnsModules: ['cname', 'ns', 'mx', 'txt', 'spf', 'dmarc', 'wildcard'],
    baddnsRunTimeout: 1800,

    // ============================================================
    // OFF: CVE / MITRE / SecurityChecks / OSINT / GraphQL
    // ============================================================
    cveLookupEnabled: false,
    mitreEnabled: false,
    securityCheckEnabled: false,
    osintEnrichmentEnabled: false,
    shodanEnabled: false,
    censysEnabled: false,
    urlscanEnabled: false,
    otxEnabled: false,
    fofaEnabled: false,
    netlasEnabled: false,
    virusTotalEnabled: false,
    zoomEyeEnabled: false,
    criminalIpEnabled: false,
    uncoverEnabled: false,
    graphqlSecurityEnabled: false,
    graphqlCopEnabled: false,
  },
}
