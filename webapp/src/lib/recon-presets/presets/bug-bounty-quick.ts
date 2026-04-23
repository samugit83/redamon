import type { ReconPreset } from '../types'

export const BUG_BOUNTY_QUICK: ReconPreset = {
  id: 'bug-bounty-quick',
  name: 'Bug Bounty - Quick Wins',
  icon: '',
  image: '/preset-bug.svg',
  shortDescription: 'Fast, lightweight scan for low-hanging fruit. Get actionable results in under 15 minutes.',
  fullDescription: `### Pipeline Goal
Speed over depth. Discover subdomains, probe HTTP, run a shallow crawl, and fire Nuclei at critical+high severity only. Designed to surface easy wins fast -- exposed panels, known CVEs, misconfigurations, default credentials -- before investing time in deeper analysis.

### Who is this for?
Bug bounty hunters triaging a new target. You want to know if there are quick wins before committing to a multi-hour deep scan. Also useful for a fast initial sweep at the start of a pentest engagement.

### What it enables
- Full subdomain discovery (all 5 tools at default limits) for broad target coverage
- Puredns wildcard filtering to remove junk subdomains
- httpx probing with essential probes (status, title, tech detect, TLS info)
- Katana shallow crawl (depth 1, 200 URLs) for basic endpoint discovery
- jsluice on discovered JS files (capped at 50 files) for quick secret extraction
- Nuclei with critical + high severity only, DAST mode, high rate for fast results
- Security checks enabled for header/TLS misconfigurations

### What it disables
- Port scanning (Naabu, Masscan, Nmap) -- httpx uses common web ports, saves significant time
- Hakrawler -- Katana alone is sufficient for shallow crawl
- GAU, ParamSpider -- archive lookups add time without quick wins
- ffuf, Kiterunner -- directory/API fuzzing is slow, not needed for quick triage
- Arjun -- parameter discovery is slow and better suited for deep dives
- JS Recon -- deep JS analysis takes too long for a quick scan
- All OSINT enrichment -- passive intel adds time without direct vulnerabilities
- CVE lookup, MITRE enrichment -- Nuclei already finds exploitable CVEs directly
- Banner grabbing -- not needed without port scanning
- Wappalyzer -- httpx tech detect covers this sufficiently

### How it works
1. Subdomain discovery enumerates all subdomains quickly using all 5 tools in parallel
2. httpx probes discovered hosts on common web ports
3. Katana does a shallow depth-1 crawl to find basic endpoints
4. jsluice extracts secrets and URLs from discovered JS files
5. Nuclei runs critical+high templates in DAST mode against all discovered URLs
6. Security checks flag missing headers, TLS issues, and exposed services`,
  parameters: {
    // Modules: domain discovery + http probe + resource enum (katana only) + vuln scan
    // No port_scan (saves time), no js_recon (too slow)
    scanModules: ['domain_discovery', 'http_probe', 'resource_enum', 'vuln_scan'],

    // No stealth, no Tor
    stealthMode: false,
    useTorForRecon: false,

    // --- Subdomain Discovery: all tools at default limits ---
    subdomainDiscoveryEnabled: true,
    crtshEnabled: true,
    hackerTargetEnabled: true,
    knockpyReconEnabled: true,
    subfinderEnabled: true,
    amassEnabled: true,
    amassActive: false,
    amassBrute: false,
    amassTimeout: 10,
    purednsEnabled: true,
    useBruteforceForSubdomains: false,

    // --- WHOIS & DNS ---
    whoisEnabled: true,
    dnsEnabled: true,

    // --- DISABLE port scanning (httpx handles common web ports) ---
    naabuEnabled: false,
    masscanEnabled: false,
    nmapEnabled: false,

    // --- httpx: essential probes only, fast ---
    httpxEnabled: true,
    httpxThreads: 50,
    httpxTimeout: 10,
    httpxRetries: 2,
    httpxRateLimit: 100,
    httpxFollowRedirects: true,
    httpxMaxRedirects: 10,
    httpxProbeStatusCode: true,
    httpxProbeContentLength: true,
    httpxProbeContentType: true,
    httpxProbeTitle: true,
    httpxProbeServer: true,
    httpxProbeResponseTime: true,
    httpxProbeWordCount: false,
    httpxProbeLineCount: false,
    httpxProbeTechDetect: true,
    httpxProbeIp: true,
    httpxProbeCname: true,
    httpxProbeTlsInfo: true,
    httpxProbeTlsGrab: false,
    httpxProbeFavicon: false,
    httpxProbeJarm: false,
    httpxProbeAsn: false,
    httpxProbeCdn: false,
    httpxIncludeResponse: false,
    httpxIncludeResponseHeaders: false,

    // --- DISABLE Wappalyzer (httpx tech detect is enough) ---
    wappalyzerEnabled: false,

    // --- DISABLE banner grabbing ---
    bannerGrabEnabled: false,

    // --- Katana: shallow, fast crawl ---
    katanaEnabled: true,
    katanaDepth: 1,
    katanaMaxUrls: 200,
    katanaRateLimit: 100,
    katanaTimeout: 600,
    katanaJsCrawl: true,
    katanaParallelism: 10,
    katanaConcurrency: 15,

    // --- DISABLE Hakrawler (Katana alone is sufficient) ---
    hakrawlerEnabled: false,
    hakrawlerParallelism: 5,

    // --- DISABLE GAU & ParamSpider (archive lookups too slow) ---
    gauEnabled: false,
    gauWorkers: 10,
    paramspiderEnabled: false,
    paramspiderWorkers: 8,

    // --- jsluice: quick pass on discovered JS ---
    jsluiceEnabled: true,
    jsluiceMaxFiles: 50,
    jsluiceExtractSecrets: true,
    jsluiceExtractUrls: true,
    jsluiceConcurrency: 5,

    // --- DISABLE JS Recon (too slow for quick scan) ---
    jsReconEnabled: false,

    // --- DISABLE directory fuzzing ---
    ffufEnabled: false,
    ffufParallelism: 4,

    // --- DISABLE API discovery ---
    kiterunnerEnabled: false,

    // --- DISABLE parameter discovery ---
    arjunEnabled: false,

    // --- Nuclei: critical + high only, DAST, fast ---
    nucleiEnabled: true,
    nucleiSeverity: ['critical', 'high'],
    nucleiRateLimit: 150,
    nucleiBulkSize: 50,
    nucleiConcurrency: 50,
    nucleiTimeout: 10,
    nucleiRetries: 1,
    nucleiDastMode: true,
    nucleiAutoUpdateTemplates: true,
    nucleiHeadless: false,
    nucleiSystemResolvers: true,
    nucleiFollowRedirects: true,
    nucleiMaxRedirects: 10,
    nucleiScanAllIps: false,
    nucleiInteractsh: true,

    // --- Subdomain Takeover: enabled (high-value bug bounty finding) ---
    subdomainTakeoverEnabled: true,
    subjackEnabled: true,
    nucleiTakeoversEnabled: true,
    takeoverSeverity: ['critical', 'high', 'medium'],

    // --- GraphQL: OFF by default. "Quick" preset skips niche scans that add
    //     30s-2min per BaseURL. Users can enable per-project if the target is GraphQL. ---

    // --- DISABLE CVE lookup and MITRE (Nuclei finds CVEs directly) ---
    cveLookupEnabled: false,
    mitreEnabled: false,

    // --- Security checks: enabled for quick header/TLS wins ---
    securityCheckEnabled: true,
    securityCheckDirectIpHttp: true,
    securityCheckDirectIpHttps: true,
    securityCheckIpApiExposed: true,
    securityCheckWafBypass: true,
    securityCheckTlsExpiringSoon: true,
    securityCheckTlsExpiryDays: 30,
    securityCheckMissingReferrerPolicy: true,
    securityCheckMissingPermissionsPolicy: true,
    securityCheckMissingCoop: true,
    securityCheckMissingCorp: true,
    securityCheckMissingCoep: true,
    securityCheckCacheControlMissing: true,
    securityCheckLoginNoHttps: true,
    securityCheckSessionNoSecure: true,
    securityCheckSessionNoHttponly: true,
    securityCheckBasicAuthNoTls: true,
    securityCheckSpfMissing: true,
    securityCheckDmarcMissing: true,
    securityCheckDnssecMissing: true,
    securityCheckZoneTransfer: true,
    securityCheckAdminPortExposed: true,
    securityCheckDatabaseExposed: true,
    securityCheckRedisNoAuth: true,
    securityCheckKubernetesApiExposed: true,
    securityCheckSmtpOpenRelay: true,
    securityCheckCspUnsafeInline: true,
    securityCheckInsecureFormAction: true,
    securityCheckNoRateLimiting: true,
    securityCheckTimeout: 10,
    securityCheckMaxWorkers: 10,

    // --- DISABLE all OSINT ---
    osintEnrichmentEnabled: false,
    shodanEnabled: false,
    urlscanEnabled: false,
    otxEnabled: false,
    censysEnabled: false,
    fofaEnabled: false,
    netlasEnabled: false,
    virusTotalEnabled: false,
    zoomEyeEnabled: false,
    criminalIpEnabled: false,
    uncoverEnabled: false,

    // --- GraphQL: explicit OFF so switching from a GraphQL-enabled preset resets cleanly ---
    graphqlSecurityEnabled: false,
    graphqlCopEnabled: false,
  },
}
