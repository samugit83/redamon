import type { ReconPreset } from '../types'

export const BUG_BOUNTY_DEEP: ReconPreset = {
  id: 'bug-bounty-deep',
  name: 'Bug Bounty - Deep Dive',
  icon: '',
  image: '/preset-submarine.svg',
  shortDescription: 'Thorough single-target assessment. Deep crawling, JS analysis, all Nuclei severities, balanced to avoid IP bans.',
  fullDescription: `### Pipeline Goal
Go deep on a single target without getting blocked. This preset balances thoroughness with responsible rate limiting -- deep crawling, JS secret extraction, full Nuclei coverage, and parameter discovery, all with moderate concurrency to stay under WAF thresholds.

### Who is this for?
Bug bounty hunters who have already triaged a target (perhaps with the Quick Wins preset) and want to go deeper. Pentesters doing a thorough web application assessment on a specific scope. You are willing to wait 1-2 hours for comprehensive results.

### What it enables
- Full subdomain discovery (all 5 tools at max results) for maximum subdomain coverage
- Puredns wildcard filtering
- httpx probing with all probes enabled for full fingerprinting
- Wappalyzer technology detection
- Katana depth 3 with JS crawl + 1500 URLs for deep endpoint discovery
- Hakrawler depth 3 for complementary crawl coverage
- GAU with all providers for historical endpoint discovery
- jsluice on 300 JS files for secret and URL extraction
- JS Recon with full analysis (source maps, DOM sinks, dependency checks, key validation)
- Arjun parameter discovery on GET/POST methods
- Nuclei with all severity levels + DAST mode + Interactsh OOB detection
- Security checks for comprehensive header/TLS/infrastructure validation
- CVE lookup and MITRE enrichment

### What it disables
- Port scanning (Naabu, Masscan, Nmap) -- not needed for web-focused bounty hunting, httpx handles web ports
- ffuf directory fuzzing -- too noisy for bug bounty, risk of IP ban
- Kiterunner API brute-force -- too noisy, risk of IP ban
- ParamSpider -- Arjun + GAU cover parameter discovery better
- Nuclei headless mode -- slow and resource-intensive, not worth the tradeoff
- Banner grabbing -- not needed without port scanning
- All OSINT enrichment -- passive intel rarely leads to bounty-eligible findings

### How it works
1. All subdomain discovery tools run in parallel with high result limits
2. httpx probes all discovered hosts with full technology fingerprinting
3. Katana + Hakrawler crawl deeply in parallel, GAU adds historical URLs
4. jsluice extracts secrets and endpoints from all discovered JS files
5. JS Recon performs deep analysis: source maps, DOM XSS sinks, dependency confusion, key validation
6. Arjun discovers hidden parameters on found endpoints
7. Nuclei runs all templates in DAST mode using crawled URLs with OOB detection
8. Security checks validate headers, TLS, cookies, and infrastructure exposure
9. CVE lookup and MITRE enrichment map findings to known vulnerabilities`,
  parameters: {
    // Modules: all except port_scan (web-focused) and js_recon handled via tool toggle
    scanModules: ['domain_discovery', 'http_probe', 'resource_enum', 'vuln_scan', 'js_recon'],

    // No stealth, no Tor
    stealthMode: false,
    useTorForRecon: false,

    // --- Subdomain Discovery: all tools at high limits ---
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
    amassActive: false,
    amassBrute: false,
    amassMaxResults: 10000,
    amassTimeout: 15,
    purednsEnabled: true,
    useBruteforceForSubdomains: false,

    // --- WHOIS & DNS ---
    whoisEnabled: true,
    dnsEnabled: true,

    // --- DISABLE port scanning ---
    naabuEnabled: false,
    masscanEnabled: false,
    nmapEnabled: false,

    // --- httpx: all probes enabled for full fingerprinting ---
    httpxEnabled: true,
    httpxThreads: 50,
    httpxTimeout: 15,
    httpxRetries: 2,
    httpxRateLimit: 50,
    httpxFollowRedirects: true,
    httpxMaxRedirects: 10,
    httpxProbeStatusCode: true,
    httpxProbeContentLength: true,
    httpxProbeContentType: true,
    httpxProbeTitle: true,
    httpxProbeServer: true,
    httpxProbeResponseTime: true,
    httpxProbeWordCount: true,
    httpxProbeLineCount: true,
    httpxProbeTechDetect: true,
    httpxProbeIp: true,
    httpxProbeCname: true,
    httpxProbeTlsInfo: true,
    httpxProbeTlsGrab: true,
    httpxProbeFavicon: true,
    httpxProbeJarm: true,
    httpxProbeHash: 'sha256',
    httpxProbeAsn: true,
    httpxProbeCdn: true,
    httpxIncludeResponse: true,
    httpxIncludeResponseHeaders: true,

    // --- Wappalyzer: enabled ---
    wappalyzerEnabled: true,
    wappalyzerMinConfidence: 30,
    wappalyzerAutoUpdate: true,

    // --- DISABLE banner grabbing (no port scan) ---
    bannerGrabEnabled: false,

    // --- Katana: deep crawl, moderate rate ---
    katanaEnabled: true,
    katanaDepth: 3,
    katanaMaxUrls: 1500,
    katanaRateLimit: 50,
    katanaTimeout: 3600,
    katanaJsCrawl: true,
    katanaParallelism: 8,
    katanaConcurrency: 15,

    // --- Hakrawler: deep crawl ---
    hakrawlerEnabled: true,
    hakrawlerDepth: 3,
    hakrawlerThreads: 5,
    hakrawlerTimeout: 45,
    hakrawlerMaxUrls: 800,
    hakrawlerIncludeSubs: true,
    hakrawlerInsecure: true,

    // --- GAU: all providers for historical URLs ---
    gauEnabled: true,
    gauProviders: ['wayback', 'commoncrawl', 'otx', 'urlscan'],
    gauMaxUrls: 5000,
    gauTimeout: 90,
    gauThreads: 5,
    gauVerifyUrls: true,
    gauDetectMethods: true,
    gauFilterDeadEndpoints: true,
    gauWorkers: 10,

    // --- DISABLE ParamSpider (Arjun + GAU cover this) ---
    paramspiderEnabled: false,
    paramspiderWorkers: 8,

    // --- jsluice: moderate limits ---
    jsluiceEnabled: true,
    jsluiceMaxFiles: 300,
    jsluiceExtractSecrets: true,
    jsluiceExtractUrls: true,
    jsluiceConcurrency: 5,

    // --- JS Recon: full analysis ---
    jsReconEnabled: true,
    jsReconMaxFiles: 800,
    jsReconTimeout: 1800,
    jsReconConcurrency: 10,
    jsReconValidateKeys: true,
    jsReconValidationTimeout: 5,
    jsReconExtractEndpoints: true,
    jsReconRegexPatterns: true,
    jsReconSourceMaps: true,
    jsReconDependencyCheck: true,
    jsReconDomSinks: true,
    jsReconFrameworkDetect: true,
    jsReconDevComments: true,
    jsReconIncludeChunks: true,
    jsReconIncludeFrameworkJs: true,
    jsReconIncludeArchivedJs: true,
    jsReconMinConfidence: 'low',
    jsReconStandaloneCrawlDepth: 3,

    // --- DISABLE ffuf (too noisy, risk of IP ban) ---
    ffufEnabled: false,

    // --- DISABLE Kiterunner (too noisy) ---
    kiterunnerEnabled: false,

    // --- Arjun: GET + POST parameter discovery ---
    arjunEnabled: true,
    arjunThreads: 2,
    arjunTimeout: 15,
    arjunScanTimeout: 600,
    arjunMethods: ['GET', 'POST'],
    arjunMaxEndpoints: 50,
    arjunChunkSize: 500,
    arjunPassive: false,

    // --- Nuclei: all severities, DAST, moderate rate ---
    nucleiEnabled: true,
    nucleiSeverity: ['critical', 'high', 'medium', 'low'],
    nucleiRateLimit: 100,
    nucleiBulkSize: 25,
    nucleiConcurrency: 25,
    nucleiTimeout: 10,
    nucleiRetries: 2,
    nucleiDastMode: true,
    nucleiAutoUpdateTemplates: true,
    nucleiHeadless: false,
    nucleiSystemResolvers: true,
    nucleiFollowRedirects: true,
    nucleiMaxRedirects: 10,
    nucleiScanAllIps: false,
    nucleiInteractsh: true,

    // --- Subdomain Takeover: all layers on (bug bounty gold) ---
    subdomainTakeoverEnabled: true,
    subjackEnabled: true,
    subjackAll: true,
    subjackCheckNs: true,
    subjackCheckMail: true,
    nucleiTakeoversEnabled: true,
    takeoverSeverity: ['critical', 'high', 'medium', 'low'],
    takeoverConfidenceThreshold: 55,

    // --- GraphQL Security: coverage for deep hunt, but DoS probes OFF.
    //     This preset's mission ("balanced to avoid IP bans", "moderate concurrency
    //     to stay under WAF thresholds") is incompatible with graphql-cop's four
    //     DoS probes (alias overloading / array batching / directive overloading /
    //     circular introspection) which default-on and frequently trigger WAF bans.
    graphqlSecurityEnabled: true,
    graphqlCopEnabled: true,
    graphqlCopTestAliasOverloading: false,
    graphqlCopTestBatchQuery: false,
    graphqlCopTestDirectiveOverloading: false,
    graphqlCopTestCircularIntrospection: false,

    // --- CVE Lookup + MITRE: enabled ---
    cveLookupEnabled: true,
    cveLookupMaxCves: 20,
    cveLookupMinCvss: 0.0,

    mitreEnabled: true,
    mitreAutoUpdateDb: true,
    mitreIncludeCwe: true,
    mitreIncludeCapec: true,
    mitreEnrichRecon: true,

    // --- Security checks: all enabled ---
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
  },
}
