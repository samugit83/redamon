import type { ReconPreset } from '../types'

export const FULL_MAXIMUM_SCAN: ReconPreset = {
  id: 'full-maximum-scan',
  name: 'Full Pipeline - Maximum',
  icon: '',
  image: '/preset-bolt.svg',
  shortDescription: 'Every tool enabled with every parameter pushed to the limit. The longest, most thorough scan possible.',
  fullDescription: `### Pipeline Goal
Enable every single tool in the pipeline and push every parameter to its maximum useful value. Active scanning, passive OSINT, JS analysis, directory fuzzing, API discovery, vulnerability scanning -- all running with the highest depth, concurrency, and result limits. This is the "leave no stone unturned" preset.

### Who is this for?
Pentesters running a final comprehensive sweep on a target they have full authorization to test, or security teams doing a thorough baseline assessment of their own infrastructure. Expect this scan to take several hours on large targets.

### What it enables
- All 6 scan modules: domain_discovery, port_scan, http_probe, resource_enum, vuln_scan, js_recon
- Subdomain discovery: all 5 tools at 10000 max results + Amass active + brute force + Puredns validation
- Port scanning: Naabu SYN (top 1000) + Masscan (10000 pps) + Nmap T4 with version detection and NSE scripts
- httpx: all 20 probes enabled, response body capture, high concurrency
- Wappalyzer: low confidence threshold (20%) to catch more technologies
- Banner grabbing: 40 threads, 2000 byte max length
- Katana: depth 5, 5000 URLs, JS crawl, rate 150/s
- Hakrawler: depth 5, 2000 URLs, 15 threads
- GAU: all 4 providers, 10000 URLs, with verification and method detection
- ParamSpider: enabled with extended timeout
- jsluice: 1000 files, 15 concurrency
- JS Recon: 2000 files, all analysis modules, crawl depth 5, key validation
- ffuf: recursion depth 3, 60 threads, smart fuzz, auto-calibrate
- Kiterunner: routes-large, 200 connections, method detection
- Arjun: all 5 HTTP methods, 200 max endpoints, 10 threads
- Nuclei: all severities + DAST + headless + Interactsh + scan all IPs, 200 rate, 75 concurrency
- All 28 security checks with 20 workers
- CVE lookup: 50 max CVEs per service, min CVSS 0
- MITRE: full CWE + CAPEC enrichment
- All 10 OSINT providers at maximum results (Shodan, URLScan 10000, OTX, Censys, FOFA 5000, Netlas, VirusTotal, ZoomEye 5000, CriminalIP, Uncover 1000)

### What it disables
- Nothing. Every tool is enabled.
- Stealth mode is OFF (contradicts maximum scanning)
- Tor routing is OFF (would throttle throughput)

### How it works
1. All subdomain discovery tools run in parallel with Amass active brute forcing
2. Puredns filters wildcards, DNS resolves all subdomains
3. Naabu + Masscan scan ports in parallel, Nmap enriches with service versions and NSE scripts
4. httpx probes all host:port combos with complete fingerprinting
5. Banner grabbing identifies non-HTTP services
6. Katana + Hakrawler + GAU + ParamSpider discover every reachable endpoint
7. jsluice + JS Recon perform deep JavaScript analysis (endpoints, secrets, source maps, DOM sinks)
8. ffuf fuzzes directories recursively, Kiterunner discovers API routes
9. Arjun discovers hidden parameters on all found endpoints
10. Nuclei runs all templates in DAST mode with headless browser and OOB detection
11. All OSINT providers enrich IPs with threat intelligence
12. CVE lookup + MITRE enrichment map everything to known vulnerabilities and attack patterns`,
  parameters: {
    // All 6 scan modules
    scanModules: ['domain_discovery', 'port_scan', 'http_probe', 'resource_enum', 'vuln_scan', 'js_recon'],

    // No stealth, no Tor
    stealthMode: false,
    useTorForRecon: false,

    // --- Subdomain Discovery: everything maxed ---
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
    amassActive: true,
    amassBrute: true,
    amassMaxResults: 10000,
    amassTimeout: 20,
    purednsEnabled: true,
    useBruteforceForSubdomains: true,

    // --- WHOIS & DNS ---
    whoisEnabled: true,
    dnsEnabled: true,
    dnsMaxWorkers: 100,

    // --- Port Scanning: all 3 maxed ---
    naabuEnabled: true,
    naabuPassiveMode: false,
    naabuScanType: 's',
    naabuTopPorts: '1000',
    naabuRateLimit: 1500,
    naabuThreads: 50,
    naabuTimeout: 10000,
    naabuRetries: 3,
    naabuExcludeCdn: false,
    naabuDisplayCdn: true,
    naabuSkipHostDiscovery: true,
    naabuVerifyPorts: true,

    masscanEnabled: true,
    masscanTopPorts: '1000',
    masscanRate: 10000,
    masscanBanners: true,
    masscanWait: 10,
    masscanRetries: 3,

    nmapEnabled: true,
    nmapVersionDetection: true,
    nmapScriptScan: true,
    nmapTimingTemplate: 'T4',
    nmapTimeout: 1200,
    nmapHostTimeout: 600,
    nmapParallelism: 5,

    // --- httpx: all probes maxed ---
    httpxEnabled: true,
    httpxThreads: 75,
    httpxTimeout: 20,
    httpxRetries: 3,
    httpxRateLimit: 150,
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

    // --- Wappalyzer: low confidence to catch more ---
    wappalyzerEnabled: true,
    wappalyzerMinConfidence: 20,
    wappalyzerRequireHtml: false,
    wappalyzerAutoUpdate: true,

    // --- Banner Grabbing: high threads, large buffer ---
    bannerGrabEnabled: true,
    bannerGrabTimeout: 15,
    bannerGrabThreads: 40,
    bannerGrabMaxLength: 2000,

    // --- Katana: maximum crawl ---
    katanaEnabled: true,
    katanaDepth: 5,
    katanaMaxUrls: 5000,
    katanaRateLimit: 150,
    katanaTimeout: 7200,
    katanaJsCrawl: true,
    katanaParallelism: 15,
    katanaConcurrency: 25,

    // --- Hakrawler: maximum crawl ---
    hakrawlerEnabled: true,
    hakrawlerDepth: 5,
    hakrawlerThreads: 15,
    hakrawlerTimeout: 90,
    hakrawlerMaxUrls: 2000,
    hakrawlerIncludeSubs: true,
    hakrawlerInsecure: true,
    hakrawlerParallelism: 8,

    // --- GAU: all providers, high limits, with verification ---
    gauEnabled: true,
    gauProviders: ['wayback', 'commoncrawl', 'otx', 'urlscan'],
    gauMaxUrls: 10000,
    gauTimeout: 120,
    gauThreads: 10,
    gauVerifyUrls: true,
    gauDetectMethods: true,
    gauFilterDeadEndpoints: true,
    gauWorkers: 15,

    // --- ParamSpider: enabled ---
    paramspiderEnabled: true,
    paramspiderTimeout: 180,
    paramspiderWorkers: 10,

    // --- jsluice: high limits ---
    jsluiceEnabled: true,
    jsluiceMaxFiles: 1000,
    jsluiceExtractSecrets: true,
    jsluiceExtractUrls: true,
    jsluiceConcurrency: 15,
    jsluiceParallelism: 5,

    // --- JS Recon: everything enabled, max files ---
    jsReconEnabled: true,
    jsReconMaxFiles: 2000,
    jsReconTimeout: 3600,
    jsReconConcurrency: 15,
    jsReconValidateKeys: true,
    jsReconValidationTimeout: 10,
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
    jsReconStandaloneCrawlDepth: 5,

    // --- ffuf: recursion, high threads ---
    ffufEnabled: true,
    ffufThreads: 60,
    ffufRate: 0,
    ffufTimeout: 15,
    ffufMaxTime: 1200,
    ffufRecursion: true,
    ffufRecursionDepth: 3,
    ffufAutoCalibrate: true,
    ffufFollowRedirects: false,
    ffufSmartFuzz: true,
    ffufParallelism: 5,

    // --- Kiterunner: routes-large, high connections ---
    kiterunnerEnabled: true,
    kiterunnerWordlists: ['routes-large'],
    kiterunnerRateLimit: 200,
    kiterunnerConnections: 200,
    kiterunnerTimeout: 15,
    kiterunnerScanTimeout: 1800,
    kiterunnerThreads: 75,
    kiterunnerDetectMethods: true,
    kiterunnerMethodDetectionMode: 'bruteforce',
    kiterunnerBruteforceMethods: ['POST', 'PUT', 'DELETE', 'PATCH'],
    kiterunnerParallelism: 3,

    // --- Arjun: all methods, high limits ---
    arjunEnabled: true,
    arjunThreads: 10,
    arjunTimeout: 20,
    arjunScanTimeout: 1200,
    arjunMethods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
    arjunMaxEndpoints: 200,
    arjunChunkSize: 1000,
    arjunPassive: false,

    // --- Nuclei: everything maxed ---
    nucleiEnabled: true,
    nucleiSeverity: ['critical', 'high', 'medium', 'low'],
    nucleiRateLimit: 200,
    nucleiBulkSize: 75,
    nucleiConcurrency: 75,
    nucleiTimeout: 20,
    nucleiRetries: 3,
    nucleiDastMode: true,
    nucleiAutoUpdateTemplates: true,
    nucleiHeadless: true,
    nucleiSystemResolvers: true,
    nucleiFollowRedirects: true,
    nucleiMaxRedirects: 10,
    nucleiScanAllIps: true,
    nucleiInteractsh: true,

    // --- GraphQL Security: max coverage ---
    graphqlSecurityEnabled: true,
    graphqlCopEnabled: true,
    graphqlCopTestIntrospection: true,  // Both scanners for cross-validation

    // --- CVE Lookup: max ---
    cveLookupEnabled: true,
    cveLookupMaxCves: 50,
    cveLookupMinCvss: 0.0,

    // --- MITRE: full enrichment ---
    mitreEnabled: true,
    mitreAutoUpdateDb: true,
    mitreIncludeCwe: true,
    mitreIncludeCapec: true,
    mitreEnrichRecon: true,

    // --- All 28 security checks ---
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
    securityCheckTimeout: 20,
    securityCheckMaxWorkers: 20,

    // --- All 10 OSINT providers at maximum ---
    osintEnrichmentEnabled: true,

    shodanEnabled: true,
    shodanHostLookup: true,
    shodanReverseDns: true,
    shodanDomainDns: true,
    shodanPassiveCves: true,
    shodanWorkers: 10,

    urlscanEnabled: true,
    urlscanMaxResults: 10000,

    otxEnabled: true,
    otxWorkers: 10,

    censysEnabled: true,
    censysWorkers: 10,

    fofaEnabled: true,
    fofaMaxResults: 5000,
    fofaWorkers: 10,

    netlasEnabled: true,
    netlasWorkers: 10,

    virusTotalEnabled: true,
    virusTotalWorkers: 4,

    zoomEyeEnabled: true,
    zoomEyeMaxResults: 5000,
    zoomEyeWorkers: 10,

    criminalIpEnabled: true,
    criminalIpWorkers: 10,

    uncoverEnabled: true,
    uncoverMaxResults: 1000,
  },
}
