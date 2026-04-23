import type { ReconPreset } from '../types'

export const FULL_ACTIVE_SCAN: ReconPreset = {
  id: 'full-active-scan',
  name: 'Full Pipeline - Active Only',
  icon: '',
  image: '/preset-radar.svg',
  shortDescription: 'Every active tool maxed out, all passive sources disabled. Maximum noise, maximum coverage.',
  fullDescription: `### Pipeline Goal
Unleash every active reconnaissance tool at maximum intensity. This preset sends packets directly to the target across all attack surfaces: ports, HTTP, crawling, fuzzing, API discovery, and vulnerability scanning. No passive OSINT, no archive lookups -- pure active probing.

### Who is this for?
Pentesters with full authorization on an engagement where stealth is irrelevant. Internal network assessments, lab environments, or authorized external pentests where the goal is to find everything as fast as possible regardless of detection.

### What it enables
- Full port scanning: Naabu SYN scan (top 1000) + Masscan (high rate) + Nmap with version detection and NSE vuln scripts (T4 aggressive timing)
- Banner grabbing on all non-HTTP services (SSH, FTP, SMTP, MySQL, Redis, etc.)
- httpx with every probe enabled (tech detect, TLS, JARM, favicon, ASN, CDN, response body)
- Wappalyzer technology fingerprinting
- Katana depth 4 with JS crawl + 2000 max URLs
- Hakrawler depth 4 with subdomain inclusion
- ffuf directory fuzzing with recursion depth 2 and auto-calibration
- Kiterunner API endpoint discovery with routes-large wordlist
- Arjun parameter discovery on GET/POST/PUT/DELETE/PATCH methods
- Nuclei with all severity levels + DAST mode + headless browser + Interactsh OOB detection
- All 28 security checks enabled
- CVE lookup and MITRE CWE/CAPEC enrichment
- Amass in active mode with DNS brute forcing
- JS Recon with standalone crawl depth 4, source map analysis, DOM sinks, dependency checks, key validation

### What it disables
- GAU (Wayback Machine / archive lookups) - passive source
- ParamSpider (Wayback parameter mining) - passive source
- All OSINT enrichment (Shodan, URLScan, OTX, Censys, FOFA, Netlas, VirusTotal, ZoomEye, CriminalIP, Uncover) - passive sources
- jsReconIncludeArchivedJs disabled (Wayback archived JS is a passive source)
- Stealth mode and Tor routing - contradicts active scanning goal
- Naabu passive mode (InternetDB) - we want real SYN scanning

### How it works
1. Subdomain discovery (all tools + Amass active + DNS brute forcing) finds all subdomains
2. Naabu SYN scans top 1000 ports, Masscan adds speed, Nmap enriches with service versions and NSE scripts
3. httpx probes all discovered host:port combos with full fingerprinting
4. Banner grabbing identifies non-HTTP services
5. Katana + Hakrawler aggressively crawl all live web apps
6. ffuf fuzzes directories with recursion, Kiterunner discovers API routes
7. Arjun discovers hidden parameters on found endpoints
8. Nuclei runs all templates in DAST mode using crawled URLs, with headless browser for JS-rendered pages
9. JS Recon crawls and downloads JS files, extracts endpoints, secrets, source maps, and DOM XSS sinks
10. CVE lookup maps service versions to known vulnerabilities
11. Security checks validate headers, TLS, DNS, and infrastructure exposure`,
  parameters: {
    // All scan modules enabled including js_recon (actively crawls and downloads JS files)
    scanModules: ['domain_discovery', 'port_scan', 'http_probe', 'resource_enum', 'vuln_scan', 'js_recon'],

    // Stealth OFF, Tor OFF
    stealthMode: false,
    useTorForRecon: false,

    // --- Subdomain Discovery: all tools enabled, Amass in active + brute mode ---
    subdomainDiscoveryEnabled: true,
    crtshEnabled: true,
    hackerTargetEnabled: true,
    knockpyReconEnabled: true,
    subfinderEnabled: true,
    amassEnabled: true,
    amassActive: true,
    amassBrute: true,
    purednsEnabled: true,
    useBruteforceForSubdomains: true,

    // --- Port Scanning: all 3 scanners enabled ---
    naabuEnabled: true,
    naabuPassiveMode: false,
    naabuScanType: 's',
    naabuTopPorts: '1000',
    naabuRateLimit: 1000,
    naabuThreads: 25,
    naabuTimeout: 10000,
    naabuRetries: 2,
    naabuExcludeCdn: false,
    naabuDisplayCdn: true,
    naabuSkipHostDiscovery: true,
    naabuVerifyPorts: true,

    masscanEnabled: true,
    masscanTopPorts: '1000',
    masscanRate: 5000,
    masscanBanners: true,
    masscanWait: 10,
    masscanRetries: 2,

    nmapEnabled: true,
    nmapVersionDetection: true,
    nmapScriptScan: true,
    nmapTimingTemplate: 'T4',
    nmapTimeout: 900,
    nmapHostTimeout: 450,

    // --- HTTP Probing: all probes maxed ---
    httpxEnabled: true,
    httpxThreads: 50,
    httpxTimeout: 15,
    httpxRetries: 3,
    httpxRateLimit: 100,
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
    wappalyzerRequireHtml: false,
    wappalyzerAutoUpdate: true,

    // --- Banner Grabbing: enabled ---
    bannerGrabEnabled: true,
    bannerGrabTimeout: 10,
    bannerGrabThreads: 30,
    bannerGrabMaxLength: 1000,

    // --- Katana: deep aggressive crawl ---
    katanaEnabled: true,
    katanaDepth: 4,
    katanaMaxUrls: 2000,
    katanaRateLimit: 100,
    katanaTimeout: 5400,
    katanaJsCrawl: true,

    // --- Hakrawler: deep aggressive crawl ---
    hakrawlerEnabled: true,
    hakrawlerDepth: 4,
    hakrawlerThreads: 10,
    hakrawlerTimeout: 60,
    hakrawlerMaxUrls: 1000,
    hakrawlerIncludeSubs: true,
    hakrawlerInsecure: true,

    // --- ffuf: directory fuzzing with recursion ---
    ffufEnabled: true,
    ffufThreads: 50,
    ffufRate: 0,
    ffufTimeout: 10,
    ffufMaxTime: 900,
    ffufRecursion: true,
    ffufRecursionDepth: 2,
    ffufAutoCalibrate: true,
    ffufFollowRedirects: false,
    ffufSmartFuzz: true,

    // --- Kiterunner: API endpoint discovery ---
    kiterunnerEnabled: true,
    kiterunnerWordlists: ['routes-large'],
    kiterunnerRateLimit: 150,
    kiterunnerConnections: 150,
    kiterunnerTimeout: 10,
    kiterunnerScanTimeout: 1200,
    kiterunnerThreads: 50,
    kiterunnerDetectMethods: true,
    kiterunnerMethodDetectionMode: 'bruteforce',
    kiterunnerBruteforceMethods: ['POST', 'PUT', 'DELETE', 'PATCH'],

    // --- Arjun: parameter discovery (active, not passive) ---
    arjunEnabled: true,
    arjunThreads: 5,
    arjunTimeout: 15,
    arjunScanTimeout: 900,
    arjunMethods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
    arjunMaxEndpoints: 100,
    arjunChunkSize: 500,
    arjunPassive: false,

    // --- jsluice: runs post-crawl on discovered JS files ---
    jsluiceEnabled: true,
    jsluiceMaxFiles: 300,
    jsluiceExtractSecrets: true,
    jsluiceExtractUrls: true,
    jsluiceConcurrency: 10,

    // --- Nuclei: full DAST + headless + OOB ---
    nucleiEnabled: true,
    nucleiSeverity: ['critical', 'high', 'medium', 'low'],
    nucleiRateLimit: 150,
    nucleiBulkSize: 50,
    nucleiConcurrency: 50,
    nucleiTimeout: 15,
    nucleiRetries: 2,
    nucleiDastMode: true,
    nucleiAutoUpdateTemplates: true,
    nucleiHeadless: true,
    nucleiSystemResolvers: true,
    nucleiFollowRedirects: true,
    nucleiMaxRedirects: 10,
    nucleiScanAllIps: true,
    nucleiInteractsh: true,

    // --- Subdomain Takeover: all layers on ---
    subdomainTakeoverEnabled: true,
    subjackEnabled: true,
    subjackAll: true,
    subjackCheckNs: true,
    subjackCheckAr: true,
    subjackCheckMail: true,
    nucleiTakeoversEnabled: true,
    takeoverSeverity: ['critical', 'high', 'medium', 'low'],

    // --- GraphQL Security: full active coverage ---
    graphqlSecurityEnabled: true,
    graphqlCopEnabled: true,

    // --- CVE Lookup: enabled ---
    cveLookupEnabled: true,
    cveLookupMaxCves: 30,
    cveLookupMinCvss: 0.0,

    // --- MITRE Enrichment: enabled ---
    mitreEnabled: true,
    mitreAutoUpdateDb: true,
    mitreIncludeCwe: true,
    mitreIncludeCapec: true,
    mitreEnrichRecon: true,

    // --- Security Checks: all enabled ---
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
    securityCheckTimeout: 15,
    securityCheckMaxWorkers: 15,

    // --- DISABLE all passive sources ---
    gauEnabled: false,
    paramspiderEnabled: false,
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

    // --- JS Recon: actively crawls and downloads JS files for deep analysis ---
    jsReconEnabled: true,
    jsReconMaxFiles: 1000,
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
    jsReconIncludeArchivedJs: false,
    jsReconMinConfidence: 'low',
    jsReconStandaloneCrawlDepth: 4,
  },
}
