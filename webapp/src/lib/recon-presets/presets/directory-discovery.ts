import type { ReconPreset } from '../types'

export const DIRECTORY_DISCOVERY: ReconPreset = {
  id: 'directory-discovery',
  name: 'Directory & Content Discovery',
  icon: '',
  image: '/preset-folder-search.svg',
  shortDescription: 'Maximize hidden content discovery. ffuf with deep recursion and many extensions, Kiterunner for API routes, Katana + Hakrawler deep crawl, GAU historical URLs. No vuln scanning or OSINT.',
  fullDescription: `### Pipeline Goal
Find every hidden directory, file, API route, and piece of content on the target. This preset combines aggressive directory fuzzing (ffuf with recursion depth 3 and a wide set of backup/config extensions), API route brute-forcing via Kiterunner, deep crawling from Katana and Hakrawler, historical URL mining from GAU, and JavaScript endpoint extraction via jsluice. The goal is content inventory -- not vulnerability detection.

### Who is this for?
Pentesters and bug bounty hunters in the early recon phase who want a complete map of what exists on a target before pivoting into exploitation. Also useful for security teams auditing forgotten files, backup archives, exposed configs, and undocumented API endpoints.

### What it enables
- Full subdomain discovery (all tools, default limits)
- httpx with essential probes for live-host fingerprinting
- ffuf with recursion depth 3, 60 threads, and 13 extensions including .bak, .old, .config, .env, .sql, .zip, .tar.gz
- Kiterunner with routes-large wordlist, 150 connections, and brute-force method detection (POST, PUT, DELETE, PATCH)
- Katana depth 4 with JS crawl for deep endpoint discovery (2000 URLs)
- Hakrawler depth 4 for complementary DOM-aware crawling (1000 URLs)
- GAU with all 4 providers for historical URL mining (5000 URLs)
- jsluice for extracting endpoints and secrets from JavaScript files

### What it disables
- Port scanning (Naabu, Masscan, Nmap) -- content discovery targets known HTTP endpoints
- Nuclei, CVE lookup, MITRE -- no vulnerability scanning in this preset
- ParamSpider, Arjun -- not about parameter discovery
- JS Recon -- jsluice covers endpoint extraction
- Banner grabbing, Wappalyzer -- not relevant without port scanning focus
- All OSINT enrichment -- not relevant for content discovery
- Security checks -- no header/cookie/TLS validation needed

### How it works
1. Subdomain discovery finds all subdomains of the target
2. httpx probes all discovered hosts with essential fingerprinting
3. Katana + Hakrawler deep crawl all live web apps from two crawling engines
4. GAU adds historical URLs from 4 archive providers
5. jsluice extracts hidden endpoints and secrets from JavaScript files
6. ffuf fuzzes directories recursively (depth 3) with backup, config, and archive extensions
7. Kiterunner brute-forces API routes with method detection across POST/PUT/DELETE/PATCH`,
  parameters: {
    // Modules: discovery + probing + resource enum, no vuln_scan or js_recon
    scanModules: ['domain_discovery', 'http_probe', 'resource_enum'],

    stealthMode: false,
    useTorForRecon: false,

    // --- Subdomain Discovery: all tools, default limits ---
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
    purednsEnabled: true,
    useBruteforceForSubdomains: false,

    whoisEnabled: true,
    dnsEnabled: true,

    // --- DISABLE port scanning ---
    naabuEnabled: false,
    masscanEnabled: false,
    nmapEnabled: false,

    // --- httpx: essential probes only ---
    httpxEnabled: true,
    httpxThreads: 50,
    httpxTimeout: 15,
    httpxRetries: 2,
    httpxRateLimit: 75,
    httpxFollowRedirects: true,
    httpxProbeStatusCode: true,
    httpxProbeContentLength: true,
    httpxProbeContentType: true,
    httpxProbeTitle: true,
    httpxProbeServer: true,
    httpxProbeResponseTime: true,
    httpxProbeTechDetect: true,
    httpxProbeIp: true,
    httpxProbeWordCount: false,
    httpxProbeLineCount: false,
    httpxProbeCname: false,
    httpxProbeTlsInfo: false,
    httpxProbeTlsGrab: false,
    httpxProbeFavicon: false,
    httpxProbeJarm: false,
    httpxProbeAsn: false,
    httpxProbeCdn: false,
    httpxIncludeResponse: false,
    httpxIncludeResponseHeaders: false,

    // --- DISABLE Wappalyzer ---
    wappalyzerEnabled: false,

    // --- DISABLE banner grabbing ---
    bannerGrabEnabled: false,

    // --- Katana: deep crawl ---
    katanaEnabled: true,
    katanaDepth: 4,
    katanaMaxUrls: 2000,
    katanaRateLimit: 75,
    katanaTimeout: 5400,
    katanaJsCrawl: true,

    // --- Hakrawler: deep complementary crawl ---
    hakrawlerEnabled: true,
    hakrawlerDepth: 4,
    hakrawlerThreads: 10,
    hakrawlerTimeout: 60,
    hakrawlerMaxUrls: 1000,
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

    // --- DISABLE ParamSpider (not about parameters) ---
    paramspiderEnabled: false,

    // --- jsluice: endpoint and secret extraction ---
    jsluiceEnabled: true,
    jsluiceMaxFiles: 200,
    jsluiceExtractSecrets: true,
    jsluiceExtractUrls: true,
    jsluiceConcurrency: 5,

    // --- DISABLE JS Recon (jsluice is enough) ---
    jsReconEnabled: false,

    // --- ffuf: deep recursion + many extensions ---
    ffufEnabled: true,
    ffufThreads: 60,
    ffufRate: 0,
    ffufTimeout: 10,
    ffufMaxTime: 1200,
    ffufExtensions: ['.php', '.asp', '.aspx', '.jsp', '.html', '.js', '.bak', '.old', '.config', '.env', '.sql', '.zip', '.tar.gz'],
    ffufRecursion: true,
    ffufRecursionDepth: 3,
    ffufAutoCalibrate: true,
    ffufFollowRedirects: false,
    ffufSmartFuzz: true,

    // --- Kiterunner: API route brute-forcing ---
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

    // --- DISABLE Arjun ---
    arjunEnabled: false,

    // --- DISABLE Nuclei ---
    nucleiEnabled: false,

    // --- GraphQL: OFF -- this preset's short/full descriptions both state "no vuln
    //     scanning". GraphQL scanners (native + graphql-cop) write Vulnerability nodes
    //     and therefore count as vuln scanning. Users who want GraphQL coverage should
    //     pick graphql-recon or api-security.
    graphqlSecurityEnabled: false,
    graphqlCopEnabled: false,

    // --- DISABLE CVE lookup & MITRE ---
    cveLookupEnabled: false,
    mitreEnabled: false,

    // --- DISABLE security checks ---
    securityCheckEnabled: false,

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
