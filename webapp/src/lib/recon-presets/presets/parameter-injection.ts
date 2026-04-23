import type { ReconPreset } from '../types'

export const PARAMETER_INJECTION: ReconPreset = {
  id: 'parameter-injection',
  name: 'Parameter & Injection Surface',
  icon: '',
  image: '/preset-terminal.svg',
  shortDescription: 'Maximize parameter discovery for injection testing. Arjun all methods, ParamSpider, GAU with verification, Katana paramsOnly, Nuclei DAST with injection tags.',
  fullDescription: `### Pipeline Goal
Discover every reachable parameter and input vector across the target, then test them for injection vulnerabilities. This preset chains multiple parameter-extraction tools -- Arjun brute-forces hidden parameters on all HTTP methods, ParamSpider mines historical parameter names, GAU pulls archived URLs with query strings, and Katana crawls in paramsOnly mode to extract only parameterized URLs. Nuclei then runs in DAST mode with injection-specific templates (SQLi, XSS, SSRF, LFI, RFI, SSTI).

### Who is this for?
Pentesters and bug bounty hunters focused on injection vulnerabilities. Ideal for applications with large parameter surfaces -- legacy apps, CMS platforms, multi-step forms, or any target where hidden and undocumented parameters are likely present. Use this when your primary goal is finding injectable inputs rather than mapping infrastructure.

### What it enables
- Subdomain discovery (all tools) to maximize the number of hosts with testable parameters
- httpx probing with tech detection to identify live hosts
- Katana in paramsOnly mode -- crawls pages but only outputs URLs that contain query parameters
- GAU with URL verification and method detection to pull historical parameterized URLs
- ParamSpider for passive parameter mining from web archives
- Arjun on all 5 HTTP methods (GET/POST/PUT/DELETE/PATCH) with 200 max endpoints and 1000 chunk size
- jsluice to extract parameterized URLs from JavaScript files
- Nuclei DAST mode with injection-focused tags: sqli, xss, ssrf, lfi, rfi, ssti, injection

### What it disables
- Port scanning (Naabu, Masscan, Nmap) -- parameter testing targets HTTP endpoints, not ports
- Hakrawler -- Katana paramsOnly mode is more targeted for parameter extraction
- ffuf, Kiterunner -- directory brute-forcing is not the focus; parameters are
- JS Recon -- deep JS analysis not needed; jsluice handles URL extraction
- Banner grabbing, Wappalyzer -- not relevant for parameter-focused testing
- All OSINT enrichment -- not relevant for injection testing
- Security checks -- header analysis is secondary to input validation flaws
- CVE lookup, MITRE enrichment -- Nuclei handles vulnerability detection directly

### How it works
1. Subdomain discovery finds all subdomains to maximize parameter surface
2. httpx probes discovered hosts and identifies live targets
3. Katana crawls in paramsOnly mode, extracting only URLs with query parameters
4. GAU pulls historical parameterized URLs from web archives with verification
5. ParamSpider mines additional parameter names from archive sources
6. Arjun brute-forces hidden parameters on all endpoints across 5 HTTP methods
7. jsluice extracts parameterized URLs from JavaScript files
8. Nuclei runs injection-targeted templates in DAST mode with OOB detection`,
  parameters: {
    // Modules: domain discovery + http probe + resource enum + vuln scan
    scanModules: ['domain_discovery', 'http_probe', 'resource_enum', 'vuln_scan'],

    stealthMode: false,
    useTorForRecon: false,

    // --- Subdomain Discovery: all tools, default limits ---
    subdomainDiscoveryEnabled: true,
    crtshEnabled: true,
    hackerTargetEnabled: true,
    knockpyReconEnabled: true,
    subfinderEnabled: true,
    amassEnabled: true,
    amassActive: false,
    amassBrute: false,
    purednsEnabled: true,
    useBruteforceForSubdomains: false,

    whoisEnabled: true,
    dnsEnabled: true,

    // --- DISABLE port scanning ---
    naabuEnabled: false,
    masscanEnabled: false,
    nmapEnabled: false,

    // --- httpx: standard probing with tech detect ---
    httpxEnabled: true,
    httpxThreads: 50,
    httpxTimeout: 15,
    httpxRetries: 2,
    httpxRateLimit: 75,
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

    // --- Katana: paramsOnly mode for parameterized URL extraction ---
    katanaEnabled: true,
    katanaDepth: 2,
    katanaMaxUrls: 500,
    katanaRateLimit: 50,
    katanaTimeout: 1800,
    katanaJsCrawl: true,
    katanaParamsOnly: true,

    // --- DISABLE Hakrawler ---
    hakrawlerEnabled: false,

    // --- GAU: enabled with URL verification and method detection ---
    gauEnabled: true,
    gauProviders: ['wayback', 'commoncrawl', 'otx', 'urlscan'],
    gauMaxUrls: 5000,
    gauTimeout: 90,
    gauThreads: 5,
    gauVerifyUrls: true,
    gauDetectMethods: true,
    gauFilterDeadEndpoints: true,

    // --- ParamSpider: enabled ---
    paramspiderEnabled: true,
    paramspiderTimeout: 180,

    // --- jsluice: extract parameterized URLs from JS ---
    jsluiceEnabled: true,
    jsluiceMaxFiles: 100,
    jsluiceExtractSecrets: false,
    jsluiceExtractUrls: true,
    jsluiceConcurrency: 5,

    // --- DISABLE JS Recon ---
    jsReconEnabled: false,

    // --- DISABLE ffuf ---
    ffufEnabled: false,

    // --- DISABLE Kiterunner ---
    kiterunnerEnabled: false,

    // --- Arjun: all methods, high endpoint limit, large chunk size ---
    arjunEnabled: true,
    arjunThreads: 5,
    arjunTimeout: 20,
    arjunScanTimeout: 1200,
    arjunMethods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
    arjunMaxEndpoints: 200,
    arjunChunkSize: 1000,
    arjunPassive: false,

    // --- Nuclei: DAST mode with injection-specific tags ---
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
    nucleiTags: ['sqli', 'xss', 'ssrf', 'lfi', 'rfi', 'ssti', 'injection'],

    // --- GraphQL Security: parameter/mutation testing fits this preset ---
    graphqlSecurityEnabled: true,
    graphqlCopEnabled: true,

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
