import type { ReconPreset } from '../types'

export const RED_TEAM_OPERATOR: ReconPreset = {
  id: 'red-team-operator',
  name: 'Red Team Operator',
  icon: '',
  image: '/preset-skull.svg',
  shortDescription: 'Balanced stealth with targeted active validation. Connect scan, throttled httpx/Katana, critical-only Nuclei, Tor routing, and full OSINT enrichment -- controlled aggression for authorized red team engagements.',
  fullDescription: `### Pipeline Goal
Perform reconnaissance that balances stealth with actionable results. Instead of going fully passive, this preset uses carefully throttled active probes -- connect scans instead of SYN, low-concurrency Nuclei limited to critical findings, and rate-limited crawling. All traffic routes through Tor. The goal is to build a comprehensive attack surface map while keeping noise low enough to avoid triggering most detection systems.

### Who is this for?
Red team operators running authorized engagements where some active probing is acceptable but detection avoidance still matters. Penetration testers who need more signal than a passive-only scan but cannot afford to trip IDS/IPS or WAF rules. Useful during the initial phases of a red team operation when you need to identify critical entry points without burning your access.

### What it enables
- Full subdomain discovery via passive sources (crt.sh, HackerTarget, Knockpy, Subfinder, Amass passive) -- no brute force
- Naabu with TCP connect scan (type 'c') at rate 50, 5 threads -- avoids raw SYN packets that trigger alerts
- httpx with essential probes (status, content length, content type, title, server, response time, tech detect, IP, CNAME, TLS) at 3 threads, rate 5/s
- Katana shallow crawl (depth 1, 100 URLs, rate 5/s) -- just enough to map immediate endpoints
- GAU with all archive providers for passive URL discovery (3000 max URLs)
- ParamSpider for passive parameter mining from Wayback CDX
- jsluice on up to 30 JS files for endpoint and secret extraction
- Arjun in passive mode -- parameter discovery without sending requests
- Nuclei limited to critical severity only, 5 req/s, concurrency 3, excludes dos/fuzz/intrusive tags
- CVE lookup and MITRE enrichment for vulnerability context
- OSINT enrichment via Shodan (host lookup, reverse DNS, passive CVEs), URLScan, OTX, and Censys
- Tor routing for all active probes

### What it disables
- Masscan (generates massive packet volume, easily detected)
- Nmap (service detection and NSE scripts are noisy and leave extensive logs)
- Hakrawler (aggressive crawling pattern)
- ffuf directory fuzzing (high request volume, trivially detected by WAFs)
- Kiterunner API discovery (brute-force approach with distinctive traffic patterns)
- JS Recon (downloads many files directly from target)
- Banner grabbing (direct service connections leave connection logs)
- Wappalyzer (requires full HTTP responses, adds unnecessary traffic)
- Security checks (some probes connect directly to target services)
- httpx JARM fingerprinting (generates distinctive TLS probe patterns)
- httpx favicon hashing (additional requests for minimal value during red teaming)
- httpx ASN/CDN detection (not needed when Shodan provides this passively)
- Nuclei DAST mode, Interactsh callbacks, headless browser probes
- FOFA, Netlas, VirusTotal, ZoomEye, CriminalIP, Uncover (reduced OSINT surface to minimize API trace)

### How it works
1. Subdomain discovery runs entirely through passive sources -- certificate logs, DNS databases, and OSINT APIs
2. DNS resolution and Puredns filtering use public resolvers
3. Naabu performs TCP connect scans at rate 50 with 5 threads -- connect scans complete the TCP handshake, avoiding the half-open SYN pattern that many IDS systems flag
4. httpx probes discovered hosts through Tor at 3 threads and rate 5/s, collecting status codes, titles, tech stack, IPs, CNAMEs, and TLS info
5. Katana performs a shallow crawl (depth 1, 100 URLs) through Tor to discover immediate endpoints without deep spidering
6. GAU pulls up to 3000 historical URLs from Wayback, CommonCrawl, OTX, and URLScan -- zero target contact
7. ParamSpider mines parameters from Wayback CDX archives
8. jsluice extracts endpoints and secrets from up to 30 JS files found during crawling
9. Arjun discovers parameters passively from archived responses
10. Nuclei runs only critical templates at rate 5/s with concurrency 3 through Tor, excluding dos/fuzz/intrusive tags entirely
11. CVE lookup maps discovered services to known vulnerabilities (up to 20 CVEs per service)
12. MITRE enrichment adds ATT&CK context to findings
13. Shodan, URLScan, OTX, and Censys enrich all discovered assets through third-party APIs`,
  parameters: {
    // Modules: vuln_scan included for critical-only Nuclei
    scanModules: ['domain_discovery', 'port_scan', 'http_probe', 'resource_enum', 'vuln_scan'],

    // Stealth mode off (we handle throttling manually), Tor on
    stealthMode: false,
    useTorForRecon: true,

    // --- Subdomain Discovery: all passive, NO brute force ---
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

    // --- Port Scanning: Naabu connect scan, throttled ---
    naabuEnabled: true,
    naabuPassiveMode: false,
    naabuScanType: 'c',
    naabuRateLimit: 50,
    naabuThreads: 5,
    naabuRetries: 1,
    naabuTimeout: 10000,

    // --- DISABLE noisy port scanners ---
    masscanEnabled: false,
    nmapEnabled: false,

    // --- httpx: essential probes, throttled ---
    httpxEnabled: true,
    httpxThreads: 3,
    httpxRateLimit: 5,
    httpxTimeout: 15,
    httpxRetries: 2,
    httpxProbeStatusCode: true,
    httpxProbeContentType: true,
    httpxProbeTitle: true,
    httpxProbeServer: true,
    httpxProbeTechDetect: true,
    httpxProbeIp: true,
    httpxProbeCname: true,
    httpxProbeTlsInfo: true,
    httpxProbeContentLength: true,
    httpxProbeResponseTime: true,
    httpxProbeWordCount: false,
    httpxProbeLineCount: false,
    httpxProbeTlsGrab: false,
    httpxProbeFavicon: false,
    httpxProbeJarm: false,
    httpxProbeAsn: false,
    httpxProbeCdn: false,
    httpxProbeHash: '',
    httpxIncludeResponse: false,
    httpxIncludeResponseHeaders: false,
    httpxFollowRedirects: true,
    httpxMaxRedirects: 10,

    // --- DISABLE Wappalyzer ---
    wappalyzerEnabled: false,

    // --- DISABLE banner grabbing ---
    bannerGrabEnabled: false,

    // --- Katana: shallow and throttled ---
    katanaEnabled: true,
    katanaDepth: 1,
    katanaMaxUrls: 100,
    katanaRateLimit: 5,
    katanaTimeout: 1800,
    katanaJsCrawl: false,

    // --- DISABLE Hakrawler ---
    hakrawlerEnabled: false,

    // --- GAU: passive archive discovery, all providers ---
    gauEnabled: true,
    gauProviders: ['wayback', 'commoncrawl', 'otx', 'urlscan'],
    gauMaxUrls: 3000,
    gauVerifyUrls: false,
    gauDetectMethods: false,
    gauFilterDeadEndpoints: false,

    // --- ParamSpider: passive Wayback parameter mining ---
    paramspiderEnabled: true,

    // --- jsluice: moderate extraction ---
    jsluiceEnabled: true,
    jsluiceMaxFiles: 30,
    jsluiceExtractSecrets: true,
    jsluiceExtractUrls: true,
    jsluiceConcurrency: 2,

    // --- DISABLE JS Recon ---
    jsReconEnabled: false,

    // --- DISABLE directory fuzzing ---
    ffufEnabled: false,

    // --- DISABLE API discovery ---
    kiterunnerEnabled: false,

    // --- Arjun: passive mode only ---
    arjunEnabled: true,
    arjunPassive: true,

    // --- Nuclei: critical only, throttled, no intrusive ---
    nucleiEnabled: true,
    nucleiSeverity: ['critical'],
    nucleiRateLimit: 5,
    nucleiBulkSize: 3,
    nucleiConcurrency: 3,
    nucleiTimeout: 15,
    nucleiRetries: 1,
    nucleiDastMode: false,
    nucleiHeadless: false,
    nucleiInteractsh: false,
    nucleiScanAllIps: false,
    nucleiAutoUpdateTemplates: true,
    nucleiFollowRedirects: true,
    nucleiMaxRedirects: 10,
    nucleiSystemResolvers: true,
    nucleiExcludeTags: ['dos', 'fuzz', 'intrusive'],

    // --- GraphQL: OFF by default. Red team prioritises stealth; pattern-based
    //     GraphQL discovery generates 4-12 extra 404s per BaseURL (IDS/WAF signal).
    //     Enable per-project only when GraphQL is a known target. ---

    // --- CVE lookup ---
    cveLookupEnabled: true,
    cveLookupMaxCves: 20,

    // --- MITRE enrichment ---
    mitreEnabled: true,

    // --- DISABLE security checks ---
    securityCheckEnabled: false,

    // --- OSINT: selective providers ---
    osintEnrichmentEnabled: true,

    shodanEnabled: true,
    shodanHostLookup: true,
    shodanReverseDns: true,
    shodanDomainDns: false,
    shodanPassiveCves: true,

    urlscanEnabled: true,
    urlscanMaxResults: 3000,

    otxEnabled: true,

    censysEnabled: true,

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
