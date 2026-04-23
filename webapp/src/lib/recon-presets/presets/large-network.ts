import type { ReconPreset } from '../types'

export const LARGE_NETWORK: ReconPreset = {
  id: 'large-network',
  name: 'Network Perimeter - Large Scale',
  icon: '',
  image: '/preset-radar-2.svg',
  shortDescription: 'Large-scale network perimeter scanning. Masscan at 10k pps for fast port discovery, Naabu verification, Nmap T4 service detection, banner grabbing, Shodan + Censys enrichment, CVE lookup.',
  fullDescription: `### Pipeline Goal
Scan large IP ranges and CIDR blocks at high speed. This preset is built for IP-mode reconnaissance -- Masscan blasts through port discovery at 10,000 packets per second, Naabu verifies open ports with SYN scanning, and Nmap identifies services with aggressive T4 timing. Banner grabbing captures protocol banners on non-HTTP ports, while Shodan and Censys provide passive enrichment. No web crawling, no fuzzing, no JavaScript analysis -- pure network-layer reconnaissance at scale.

### Who is this for?
Network security teams and pentesters who need to map large external perimeters (Class B/C networks, multiple CIDR blocks). Ideal for initial reconnaissance of enterprise networks, ISP ranges, or cloud provider IP blocks where speed matters more than stealth.

### What it enables
- Subdomain discovery (all tools enabled for reverse DNS and hostname resolution)
- WHOIS and DNS lookups for IP attribution
- Naabu SYN scan (top 1000 ports) with high rate (1500) and 50 threads for port verification
- Masscan at 10,000 pps with banner capture for rapid initial port discovery
- Nmap with version detection (-sV), NSE scripts, T4 timing, and extended timeouts (1200s scan, 600s host)
- httpx with 75 threads and full fingerprinting probes (ASN, CDN, JARM, TLS info) -- response headers captured, response body and favicon skipped
- Wappalyzer technology detection
- Banner grabbing with 40 threads and large buffer (1500 bytes) for high-throughput service identification
- Shodan enrichment (host lookup, reverse DNS, passive CVEs) and Censys for additional IP context
- CVE lookup (40 max, all CVSS scores) for comprehensive vulnerability mapping
- MITRE CWE/CAPEC enrichment for vulnerability classification
- All 27 security checks with 20 max workers for infrastructure exposure detection

### What it disables
- Web crawlers (Katana, Hakrawler) -- not crawling websites, scanning network ports
- Directory fuzzing (ffuf), API discovery (Kiterunner) -- web-layer tools not relevant at network scale
- Parameter discovery (Arjun, ParamSpider) -- not applicable to IP-mode scanning
- GAU archive lookups -- not relevant to network infrastructure
- jsluice, JS Recon -- JavaScript analysis not applicable
- Nuclei -- this preset discovers and maps; vulnerability scanning comes after
- Most OSINT providers except Shodan and Censys (the most relevant for IP/infrastructure data)

### How it works
1. Subdomain discovery resolves hostnames and builds an IP inventory (useful even in IP mode for reverse DNS)
2. Masscan sweeps all target IPs at 10,000 pps for rapid port discovery with banner capture
3. Naabu re-scans with SYN probes to verify open ports and filter false positives
4. Nmap enriches confirmed ports with service version detection and NSE vulnerability scripts
5. httpx probes all web-port combinations with full fingerprinting (ASN, CDN, JARM, TLS)
6. Banner grabbing connects to non-HTTP ports at high concurrency to identify services
7. Shodan + Censys enrich IPs with geolocation, ISP, historical data, and known CVEs
8. CVE lookup maps detected service versions to known vulnerabilities
9. MITRE enrichment classifies findings by CWE and attack patterns
10. Security checks flag exposed admin ports, databases, open relays, and misconfigurations`,
  parameters: {
    // Modules: domain_discovery + port_scan + http_probe + vuln_scan
    // vuln_scan is required for CVE lookup, MITRE enrichment, and security checks
    // (Nuclei itself is disabled below). No resource_enum, no js_recon.
    scanModules: ['domain_discovery', 'port_scan', 'http_probe', 'vuln_scan'],

    stealthMode: false,
    useTorForRecon: false,

    // --- Subdomain Discovery: all tools enabled (reverse DNS useful in IP mode) ---
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

    whoisEnabled: true,
    dnsEnabled: true,
    dnsMaxWorkers: 100,

    // --- Naabu: SYN scan, high rate and threads ---
    naabuEnabled: true,
    naabuPassiveMode: false,
    naabuScanType: 's',
    naabuTopPorts: '1000',
    naabuRateLimit: 1500,
    naabuThreads: 50,
    naabuTimeout: 10000,
    naabuRetries: 2,
    naabuExcludeCdn: false,
    naabuDisplayCdn: true,
    naabuSkipHostDiscovery: true,
    naabuVerifyPorts: true,

    // --- Masscan: very high rate for large-scale scanning ---
    masscanEnabled: true,
    masscanTopPorts: '1000',
    masscanRate: 10000,
    masscanBanners: true,
    masscanWait: 10,
    masscanRetries: 2,

    // --- Nmap: version detection + NSE scripts, T4 timing, extended timeouts ---
    nmapEnabled: true,
    nmapVersionDetection: true,
    nmapScriptScan: true,
    nmapTimingTemplate: 'T4',
    nmapTimeout: 1200,
    nmapHostTimeout: 600,
    nmapParallelism: 4,

    // --- httpx: high throughput with full fingerprinting ---
    httpxEnabled: true,
    httpxThreads: 75,
    httpxTimeout: 15,
    httpxRetries: 2,
    httpxRateLimit: 150,
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
    httpxProbeJarm: true,
    httpxProbeHash: 'sha256',
    httpxProbeAsn: true,
    httpxProbeCdn: true,
    httpxIncludeResponse: false,
    httpxIncludeResponseHeaders: true,

    // --- Wappalyzer: enabled for tech detection ---
    wappalyzerEnabled: true,
    wappalyzerMinConfidence: 30,
    wappalyzerAutoUpdate: true,

    // --- Banner Grabbing: high threads for large-scale scanning ---
    bannerGrabEnabled: true,
    bannerGrabTimeout: 10,
    bannerGrabThreads: 40,
    bannerGrabMaxLength: 1500,

    // --- DISABLE all web crawlers ---
    katanaEnabled: false,
    katanaParallelism: 10,
    katanaConcurrency: 20,
    hakrawlerEnabled: false,
    hakrawlerParallelism: 6,

    // --- DISABLE archive/passive URL discovery ---
    gauEnabled: false,
    gauWorkers: 15,
    paramspiderEnabled: false,
    paramspiderWorkers: 10,

    // --- DISABLE JS analysis ---
    jsluiceEnabled: false,
    jsReconEnabled: false,

    // --- DISABLE directory/API fuzzing ---
    ffufEnabled: false,
    kiterunnerEnabled: false,

    // --- DISABLE parameter discovery ---
    arjunEnabled: false,

    // --- DISABLE Nuclei (mapping, not vuln testing) ---
    nucleiEnabled: false,

    // --- CVE Lookup: comprehensive, all CVSS scores ---
    cveLookupEnabled: true,
    cveLookupMaxCves: 40,
    cveLookupMinCvss: 0.0,

    // --- MITRE: enabled ---
    mitreEnabled: true,
    mitreAutoUpdateDb: true,
    mitreIncludeCwe: true,
    mitreIncludeCapec: true,
    mitreEnrichRecon: true,

    // --- Security Checks: all checks, high worker count ---
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
    securityCheckMaxWorkers: 20,

    // --- OSINT: Shodan + Censys only (infrastructure-relevant) ---
    osintEnrichmentEnabled: true,
    shodanEnabled: true,
    shodanHostLookup: true,
    shodanReverseDns: true,
    shodanDomainDns: false,
    shodanPassiveCves: true,

    censysEnabled: true,
    censysWorkers: 8,

    // Disable non-infrastructure OSINT
    urlscanEnabled: false,
    otxEnabled: false,
    otxWorkers: 8,
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
