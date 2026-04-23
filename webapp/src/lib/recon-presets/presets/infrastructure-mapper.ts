import type { ReconPreset } from '../types'

export const INFRASTRUCTURE_MAPPER: ReconPreset = {
  id: 'infrastructure-mapper',
  name: 'Infrastructure Mapper',
  icon: '',
  image: '/preset-network.svg',
  shortDescription: 'Network perimeter mapping. Full port scanning, service detection, banner grabbing, Shodan enrichment, CVE lookup.',
  fullDescription: `### Pipeline Goal
Map the entire network perimeter -- every open port, every running service, every version string. This preset combines three port scanners for maximum coverage, Nmap NSE scripts for vulnerability detection, banner grabbing for non-HTTP services, and Shodan/Censys enrichment for passive context. No web crawling, no directory fuzzing -- pure infrastructure reconnaissance.

### Who is this for?
Network pentesters and infrastructure security teams mapping an external or internal perimeter before diving into service-specific testing. Useful at the start of an infrastructure pentest to understand what is exposed and where the attack surface is.

### What it enables
- Full subdomain discovery (all tools, high limits) to find all hostnames
- Naabu SYN scan (top 1000 ports) + Masscan (high rate) for fast port discovery
- Nmap with version detection (-sV), NSE vuln scripts, and T4 aggressive timing
- httpx with all fingerprinting probes for web service detection on discovered ports (headers captured, response body skipped)
- Wappalyzer technology detection
- Banner grabbing on all non-HTTP services (SSH, FTP, SMTP, MySQL, Redis, etc.) with large buffer
- Shodan enrichment (host lookup, reverse DNS, passive CVEs)
- Censys enrichment for additional host context
- CVE lookup with high max per service (40 CVEs) for comprehensive vulnerability mapping
- MITRE CWE/CAPEC enrichment for vulnerability classification
- All security checks for infrastructure exposure (admin ports, databases, open relays, etc.)

### What it disables
- Web crawlers (Katana, Hakrawler) -- not mapping web content, mapping network services
- Directory fuzzing (ffuf), API discovery (Kiterunner) -- web-layer tools
- Parameter discovery (Arjun, ParamSpider) -- not relevant to infrastructure mapping
- GAU archive lookups -- not relevant to network services
- jsluice, JS Recon -- JavaScript analysis not relevant
- Nuclei -- this preset maps infrastructure; vulnerability testing comes after
- Most OSINT providers except Shodan and Censys (most relevant for infrastructure)

### How it works
1. Subdomain discovery enumerates all hostnames and resolves IPs
2. Naabu + Masscan scan ports in parallel for maximum speed and coverage
3. Nmap enriches found ports with service version detection and NSE vulnerability scripts
4. httpx probes all web-port combos with full fingerprinting
5. Banner grabbing connects to non-HTTP ports to identify services (SSH, FTP, databases, etc.)
6. Shodan + Censys enrich IPs with geolocation, ISP, historical banners, and known CVEs
7. CVE lookup maps service versions to known vulnerabilities
8. MITRE enrichment classifies vulnerabilities by CWE and attack patterns
9. Security checks flag exposed admin ports, databases, open relays, and misconfigured services`,
  parameters: {
    // Modules: domain_discovery + port_scan + http_probe + vuln_scan
    // vuln_scan is required for CVE lookup, MITRE enrichment, and security checks
    // (Nuclei itself is disabled below). No resource_enum, no js_recon.
    scanModules: ['domain_discovery', 'port_scan', 'http_probe', 'vuln_scan'],

    stealthMode: false,
    useTorForRecon: false,

    // --- Subdomain Discovery: all tools, high limits ---
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
    amassBrute: false,
    amassMaxResults: 10000,
    amassTimeout: 15,
    purednsEnabled: true,
    useBruteforceForSubdomains: false,

    whoisEnabled: true,
    dnsEnabled: true,

    // --- Naabu: SYN scan, high rate ---
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

    // --- Masscan: high rate for speed ---
    masscanEnabled: true,
    masscanTopPorts: '1000',
    masscanRate: 5000,
    masscanBanners: true,
    masscanWait: 10,
    masscanRetries: 2,

    // --- Nmap: version detection + NSE scripts, aggressive timing ---
    nmapEnabled: true,
    nmapVersionDetection: true,
    nmapScriptScan: true,
    nmapTimingTemplate: 'T4',
    nmapTimeout: 900,
    nmapHostTimeout: 450,

    // --- httpx: all probes for web service fingerprinting ---
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
    httpxIncludeResponse: false,
    httpxIncludeResponseHeaders: true,

    // --- Wappalyzer: enabled for tech detection ---
    wappalyzerEnabled: true,
    wappalyzerMinConfidence: 30,
    wappalyzerAutoUpdate: true,

    // --- Banner Grabbing: high threads, large buffer ---
    bannerGrabEnabled: true,
    bannerGrabTimeout: 10,
    bannerGrabThreads: 30,
    bannerGrabMaxLength: 1500,

    // --- DISABLE all web crawlers ---
    katanaEnabled: false,
    hakrawlerEnabled: false,

    // --- DISABLE archive/passive URL discovery ---
    gauEnabled: false,
    paramspiderEnabled: false,

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

    // --- CVE Lookup: high max for comprehensive mapping ---
    cveLookupEnabled: true,
    cveLookupMaxCves: 40,
    cveLookupMinCvss: 0.0,

    // --- MITRE: enabled ---
    mitreEnabled: true,
    mitreAutoUpdateDb: true,
    mitreIncludeCwe: true,
    mitreIncludeCapec: true,
    mitreEnrichRecon: true,

    // --- Security Checks: all infrastructure checks ---
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

    // --- OSINT: Shodan + Censys only (infra-relevant) ---
    osintEnrichmentEnabled: true,
    shodanEnabled: true,
    shodanHostLookup: true,
    shodanReverseDns: true,
    shodanDomainDns: false,
    shodanPassiveCves: true,

    censysEnabled: true,

    // Disable non-infrastructure OSINT
    urlscanEnabled: false,
    otxEnabled: false,
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
