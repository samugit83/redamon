import type { ReconPreset } from '../types'

export const COMPLIANCE_AUDIT: ReconPreset = {
  id: 'compliance-audit',
  name: 'Compliance & Header Audit',
  icon: '',
  image: '/preset-certificate.svg',
  shortDescription: 'Security posture validation. httpx with all header probes, TLS analysis, SPF/DMARC/DNSSEC checks, Wappalyzer tech detection, and Nuclei misconfig/exposure scanning.',
  fullDescription: `### Pipeline Goal
Validate the security posture of your targets by auditing HTTP headers, TLS certificates, DNS security records, and common misconfigurations. This preset focuses on compliance-relevant checks -- missing security headers, expiring certificates, absent SPF/DMARC/DNSSEC, and exposed services -- without aggressive crawling or fuzzing.

### Who is this for?
Security teams running compliance audits, blue teamers validating hardening baselines, and consultants producing posture reports. Ideal for periodic checks against frameworks like OWASP Secure Headers, CIS benchmarks, or internal security policies.

### What it enables
- Full subdomain discovery (all tools, default limits) to enumerate the audit surface
- WHOIS and DNS lookups for domain context
- httpx with every header and fingerprinting probe enabled -- status codes, content types, server banners, response times, TLS info, TLS grab, JARM fingerprints, ASN, CDN detection, favicons, and tech detection
- Response headers captured (includeResponseHeaders) for offline header analysis
- Wappalyzer technology detection to identify frameworks, CMS, and server software
- All 27 security checks enabled -- SPF/DMARC/DNSSEC validation, TLS expiry, missing security headers (Referrer-Policy, Permissions-Policy, COOP, CORP, COEP, Cache-Control, CSP unsafe-inline), session cookie flags, basic auth over plain HTTP, admin ports, exposed databases, open relays, and more
- Nuclei with misconfig and exposure tags only -- no DAST, no interactsh, no headless

### What it disables
- Port scanning (Naabu, Masscan, Nmap) -- not mapping ports, auditing web posture
- Web crawlers (Katana, Hakrawler) -- no deep crawling needed
- Archive/passive URL discovery (GAU, ParamSpider) -- not collecting URLs
- JavaScript analysis (jsluice, JS Recon) -- not hunting secrets in JS
- Directory and API fuzzing (ffuf, Kiterunner, Arjun) -- no brute-force discovery
- Banner grabbing -- not probing raw sockets
- CVE lookup -- compliance focus, not vulnerability enumeration
- MITRE CWE/CAPEC enrichment -- not classifying CVEs
- All OSINT providers (Shodan, Censys, URLScan, etc.) -- passive enrichment not needed

### How it works
1. Subdomain discovery enumerates all hostnames under the target domain
2. DNS and WHOIS lookups gather domain registration and resolver data
3. httpx probes every discovered host with all fingerprinting options -- headers, TLS details, JARM, ASN, CDN, tech detection
4. Wappalyzer identifies technologies running on each host
5. The 27 security checks validate headers, TLS, DNS security records, cookie flags, and exposed services
6. Nuclei runs misconfig and exposure templates to catch common server misconfigurations
7. Results feed into the graph for a comprehensive compliance posture view`,
  parameters: {
    // Modules: domain_discovery + http_probe + vuln_scan (nuclei misconfig)
    scanModules: ['domain_discovery', 'http_probe', 'vuln_scan'],

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
    amassTimeout: 15,
    purednsEnabled: true,
    useBruteforceForSubdomains: false,

    whoisEnabled: true,
    dnsEnabled: true,

    // --- Port Scanning: ALL disabled ---
    naabuEnabled: false,
    masscanEnabled: false,
    nmapEnabled: false,

    // --- httpx: all probes enabled for header auditing ---
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
    httpxIncludeResponse: false,
    httpxIncludeResponseHeaders: true,

    // --- Wappalyzer: enabled for tech detection ---
    wappalyzerEnabled: true,
    wappalyzerMinConfidence: 30,
    wappalyzerAutoUpdate: true,

    // --- Banner Grabbing: disabled ---
    bannerGrabEnabled: false,

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

    // --- Nuclei: misconfig and exposure focus ---
    nucleiEnabled: true,
    nucleiSeverity: ['critical', 'high', 'medium'],
    nucleiTags: ['misconfig', 'exposure'],
    nucleiRateLimit: 50,
    nucleiBulkSize: 15,
    nucleiConcurrency: 15,
    nucleiTimeout: 10,
    nucleiRetries: 2,
    nucleiDastMode: false,
    nucleiHeadless: false,
    nucleiAutoUpdateTemplates: true,
    nucleiSystemResolvers: true,
    nucleiFollowRedirects: true,
    nucleiMaxRedirects: 10,
    nucleiScanAllIps: false,
    nucleiInteractsh: false,

    // --- GraphQL: OFF by default. Compliance audits have defined scope; no crawlers
    //     enabled (Katana/Hakrawler off) means GraphQL discovery has minimal signal.
    //     If GraphQL is in scope, enable per-project. ---

    // --- CVE Lookup: disabled ---
    cveLookupEnabled: false,

    // --- MITRE: disabled ---
    mitreEnabled: false,

    // --- Security Checks: ALL 27 enabled ---
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

    // --- OSINT: all disabled ---
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

    // --- GraphQL: explicit OFF so switching from a GraphQL-enabled preset resets cleanly ---
    graphqlSecurityEnabled: false,
    graphqlCopEnabled: false,
  },
}
