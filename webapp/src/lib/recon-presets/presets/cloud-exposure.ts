import type { ReconPreset } from '../types'

export const CLOUD_EXPOSURE: ReconPreset = {
  id: 'cloud-exposure',
  name: 'Cloud & External Exposure',
  icon: '',
  image: '/preset-cloud-lock.svg',
  shortDescription: 'Cloud-focused security assessment. OSINT providers for cloud-exposed services, httpx with ASN/CDN/TLS probes, security checks for cloud misconfigs, Nuclei with cloud templates.',
  fullDescription: `### Pipeline Goal
Identify cloud-exposed services, misconfigurations, and shadow infrastructure across your external attack surface. This preset combines all OSINT providers for maximum cloud asset discovery, httpx with full fingerprinting including ASN and CDN detection, port scanning focused on cloud-common ports (Kubernetes API, databases, admin panels), Nuclei with cloud/misconfig templates, and all security checks for infrastructure exposure.

### Who is this for?
Cloud security engineers, red teams targeting cloud-hosted organizations, and security teams auditing their external cloud footprint. Ideal when you suspect services are exposed through misconfigured cloud environments -- Kubernetes dashboards, open databases, unprotected admin panels, or forgotten development instances.

### What it enables
- Full subdomain discovery (all tools, 10000 max) to find cloud-hosted hostnames
- Naabu SYN scan on cloud-common ports (K8s API 6443/10250, databases 5432/6379/9200/27017, admin 8080/8443/8888, Docker 2376)
- Nmap with version detection and NSE scripts for service fingerprinting
- httpx with ALL probes -- ASN, CDN detection, TLS info, JARM fingerprinting, favicon hashing
- Wappalyzer technology detection for identifying cloud platforms
- Banner grabbing for non-HTTP cloud services
- Nuclei scanning for critical/high/medium vulnerabilities with interactsh for OOB detection
- CVE lookup (30 max per service) and MITRE CWE/CAPEC enrichment
- All 10 OSINT providers enabled -- Shodan, Censys, URLScan, OTX, FOFA, Netlas, VirusTotal, ZoomEye, CriminalIP, Uncover
- All 28 security checks -- especially Kubernetes API exposed, database exposed, admin port exposed, Redis no auth

### What it disables
- Web crawlers (Katana, Hakrawler) -- not crawling web content, scanning cloud infrastructure
- Directory fuzzing (ffuf), API discovery (Kiterunner) -- web-layer tools not relevant here
- Parameter discovery (Arjun, ParamSpider) -- not testing web app parameters
- GAU archive lookups -- not relevant to live cloud exposure
- jsluice, JS Recon -- JavaScript analysis not relevant to cloud infrastructure
- Masscan -- using Naabu with targeted cloud ports instead of broad sweeps

### How it works
1. Subdomain discovery enumerates all hostnames including cloud-hosted subdomains
2. Naabu scans cloud-relevant ports (K8s, databases, admin panels, Docker API)
3. Nmap enriches discovered ports with version detection and vulnerability scripts
4. httpx probes all web endpoints with ASN/CDN/TLS fingerprinting to identify cloud providers
5. All 10 OSINT providers query external databases for cloud-exposed assets and historical data
6. Nuclei runs cloud/misconfig templates against discovered services with OOB detection
7. CVE lookup maps service versions to known cloud-related vulnerabilities
8. MITRE enrichment classifies findings by CWE weakness type and CAPEC attack pattern
9. Security checks flag Kubernetes API exposure, open databases, admin panels, and cloud misconfigs`,
  parameters: {
    // Modules: domain_discovery + port_scan + http_probe + vuln_scan
    // No resource_enum, no js_recon
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
    amassActive: false,
    amassBrute: false,
    amassMaxResults: 10000,
    amassTimeout: 15,
    purednsEnabled: true,
    useBruteforceForSubdomains: false,

    whoisEnabled: true,
    dnsEnabled: true,

    // --- Naabu: SYN scan, cloud-common ports ---
    naabuEnabled: true,
    naabuPassiveMode: false,
    naabuScanType: 's',
    naabuCustomPorts: '22,80,443,2376,3389,5432,6379,8080,8443,9200,9300,27017,5601,8888,10250,6443',
    naabuRateLimit: 500,
    naabuThreads: 25,
    naabuTimeout: 10000,
    naabuRetries: 2,
    naabuVerifyPorts: true,
    naabuSkipHostDiscovery: true,

    // --- Masscan: disabled ---
    masscanEnabled: false,

    // --- Nmap: version detection + NSE scripts ---
    nmapEnabled: true,
    nmapVersionDetection: true,
    nmapScriptScan: true,
    nmapTimingTemplate: 'T3',
    nmapTimeout: 600,
    nmapHostTimeout: 300,

    // --- httpx: all probes including ASN, CDN, TLS ---
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

    // --- Wappalyzer: enabled ---
    wappalyzerEnabled: true,
    wappalyzerMinConfidence: 30,
    wappalyzerAutoUpdate: true,

    // --- Banner Grabbing: enabled ---
    bannerGrabEnabled: true,
    bannerGrabTimeout: 10,
    bannerGrabThreads: 20,
    bannerGrabMaxLength: 1000,

    // --- DISABLE web crawlers ---
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

    // --- Nuclei: cloud/misconfig focus ---
    nucleiEnabled: true,
    nucleiSeverity: ['critical', 'high', 'medium'],
    nucleiTags: ['cloud', 'kubernetes', 'k8s', 'aws', 'gcp', 'azure', 'docker', 'misconfig', 'exposure'],
    nucleiRateLimit: 100,
    nucleiBulkSize: 25,
    nucleiConcurrency: 25,
    nucleiTimeout: 10,
    nucleiRetries: 2,
    nucleiDastMode: false,
    nucleiHeadless: false,
    nucleiAutoUpdateTemplates: true,
    nucleiSystemResolvers: true,
    nucleiFollowRedirects: true,
    nucleiMaxRedirects: 10,
    nucleiScanAllIps: false,
    nucleiInteractsh: true,

    // --- CVE Lookup ---
    cveLookupEnabled: true,
    cveLookupMaxCves: 30,
    cveLookupMinCvss: 0.0,

    // --- MITRE ---
    mitreEnabled: true,
    mitreAutoUpdateDb: true,
    mitreIncludeCwe: true,
    mitreIncludeCapec: true,
    mitreEnrichRecon: true,

    // --- Security Checks: ALL enabled ---
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

    // --- OSINT: ALL providers enabled ---
    osintEnrichmentEnabled: true,
    shodanEnabled: true,
    shodanHostLookup: true,
    shodanReverseDns: true,
    shodanDomainDns: false,
    shodanPassiveCves: true,

    censysEnabled: true,

    urlscanEnabled: true,
    urlscanMaxResults: 5000,

    otxEnabled: true,

    fofaEnabled: true,
    fofaMaxResults: 3000,

    netlasEnabled: true,

    virusTotalEnabled: true,

    zoomEyeEnabled: true,
    zoomEyeMaxResults: 3000,

    criminalIpEnabled: true,

    uncoverEnabled: true,
    uncoverMaxResults: 500,

    // --- GraphQL: explicit OFF so switching from a GraphQL-enabled preset resets cleanly ---
    graphqlSecurityEnabled: false,
    graphqlCopEnabled: false,
  },
}
