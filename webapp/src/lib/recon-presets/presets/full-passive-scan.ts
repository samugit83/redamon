import type { ReconPreset } from '../types'

export const FULL_PASSIVE_SCAN: ReconPreset = {
  id: 'full-passive-scan',
  name: 'Full Pipeline - Passive Only',
  icon: '',
  image: '/preset-spy.svg',
  shortDescription: 'Zero packets to target. Maximum intelligence from third-party sources, archives, and passive databases only.',
  fullDescription: `### Pipeline Goal
Gather the maximum amount of intelligence about a target without sending a single packet to it. Every tool in this preset queries third-party APIs, public databases, certificate transparency logs, and web archives -- never the target itself.

### Who is this for?
Red team operators in the pre-engagement phase, OSINT analysts building target profiles, or anyone who needs to understand an attack surface before authorization is granted. Also useful when you want to assess exposure without alerting the target's SOC or WAF.

### What it enables
- Full subdomain discovery: crt.sh, HackerTarget, Knockpy, Subfinder, Amass (passive mode only, no active probing or brute force)
- WHOIS domain registration lookups
- DNS resolution (A, AAAA, MX, NS, TXT, SOA, CNAME records via public resolvers)
- Puredns wildcard filtering (validates via public DNS, not target nameservers)
- Naabu in passive mode (queries Shodan InternetDB for known open ports -- zero scanning)
- GAU with all 4 providers (Wayback Machine, CommonCrawl, OTX, URLScan) at 10000 URL limit
- ParamSpider for historical parameterized URLs from Wayback CDX
- All 10 OSINT enrichment providers at maximum results:
  - Shodan (host lookup, reverse DNS, passive CVEs)
  - URLScan.io (10000 results)
  - OTX AlienVault (threat intelligence, passive DNS, malware)
  - Censys (host info, certificates, autonomous systems)
  - FOFA (5000 results)
  - Netlas (host reconnaissance)
  - VirusTotal (domain/IP reputation, malware detection)
  - ZoomEye (5000 results)
  - CriminalIP (IP threat intelligence)
  - Uncover (aggregated multi-engine search, 1000 results)
- CVE lookup from NVD for any service versions found via passive sources
- MITRE CWE/CAPEC enrichment for discovered CVEs

### What it disables
- httpx HTTP probing (sends requests to target)
- All web crawlers: Katana, Hakrawler (actively crawl target)
- jsluice (downloads JS files from target)
- JS Recon (crawls and downloads from target)
- ffuf directory fuzzing (brute-forces target)
- Kiterunner API discovery (brute-forces target)
- Arjun active mode (passive mode is enabled instead)
- Nuclei vulnerability scanning (actively tests target)
- Masscan and Nmap (send packets to target)
- Banner grabbing (connects to target services)
- Wappalyzer (requires HTTP responses from target)
- Security checks (some connect to target directly)
- Amass active mode and brute force (DNS brute-forcing touches target nameservers)
- Stealth mode (not needed -- we never touch the target at all)

### How it works
1. Subdomain discovery queries certificate transparency logs, DNS databases, and OSINT APIs to enumerate all known subdomains
2. DNS resolution uses public resolvers to map subdomains to IPs
3. Puredns filters out wildcard domains via public DNS validation
4. Naabu passive mode queries Shodan InternetDB for historically known open ports on discovered IPs
5. GAU + ParamSpider pull historical URLs and parameters from Wayback Machine, CommonCrawl, OTX, and URLScan archives
6. Arjun in passive mode discovers parameters without sending requests to the target
7. All 10 OSINT providers enrich discovered IPs with geolocation, services, banners, threat intelligence, and passive CVEs
8. CVE lookup and MITRE enrichment map found service versions to known vulnerabilities and attack patterns`,
  parameters: {
    // Modules: domain_discovery + port_scan (passive) + resource_enum (GAU/ParamSpider only)
    //        + vuln_scan (needed for CVE lookup + MITRE enrichment -- Nuclei itself is
    //          disabled below so nothing active is sent to the target).
    // No http_probe (sends requests), no js_recon (downloads files).
    scanModules: ['domain_discovery', 'port_scan', 'resource_enum', 'vuln_scan'],

    // Stealth OFF (not needed -- nothing active), Tor OFF
    stealthMode: false,
    useTorForRecon: false,

    // --- Subdomain Discovery: all tools enabled, Amass PASSIVE only ---
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

    // --- WHOIS & DNS: enabled ---
    whoisEnabled: true,
    dnsEnabled: true,

    // --- Port Scanning: Naabu PASSIVE ONLY (InternetDB) ---
    naabuEnabled: true,
    naabuPassiveMode: true,
    naabuScanType: 'c',
    naabuRateLimit: 10,
    naabuThreads: 1,

    // --- DISABLE all active port scanners ---
    masscanEnabled: false,
    nmapEnabled: false,

    // --- DISABLE httpx (sends HTTP requests to target) ---
    httpxEnabled: false,

    // --- DISABLE Wappalyzer (needs HTTP responses) ---
    wappalyzerEnabled: false,

    // --- DISABLE banner grabbing (connects to target services) ---
    bannerGrabEnabled: false,

    // --- DISABLE all active crawlers ---
    katanaEnabled: false,
    hakrawlerEnabled: false,

    // --- DISABLE jsluice (downloads JS files from target) ---
    jsluiceEnabled: false,

    // --- DISABLE JS Recon (crawls and downloads from target) ---
    jsReconEnabled: false,

    // --- DISABLE directory fuzzing ---
    ffufEnabled: false,

    // --- DISABLE API discovery ---
    kiterunnerEnabled: false,

    // --- Arjun: passive mode only (no requests to target) ---
    arjunEnabled: true,
    arjunPassive: true,

    // --- ENABLE GAU: passive archive URL discovery, all providers, high limits ---
    gauEnabled: true,
    gauProviders: ['wayback', 'commoncrawl', 'otx', 'urlscan'],
    gauMaxUrls: 10000,
    gauTimeout: 120,
    gauThreads: 10,
    gauVerbose: false,
    gauVerifyUrls: false,
    gauDetectMethods: false,
    gauFilterDeadEndpoints: false,

    // --- ENABLE ParamSpider: passive Wayback parameter mining ---
    paramspiderEnabled: true,
    paramspiderTimeout: 180,

    // --- DISABLE all vulnerability scanning ---
    nucleiEnabled: false,
    securityCheckEnabled: false,

    // --- ENABLE CVE lookup (queries NVD/Vulners APIs, not the target) ---
    cveLookupEnabled: true,
    cveLookupMaxCves: 50,
    cveLookupMinCvss: 0.0,

    // --- ENABLE MITRE enrichment (offline database, no network) ---
    mitreEnabled: true,
    mitreAutoUpdateDb: true,
    mitreIncludeCwe: true,
    mitreIncludeCapec: true,
    mitreEnrichRecon: true,

    // --- ENABLE all OSINT providers at maximum ---
    osintEnrichmentEnabled: true,

    shodanEnabled: true,
    shodanHostLookup: true,
    shodanReverseDns: true,
    shodanDomainDns: true,
    shodanPassiveCves: true,

    urlscanEnabled: true,
    urlscanMaxResults: 10000,

    otxEnabled: true,

    censysEnabled: true,

    fofaEnabled: true,
    fofaMaxResults: 5000,

    netlasEnabled: true,

    virusTotalEnabled: true,

    zoomEyeEnabled: true,
    zoomEyeMaxResults: 5000,

    criminalIpEnabled: true,

    uncoverEnabled: true,
    uncoverMaxResults: 1000,

    // --- GraphQL: explicit OFF so switching from a GraphQL-enabled preset resets cleanly ---
    graphqlSecurityEnabled: false,
    graphqlCopEnabled: false,
  },
}
