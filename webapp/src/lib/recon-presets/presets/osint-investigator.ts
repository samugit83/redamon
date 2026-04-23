import type { ReconPreset } from '../types'

export const OSINT_INVESTIGATOR: ReconPreset = {
  id: 'osint-investigator',
  name: 'OSINT Investigator',
  icon: '',
  image: '/preset-binoculars.svg',
  shortDescription: 'Maximum passive intelligence from all 10 OSINT providers, archives, and public databases. No active scanning.',
  fullDescription: `### Pipeline Goal
Extract the maximum amount of intelligence from every available passive source. This preset enables all 10 OSINT providers at their highest result limits, plus GAU archive discovery, ParamSpider historical parameters, and Arjun in passive mode. The focus is on building a complete target profile from third-party data -- not on finding exploitable vulnerabilities.

### Who is this for?
OSINT analysts, threat intelligence teams, or red team operators building a target dossier before an engagement. Security teams wanting to understand their organization's external exposure from an attacker's perspective without touching production systems.

### What it enables
- Full subdomain discovery (all 5 tools at 10000 max results)
- WHOIS domain registration and DNS resolution
- Puredns wildcard filtering
- Naabu passive mode (Shodan InternetDB) for known open ports
- GAU with all 4 providers at 10000 URLs (Wayback, CommonCrawl, OTX, URLScan)
- ParamSpider for historical parameterized URLs
- Arjun in passive mode for parameter inference
- All 10 OSINT providers at maximum results:
  - Shodan: host lookup, reverse DNS, domain DNS, passive CVEs
  - URLScan.io: 10000 results
  - OTX AlienVault: threat pulses, passive DNS, malware samples
  - Censys: host info, certificates, autonomous systems
  - FOFA: 5000 results
  - Netlas: host reconnaissance
  - VirusTotal: domain/IP reputation, malware detection
  - ZoomEye: 5000 results
  - CriminalIP: IP threat intelligence
  - Uncover: 1000 results (aggregated multi-engine)
- CVE lookup (50 max per service) from NVD
- MITRE CWE/CAPEC enrichment

### What it disables
- httpx HTTP probing (sends requests to target)
- All web crawlers (Katana, Hakrawler)
- jsluice, JS Recon (download files from target)
- ffuf, Kiterunner (brute-force target)
- Active port scanners (Masscan, Nmap)
- Nuclei vulnerability scanning
- Banner grabbing
- Wappalyzer
- Security checks (some connect to target)
- Amass active mode and brute force
- GAU URL verification and method detection (would send requests to target)

### How it works
1. Subdomain discovery queries certificate transparency, DNS databases, and OSINT APIs
2. DNS resolution maps subdomains to IPs via public resolvers
3. Puredns filters wildcard domains
4. Naabu passive mode queries Shodan InternetDB for historically known ports
5. GAU + ParamSpider pull historical URLs and parameters from web archives
6. Arjun passive mode infers parameters from archive data
7. All 10 OSINT providers enrich discovered IPs and domains with threat intelligence, services, geolocation, reputation, and passive CVEs
8. CVE lookup maps found service versions to known vulnerabilities
9. MITRE enrichment classifies findings by CWE weakness and CAPEC attack patterns`,
  parameters: {
    // Modules: domain_discovery + port_scan (passive) + resource_enum (GAU/ParamSpider/Arjun passive)
    //        + vuln_scan (needed for CVE lookup + MITRE enrichment -- Nuclei itself is
    //          disabled below so nothing active is sent to the target).
    scanModules: ['domain_discovery', 'port_scan', 'resource_enum', 'vuln_scan'],

    stealthMode: false,
    useTorForRecon: false,

    // --- Subdomain Discovery: all tools, max limits ---
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

    // --- Naabu: passive InternetDB only ---
    naabuEnabled: true,
    naabuPassiveMode: true,
    naabuScanType: 'c',
    naabuRateLimit: 10,
    naabuThreads: 1,

    // --- DISABLE active port scanners ---
    masscanEnabled: false,
    nmapEnabled: false,

    // --- DISABLE httpx ---
    httpxEnabled: false,

    // --- DISABLE Wappalyzer ---
    wappalyzerEnabled: false,

    // --- DISABLE banner grabbing ---
    bannerGrabEnabled: false,

    // --- DISABLE all active crawlers ---
    katanaEnabled: false,
    hakrawlerEnabled: false,

    // --- GAU: all providers, max results, NO verification (would hit target) ---
    gauEnabled: true,
    gauProviders: ['wayback', 'commoncrawl', 'otx', 'urlscan'],
    gauMaxUrls: 10000,
    gauTimeout: 120,
    gauThreads: 10,
    gauVerbose: false,
    gauVerifyUrls: false,
    gauDetectMethods: false,
    gauFilterDeadEndpoints: false,

    // --- ParamSpider: enabled ---
    paramspiderEnabled: true,
    paramspiderTimeout: 180,

    // --- DISABLE jsluice (downloads from target) ---
    jsluiceEnabled: false,

    // --- DISABLE JS Recon (crawls target) ---
    jsReconEnabled: false,

    // --- DISABLE directory/API fuzzing ---
    ffufEnabled: false,
    kiterunnerEnabled: false,

    // --- Arjun: passive mode only ---
    arjunEnabled: true,
    arjunPassive: true,

    // --- DISABLE Nuclei ---
    nucleiEnabled: false,

    // --- DISABLE security checks ---
    securityCheckEnabled: false,

    // --- CVE Lookup: high max ---
    cveLookupEnabled: true,
    cveLookupMaxCves: 50,
    cveLookupMinCvss: 0.0,

    // --- MITRE: full enrichment ---
    mitreEnabled: true,
    mitreAutoUpdateDb: true,
    mitreIncludeCwe: true,
    mitreIncludeCapec: true,
    mitreEnrichRecon: true,

    // --- All 10 OSINT providers at maximum ---
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
