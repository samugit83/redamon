import type { ReconPreset } from '../types'

export const STEALTH_RECON: ReconPreset = {
  id: 'stealth-recon',
  name: 'Stealth Recon',
  icon: '',
  image: '/preset-ghost.svg',
  shortDescription: 'Minimal detection footprint. All traffic routed through Tor, passive tools preferred, extremely low rate limits on active probes. Designed for targets with aggressive monitoring.',
  fullDescription: `### Pipeline Goal
Gather intelligence with the smallest possible detection footprint. All traffic is routed through Tor, active tools are throttled to near-passive levels, and anything that generates noisy traffic patterns (brute force, fuzzing, aggressive crawling) is disabled entirely. The goal is to learn as much as possible while staying below the target's detection threshold.

### Who is this for?
Red team operators performing authorized reconnaissance against targets with active SOC monitoring, IDS/IPS, or WAF rate limiting. Also useful for initial recon when you need to avoid triggering alerts before the engagement formally begins, or when testing detection capabilities of a blue team.

### What it enables
- Full subdomain discovery via passive sources (crt.sh, HackerTarget, Knockpy, Subfinder, Amass passive) -- no brute force
- Naabu in passive mode (Shodan InternetDB only -- zero packets to target)
- httpx with minimal probes (status code, title, tech detect, IP, TLS) at 1 thread and rate limit 2/s
- Katana at depth 1, max 50 URLs, rate limit 2/s -- minimal crawl footprint
- GAU with all archive providers -- completely passive, no target contact
- ParamSpider -- queries Wayback CDX, no target contact
- jsluice on 20 JS files max -- light extraction
- Arjun in passive mode -- parameter discovery without sending requests
- Nuclei limited to critical/high severity at 5 req/s, 2 concurrent templates, no DAST, no Interactsh, excludes intrusive/fuzz/dos tags
- CVE lookup and MITRE enrichment (offline/API only)
- All OSINT providers at reduced limits
- All Shodan features enabled

### What it disables
- Masscan and Nmap (active port scanning generates significant traffic)
- Hakrawler (aggressive crawling pattern)
- ffuf directory fuzzing (high request volume, easily detected)
- Kiterunner API discovery (brute-force approach)
- JS Recon (downloads many files from target)
- Banner grabbing (direct service connections leave logs)
- Wappalyzer (requires full HTTP responses)
- Security checks (some probes connect directly to target services)
- Amass active mode and brute force
- Nuclei DAST mode, Interactsh, and intrusive/fuzz/dos templates

### How it works
1. Subdomain discovery runs entirely through passive sources -- certificate logs, DNS databases, and OSINT APIs
2. DNS resolution and Puredns filtering use public resolvers only
3. Naabu queries Shodan InternetDB for known open ports without sending any packets
4. httpx probes discovered hosts at a trickle (1 thread, 2 req/s) through Tor, collecting only essential metadata
5. Katana performs a shallow crawl (depth 1, 50 URLs) through Tor to discover immediate endpoints
6. GAU and ParamSpider pull historical URLs and parameters from web archives -- zero target contact
7. jsluice extracts endpoints from up to 20 JS files found during crawling
8. Arjun discovers parameters passively from archived responses
9. Nuclei runs only critical/high templates at 5 req/s through Tor, with intrusive and fuzzing templates excluded
10. OSINT providers enrich all discovered assets through third-party APIs at reduced query limits
11. CVE and MITRE enrichment map services to known vulnerabilities offline`,
  parameters: {
    // Modules: include vuln_scan so the throttled Nuclei config below (critical/high,
    // 5 rps, 2 concurrent, no DAST/Interactsh) plus CVE lookup and MITRE enrichment
    // actually execute. No js_recon (too many downloads).
    scanModules: ['domain_discovery', 'port_scan', 'http_probe', 'resource_enum', 'vuln_scan'],

    // Stealth + Tor: core of this preset
    stealthMode: true,
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
    dnsMaxWorkers: 5,
    dnsRecordParallelism: false,

    // --- Port Scanning: Naabu PASSIVE ONLY (InternetDB) ---
    naabuEnabled: true,
    naabuPassiveMode: true,
    naabuScanType: 'c',
    naabuRateLimit: 2,
    naabuThreads: 1,

    // --- DISABLE active port scanners ---
    masscanEnabled: false,
    nmapEnabled: false,
    nmapParallelism: 1,

    // --- httpx: minimal probes, throttled ---
    httpxEnabled: true,
    httpxThreads: 1,
    httpxRateLimit: 2,
    httpxProbeStatusCode: true,
    httpxProbeTitle: true,
    httpxProbeTechDetect: true,
    httpxProbeIp: true,
    httpxProbeTlsInfo: true,
    httpxProbeJarm: false,
    httpxProbeFavicon: false,
    httpxProbeAsn: false,
    httpxProbeCdn: false,
    httpxIncludeResponse: false,
    httpxIncludeResponseHeaders: false,

    // --- DISABLE Wappalyzer ---
    wappalyzerEnabled: false,

    // --- DISABLE banner grabbing ---
    bannerGrabEnabled: false,

    // --- Katana: shallow and throttled ---
    katanaEnabled: true,
    katanaDepth: 1,
    katanaMaxUrls: 50,
    katanaRateLimit: 2,
    katanaJsCrawl: false,
    katanaParallelism: 1,
    katanaConcurrency: 1,

    // --- DISABLE Hakrawler ---
    hakrawlerEnabled: false,

    // --- GAU: passive archive discovery, all providers ---
    gauEnabled: true,
    gauProviders: ['wayback', 'commoncrawl', 'otx', 'urlscan'],
    gauMaxUrls: 5000,
    gauTimeout: 120,
    gauThreads: 5,
    gauVerbose: false,
    gauVerifyUrls: false,
    gauDetectMethods: false,
    gauFilterDeadEndpoints: false,
    gauWorkers: 1,

    // --- ParamSpider: passive Wayback parameter mining ---
    paramspiderEnabled: true,
    paramspiderTimeout: 180,
    paramspiderWorkers: 1,

    // --- jsluice: light extraction ---
    jsluiceEnabled: true,
    jsluiceMaxFiles: 20,

    // --- DISABLE JS Recon ---
    jsReconEnabled: false,

    // --- DISABLE directory fuzzing ---
    ffufEnabled: false,

    // --- DISABLE API discovery ---
    kiterunnerEnabled: false,

    // --- Arjun: passive mode only ---
    arjunEnabled: true,
    arjunPassive: true,

    // --- Nuclei: throttled, critical/high only, no intrusive ---
    nucleiEnabled: true,
    nucleiSeverity: ['critical', 'high'],
    nucleiRateLimit: 5,
    nucleiConcurrency: 2,
    nucleiBulkSize: 5,
    nucleiDastMode: false,
    nucleiHeadless: false,
    nucleiInteractsh: false,
    nucleiScanAllIps: false,
    nucleiExcludeTags: ['dos', 'fuzz', 'intrusive', 'sqli', 'rce'],

    // --- Subdomain Takeover: passive DNS-only (subjack), disable active Nuclei templates ---
    subdomainTakeoverEnabled: true,
    subjackEnabled: true,
    subjackAll: false,           // CNAME-identified only — avoids probing every host
    subjackCheckNs: true,        // Pure DNS, safe
    subjackCheckMail: true,      // Pure DNS, safe
    subjackThreads: 3,
    nucleiTakeoversEnabled: false, // No active HTTP fingerprint probes in stealth
    takeoverRateLimit: 10,

    // --- GraphQL: we set graphqlSecurityEnabled: false below for clean preset-switch
    //     state, but note that apply_stealth_overrides (project_settings.py) FORCES
    //     GRAPHQL_SECURITY_ENABLED = True at runtime whenever stealthMode is on,
    //     restricted to passive introspection only (no mutations, no proxy testing,
    //     safe-mode on, rate 2, concurrency 1). DoS graphql-cop probes are also
    //     force-disabled. So the effective GraphQL behaviour is passive-only. ---

    // --- DISABLE security checks ---
    securityCheckEnabled: false,

    // --- CVE lookup ---
    cveLookupEnabled: true,
    cveLookupMaxCves: 50,
    cveLookupMinCvss: 0.0,

    // --- MITRE enrichment ---
    mitreEnabled: true,
    mitreAutoUpdateDb: true,
    mitreIncludeCwe: true,
    mitreIncludeCapec: true,
    mitreEnrichRecon: true,

    // --- OSINT: all enabled at reduced limits ---
    osintEnrichmentEnabled: true,

    shodanEnabled: true,
    shodanHostLookup: true,
    shodanReverseDns: true,
    shodanDomainDns: true,
    shodanPassiveCves: true,
    shodanWorkers: 1,

    urlscanEnabled: true,
    urlscanMaxResults: 1000,

    otxEnabled: true,

    censysEnabled: true,

    fofaEnabled: true,
    fofaMaxResults: 500,

    netlasEnabled: true,

    virusTotalEnabled: true,

    zoomEyeEnabled: true,
    zoomEyeMaxResults: 500,

    criminalIpEnabled: true,

    uncoverEnabled: true,
    uncoverMaxResults: 200,

    // --- GraphQL: explicit OFF so switching from a GraphQL-enabled preset resets cleanly ---
    graphqlSecurityEnabled: false,
    graphqlCopEnabled: false,
  },
}
