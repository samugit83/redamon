import type { ReconPreset } from '../types'

export const INTERNAL_NETWORK: ReconPreset = {
  id: 'internal-network',
  name: 'Internal Network & Active Directory',
  icon: '',
  image: '/preset-radar-2.svg',
  shortDescription: 'Local/private network reconnaissance (RFC1918, Active Directory). Port scan tuned to AD & internal service ports (SMB/LDAP/Kerberos/RDP/WinRM/DB), Nmap NSE service + script scan, banner grabbing. Public OSINT and subdomain enumeration are OFF because they return nothing for private IPs.',
  targetProfile: 'ip',
  environment: 'internal',
  fullDescription: `### Pipeline Goal
Map an internal network or Active Directory environment reached over a VPN or from inside the perimeter. This preset is built for IP-mode reconnaissance against private/RFC1918 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) and AD subnets. It sweeps ports with an emphasis on the services that matter inside a Windows domain -- SMB, LDAP, Kerberos, RDP, WinRM -- then uses Nmap's version detection and NSE scripts to enumerate what those services expose. Every internet-facing technique that cannot see a private IP (public OSINT, certificate-transparency subdomain enumeration, WHOIS) is turned off, so the results are clean and the scan does not waste time querying public databases that know nothing about your LAN.

### Who is this for?
Internal penetration testers and red teamers assessing a corporate LAN, a VPN-reachable segment, or an Active Directory domain from a foothold host. Use this when your targets are IP addresses or CIDR ranges on a private network rather than a public domain. It is the natural starting point when "Start from IP" is on and the addresses are internal.

### What it enables
- Reverse DNS on every target IP to recover internal hostnames (via the internal resolver)
- Naabu SYN scan across the top 1000 ports PLUS an explicit Active Directory / internal-service port list (Kerberos 88, RPC 135, NetBIOS 139, LDAP 389/636, SMB 445, LDAP GC 3268/3269, RDP 3389, WinRM 5985/5986, and common DB/cache/monitoring ports)
- Masscan at a LAN-safe 1500 pps (deliberately far below the external 10k default so it does not flood a switched network) with banner capture
- Nmap with version detection (-sV), NSE script scan, T4 timing and extended timeouts -- this is where SMB/LDAP/RPC/RDP enumeration actually happens
- Banner grabbing on non-HTTP ports to fingerprint internal services
- httpx probing with tech detection and favicon hashing for internal web apps, admin panels and appliance UIs
- Wappalyzer technology detection for internal web backends
- CVE lookup (all CVSS scores) and MITRE CWE/CAPEC enrichment against detected service versions
- Security checks focused on internal exposure: exposed admin ports, unauthenticated databases, Redis without auth, exposed Kubernetes API, open SMTP relay, DNS zone transfer, and direct-IP HTTP/HTTPS services

### What it disables
- Public subdomain enumeration (crt.sh, HackerTarget, Subfinder, Amass, Knockpy, puredns) -- certificate transparency and passive DNS databases have no record of private hosts
- WHOIS -- there is no registrar record for an RFC1918 address
- All OSINT providers (Shodan, Censys, urlscan, FOFA, Netlas, etc.) -- they only index the public internet, so they return nothing for a LAN
- Web crawlers (Katana, Hakrawler, ZAP spider) and directory/parameter fuzzing (ffuf, Kiterunner, Arjun, GAU, ParamSpider) -- run the Directory & Content Discovery or Web App Pentester preset against a specific internal web host instead
- JavaScript analysis (jsluice, JS Recon) -- not the focus of a network/AD sweep
- Nuclei -- this preset discovers and maps the network; template-based vulnerability testing is a follow-up step against the hosts it finds
- VHost & SNI enumeration -- a per-IP serial loop is impractical across a subnet
- WAF classification / bypass checks -- there is no public WAF in front of an internal service

### How it works
1. Each target IP gets a reverse-DNS lookup to recover its internal hostname
2. Masscan sweeps the range at a LAN-safe rate for a fast first pass of open ports
3. Naabu re-scans with SYN probes across the top 1000 ports plus the explicit AD/internal-service list to confirm what is open
4. Nmap enriches every confirmed port with service version detection and NSE scripts -- this is what enumerates SMB shares, LDAP naming contexts, RPC endpoints and RDP security settings
5. Banner grabbing fingerprints any remaining non-HTTP services
6. httpx + Wappalyzer identify internal web applications and appliance interfaces
7. CVE lookup maps detected service versions to known vulnerabilities and MITRE classifies them
8. Security checks flag the classic internal findings: exposed databases, no-auth Redis, open admin ports, exposed Kubernetes API and DNS zone transfers`,
  parameters: {
    // Modules: domain_discovery (reverse DNS only) + port_scan + http_probe + vuln_scan.
    // No resource_enum, no js_recon -- this is a network/AD sweep, not a web crawl.
    scanModules: ['domain_discovery', 'port_scan', 'http_probe', 'vuln_scan'],

    stealthMode: false,

    // --- Subdomain Discovery: OFF. Every source here queries the PUBLIC internet
    //     (certificate transparency, passive DNS), which has no record of RFC1918
    //     hosts. Reverse DNS on the target IPs (run automatically in IP mode)
    //     recovers internal hostnames instead. ---
    subdomainDiscoveryEnabled: false,
    crtshEnabled: false,
    crtshMaxResults: 10000,
    hackerTargetEnabled: false,
    hackerTargetMaxResults: 10000,
    knockpyReconEnabled: false,
    knockpyReconMaxResults: 10000,
    subfinderEnabled: false,
    subfinderMaxResults: 10000,
    amassEnabled: false,
    amassActive: false,
    amassBrute: false,
    amassMaxResults: 10000,
    amassTimeout: 15,
    purednsEnabled: false,
    useBruteforceForSubdomains: false,

    // WHOIS is meaningless for a private IP (no registrar record). DNS stays on
    // for reverse lookups against the internal resolver.
    whoisEnabled: false,
    dnsEnabled: true,
    dnsMaxWorkers: 50,

    // --- Naabu: SYN scan across top 1000 PLUS an explicit AD / internal-service
    //     port list. 88 Kerberos, 135 RPC, 139 NetBIOS, 389/636 LDAP(S),
    //     445 SMB, 464 kpasswd, 3268/3269 LDAP Global Catalog, 3389 RDP,
    //     5985/5986 WinRM; plus common DB/cache/monitoring/NFS/SNMP ports. ---
    naabuEnabled: true,
    naabuPassiveMode: false,
    naabuScanType: 's',
    naabuTopPorts: '1000',
    naabuCustomPorts: '88,135,139,389,445,464,636,3268,3269,3389,5985,5986,1433,3306,5432,6379,9200,11211,2049,111,161,5900',
    naabuRateLimit: 1500,
    naabuThreads: 50,
    naabuTimeout: 10000,
    naabuRetries: 2,
    naabuExcludeCdn: false,
    naabuDisplayCdn: true,
    naabuSkipHostDiscovery: true,
    naabuVerifyPorts: true,

    // --- Masscan: LAN-safe rate. 10k pps (the external default) can saturate a
    //     switched network and trip IDS on an internal segment, so this drops to
    //     1500 pps. ---
    masscanEnabled: true,
    masscanTopPorts: '1000',
    masscanRate: 1500,
    masscanBanners: true,
    masscanWait: 10,
    masscanRetries: 2,

    // --- Nmap: version detection + NSE scripts. This is where SMB/LDAP/RPC/RDP
    //     enumeration happens -- the core value of an AD sweep. ---
    nmapEnabled: true,
    nmapVersionDetection: true,
    nmapScriptScan: true,
    nmapTimingTemplate: 'T4',
    nmapTimeout: 1200,
    nmapHostTimeout: 600,
    nmapParallelism: 4,

    // --- httpx: internal web apps, admin panels, appliance UIs ---
    httpxEnabled: true,
    httpxThreads: 50,
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
    httpxProbeFavicon: true,
    httpxProbeJarm: false,
    httpxProbeHash: 'sha256',
    httpxProbeAsn: false,
    httpxProbeCdn: false,
    httpxIncludeResponse: false,
    httpxIncludeResponseHeaders: true,

    // --- Wappalyzer: tech detection for internal web backends ---
    wappalyzerEnabled: true,
    wappalyzerMinConfidence: 30,
    wappalyzerAutoUpdate: true,

    // --- Banner Grabbing: fingerprint non-HTTP internal services ---
    bannerGrabEnabled: true,
    bannerGrabTimeout: 10,
    bannerGrabThreads: 30,
    bannerGrabMaxLength: 1500,

    // --- DISABLE web crawlers (use a web-focused preset on a specific host) ---
    katanaEnabled: false,
    katanaParallelism: 10,
    katanaConcurrency: 20,
    hakrawlerEnabled: false,
    zapAjaxSpiderEnabled: false,
    hakrawlerParallelism: 6,

    // --- DISABLE archive/passive URL discovery (public sources) ---
    gauEnabled: false,
    gauWorkers: 15,
    paramspiderEnabled: false,
    paramspiderWorkers: 10,

    // --- DISABLE JS analysis ---
    jsluiceEnabled: false,
    jsReconEnabled: false,

    aiSurfaceReconEnabled: false,

    // --- DISABLE directory/API fuzzing and parameter discovery ---
    ffufEnabled: false,
    kiterunnerEnabled: false,
    arjunEnabled: false,

    // --- DISABLE Nuclei (map first; template testing is a follow-up) ---
    nucleiEnabled: false,

    // --- VHost & SNI: impractical per-IP serial loop across a subnet ---
    vhostSniEnabled: false,

    // --- CVE Lookup: comprehensive against detected service versions ---
    cveLookupEnabled: true,
    cveLookupMaxCves: 40,
    cveLookupMinCvss: 0.0,

    // --- MITRE: enabled ---
    mitreEnabled: true,
    mitreAutoUpdateDb: true,
    mitreIncludeCwe: true,
    mitreIncludeCapec: true,
    mitreEnrichRecon: true,

    // --- Security Checks: internal-exposure focus. WAF bypass is off (no public
    //     WAF in front of a LAN service); the network/service checks are on. ---
    securityCheckEnabled: true,
    securityCheckDirectIpHttp: true,
    securityCheckDirectIpHttps: true,
    securityCheckIpApiExposed: true,
    securityCheckWafBypass: false,
    securityCheckTlsExpiringSoon: true,
    securityCheckTlsExpiryDays: 30,
    securityCheckMissingReferrerPolicy: false,
    securityCheckMissingPermissionsPolicy: false,
    securityCheckMissingCoop: false,
    securityCheckMissingCorp: false,
    securityCheckMissingCoep: false,
    securityCheckCacheControlMissing: false,
    securityCheckLoginNoHttps: true,
    securityCheckSessionNoSecure: true,
    securityCheckSessionNoHttponly: true,
    securityCheckBasicAuthNoTls: true,
    securityCheckSpfMissing: false,
    securityCheckDmarcMissing: false,
    securityCheckDnssecMissing: false,
    securityCheckZoneTransfer: true,
    securityCheckAdminPortExposed: true,
    securityCheckDatabaseExposed: true,
    securityCheckRedisNoAuth: true,
    securityCheckKubernetesApiExposed: true,
    securityCheckSmtpOpenRelay: true,
    securityCheckCspUnsafeInline: false,
    securityCheckInsecureFormAction: false,
    securityCheckNoRateLimiting: false,
    securityCheckTimeout: 15,
    securityCheckMaxWorkers: 20,

    // --- OSINT: OFF. Shodan/Censys/etc. only index the public internet and
    //     return nothing for RFC1918 targets. ---
    osintEnrichmentEnabled: false,
    shodanEnabled: false,
    shodanHostLookup: false,
    shodanReverseDns: false,
    shodanDomainDns: false,
    shodanPassiveCves: false,
    censysEnabled: false,
    censysWorkers: 8,
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
