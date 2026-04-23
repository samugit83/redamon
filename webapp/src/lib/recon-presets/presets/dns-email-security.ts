import type { ReconPreset } from '../types'

export const DNS_EMAIL_SECURITY: ReconPreset = {
  id: 'dns-email-security',
  name: 'DNS & Email Security',
  icon: '',
  image: '/preset-mail-search.svg',
  shortDescription: 'DNS infrastructure and email security audit. Full subdomain enumeration, DNS resolution with all record types, WHOIS, SPF/DMARC/DNSSEC checks, zone transfer detection, SMTP open relay testing.',
  fullDescription: `### Pipeline Goal
Audit DNS infrastructure and email security posture for a target domain. This preset maximizes subdomain discovery to map the full DNS footprint, resolves all record types (A, AAAA, MX, TXT, NS, SOA, CNAME), performs WHOIS lookups, and runs targeted security checks for email spoofing defenses and DNS misconfigurations. Shodan DNS enrichment adds passive context. No port scanning, no web crawling, no vulnerability scanning -- pure DNS and email security reconnaissance.

### Who is this for?
Security teams auditing email spoofing defenses (SPF, DMARC, DKIM), DNS administrators verifying DNSSEC deployment, compliance teams checking domain hygiene, and red teamers looking for zone transfer leaks or open SMTP relays before phishing engagements.

### What it enables
- Full subdomain discovery with ALL tools enabled at high limits (10000 max results each)
- Amass active DNS probing + brute-force for maximum subdomain coverage
- PureDNS for DNS resolution and wildcard filtering
- Brute-force subdomain enumeration for discovering hidden subdomains
- WHOIS lookup with retries for registrar and registrant intelligence
- DNS resolution with retries for complete record enumeration
- Security checks focused on DNS and email: SPF missing, DMARC missing, DNSSEC missing, zone transfer, SMTP open relay
- Shodan OSINT with reverse DNS and domain DNS enrichment

### What it disables
- All port scanners (Naabu, Masscan, Nmap) -- not scanning ports, auditing DNS
- httpx and Wappalyzer -- no web service fingerprinting needed
- Banner grabbing -- no service banner collection
- All web crawlers (Katana, Hakrawler) -- not crawling web content
- GAU, ParamSpider -- no passive URL discovery
- jsluice, JS Recon -- no JavaScript analysis
- Directory fuzzing (ffuf), API discovery (Kiterunner), parameter discovery (Arjun)
- Nuclei vulnerability scanner -- not testing web vulnerabilities
- CVE lookup and MITRE enrichment -- not relevant to DNS/email checks
- All HTTP/web security checks (WAF bypass, TLS expiry, CSP, session security, etc.)
- Most OSINT providers (Censys, URLScan, OTX, etc.) -- Shodan DNS features are sufficient

### How it works
1. Subdomain discovery runs all tools (crt.sh, HackerTarget, Knockpy, Subfinder, Amass, PureDNS) with brute-force to enumerate every hostname
2. DNS resolution collects A, AAAA, MX, TXT, NS, SOA, and CNAME records for all discovered subdomains
3. WHOIS queries retrieve registrar, registrant, and expiry information
4. Security checks test for missing SPF records (email spoofing risk), missing DMARC policies (no email authentication enforcement), missing DNSSEC (DNS spoofing risk), zone transfer misconfiguration (full zone disclosure), and SMTP open relay (spam/phishing relay)
5. Shodan reverse DNS and domain DNS enrichment adds passive DNS intelligence and historical records`,
  parameters: {
    // Modules: domain_discovery + vuln_scan (SPF/DMARC/DNSSEC/zone-transfer/SMTP
    // security checks all live inside vuln_scan). No port scanning, no web probing.
    scanModules: ['domain_discovery', 'vuln_scan'],

    stealthMode: false,
    useTorForRecon: false,

    // --- Subdomain Discovery: ALL tools, max results, aggressive ---
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
    amassBrute: true,
    amassMaxResults: 10000,
    amassTimeout: 15,
    purednsEnabled: true,
    useBruteforceForSubdomains: true,

    // --- WHOIS and DNS: enabled with retries ---
    whoisEnabled: true,
    whoisMaxRetries: 6,
    dnsEnabled: true,
    dnsMaxRetries: 5,

    // --- Port Scanning: ALL disabled ---
    naabuEnabled: false,
    masscanEnabled: false,
    nmapEnabled: false,

    // --- httpx: disabled ---
    httpxEnabled: false,

    // --- Wappalyzer: disabled ---
    wappalyzerEnabled: false,

    // --- Banner Grabbing: disabled ---
    bannerGrabEnabled: false,

    // --- Web Crawlers: ALL disabled ---
    katanaEnabled: false,
    hakrawlerEnabled: false,

    // --- Passive URL discovery: disabled ---
    gauEnabled: false,
    paramspiderEnabled: false,

    // --- JS analysis: disabled ---
    jsluiceEnabled: false,
    jsReconEnabled: false,

    // --- Directory/API/Parameter fuzzing: disabled ---
    ffufEnabled: false,
    kiterunnerEnabled: false,
    arjunEnabled: false,

    // --- Nuclei: disabled ---
    nucleiEnabled: false,

    // --- CVE Lookup: disabled ---
    cveLookupEnabled: false,

    // --- MITRE: disabled ---
    mitreEnabled: false,

    // --- Security Checks: DNS and email checks only ---
    securityCheckEnabled: true,
    securityCheckSpfMissing: true,
    securityCheckDmarcMissing: true,
    securityCheckDnssecMissing: true,
    securityCheckZoneTransfer: true,
    securityCheckSmtpOpenRelay: true,
    securityCheckDirectIpHttp: false,
    securityCheckDirectIpHttps: false,
    securityCheckIpApiExposed: false,
    securityCheckWafBypass: false,
    securityCheckTlsExpiringSoon: false,
    securityCheckMissingReferrerPolicy: false,
    securityCheckMissingPermissionsPolicy: false,
    securityCheckMissingCoop: false,
    securityCheckMissingCorp: false,
    securityCheckMissingCoep: false,
    securityCheckCacheControlMissing: false,
    securityCheckLoginNoHttps: false,
    securityCheckSessionNoSecure: false,
    securityCheckSessionNoHttponly: false,
    securityCheckBasicAuthNoTls: false,
    securityCheckAdminPortExposed: false,
    securityCheckDatabaseExposed: false,
    securityCheckRedisNoAuth: false,
    securityCheckKubernetesApiExposed: false,
    securityCheckCspUnsafeInline: false,
    securityCheckInsecureFormAction: false,
    securityCheckNoRateLimiting: false,
    securityCheckTimeout: 15,
    securityCheckMaxWorkers: 10,

    // --- OSINT: Shodan DNS enrichment only ---
    osintEnrichmentEnabled: true,
    shodanEnabled: true,
    shodanHostLookup: false,
    shodanReverseDns: true,
    shodanDomainDns: true,
    shodanPassiveCves: false,

    // Disable all other OSINT providers
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
