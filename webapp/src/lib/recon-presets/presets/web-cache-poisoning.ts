import type { ReconPreset } from '../types'

export const WEB_CACHE_POISONING: ReconPreset = {
  id: 'web-cache-poisoning',
  name: 'Web Cache Poisoning',
  icon: '',
  image: '/preset-spider.svg',
  shortDescription: 'Laser-focused on web cache poisoning & deception. WCVS breadth sweep + native 5-phase confirmation (reflected + non-reflective differential), framework packs (Next.js/Nuxt/Remix), behavioral silent-cache detection.',
  fullDescription: `### Pipeline Goal
Find URLs served through a cache (CDN, reverse proxy, or silent Varnish/nginx) and prove whether an attacker-controlled *unkeyed* request component (header, query param, or path trick) can be smuggled into a **shared cache entry** and served to other visitors. Pairs Hackmanit's WCVS (breadth, 10+ technique classes) with RedAmon's native 5-phase confirmation engine (depth: baseline → poison → clean → persistence), which now proves both **reflected** poisoning (a benign canary echoed back) and **non-reflective / differential** poisoning (a persisted status / Location / body change with no echoed marker).

### Who is this for?
Pentesters and bug-bounty hunters whose target sits behind a cache and who want a focused, high-signal web-cache-poisoning + web-cache-deception assessment rather than a general scan. Ideal for:
- CDN-fronted apps (Cloudflare, Fastly, Akamai, CloudFront)
- Reverse-proxy / Varnish / nginx-cached sites (including *silent* caches that strip cache-status headers)
- Modern SSR frameworks (Next.js, Nuxt, Remix/React Router) with framework-specific cache quirks
- Sites with cacheable static-ish routes reachable with unkeyed headers/params

Use \`Web App Pentester\` or \`Full Active Scan\` if you want WCP as one tool among many. Use this preset when cache poisoning specifically is the target.

### What it enables
- Passive subdomain discovery (crt.sh + Subfinder + Amass passive + HackerTarget + PureDNS) to surface CDN-fronted hosts
- httpx with **CDN detection** + tech detect + response/header capture - CDN-fronted hosts are prime cache targets and the fingerprint drives framework packs
- Wappalyzer + httpx tech-detect framework detection so the Next.js / Nuxt / Remix hypothesis packs only fire when plausible
- Katana depth 3 + Hakrawler + GAU (historical) to harvest the live URL + parameterized-endpoint surface WCP tests against (you cannot test caching before you know which URLs are live). Query strings surfaced here feed WCP's unkeyed-parameter vectors
- **Web Cache Poisoning module**: WCVS breadth sweep (safe profile, deception on, CPDoS off) + native confirmation with framework packs, **behavioral silent-cache detection** (frozen-Date probe), and isolated per-test cache-busters so the real cached page is never touched
- Minimal security checks (TLS / headers) to catch transport + cache-control misconfigurations

### What it disables
- Knockpy brute-force subdomains - standard CDN hostnames are already in passive indexes
- Masscan / Nmap / Naabu heavy port scans - WCP targets are web ports (80/443), already covered by httpx
- Kiterunner & ffuf directory brute force - WCP tests *existing* live/cacheable URLs, not brute-forced paths
- Nuclei, GVM, GraphQL, secret scanners - out of scope for a focused cache-poisoning hunt (use a broader preset for those)
- All OSINT enrichment, banner grabbing, CVE/MITRE lookup - not cache-poisoning signals

### How it works
1. Subdomain discovery + httpx surface live, CDN-fronted hosts (httpx CDN probe flags Cloudflare/Fastly/Akamai/CloudFront)
2. Wappalyzer + httpx tech-detect fingerprint the stack so framework-specific cache vectors (Next.js \`x-invoke-status\`/\`Rsc\`, Nuxt \`_payload.json\`, Remix \`_data\`) only fire on matching tech
3. Katana + Hakrawler + GAU build the live URL + endpoint list (their query strings become unkeyed-parameter candidates)
4. The cache oracle decides per-URL whether a usable cache exists (cache-status headers, Age, Cache-Control, Vary, or the behavioral frozen-Date fallback for silent caches)
5. WCVS runs the breadth sweep (deception on, time-based detection + CPDoS off for safety) and surfaces candidates
6. The native engine carves an isolated cache-buster slot per vector and runs baseline → poison → clean → persistence with a benign \`.invalid\` canary, catching both reflected and non-reflective poisoning
7. Findings scoring at or above the confidence gate become \`Vulnerability {source:'cache_poisoning'}\` nodes linked to the affected Endpoint/BaseURL, tagged with the detection mode (reflected / differential / both)

### Expected findings (severity class)
- **Critical/High**: Stored XSS via poisoned cache, open redirect via unkeyed Host/scheme headers, cache-poisoned DoS (research profile only)
- **High**: Web cache deception (private-page caching), persisted redirect poisoning
- **Medium**: Reflected unkeyed-input poisoning without high-impact sink`,
  targetProfile: 'domain',
  environment: 'external',
  parameters: {
    // Modules: discovery -> probe -> crawl -> vuln_scan (where the WCP module lives).
    scanModules: ['domain_discovery', 'http_probe', 'resource_enum', 'vuln_scan'],

    stealthMode: false,

    // --- Subdomain discovery: passive (surface CDN-fronted hosts; no brute force) ---
    subdomainDiscoveryEnabled: true,
    crtshEnabled: true,
    hackerTargetEnabled: true,
    knockpyReconEnabled: false,
    subfinderEnabled: true,
    amassEnabled: true,
    amassActive: false,
    amassBrute: false,
    purednsEnabled: true,
    useBruteforceForSubdomains: false,

    whoisEnabled: true,
    dnsEnabled: true,

    // --- Port scanning: OFF. WCP targets are web ports (80/443) that httpx covers. ---
    naabuEnabled: false,
    masscanEnabled: false,
    nmapEnabled: false,

    // --- httpx: CDN detection + tech detect + response capture (cache targeting) ---
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
    httpxProbeTechDetect: true,
    httpxProbeIp: true,
    httpxProbeCname: true,
    httpxProbeTlsInfo: true,
    httpxProbeTlsGrab: false,
    httpxProbeFavicon: false,
    httpxProbeJarm: false,
    httpxProbeAsn: false,
    httpxProbeCdn: true,                 // CDN-fronted hosts are the prime cache targets
    httpxIncludeResponse: true,
    httpxIncludeResponseHeaders: true,

    // --- Wappalyzer: framework detection gates the Next/Nuxt/Remix hypothesis packs ---
    wappalyzerEnabled: true,
    wappalyzerMinConfidence: 50,
    bannerGrabEnabled: false,

    // --- VHost & SNI: OFF. Virtual-host discovery is host-enumeration, not cache
    //     poisoning; it doesn't help prove a cache bug on the URLs we already have. ---
    vhostSniEnabled: false,

    // --- Katana: crawl for the live URL + endpoint surface WCP tests against ---
    katanaEnabled: true,
    katanaDepth: 3,
    katanaMaxUrls: 800,
    katanaRateLimit: 75,
    katanaTimeout: 2400,
    katanaJsCrawl: true,

    // --- Hakrawler: secondary crawler ---
    hakrawlerEnabled: true,
    zapAjaxSpiderEnabled: false,
    hakrawlerDepth: 2,
    hakrawlerThreads: 10,

    // --- GAU: historical URLs (cacheable static-ish routes from old deploys) ---
    gauEnabled: true,
    gauThreads: 5,
    gauProviders: ['wayback', 'commoncrawl', 'otx'],
    gauVerifyUrls: true,
    gauDetectMethods: true,
    gauFilterDeadEndpoints: true,

    // ParamSpider OFF: GAU already pulls historical parameterized URLs.
    paramspiderEnabled: false,

    // --- JS Recon / jsluice: OFF. Framework fingerprint comes from Wappalyzer +
    //     httpx tech-detect (what the WCP packs actually read); JS bundle parsing is
    //     extra cost not needed for cache poisoning. ---
    jsReconEnabled: false,
    jsluiceEnabled: false,

    // --- Directory/path brute force: OFF (WCP tests existing live URLs) ---
    kiterunnerEnabled: false,
    ffufEnabled: false,

    // --- Arjun: OFF. Active hidden-parameter brute force is heavier than a focused
    //     cache-poisoning hunt needs; the param vectors WCP tests come from the query
    //     strings already surfaced by Katana crawling + GAU. (Enable Arjun if you want
    //     deeper unkeyed-parameter coverage.) ---
    arjunEnabled: false,

    // --- Nuclei / GVM / GraphQL: OFF (focused cache-poisoning hunt) ---
    nucleiEnabled: false,
    graphqlSecurityEnabled: false,
    graphqlCopEnabled: false,

    // --- AI enrichment: OFF. These default ON globally, so a focused preset must
    //     disable them explicitly or they leak in. None are needed for WCP and they
    //     each spend LLM calls. (AI Surface Recon targets LLM/MCP apps; the Endpoint
    //     AI Classifier + resource-enum AI flags classify endpoints; the httpx AI
    //     sub-probes enrich fingerprinting - basic Wappalyzer/tech-detect suffices.) ---
    aiSurfaceReconEnabled: false,
    resourceEnumAiClassifierEnabled: false,
    resourceEnumAiPathClassifierEnabled: false,
    resourceEnumAiRagPathFlagEnabled: false,
    resourceEnumAiParamInjectableFlagEnabled: false,
    resourceEnumAiToolArgPathEnabled: false,
    httpProbeAiHeaderScanEnabled: false,
    httpProbeAiFaviconHashEnabled: false,
    httpProbeAiTitleDetectionEnabled: false,
    httpProbeAiWappalyzerEnabled: false,

    // --- Web Cache Poisoning: THE focus. Safe profile, breadth + native confirm. ---
    webCachePoisonEnabled: true,
    webCachePoisonScanProfile: 'safe-confirm',   // benign canaries, always isolated, no CPDoS
    webCachePoisonTimeout: 1800,                 // WCVS breadth subprocess budget
    webCachePoisonTimeoutPerReq: 10,
    webCachePoisonConcurrency: 10,               // WCVS threads
    webCachePoisonConfirmWorkers: 6,             // native confirmation URLs in flight
    webCachePoisonMaxRpsPerHost: 0,
    webCachePoisonMinConfidence: 0.8,            // keep Confirmed + Strong
    webCachePoisonAllowFrameworkPacks: true,     // Next.js / Nuxt / Remix vectors
    webCachePoisonAllowDeception: true,          // web-cache-deception path tricks
    webCachePoisonAllowCpdos: false,             // CPDoS stays off (research profile only)
    webCachePoisonCrossVantage: false,
    webCachePoisonCacheBusterParam: 'rdmncb',
    webCachePoisonVerifySsl: true,
    webCachePoisonBehavioralOracle: true,        // detect silent Varnish/nginx caches
    webCachePoisonBehavioralDelay: 1.1,
    webCachePoisonDifferential: true,            // catch non-reflective (status/Location/body) poisoning

    // --- Security checks: transport + header/cache-control misconfig ---
    securityCheckEnabled: true,
    securityCheckTlsExpiringSoon: true,
    securityCheckLoginNoHttps: true,
    securityCheckSessionNoSecure: true,
    securityCheckBasicAuthNoTls: true,
    securityCheckDirectIpHttp: false,
    securityCheckIpApiExposed: false,
    securityCheckWafBypass: false,

    // --- CVE / MITRE: OFF (no Nuclei CVE feed in this focused preset) ---
    cveLookupEnabled: false,
    mitreEnabled: false,

    // --- OSINT: OFF (not cache-poisoning signals) ---
    osintEnrichmentEnabled: false,
    shodanEnabled: false,
    urlscanEnabled: false,
    otxEnabled: false,
    censysEnabled: false,
    fofaEnabled: false,
    netlasEnabled: false,
    virusTotalEnabled: false,
    zoomEyeEnabled: false,
    criminalIpEnabled: false,
    uncoverEnabled: false,
  },
}
