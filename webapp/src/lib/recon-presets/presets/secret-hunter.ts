import type { ReconPreset } from '../types'

export const SECRET_HUNTER: ReconPreset = {
  id: 'secret-hunter',
  name: 'Secret & Credential Hunter',
  icon: '',
  image: '/preset-key.svg',
  shortDescription: 'Go beyond JS -- find secrets everywhere. Deep JS analysis, GAU for historical files, ffuf with sensitive extensions, and Nuclei exposure/token detection.',
  fullDescription: `### Pipeline Goal
Hunt for secrets, credentials, and sensitive configuration files across every reachable surface of the target. This preset combines deep JavaScript analysis with directory fuzzing for sensitive extensions, historical URL mining, and Nuclei templates targeting exposed tokens and config files.

### Who is this for?
Bug bounty hunters and red teamers who want to maximize credential and secret discovery. Ideal when the target has a large web footprint and you suspect leaked API keys, database credentials, or exposed configuration files.

### What it enables
- JS Recon fully enabled with all analysis modules, 2000 max files, and key validation
- jsluice at 1000 files with full secret and URL extraction
- GAU enabled to pull historical files from Wayback Machine, Common Crawl, and other archives
- ffuf with sensitive extensions (.env, .config, .yml, .yaml, .json, .bak, .old, .sql, .log, .key, .pem)
- Katana depth 3 with JS crawl for thorough discovery of dynamically loaded scripts
- Hakrawler for complementary crawl coverage
- Nuclei with exposure, token, secret, and config tags for targeted vulnerability detection

### What it disables
- Port scanning (Naabu, Nmap, Masscan) -- not needed, httpx handles port detection
- Parameter discovery (Arjun, ParamSpider) -- not relevant to secret hunting
- Kiterunner -- replaced by targeted ffuf with sensitive extensions
- Banner grabbing and Wappalyzer -- not useful for credential discovery
- OSINT enrichment -- disabled to keep focus on technical secret extraction
- CVE lookup, MITRE, and security checks -- disabled to reduce noise

### How it works
1. Subdomain discovery finds all subdomains using multiple tools
2. HTTP probing identifies live web servers with technology detection
3. Katana + Hakrawler + GAU aggressively crawl and mine historical URLs
4. ffuf fuzzes for sensitive file extensions (.env, .bak, .key, .pem, etc.)
5. jsluice extracts secrets and URLs from discovered JS files
6. JS Recon runs deep analysis: source maps, key validation, regex patterns, DOM sinks, and more
7. Nuclei scans with exposure/token/secret/config templates to catch anything else`,
  parameters: {
    // Pipeline modules
    scanModules: ['domain_discovery', 'http_probe', 'resource_enum', 'vuln_scan', 'js_recon'],

    // Stealth
    stealthMode: false,
    useTorForRecon: false,

    // WHOIS & DNS
    whoisEnabled: true,
    dnsEnabled: true,

    // Port scanning: ALL disabled
    naabuEnabled: false,
    nmapEnabled: false,
    masscanEnabled: false,

    // httpx
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
    httpxProbeWordCount: false,
    httpxProbeLineCount: false,
    httpxProbeCname: false,
    httpxProbeTlsInfo: false,
    httpxProbeTlsGrab: false,
    httpxProbeFavicon: false,
    httpxProbeJarm: false,
    httpxProbeAsn: false,
    httpxProbeCdn: false,
    httpxIncludeResponse: false,
    httpxIncludeResponseHeaders: false,

    // Wappalyzer: disabled
    wappalyzerEnabled: false,

    // Banner grabbing: disabled
    bannerGrabEnabled: false,

    // Katana
    katanaEnabled: true,
    katanaDepth: 3,
    katanaMaxUrls: 1500,
    katanaRateLimit: 75,
    katanaTimeout: 3600,
    katanaJsCrawl: true,

    // Hakrawler
    hakrawlerEnabled: true,
    hakrawlerDepth: 3,
    hakrawlerThreads: 5,
    hakrawlerTimeout: 45,
    hakrawlerMaxUrls: 800,
    hakrawlerIncludeSubs: true,
    hakrawlerInsecure: true,

    // GAU
    gauEnabled: true,
    gauProviders: ['wayback', 'commoncrawl', 'otx', 'urlscan'],
    gauMaxUrls: 5000,
    gauTimeout: 90,
    gauThreads: 5,
    gauVerifyUrls: true,
    gauDetectMethods: false,
    gauFilterDeadEndpoints: true,

    // ParamSpider: disabled
    paramspiderEnabled: false,

    // jsluice
    jsluiceEnabled: true,
    jsluiceMaxFiles: 1000,
    jsluiceExtractSecrets: true,
    jsluiceExtractUrls: true,
    jsluiceConcurrency: 10,

    // JS Recon (fully enabled)
    jsReconEnabled: true,
    jsReconMaxFiles: 2000,
    jsReconTimeout: 3600,
    jsReconConcurrency: 15,
    jsReconValidateKeys: true,
    jsReconValidationTimeout: 10,
    jsReconExtractEndpoints: true,
    jsReconRegexPatterns: true,
    jsReconSourceMaps: true,
    jsReconDependencyCheck: true,
    jsReconDomSinks: true,
    jsReconFrameworkDetect: true,
    jsReconDevComments: true,
    jsReconIncludeChunks: true,
    jsReconIncludeFrameworkJs: true,
    jsReconIncludeArchivedJs: true,
    jsReconMinConfidence: 'low',
    jsReconStandaloneCrawlDepth: 3,

    // ffuf
    ffufEnabled: true,
    ffufThreads: 40,
    ffufRate: 0,
    ffufTimeout: 10,
    ffufMaxTime: 900,
    ffufExtensions: ['.env', '.config', '.yml', '.yaml', '.json', '.bak', '.old', '.sql', '.log', '.key', '.pem'],
    ffufRecursion: false,
    ffufAutoCalibrate: true,
    ffufFollowRedirects: false,
    ffufSmartFuzz: true,

    // Kiterunner: disabled
    kiterunnerEnabled: false,

    // Arjun: disabled
    arjunEnabled: false,

    // Nuclei
    nucleiEnabled: true,
    nucleiSeverity: ['critical', 'high', 'medium', 'low'],
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
    nucleiInteractsh: false,
    nucleiTags: ['exposure', 'token', 'secret', 'config'],

    // CVE lookup: disabled
    cveLookupEnabled: false,

    // MITRE: disabled
    mitreEnabled: false,

    // Security checks: disabled
    securityCheckEnabled: false,

    // OSINT: all disabled
    osintEnrichmentEnabled: false,

    // --- GraphQL: explicit OFF so switching from a GraphQL-enabled preset resets cleanly ---
    graphqlSecurityEnabled: false,
    graphqlCopEnabled: false,
  },
}
