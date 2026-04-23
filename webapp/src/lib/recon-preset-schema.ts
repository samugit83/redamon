import { z } from 'zod/v4'

// ---------------------------------------------------------------------------
// Zod schema covering every recon-pipeline parameter from the Prisma Project
// model.  All fields are optional (presets are Partial<ProjectFormData>).
// Unknown keys are stripped so the LLM cannot inject garbage.
// ---------------------------------------------------------------------------

const bool = z.boolean().optional()
const int = z.coerce.number().int().optional()
const float = z.coerce.number().optional()
const str = z.string().optional()
const strArr = z.array(z.string()).optional()
const intArr = z.array(z.coerce.number().int()).optional()

export const reconPresetSchema = z.object({
  // -- Global --
  scanModules: strArr,
  stealthMode: bool,
  updateGraphDb: bool,
  useTorForRecon: bool,
  useBruteforceForSubdomains: bool,

  // -- WHOIS / DNS --
  whoisEnabled: bool,
  whoisMaxRetries: int,
  dnsEnabled: bool,
  dnsMaxRetries: int,
  dnsMaxWorkers: int,
  dnsRecordParallelism: bool,

  // -- Subdomain Discovery --
  subdomainDiscoveryEnabled: bool,
  crtshEnabled: bool,
  crtshMaxResults: int,
  hackerTargetEnabled: bool,
  hackerTargetMaxResults: int,
  knockpyReconEnabled: bool,
  knockpyReconMaxResults: int,
  subfinderEnabled: bool,
  subfinderMaxResults: int,
  amassEnabled: bool,
  amassMaxResults: int,
  amassTimeout: int,
  amassActive: bool,
  amassBrute: bool,
  purednsEnabled: bool,
  purednsThreads: int,
  purednsRateLimit: int,
  purednsWildcardBatch: int,
  purednsSkipValidation: bool,

  // -- Port Scanning: Naabu --
  naabuEnabled: bool,
  naabuTopPorts: str,
  naabuCustomPorts: str,
  naabuRateLimit: int,
  naabuThreads: int,
  naabuTimeout: int,
  naabuRetries: int,
  naabuScanType: str,
  naabuExcludeCdn: bool,
  naabuDisplayCdn: bool,
  naabuSkipHostDiscovery: bool,
  naabuVerifyPorts: bool,
  naabuPassiveMode: bool,

  // -- Port Scanning: Masscan --
  masscanEnabled: bool,
  masscanTopPorts: str,
  masscanCustomPorts: str,
  masscanRate: int,
  masscanBanners: bool,
  masscanWait: int,
  masscanRetries: int,
  masscanExcludeTargets: str,

  // -- Port Scanning: Nmap --
  nmapEnabled: bool,
  nmapVersionDetection: bool,
  nmapScriptScan: bool,
  nmapTimingTemplate: str,
  nmapTimeout: int,
  nmapHostTimeout: int,
  nmapParallelism: int,

  // -- HTTP Probing: httpx --
  httpxEnabled: bool,
  httpxThreads: int,
  httpxTimeout: int,
  httpxRetries: int,
  httpxRateLimit: int,
  httpxFollowRedirects: bool,
  httpxMaxRedirects: int,
  httpxProbeStatusCode: bool,
  httpxProbeContentLength: bool,
  httpxProbeContentType: bool,
  httpxProbeTitle: bool,
  httpxProbeServer: bool,
  httpxProbeResponseTime: bool,
  httpxProbeWordCount: bool,
  httpxProbeLineCount: bool,
  httpxProbeTechDetect: bool,
  httpxProbeIp: bool,
  httpxProbeCname: bool,
  httpxProbeTlsInfo: bool,
  httpxProbeTlsGrab: bool,
  httpxProbeFavicon: bool,
  httpxProbeJarm: bool,
  httpxProbeHash: str,
  httpxIncludeResponse: bool,
  httpxIncludeResponseHeaders: bool,
  httpxProbeAsn: bool,
  httpxProbeCdn: bool,
  httpxPaths: strArr,
  httpxCustomHeaders: strArr,
  httpxMatchCodes: strArr,
  httpxFilterCodes: strArr,

  // -- Wappalyzer --
  wappalyzerEnabled: bool,
  wappalyzerMinConfidence: int,
  wappalyzerRequireHtml: bool,
  wappalyzerAutoUpdate: bool,
  wappalyzerCacheTtlHours: int,

  // -- Banner Grabbing --
  bannerGrabEnabled: bool,
  bannerGrabTimeout: int,
  bannerGrabThreads: int,
  bannerGrabMaxLength: int,

  // -- Web Crawling: Katana --
  katanaEnabled: bool,
  katanaDepth: int,
  katanaMaxUrls: int,
  katanaRateLimit: int,
  katanaTimeout: int,
  katanaJsCrawl: bool,
  katanaParamsOnly: bool,
  katanaExcludePatterns: strArr,
  katanaScope: str,
  katanaCustomHeaders: strArr,
  katanaParallelism: int,
  katanaConcurrency: int,

  // -- Web Crawling: Hakrawler --
  hakrawlerEnabled: bool,
  hakrawlerDepth: int,
  hakrawlerThreads: int,
  hakrawlerTimeout: int,
  hakrawlerMaxUrls: int,
  hakrawlerIncludeSubs: bool,
  hakrawlerInsecure: bool,
  hakrawlerParallelism: int,

  // -- JS Analysis: jsluice --
  jsluiceEnabled: bool,
  jsluiceMaxFiles: int,
  jsluiceTimeout: int,
  jsluiceExtractUrls: bool,
  jsluiceExtractSecrets: bool,
  jsluiceConcurrency: int,
  jsluiceParallelism: int,

  // -- JS Analysis: JS Recon --
  jsReconEnabled: bool,
  jsReconMaxFiles: int,
  jsReconTimeout: int,
  jsReconConcurrency: int,
  jsReconValidateKeys: bool,
  jsReconValidationTimeout: int,
  jsReconExtractEndpoints: bool,
  jsReconRegexPatterns: bool,
  jsReconSourceMaps: bool,
  jsReconDependencyCheck: bool,
  jsReconDomSinks: bool,
  jsReconFrameworkDetect: bool,
  jsReconDevComments: bool,
  jsReconIncludeChunks: bool,
  jsReconIncludeFrameworkJs: bool,
  jsReconIncludeArchivedJs: bool,
  jsReconMinConfidence: str,
  jsReconStandaloneCrawlDepth: int,

  // -- GraphQL Security Scanner --
  graphqlSecurityEnabled: bool,
  graphqlIntrospectionTest: bool,
  graphqlTimeout: int,
  graphqlRateLimit: int,
  graphqlConcurrency: int,
  graphqlAuthType: str,
  graphqlAuthValue: str,
  graphqlAuthHeader: str,
  graphqlEndpoints: str,
  graphqlDepthLimit: int,
  graphqlRetryCount: int,
  graphqlRetryBackoff: float,
  graphqlVerifySsl: bool,

  // -- GraphQL Cop (external Docker-based misconfig scanner) --
  graphqlCopEnabled: bool,
  graphqlCopDockerImage: str,
  graphqlCopTimeout: int,
  graphqlCopForceScan: bool,
  graphqlCopDebug: bool,
  graphqlCopTestFieldSuggestions: bool,
  graphqlCopTestIntrospection: bool,
  graphqlCopTestGraphiql: bool,
  graphqlCopTestGetMethod: bool,
  graphqlCopTestAliasOverloading: bool,
  graphqlCopTestBatchQuery: bool,
  graphqlCopTestTraceMode: bool,
  graphqlCopTestDirectiveOverloading: bool,
  graphqlCopTestCircularIntrospection: bool,
  graphqlCopTestGetMutation: bool,
  graphqlCopTestPostCsrf: bool,
  graphqlCopTestUnhandledError: bool,

  // -- Directory Fuzzing: ffuf --
  ffufEnabled: bool,
  ffufWordlist: str,
  ffufThreads: int,
  ffufRate: int,
  ffufTimeout: int,
  ffufMaxTime: int,
  ffufMatchCodes: intArr,
  ffufFilterCodes: intArr,
  ffufFilterSize: str,
  ffufExtensions: strArr,
  ffufRecursion: bool,
  ffufRecursionDepth: int,
  ffufAutoCalibrate: bool,
  ffufFollowRedirects: bool,
  ffufSmartFuzz: bool,
  ffufParallelism: int,

  // -- Parameter Discovery: Arjun --
  arjunEnabled: bool,
  arjunThreads: int,
  arjunTimeout: int,
  arjunScanTimeout: int,
  arjunMethods: strArr,
  arjunMaxEndpoints: int,
  arjunChunkSize: int,
  arjunRateLimit: int,
  arjunStable: bool,
  arjunPassive: bool,
  arjunDisableRedirects: bool,

  // -- Passive URL Discovery: GAU --
  gauEnabled: bool,
  gauProviders: strArr,
  gauMaxUrls: int,
  gauTimeout: int,
  gauThreads: int,
  gauBlacklistExtensions: strArr,
  gauVerbose: bool,
  gauVerifyUrls: bool,
  gauDetectMethods: bool,
  gauFilterDeadEndpoints: bool,
  gauWorkers: int,

  // -- ParamSpider --
  paramspiderEnabled: bool,
  paramspiderTimeout: int,
  paramspiderWorkers: int,

  // -- API Discovery: Kiterunner --
  kiterunnerEnabled: bool,
  kiterunnerWordlists: strArr,
  kiterunnerRateLimit: int,
  kiterunnerConnections: int,
  kiterunnerTimeout: int,
  kiterunnerScanTimeout: int,
  kiterunnerThreads: int,
  kiterunnerDetectMethods: bool,
  kiterunnerMethodDetectionMode: str,
  kiterunnerBruteforceMethods: strArr,
  kiterunnerParallelism: int,

  // -- Vulnerability Scanning: Nuclei --
  nucleiEnabled: bool,
  nucleiSeverity: strArr,
  nucleiTemplates: strArr,
  nucleiExcludeTemplates: strArr,
  nucleiCustomTemplates: strArr,
  nucleiRateLimit: int,
  nucleiBulkSize: int,
  nucleiConcurrency: int,
  nucleiTimeout: int,
  nucleiRetries: int,
  nucleiTags: strArr,
  nucleiExcludeTags: strArr,
  nucleiDastMode: bool,
  nucleiAutoUpdateTemplates: bool,
  nucleiNewTemplatesOnly: bool,
  nucleiHeadless: bool,
  nucleiSystemResolvers: bool,
  nucleiFollowRedirects: bool,
  nucleiMaxRedirects: int,
  nucleiScanAllIps: bool,
  nucleiInteractsh: bool,

  // -- Subdomain Takeover --
  subdomainTakeoverEnabled: bool,
  subjackEnabled: bool,
  subjackThreads: int,
  subjackTimeout: int,
  subjackSsl: bool,
  subjackAll: bool,
  subjackCheckNs: bool,
  subjackCheckAr: bool,
  subjackCheckMail: bool,
  subjackRunTimeout: int,
  nucleiTakeoversEnabled: bool,
  nucleiTakeoverRunTimeout: int,
  takeoverSeverity: strArr,
  takeoverConfidenceThreshold: int,
  takeoverRateLimit: int,
  takeoverManualReviewAutoPublish: bool,
  baddnsEnabled: bool,
  baddnsDockerImage: str,
  baddnsModules: strArr,
  baddnsNameservers: strArr,
  baddnsRunTimeout: int,

  // -- CVE Lookup --
  cveLookupEnabled: bool,
  cveLookupSource: str,
  cveLookupMaxCves: int,
  cveLookupMinCvss: float,

  // -- MITRE CWE/CAPEC --
  mitreEnabled: bool,
  mitreAutoUpdateDb: bool,
  mitreIncludeCwe: bool,
  mitreIncludeCapec: bool,
  mitreEnrichRecon: bool,
  mitreEnrichGvm: bool,
  mitreCacheTtlHours: int,

  // -- Security Checks --
  securityCheckEnabled: bool,
  securityCheckDirectIpHttp: bool,
  securityCheckDirectIpHttps: bool,
  securityCheckIpApiExposed: bool,
  securityCheckWafBypass: bool,
  securityCheckTlsExpiringSoon: bool,
  securityCheckTlsExpiryDays: int,
  securityCheckMissingReferrerPolicy: bool,
  securityCheckMissingPermissionsPolicy: bool,
  securityCheckMissingCoop: bool,
  securityCheckMissingCorp: bool,
  securityCheckMissingCoep: bool,
  securityCheckCacheControlMissing: bool,
  securityCheckLoginNoHttps: bool,
  securityCheckSessionNoSecure: bool,
  securityCheckSessionNoHttponly: bool,
  securityCheckBasicAuthNoTls: bool,
  securityCheckSpfMissing: bool,
  securityCheckDmarcMissing: bool,
  securityCheckDnssecMissing: bool,
  securityCheckZoneTransfer: bool,
  securityCheckAdminPortExposed: bool,
  securityCheckDatabaseExposed: bool,
  securityCheckRedisNoAuth: bool,
  securityCheckKubernetesApiExposed: bool,
  securityCheckSmtpOpenRelay: bool,
  securityCheckCspUnsafeInline: bool,
  securityCheckInsecureFormAction: bool,
  securityCheckNoRateLimiting: bool,
  securityCheckTimeout: int,
  securityCheckMaxWorkers: int,

  // -- OSINT Enrichment --
  osintEnrichmentEnabled: bool,
  shodanEnabled: bool,
  shodanHostLookup: bool,
  shodanReverseDns: bool,
  shodanDomainDns: bool,
  shodanPassiveCves: bool,
  shodanWorkers: int,
  urlscanEnabled: bool,
  urlscanMaxResults: int,
  censysEnabled: bool,
  fofaEnabled: bool,
  fofaMaxResults: int,
  otxEnabled: bool,
  netlasEnabled: bool,
  virusTotalEnabled: bool,
  zoomEyeEnabled: bool,
  zoomEyeMaxResults: int,
  criminalIpEnabled: bool,
  criminalIpWorkers: int,
  uncoverEnabled: bool,
  uncoverMaxResults: int,
  otxWorkers: int,
  virusTotalWorkers: int,
  censysWorkers: int,
  fofaWorkers: int,
  netlasWorkers: int,
  zoomEyeWorkers: int,
}).strip()

export type ReconPresetParams = z.infer<typeof reconPresetSchema>

// ---------------------------------------------------------------------------
// LLM system prompt parameter catalog.
// Embedded in the system message so the LLM knows what keys exist and how to
// set them.  Descriptions are intentionally terse to save tokens.
// ---------------------------------------------------------------------------

export const RECON_PARAMETER_CATALOG = `
## Scan Modules & Global
- scanModules: string[] - Pipeline phases to run. Values: "domain_discovery", "port_scan", "http_probe", "resource_enum", "vuln_scan", "js_recon"
- stealthMode: boolean - Reduce scan aggressiveness and network noise
- updateGraphDb: boolean - Store results in the graph database
- useTorForRecon: boolean - Route traffic through Tor
- useBruteforceForSubdomains: boolean - Enable DNS brute-force for subdomain discovery

## WHOIS & DNS
- whoisEnabled: boolean - Run WHOIS lookups
- whoisMaxRetries: integer - Max WHOIS retries (default 6)
- dnsEnabled: boolean - Run DNS resolution
- dnsMaxRetries: integer - Max DNS retries (default 3)
- dnsMaxWorkers: integer - DNS resolution parallel workers
- dnsRecordParallelism: boolean - Query DNS record types in parallel

## Subdomain Discovery
- subdomainDiscoveryEnabled: boolean - Master switch for subdomain discovery
- crtshEnabled: boolean - Query crt.sh certificate transparency
- crtshMaxResults: integer
- hackerTargetEnabled: boolean - Query HackerTarget
- hackerTargetMaxResults: integer
- knockpyReconEnabled: boolean - Run Knockpy
- knockpyReconMaxResults: integer
- subfinderEnabled: boolean - Run Subfinder
- subfinderMaxResults: integer
- amassEnabled: boolean - Run Amass
- amassMaxResults: integer
- amassTimeout: integer - Amass timeout in MINUTES (default 10)
- amassActive: boolean - Amass active probing mode
- amassBrute: boolean - Amass DNS brute-force
- purednsEnabled: boolean - Run PureDNS wildcard filtering
- purednsThreads: integer
- purednsRateLimit: integer
- purednsWildcardBatch: integer - Wildcard filtering batch size
- purednsSkipValidation: boolean

## Port Scanning - Naabu
- naabuEnabled: boolean - Run Naabu port scanner
- naabuTopPorts: string - Top N ports, e.g. "1000"
- naabuCustomPorts: string - Custom port list, e.g. "80,443,8080"
- naabuRateLimit: integer - Packets per second
- naabuThreads: integer
- naabuTimeout: integer - Timeout in milliseconds
- naabuRetries: integer
- naabuScanType: string - "s" (SYN) or "c" (connect)
- naabuExcludeCdn: boolean - Skip CDN IPs
- naabuDisplayCdn: boolean - Show CDN info
- naabuSkipHostDiscovery: boolean
- naabuVerifyPorts: boolean
- naabuPassiveMode: boolean - Use Shodan InternetDB instead of active scan

## Port Scanning - Masscan
- masscanEnabled: boolean - Run Masscan
- masscanTopPorts: string
- masscanCustomPorts: string
- masscanRate: integer - Packets per second
- masscanBanners: boolean - Grab banners
- masscanWait: integer - Wait time in seconds
- masscanRetries: integer
- masscanExcludeTargets: string - Comma-separated targets to exclude

## Port Scanning - Nmap
- nmapEnabled: boolean - Run Nmap service detection
- nmapVersionDetection: boolean - Detect service versions
- nmapScriptScan: boolean - Run NSE vuln scripts
- nmapTimingTemplate: string - "T0" to "T5"
- nmapTimeout: integer - Timeout in seconds
- nmapHostTimeout: integer - Per-host timeout in seconds
- nmapParallelism: integer - IPs scanned concurrently by Nmap

## HTTP Probing - httpx
- httpxEnabled: boolean - Run httpx HTTP prober
- httpxThreads: integer
- httpxTimeout: integer - Seconds
- httpxRetries: integer
- httpxRateLimit: integer - Requests per second
- httpxFollowRedirects: boolean
- httpxMaxRedirects: integer
- httpxProbeStatusCode: boolean
- httpxProbeContentLength: boolean
- httpxProbeContentType: boolean
- httpxProbeTitle: boolean - Extract page title
- httpxProbeServer: boolean - Extract server header
- httpxProbeResponseTime: boolean
- httpxProbeWordCount: boolean
- httpxProbeLineCount: boolean
- httpxProbeTechDetect: boolean - Fingerprint technologies
- httpxProbeIp: boolean
- httpxProbeCname: boolean
- httpxProbeTlsInfo: boolean
- httpxProbeTlsGrab: boolean
- httpxProbeFavicon: boolean
- httpxProbeJarm: boolean - JARM TLS fingerprint
- httpxProbeHash: string - Hash algo: "md5", "sha256", etc.
- httpxIncludeResponse: boolean - Store full response body
- httpxIncludeResponseHeaders: boolean
- httpxProbeAsn: boolean
- httpxProbeCdn: boolean
- httpxPaths: string[] - Additional URL paths to probe
- httpxCustomHeaders: string[] - Custom HTTP headers
- httpxMatchCodes: string[] - Only show responses with these status codes
- httpxFilterCodes: string[] - Hide responses with these status codes

## Technology Fingerprinting - Wappalyzer
- wappalyzerEnabled: boolean
- wappalyzerMinConfidence: integer - 0-100
- wappalyzerRequireHtml: boolean
- wappalyzerAutoUpdate: boolean
- wappalyzerCacheTtlHours: integer

## Banner Grabbing
- bannerGrabEnabled: boolean
- bannerGrabTimeout: integer - Seconds
- bannerGrabThreads: integer
- bannerGrabMaxLength: integer

## Web Crawling - Katana
- katanaEnabled: boolean - Run Katana web crawler
- katanaDepth: integer - Crawl depth
- katanaMaxUrls: integer - Max URLs to crawl
- katanaRateLimit: integer
- katanaTimeout: integer - Seconds
- katanaJsCrawl: boolean - Crawl JS files
- katanaParamsOnly: boolean - Only extract parameterized URLs
- katanaExcludePatterns: string[] - Regex patterns to exclude from crawling
- katanaScope: string - Scope filter: "dn" (domain), "rdn" (root domain), etc.
- katanaCustomHeaders: string[] - Custom HTTP headers for crawler
- katanaParallelism: integer - Targets crawled simultaneously
- katanaConcurrency: integer - Concurrent fetchers per target

## Web Crawling - Hakrawler
- hakrawlerEnabled: boolean
- hakrawlerDepth: integer
- hakrawlerThreads: integer
- hakrawlerTimeout: integer - Seconds
- hakrawlerMaxUrls: integer
- hakrawlerIncludeSubs: boolean - Include subdomains
- hakrawlerInsecure: boolean - Skip TLS verification
- hakrawlerParallelism: integer - Parallel crawler instances

## JavaScript Analysis - jsluice
- jsluiceEnabled: boolean - Run jsluice JS analyzer (active tool, sends HTTP requests)
- jsluiceMaxFiles: integer
- jsluiceTimeout: integer - Seconds
- jsluiceExtractUrls: boolean
- jsluiceExtractSecrets: boolean
- jsluiceConcurrency: integer
- jsluiceParallelism: integer - Base URLs analyzed in parallel

## JavaScript Analysis - JS Recon (deep)
- jsReconEnabled: boolean - Run deep JS analysis
- jsReconMaxFiles: integer
- jsReconTimeout: integer - Seconds
- jsReconConcurrency: integer
- jsReconValidateKeys: boolean - Validate discovered API keys
- jsReconValidationTimeout: integer
- jsReconExtractEndpoints: boolean
- jsReconRegexPatterns: boolean
- jsReconSourceMaps: boolean - Analyze source maps
- jsReconDependencyCheck: boolean
- jsReconDomSinks: boolean - Detect DOM XSS sinks
- jsReconFrameworkDetect: boolean
- jsReconDevComments: boolean - Extract developer comments
- jsReconIncludeChunks: boolean
- jsReconIncludeFrameworkJs: boolean
- jsReconIncludeArchivedJs: boolean
- jsReconMinConfidence: string - "low", "medium", "high"
- jsReconStandaloneCrawlDepth: integer

## GraphQL Security Scanner (Group 6 - active, sends introspection probes)
- graphqlSecurityEnabled: boolean - Master toggle for GraphQL scanning (default false)
- graphqlIntrospectionTest: boolean - Probe __schema to detect exposed introspection (default true)
- graphqlTimeout: integer - Per-endpoint request timeout in seconds (default 30)
- graphqlRateLimit: integer - Requests per second, capped by ROE_GLOBAL_MAX_RPS (default 10)
- graphqlConcurrency: integer - Parallel endpoint tests (default 5)
- graphqlAuthType: string - "", "bearer", "basic", "cookie", "custom"
- graphqlAuthValue: string - Auth credential (token / user:pass / cookie string)
- graphqlAuthHeader: string - Header name when graphqlAuthType = "custom"
- graphqlEndpoints: string - Comma-separated custom GraphQL endpoints (empty = auto-discover)
- graphqlDepthLimit: integer - Max introspection query nesting depth (default 10)
- graphqlRetryCount: integer - Retry attempts on network failure (default 3)
- graphqlRetryBackoff: number - Exponential backoff base seconds between retries (default 2.0)
- graphqlVerifySsl: boolean - Reject invalid / self-signed TLS certs (default true)

## GraphQL Cop (external Docker-based misconfig scanner - Phase 2)
- graphqlCopEnabled: boolean - Master toggle for graphql-cop (default false, opt-in)
- graphqlCopDockerImage: string - Pinned image tag (default "dolevf/graphql-cop:1.14")
- graphqlCopTimeout: integer - Per-endpoint timeout in seconds (default 120)
- graphqlCopForceScan: boolean - -f flag: scan even if endpoint doesn't look GraphQL-like
- graphqlCopDebug: boolean - -d flag: adds X-GraphQL-Cop-Test header per request
- graphqlCopTestFieldSuggestions: boolean - LOW info-leak check (default true)
- graphqlCopTestIntrospection: boolean - HIGH info-leak check (default false, dedupes with native scanner)
- graphqlCopTestGraphiql: boolean - LOW info-leak, detects GraphiQL/Playground UI (default true)
- graphqlCopTestGetMethod: boolean - MEDIUM CSRF, GET-method queries allowed (default true)
- graphqlCopTestAliasOverloading: boolean - HIGH DoS, 101-alias rate-limit bypass (default true, disabled in stealth)
- graphqlCopTestBatchQuery: boolean - HIGH DoS, array-based batch queries (default true, disabled in stealth)
- graphqlCopTestTraceMode: boolean - INFO, Apollo tracing extension disclosure (default true)
- graphqlCopTestDirectiveOverloading: boolean - HIGH DoS (default true, disabled in stealth)
- graphqlCopTestCircularIntrospection: boolean - HIGH DoS, deep nested introspection (default true, disabled in stealth)
- graphqlCopTestGetMutation: boolean - MEDIUM CSRF, GET-based mutations (default true)
- graphqlCopTestPostCsrf: boolean - MEDIUM CSRF, url-encoded POST (default true)
- graphqlCopTestUnhandledError: boolean - INFO info-leak, exception stack traces (default true)

## Directory Fuzzing - ffuf
- ffufEnabled: boolean - Run ffuf directory fuzzer
- ffufWordlist: string - Path to wordlist file
- ffufThreads: integer
- ffufRate: integer - Requests per second (0 = unlimited)
- ffufTimeout: integer - Seconds
- ffufMaxTime: integer - Max total time in seconds
- ffufMatchCodes: integer[] - HTTP status codes to match, e.g. [200, 301, 403]
- ffufFilterCodes: integer[] - HTTP status codes to filter out
- ffufFilterSize: string - Filter responses by size
- ffufExtensions: string[] - File extensions to fuzz, e.g. [".php", ".asp"]
- ffufRecursion: boolean
- ffufRecursionDepth: integer
- ffufAutoCalibrate: boolean
- ffufFollowRedirects: boolean
- ffufSmartFuzz: boolean
- ffufParallelism: integer - Targets fuzzed in parallel

## Parameter Discovery - Arjun
- arjunEnabled: boolean - Run Arjun parameter discovery
- arjunThreads: integer
- arjunTimeout: integer - Seconds
- arjunScanTimeout: integer - Total scan timeout in seconds
- arjunMethods: string[] - HTTP methods: ["GET", "POST", "PUT", "DELETE", "PATCH"]
- arjunMaxEndpoints: integer
- arjunChunkSize: integer
- arjunRateLimit: integer - Requests per second (0 = unlimited)
- arjunPassive: boolean - Passive mode (no requests)
- arjunStable: boolean - Stability mode (slower but more reliable)
- arjunDisableRedirects: boolean - Disable following redirects

## Passive URL Discovery - GAU
- gauEnabled: boolean - Run GAU (GetAllUrls) archive lookup
- gauProviders: string[] - Sources: "wayback", "commoncrawl", "otx", "urlscan"
- gauMaxUrls: integer
- gauTimeout: integer - Seconds
- gauThreads: integer
- gauBlacklistExtensions: string[] - File extensions to skip, e.g. [".jpg", ".css"]
- gauVerbose: boolean
- gauVerifyUrls: boolean - Verify discovered URLs are alive
- gauDetectMethods: boolean - Detect allowed HTTP methods
- gauFilterDeadEndpoints: boolean
- gauWorkers: integer - Parallel domain query workers

## ParamSpider
- paramspiderEnabled: boolean - Run ParamSpider passive parameter discovery
- paramspiderTimeout: integer - Seconds
- paramspiderWorkers: integer - Parallel domain workers

## API Discovery - Kiterunner
- kiterunnerEnabled: boolean - Run Kiterunner API endpoint discovery
- kiterunnerWordlists: string[] - Wordlists: "routes-small", "routes-large"
- kiterunnerRateLimit: integer
- kiterunnerConnections: integer
- kiterunnerTimeout: integer - Per-request timeout in seconds
- kiterunnerScanTimeout: integer - Total scan timeout in seconds
- kiterunnerThreads: integer
- kiterunnerDetectMethods: boolean
- kiterunnerMethodDetectionMode: string - "bruteforce"
- kiterunnerBruteforceMethods: string[] - ["GET", "POST", "PUT", "DELETE", "PATCH"]
- kiterunnerParallelism: integer - Wordlists processed in parallel

## Vulnerability Scanning - Nuclei
- nucleiEnabled: boolean - Run Nuclei vulnerability scanner
- nucleiSeverity: string[] - Severity filter: "critical", "high", "medium", "low"
- nucleiTemplates: string[] - Specific template paths to include
- nucleiExcludeTemplates: string[] - Template paths to exclude
- nucleiCustomTemplates: string[] - Custom template paths
- nucleiRateLimit: integer - Requests per second
- nucleiBulkSize: integer
- nucleiConcurrency: integer
- nucleiTimeout: integer - Seconds
- nucleiRetries: integer
- nucleiTags: string[] - Template tags to include
- nucleiExcludeTags: string[] - Template tags to exclude, e.g. ["dos", "fuzz"]
- nucleiDastMode: boolean - Dynamic testing mode
- nucleiAutoUpdateTemplates: boolean
- nucleiNewTemplatesOnly: boolean
- nucleiHeadless: boolean - Browser-based testing
- nucleiSystemResolvers: boolean
- nucleiFollowRedirects: boolean
- nucleiMaxRedirects: integer
- nucleiScanAllIps: boolean
- nucleiInteractsh: boolean - Out-of-band interaction detection

## Subdomain Takeover (Subjack + Nuclei takeover templates)
- subdomainTakeoverEnabled: boolean - Master switch for the layered takeover scanner (default false)
- subjackEnabled: boolean - Run Subjack (DNS-first, Apache-2.0 Go binary). Default true.
- subjackThreads: integer - Subjack concurrent threads (default 10)
- subjackTimeout: integer - Subjack per-request timeout in seconds (default 30)
- subjackSsl: boolean - Force HTTPS probing for higher accuracy (default true)
- subjackAll: boolean - Test every URL, not just identified CNAMEs — slower (default false)
- subjackCheckNs: boolean - Detect NS takeovers (expired nameservers / dangling cloud DNS delegations)
- subjackCheckAr: boolean - Detect stale A records pointing to dead cloud IPs (manual review)
- subjackCheckMail: boolean - Check SPF include + MX takeovers
- subjackRunTimeout: integer - Hard wall clock for a full subjack run in seconds (default 900)
- nucleiTakeoversEnabled: boolean - Run Nuclei with -t http/takeovers/ -t dns/ against alive URLs (default true)
- nucleiTakeoverRunTimeout: integer - Hard wall clock for the takeover-only nuclei pass in seconds (default 1800)
- takeoverSeverity: string[] - Severity filter for Nuclei takeover templates (e.g. ["critical","high","medium"])
- takeoverConfidenceThreshold: integer - 0..100. Findings >= threshold+10 are confirmed, >= threshold are likely, otherwise manual_review
- takeoverRateLimit: integer - Nuclei requests/second for the takeover pass (default 50)
- takeoverManualReviewAutoPublish: boolean - Publish manual_review findings into the main Vulnerability stream (default false)
- baddnsEnabled: boolean - Run the BadDNS sidecar (AGPL-3.0, isolated Docker container). Requires "docker compose --profile tools build baddns-scanner". Default false.
- baddnsDockerImage: string - BadDNS image name. Default "redamon-baddns:latest" (built locally from baddns_scan/Dockerfile)
- baddnsModules: string[] - Subset of BadDNS modules to run. Valid: cname, ns, mx, txt, spf, dmarc, wildcard, nsec, references, zonetransfer. (MTA-STS exists in baddns 2.1.0 but is not CLI-addressable due to an upstream validator regex bug -- omit.) Default: ["cname","ns","mx","txt","spf"]
- baddnsNameservers: string[] - Optional custom DNS resolvers (e.g. ["1.1.1.1","8.8.8.8"]). Empty = system resolvers.
- baddnsRunTimeout: integer - Hard wall clock for the BadDNS pass in seconds. Default 1800.

## CVE Lookup
- cveLookupEnabled: boolean
- cveLookupSource: string - "nvd"
- cveLookupMaxCves: integer
- cveLookupMinCvss: number - Minimum CVSS score (0-10)

## MITRE CWE/CAPEC Enrichment
- mitreEnabled: boolean
- mitreAutoUpdateDb: boolean
- mitreIncludeCwe: boolean
- mitreIncludeCapec: boolean
- mitreEnrichRecon: boolean
- mitreEnrichGvm: boolean
- mitreCacheTtlHours: integer - Cache time-to-live in hours

## Security Checks
- securityCheckEnabled: boolean - Master switch for passive security checks
- securityCheckDirectIpHttp: boolean - Check direct IP HTTP access
- securityCheckDirectIpHttps: boolean - Check direct IP HTTPS access
- securityCheckIpApiExposed: boolean
- securityCheckWafBypass: boolean
- securityCheckTlsExpiringSoon: boolean
- securityCheckTlsExpiryDays: integer - Days threshold
- securityCheckMissingReferrerPolicy: boolean
- securityCheckMissingPermissionsPolicy: boolean
- securityCheckMissingCoop: boolean
- securityCheckMissingCorp: boolean
- securityCheckMissingCoep: boolean
- securityCheckCacheControlMissing: boolean
- securityCheckLoginNoHttps: boolean
- securityCheckSessionNoSecure: boolean
- securityCheckSessionNoHttponly: boolean
- securityCheckBasicAuthNoTls: boolean
- securityCheckSpfMissing: boolean
- securityCheckDmarcMissing: boolean
- securityCheckDnssecMissing: boolean
- securityCheckZoneTransfer: boolean
- securityCheckAdminPortExposed: boolean
- securityCheckDatabaseExposed: boolean
- securityCheckRedisNoAuth: boolean
- securityCheckKubernetesApiExposed: boolean
- securityCheckSmtpOpenRelay: boolean
- securityCheckCspUnsafeInline: boolean
- securityCheckInsecureFormAction: boolean
- securityCheckNoRateLimiting: boolean
- securityCheckTimeout: integer - Seconds
- securityCheckMaxWorkers: integer

## OSINT & Threat Intelligence
- osintEnrichmentEnabled: boolean - Master switch for OSINT enrichment
- shodanEnabled: boolean - Shodan lookups
- shodanHostLookup: boolean
- shodanReverseDns: boolean
- shodanDomainDns: boolean
- shodanPassiveCves: boolean - Passive CVE lookup via Shodan
- shodanWorkers: integer - Parallel IP lookup workers
- urlscanEnabled: boolean - URLScan.io
- urlscanMaxResults: integer
- censysEnabled: boolean
- fofaEnabled: boolean
- fofaMaxResults: integer
- otxEnabled: boolean - AlienVault OTX
- netlasEnabled: boolean
- virusTotalEnabled: boolean
- zoomEyeEnabled: boolean
- zoomEyeMaxResults: integer
- criminalIpEnabled: boolean
- criminalIpWorkers: integer - Parallel CriminalIP IP enrichment workers
- uncoverEnabled: boolean - ProjectDiscovery Uncover
- uncoverMaxResults: integer
- otxWorkers: integer - Parallel OTX IP enrichment workers
- virusTotalWorkers: integer - Parallel VirusTotal IP enrichment workers
- censysWorkers: integer - Parallel Censys IP enrichment workers
- fofaWorkers: integer - Parallel FOFA IP enrichment workers
- netlasWorkers: integer - Parallel Netlas IP enrichment workers
- zoomEyeWorkers: integer - Parallel ZoomEye IP enrichment workers
`.trim()

// ---------------------------------------------------------------------------
// Helper: extract JSON from a string that may be wrapped in markdown fences.
// ---------------------------------------------------------------------------

export function extractJson(raw: string): string {
  // Try to extract from ```json ... ``` or ``` ... ```
  const fenceMatch = raw.match(/```(?:json)?\s*\n?([\s\S]*?)\n?\s*```/)
  if (fenceMatch) return fenceMatch[1].trim()

  // Try to find the first { ... } block
  const braceStart = raw.indexOf('{')
  const braceEnd = raw.lastIndexOf('}')
  if (braceStart !== -1 && braceEnd > braceStart) {
    return raw.slice(braceStart, braceEnd + 1)
  }

  return raw.trim()
}
