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
  aiInPipeline: bool,
  aiPipelineModel: str,
  updateGraphDb: bool,
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
  // AI surface recon hooks inside domain_recon (TXT/NS hint annotation during DNS pass)
  domainReconAiTxtHintEnabled: bool,
  domainReconAiNsHintEnabled: bool,
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
  // AI surface recon - annotate AI-bearing ports on naabu output
  portScanAiPortCatalogEnabled: bool,

  // -- Port Scanning: Masscan --
  masscanEnabled: bool,
  masscanTopPorts: str,
  masscanCustomPorts: str,
  masscanRate: int,
  masscanBanners: bool,
  masscanWait: int,
  masscanRetries: int,
  masscanExcludeTargets: str,
  // AI surface recon - same AI port catalogue applied to masscan output
  masscanAiPortCatalogEnabled: bool,

  // -- Port Scanning: Nmap --
  nmapEnabled: bool,
  nmapVersionDetection: bool,
  nmapScriptScan: bool,
  nmapTimingTemplate: str,
  nmapTimeout: int,
  nmapHostTimeout: int,
  nmapParallelism: int,
  // AI surface recon - regex nmap product/version strings against AI runtimes
  nmapAiVersionRegexEnabled: bool,

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
  // AI surface recon - annotate captured response data against AI vendor catalogues
  httpProbeAiHeaderScanEnabled: bool,
  httpProbeAiFaviconHashEnabled: bool,
  httpProbeAiTitleDetectionEnabled: bool,
  httpProbeAiWappalyzerEnabled: bool,

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

  // -- Resource Enum AI Classifier (cross-cutting endpoint + parameter tagging) --
  resourceEnumAiClassifierEnabled: bool,
  resourceEnumAiPathClassifierEnabled: bool,
  resourceEnumAiRagPathFlagEnabled: bool,
  resourceEnumAiParamInjectableFlagEnabled: bool,
  resourceEnumAiToolArgPathEnabled: bool,

  // -- AI Surface Recon (central module: active AI/LLM/MCP fingerprinting) --
  aiSurfaceReconEnabled: bool,
  aiSurfaceReconTimeout: int,
  aiSurfaceReconMaxWorkers: int,
  aiSurfaceReconUserAgent: str,
  aiSurfaceReconChatShapeProbeEnabled: bool,
  aiSurfaceReconMcpHandshakeEnabled: bool,
  aiSurfaceReconMcpListToolsEnabled: bool,
  aiSurfaceReconMcpYaraEnabled: bool,
  aiSurfaceReconOpenapiDiscoveryEnabled: bool,
  aiSurfaceReconModelListEnabled: bool,
  aiSurfaceReconVectorDbReadEnabled: bool,
  aiSurfaceReconJuliusProbePackEnabled: bool,
  aiSurfaceReconLatencyBaselineEnabled: bool,
  aiSurfaceReconCacheEnabled: bool,
  aiSurfaceReconProbePackVersion: str,

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

  // Credential-bearing source and discovery-header objects are intentionally
  // excluded from generated presets; presets may only tune non-secret controls.
  openapiEnabled: bool,
  openapiAutoDiscover: bool,
  openapiDiscoveryPaths: z.array(z.string()).max(200).optional(),
  openapiTimeout: int,
  openapiMaxDocuments: int,

  // -- Web Crawling: ZAP Ajax Spider --
  zapAjaxSpiderEnabled: bool,
  zapAjaxSpiderDockerImage: str,
  zapAjaxSpiderSeedMode: str,
  zapAjaxSpiderMaxDuration: int,
  zapAjaxSpiderMaxCrawlDepth: int,
  zapAjaxSpiderMaxCrawlStates: int,
  zapAjaxSpiderNumberOfBrowsers: int,
  zapAjaxSpiderBrowserId: str,
  zapAjaxSpiderEventWait: int,
  zapAjaxSpiderReloadWait: int,
  zapAjaxSpiderClickDefaultElems: bool,
  zapAjaxSpiderClickElemsOnce: bool,
  zapAjaxSpiderRandomInputs: bool,
  zapAjaxSpiderLogoutAvoidance: bool,
  zapAjaxSpiderScopeCheck: str,
  zapAjaxSpiderCustomHeaders: strArr,
  zapAjaxSpiderExcludePatterns: strArr,
  zapAjaxSpiderMaxUrls: int,
  zapAjaxSpiderParallelism: int,

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
  jsluiceVerifyUrls: bool,
  jsluiceVerifyDockerImage: str,
  jsluiceVerifyTimeout: int,
  jsluiceVerifyRateLimit: int,
  jsluiceVerifyThreads: int,
  jsluiceVerifyAcceptStatus: intArr,
  jsluiceExcludePatterns: strArr,

  // -- Supply Chain (malicious / vulnerable dependencies) --
  supplyChainReconEnabled: bool,
  supplyChainReconEcosystems: str,
  supplyChainReconDeepAnalysisEnabled: bool,

  // -- JS Analysis: JS Recon --
  jsReconEnabled: bool,
  jsReconMaxFiles: int,
  jsReconTimeout: int,
  jsReconConcurrency: int,
  jsReconValidateKeys: bool,
  jsReconValidationTimeout: int,
  jsReconExtractEndpoints: bool,
  jsReconValidateEndpoints: bool,
  jsReconEndpointAcceptStatus: intArr,
  jsReconEndpointCustomHeaders: strArr,
  jsReconEndpointConcurrency: int,
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
  jsReconAiSdkDetectionEnabled: bool,

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
  ffufAiExtensions: bool,

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
  nucleiAiTags: bool,
  nucleiAiResponseFilter: bool,

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
  takeoverAiClassifier: bool,
  baddnsEnabled: bool,
  baddnsDockerImage: str,
  baddnsModules: strArr,
  baddnsNameservers: strArr,
  baddnsRunTimeout: int,

  // -- VHost & SNI Enumeration --
  vhostSniEnabled: bool,
  vhostSniTimeout: int,
  vhostSniConcurrency: int,
  vhostSniBaselineSizeTolerance: int,
  vhostSniTestL7: bool,
  vhostSniTestL4: bool,
  vhostSniInjectDiscovered: bool,
  vhostSniUseDefaultWordlist: bool,
  vhostSniUseGraphCandidates: bool,
  vhostSniMaxCandidatesPerIp: int,
  vhostSniCustomWordlist: str,

  webCachePoisonEnabled: bool,
  webCachePoisonDockerImage: str,
  webCachePoisonScanProfile: str,
  webCachePoisonTimeout: int,
  webCachePoisonTimeoutPerReq: int,
  webCachePoisonConcurrency: int,
  webCachePoisonConfirmWorkers: int,
  webCachePoisonMaxRpsPerHost: float,
  webCachePoisonMinConfidence: float,
  webCachePoisonAllowFrameworkPacks: bool,
  webCachePoisonAllowDeception: bool,
  webCachePoisonAllowCpdos: bool,
  webCachePoisonCrossVantage: bool,
  webCachePoisonCacheHeader: str,
  webCachePoisonCacheBusterParam: str,
  webCachePoisonVerifySsl: bool,
  webCachePoisonBehavioralOracle: bool,
  webCachePoisonBehavioralDelay: float,
  webCachePoisonDifferential: bool,

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
  wafAiClassifier: bool,
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

  // -- Origin-IP Discovery (CDN/WAF unmasking) --
  originDiscoveryEnabled: bool,
  originDiscoveryKeyless: bool,
  originDiscoveryScanners: bool,
  originDiscoveryPassiveDns: bool,
  originDiscoveryMaxCandidates: int,
  originDiscoveryMaxSearchCalls: int,
  originDiscoveryThreshold: int,
  originDiscoveryTimeout: int,
  originDiscoveryWorkers: int,

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
- aiInPipeline: boolean - Master toggle that enables AI-powered enhancements across all recon modules that support them. Cascades on/off to per-tool AI flags (ffufAiExtensions, nucleiAiTags, wafAiClassifier, nucleiAiResponseFilter, takeoverAiClassifier).
- aiPipelineModel: string - Model identifier for the AI hooks in recon (e.g. "claude-opus-4-6", "claude-haiku-4-5-20251001"). Independent of agentOpenaiModel.
- updateGraphDb: boolean - Store results in the graph database
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
- domainReconAiTxtHintEnabled: boolean - Regex TXT/SPF/DKIM/DMARC records for AI vendor domains (anthropic.com, openai.com, huggingface.co, replicate.com, langchain.com, langfuse.com, …) and set Subdomain.ai_service_hint
- domainReconAiNsHintEnabled: boolean - Tag Subdomain.ai_service_hint="ai-hosting-candidate" when NS records point at AI-friendly hosts (Vercel, Netlify, Replit, Modal, HuggingFace Spaces). Weak signal; never overrides a TXT hint.
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
- portScanAiPortCatalogEnabled: boolean - Annotate AI-bearing ports (Ollama 11434, Qdrant 6333, Open WebUI 8080, vLLM, LiteLLM, Triton, Milvus, …) on naabu output and MERGE Technology(category=ai-*) nodes

## Port Scanning - Masscan
- masscanEnabled: boolean - Run Masscan
- masscanTopPorts: string
- masscanCustomPorts: string
- masscanRate: integer - Packets per second
- masscanBanners: boolean - Grab banners
- masscanWait: integer - Wait time in seconds
- masscanRetries: integer
- masscanExcludeTargets: string - Comma-separated targets to exclude
- masscanAiPortCatalogEnabled: boolean - Same AI port catalogue applied to masscan output (uses the same catalogue as portScanAiPortCatalogEnabled)

## Port Scanning - Nmap
- nmapEnabled: boolean - Run Nmap service detection
- nmapVersionDetection: boolean - Detect service versions
- nmapScriptScan: boolean - Run NSE vuln scripts
- nmapTimingTemplate: string - "T0" to "T5"
- nmapTimeout: integer - Timeout in seconds
- nmapHostTimeout: integer - Per-host timeout in seconds
- nmapParallelism: integer - IPs scanned concurrently by Nmap
- nmapAiVersionRegexEnabled: boolean - Regex nmap product/version strings against AI runtimes (Ollama, vLLM, LiteLLM, TGI, Triton, llama.cpp) and set Service.ai_runtime_version

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
- httpProbeAiHeaderScanEnabled: boolean - Regex captured response headers for AI runtime/framework/proxy/SDK-client markers (x-vllm-*, anthropic-ratelimit-*, x-langchain-*, x-litellm-*, cf-aig-*, x-mcp-*, …) and set BaseURL.is_ai_framework_detected / ai_framework_name
- httpProbeAiFaviconHashEnabled: boolean - Match captured favicon MMH3 hash against the AI frontend catalogue (Open WebUI, LibreChat, Flowise, Dify, Gradio, Streamlit, ComfyUI, …) and set BaseURL.ai_frontend_product_guess
- httpProbeAiTitleDetectionEnabled: boolean - Regex page title against AI frontend products; fills BaseURL.ai_frontend_product_guess when favicon hash is unknown
- httpProbeAiWappalyzerEnabled: boolean - Local Wappalyzer fingerprint additions for AI frameworks (LangChain JS marker, vLLM cookie, TGI route, …); rides existing Wappalyzer pass

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

## Resource Enum AI Classifier
- resourceEnumAiClassifierEnabled: boolean - Master toggle for the cross-cutting AI endpoint + parameter classifier that runs after the URL discovery tools (Katana, Hakrawler, GAU, FFuf, ParamSpider, Arjun, Kiterunner, jsluice). Pure regex, no extra traffic.
- resourceEnumAiPathClassifierEnabled: boolean - Stamp Endpoint.ai_interface_type by matching path against the LLM/completion/embedding/tool-call/SSE/MCP/GraphQL catalogue (OpenAI /v1/chat/completions, Anthropic /v1/messages, Ollama /api/chat, Gemini :generateContent, MCP /mcp, LangServe /stream, etc.)
- resourceEnumAiRagPathFlagEnabled: boolean - Stamp Endpoint.is_ai_rag_ingest=true for known RAG paths (OpenAI Vector Stores, Pinecone /vectors/upsert, Weaviate /v1/objects, Qdrant /collections/.../points). Ambiguous paths (/upload, /search, /query) only fire when parent BaseURL is AI-tagged.
- resourceEnumAiParamInjectableFlagEnabled: boolean - Stamp Parameter.is_ai_prompt_injectable=true on AI-classified endpoints when the parameter name matches the prompt-injection catalogue (prompt, messages, system, contents, inputs, arguments, etc.)
- resourceEnumAiToolArgPathEnabled: boolean - Reserved for the future ai_surface_recon central module - resolves Parameter.ai_tool_arg_path against discovered OpenAPI / ai-plugin.json / MCP tools/list specs. No-op today.

## AI Surface Recon (central module, ACTIVE)
- aiSurfaceReconEnabled: boolean - Master toggle. Active protocol-aware AI/LLM/MCP fingerprinting that runs after resource_enum. Benign shape-probes only (1-token chat ping, MCP handshake, read-only GETs) against hosts already showing an AI signal.
- aiSurfaceReconTimeout: number - Per-probe HTTP timeout in seconds (default 10).
- aiSurfaceReconMaxWorkers: number - Per-host probe concurrency (default 5; stealth halves to 2).
- aiSurfaceReconUserAgent: string - User-Agent sent on every probe.
- aiSurfaceReconChatShapeProbeEnabled: boolean - POST a 1-token ping to candidate chat paths and classify the response shape; confirms Endpoint.ai_interface_type + streaming.
- aiSurfaceReconMcpHandshakeEnabled: boolean - Run the MCP initialize handshake (Streamable HTTP + legacy SSE); capture server/version/protocol/capabilities/auth.
- aiSurfaceReconMcpListToolsEnabled: boolean - Enumerate MCP tools/resources/prompts; create a Parameter per tool arg. Off in stealth.
- aiSurfaceReconMcpYaraEnabled: boolean - Static YARA scan of MCP tool descriptions/schemas/instructions for tool poisoning / prompt injection / exfiltration; writes Vulnerability nodes.
- aiSurfaceReconOpenapiDiscoveryEnabled: boolean - Fetch + parse openapi.json / ai-plugin.json to extract tool schemas and capability flags; sets ai_tool_schema_ref, ai_supports_tools/vision/streaming, ai_tool_arg_path.
- aiSurfaceReconModelListEnabled: boolean - Read /v1/models and /api/tags to guess the model family (gpt/claude/llama/...). Sets Endpoint.ai_model_family_guess.
- aiSurfaceReconVectorDbReadEnabled: boolean - One benign read to candidate vector-DB ports (Chroma/Qdrant/Weaviate/Milvus) to confirm Technology(category=ai-vector-db). Off in stealth.
- aiSurfaceReconJuliusProbePackEnabled: boolean - Run the vendored Julius HTTP fingerprint packs to identify AI service software and promote a Technology node.
- aiSurfaceReconLatencyBaselineEnabled: boolean - Record p50 latency of the chat ping on each LLM endpoint (Endpoint.ai_latency_p50_ms).
- aiSurfaceReconCacheEnabled: boolean - Cache probe responses on disk so repeat scans skip already-tested payloads.
- aiSurfaceReconProbePackVersion: string - Pinned probe-pack identifier recorded on every annotation (default "latest").

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

## OpenAPI Ingestion
- openapiEnabled: boolean - Import supported in-scope operations from OpenAPI documents
- openapiAutoDiscover: boolean - Discover documents from crawl results and bounded common paths
- openapiDiscoveryPaths: string[] - Origin-relative documentation paths to probe; an empty list disables common-path probes
- openapiTimeout: integer - Per-document fetch timeout in seconds (1-60)
- openapiMaxDocuments: integer - Maximum specification documents to import (1-200)
Source URLs and fetch headers are project-specific and may contain credentials, so they must never appear in generated presets.

## Web Crawling - ZAP Ajax Spider
- zapAjaxSpiderEnabled: boolean - Enable browser-driven Ajax Spider crawling for modern SPAs and authenticated apps
- zapAjaxSpiderDockerImage: string - Docker image used for the ZAP Ajax Spider runner
- zapAjaxSpiderSeedMode: string - "base_urls" or "base_urls_and_endpoints" seed selection
- zapAjaxSpiderMaxDuration: integer - Max Ajax Spider duration per seed in minutes
- zapAjaxSpiderMaxCrawlDepth: integer - Max crawl depth per seed
- zapAjaxSpiderMaxCrawlStates: integer - Max crawl states, or 0 for unlimited
- zapAjaxSpiderNumberOfBrowsers: integer - Browser instances used by Ajax Spider
- zapAjaxSpiderBrowserId: string - ZAP browser id, such as "firefox-headless"
- zapAjaxSpiderEventWait: integer - Event wait time in milliseconds
- zapAjaxSpiderReloadWait: integer - Reload wait time in milliseconds
- zapAjaxSpiderClickDefaultElems: boolean - Click default clickable elements
- zapAjaxSpiderClickElemsOnce: boolean - Click each element only once
- zapAjaxSpiderRandomInputs: boolean - Fill inputs with random values
- zapAjaxSpiderLogoutAvoidance: boolean - Avoid actions likely to log out
- zapAjaxSpiderScopeCheck: string - Ajax Spider scope check mode
- zapAjaxSpiderCustomHeaders: string[] - Header/cookie lines for authenticated crawling
- zapAjaxSpiderExcludePatterns: string[] - Regex patterns to exclude from Ajax crawling
- zapAjaxSpiderMaxUrls: integer - Max in-scope URLs to ingest
- zapAjaxSpiderParallelism: integer - Seeds crawled simultaneously

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
- jsluiceVerifyUrls: boolean - After extraction, run extracted URLs through httpx and a deny-list filter so only live, non-asset URLs reach the graph. Disable to keep all extracted URLs (legacy behavior).
- jsluiceVerifyDockerImage: string - httpx Docker image used for verification
- jsluiceVerifyTimeout: integer - Per-request httpx timeout in seconds
- jsluiceVerifyRateLimit: integer - Max probe requests per second
- jsluiceVerifyThreads: integer - httpx worker threads
- jsluiceVerifyAcceptStatus: integer[] - HTTP status codes treated as "live" by the verifier
- jsluiceExcludePatterns: string[] - Deny-list patterns. Extensions like ".js" match the path suffix only; everything else is a substring match against the URL path and query.

## Supply Chain (malicious / vulnerable dependencies)
- supplyChainReconEnabled: boolean - Harvest the package set the live target serves (source maps, imports, detected technologies) and verdict it against the OFFLINE OSV database. Writes Package / MalPackageFinding nodes. Fully passive and offline: it re-uses data JS Recon already downloaded and sends NO extra traffic to the target, so it is safe even in stealth/passive presets. Best paired with jsReconEnabled + jsReconSourceMaps (source-map mining is the richest source); without JS Recon it still maps detected technologies to packages.
- supplyChainReconEcosystems: string - Comma-separated OSV ecosystems to report (default "npm"). Matched EXACTLY against the harvested package ecosystem, so use these names verbatim, case included: npm, PyPI, Go, Maven, crates.io, Packagist, RubyGems, NuGet. Empty string means no filter (report every ecosystem)
- supplyChainReconDeepAnalysisEnabled: boolean - GuardDog behavioural analysis of flagged packages. Downloads untrusted tarballs, so keep false unless explicitly requested

## JavaScript Analysis - JS Recon (deep)
- jsReconEnabled: boolean - Run deep JS analysis
- jsReconMaxFiles: integer
- jsReconTimeout: integer - Seconds
- jsReconConcurrency: integer
- jsReconValidateKeys: boolean - Validate discovered API keys
- jsReconValidationTimeout: integer
- jsReconExtractEndpoints: boolean
- jsReconValidateEndpoints: boolean - Probe extracted endpoints and drop confirmed-dead ones before graph ingestion (default off)
- jsReconEndpointAcceptStatus: integer[] - HTTP status codes treated as live during endpoint verification
- jsReconEndpointCustomHeaders: string[] - Header lines used when verifying extracted endpoints
- jsReconEndpointConcurrency: integer - Parallel endpoint validation probes (default 10)
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
- jsReconAiSdkDetectionEnabled: boolean - Adversarial AI Phase 6. Scan every harvested JS bundle for AI/LLM SDK imports (OpenAI, Anthropic, Gemini, LangChain, LlamaIndex, Vercel AI SDK, MCP, vector DBs), hard-coded provider keys (sk-, sk-ant-, hf_, lsv2_, gsk_, r8_, …), dangerouslyAllowBrowser opt-in, and AI-frontend product markers in async-loaded chunks the http_probe Wappalyzer pass cannot see. Writes JsReconFinding nodes with finding_type ai-sdk-client / ai-sdk-key-literal / ai-sdk-browser-allowed / ai-frontend-detected / ai-provider-url and enriches matching Secret nodes with ai_provider. Default true.

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
- ffufAiExtensions: boolean - When true, FFuf file extensions are picked per-target by AI from response headers (requires aiInPipeline=true). The static ffufExtensions list is ignored.

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
- nucleiAiTags: boolean - Use AI to prune the Nuclei tag list based on detected tech stack (requires aiInPipeline=true). Replaces the static nucleiTags list with a tech-aware subset chosen by the LLM at scan time. Default false.
- nucleiAiResponseFilter: boolean - Use AI to classify Nuclei response bodies as WAF/rate-limit block pages when the static keyword list misses (requires aiInPipeline=true). Augments is_false_positive(); kicks in only on suspicious status codes (403/406/418/429/503) so cost stays bounded. Default false.

## Subdomain Takeover (Subjack + Nuclei takeover templates)
- subdomainTakeoverEnabled: boolean - Master switch for the layered takeover scanner (default false)
- subjackEnabled: boolean - Run Subjack (DNS-first, Apache-2.0 Go binary). Default true.
- subjackThreads: integer - Subjack concurrent threads (default 10)
- subjackTimeout: integer - Subjack per-request timeout in seconds (default 30)
- subjackSsl: boolean - Force HTTPS probing for higher accuracy (default true)
- subjackAll: boolean - Test every URL, not just identified CNAMEs - slower (default false)
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
- takeoverAiClassifier: boolean - Use AI to disambiguate takeover findings from WAF "no host" block pages that match the same static fingerprint (requires aiInPipeline=true). For each finding the scanner probes the host, short-circuits on third-party vendor tokens, and otherwise asks the LLM to classify the body. AI-flagged collisions get score -40 (lands in manual_review). Default false.
- baddnsEnabled: boolean - Run the BadDNS sidecar (AGPL-3.0, isolated Docker container). Requires "docker compose --profile tools build baddns-scanner". Default false.
- baddnsDockerImage: string - BadDNS image name. Default "redamon-baddns:latest" (built locally from baddns_scan/Dockerfile)
- baddnsModules: string[] - Subset of BadDNS modules to run. Valid: cname, ns, mx, txt, spf, dmarc, wildcard, nsec, references, zonetransfer. (MTA-STS exists in baddns 2.1.0 but is not CLI-addressable due to an upstream validator regex bug -- omit.) Default: ["cname","ns","mx","txt","spf"]
- baddnsNameservers: string[] - Optional custom DNS resolvers (e.g. ["1.1.1.1","8.8.8.8"]). Empty = system resolvers.
- baddnsRunTimeout: integer - Hard wall clock for the BadDNS pass in seconds. Default 1800.

## VHost & SNI Enumeration (curl-based hidden virtual host discovery)
- vhostSniEnabled: boolean - Master switch. Tests every (subdomain, IP, port) for hidden virtual hosts via L7 (HTTP Host header trick) and L4 (TLS SNI trick). Active scan, sends extra traffic to each target IP. Default false.
- vhostSniTimeout: integer - curl --connect-timeout per request in seconds (total budget per request is 3x). Default 3.
- vhostSniConcurrency: integer - Parallel curl probes per IP/port. Higher = faster, louder. Default 20.
- vhostSniBaselineSizeTolerance: integer - Body size deltas within this many bytes are not flagged (suppresses Set-Cookie / timestamp jitter). Default 50.
- vhostSniTestL7: boolean - Run the HTTP Host header trick (catches classic Apache/Nginx vhosts). Default true.
- vhostSniTestL4: boolean - Run the TLS SNI trick via curl --resolve (catches modern reverse proxies, k8s ingress, Cloudflare). Default true.
- vhostSniInjectDiscovered: boolean - When a hidden vhost is confirmed, create a BaseURL node so a follow-up partial recon (Katana, Nuclei) can scan it. Default true.
- vhostSniUseDefaultWordlist: boolean - Use the bundled vhost-common.txt wordlist (~2,300 admin/dev/staging/internal/modern-stack prefixes, expanded as {prefix}.{target_apex}). Default true.
- vhostSniUseGraphCandidates: boolean - Pull hostnames from existing Subdomain, ExternalDomain, TLS SAN list, CNAME targets and reverse-DNS PTR records resolving to each target IP. Highest signal source. Default true.
- vhostSniMaxCandidatesPerIp: integer - Hard cap on candidates per IP to bound run time. Default 2000.
- vhostSniCustomWordlist: string - Optional newline-separated custom prefixes/hostnames (per-project file/text). Bare prefixes expand as {prefix}.{target_apex}; full hostnames are used as-is. Default "".

## Web Cache Poisoning (WCVS breadth engine + native 5-phase confirmation)
- webCachePoisonEnabled: boolean - Master switch. Active scan: detects web cache poisoning + web cache deception on live BaseURLs/Endpoints. Sends header/param mutation probes plus repeated baseline/poison/clean fetches per URL. Default false.
- webCachePoisonDockerImage: string - Docker image for the WCVS breadth engine (Hackmanit Web Cache Vulnerability Scanner), built locally. Default "redamon-wcvs:latest".
- webCachePoisonScanProfile: string - "safe-confirm" (production, benign canaries, always isolated), "extended" (owned test targets), or "research" (lab only, enables CPDoS if allowed). Default "safe-confirm".
- webCachePoisonTimeout: integer - WCVS subprocess timeout in seconds. Default 1800.
- webCachePoisonTimeoutPerReq: integer - Native confirmation per-request timeout in seconds. Default 10.
- webCachePoisonConcurrency: integer - WCVS threads for the breadth sweep. Higher = faster, louder. Default 10.
- webCachePoisonConfirmWorkers: integer - Native confirmation parallel workers (how many URLs are tested concurrently; bounds in-flight requests). 1 = fully sequential/stealthiest, up to 16. Default 6.
- webCachePoisonMaxRpsPerHost: number - Requests/sec cap per host (0 = unlimited). Default 0.
- webCachePoisonMinConfidence: number - Only findings scoring at or above this (0-1) become Vulnerability nodes. 0.8 keeps Confirmed + Strong. Default 0.8.
- webCachePoisonAllowFrameworkPacks: boolean - Fire Next.js/Nuxt/Remix-specific vectors only when the tech fingerprint matches. Default true.
- webCachePoisonAllowDeception: boolean - Web cache deception (path-confusion .css tricks). Default true.
- webCachePoisonAllowCpdos: boolean - Cache-poisoned DoS tests (oversized/meta-char). Only honored in research profile. Default false.
- webCachePoisonCrossVantage: boolean - Re-confirm from a second network vantage (requires extra egress infra). Default false.
- webCachePoisonCacheHeader: string - Override the cache hit/miss header if the target uses a non-standard one. Default "".
- webCachePoisonCacheBusterParam: string - Query param name used to isolate every test into its own cache slot. Default "rdmncb".
- webCachePoisonVerifySsl: boolean - Verify TLS certificates during native confirmation. Default true.
- webCachePoisonBehavioralOracle: boolean - Detect *silent* caches (no cache-status headers, common with default Varnish/nginx or hardened CDNs) via a frozen-Date probe: fetch twice across a short delay; a frozen Date header + identical body implies a cache. Catches caches header detection alone would miss. Default true.
- webCachePoisonBehavioralDelay: number - Seconds to wait between the two frozen-Date probes. Larger = more reliable on slow origins, but adds latency per silent URL. Default 1.1.
- webCachePoisonDifferential: boolean - Non-reflective detection. Beyond looking for a benign canary echoed back, also flag a poison that changes the response *behaviour* (a persisted status code / Location redirect / body) with no echoed marker, guarded against false positives by requiring the affected response dimension to be stable across two clean baselines. Catches CPDoS-style status flips, scheme/redirect poisoning, and cache-key confusion. Adds one extra baseline request per vector. Default true.

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
- wafAiClassifier: boolean - Use AI to classify WAF/CDN presence from response headers/body/latency when the static check misses (requires aiInPipeline=true). Augments _has_cdn_markers and check_waf_bypass; AI-detected bypasses are tagged detection_method=ai_classifier. Default false.
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

## Origin-IP Discovery (CDN/WAF unmasking)
- originDiscoveryEnabled: boolean - Master switch; finds the real origin server behind a CDN/WAF. Active validation probes + passive source queries. Enable for bug-bounty/infra-mapping/red-team intents; leave off for passive-only or stealth presets.
- originDiscoveryKeyless: boolean - Non-CDN subdomains + SPF/MX + crt.sh (no key needed)
- originDiscoveryScanners: boolean - Favicon/cert pivots via Shodan/Censys/FOFA/ZoomEye/OTX/VirusTotal (each uses its own key)
- originDiscoveryPassiveDns: boolean - SecurityTrails + ViewDNS DNS history
- originDiscoveryMaxCandidates: integer - Cap on probed candidate IPs per fronted host
- originDiscoveryMaxSearchCalls: integer - Per-scan budget of keyed scanner-search calls
- originDiscoveryThreshold: integer - Weighted-similarity confidence (0-100) needed to confirm an origin
- originDiscoveryTimeout: integer - Per-probe HTTP timeout (seconds)
- originDiscoveryWorkers: integer - Parallel source + validation workers

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
