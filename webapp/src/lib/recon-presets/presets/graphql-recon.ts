import type { ReconPreset } from '../types'

export const GRAPHQL_RECON: ReconPreset = {
  id: 'graphql-recon',
  name: 'GraphQL Recon',
  icon: '',
  image: '/preset-graphql.svg',
  shortDescription: 'Laser-focused on GraphQL endpoints. Native scanner + graphql-cop (12 checks), JsRecon for JS-extracted endpoints, introspection + mutation + DoS probes.',
  fullDescription: `### Pipeline Goal
Find every GraphQL endpoint exposed by the target, extract its schema, and test it end-to-end for the full GraphQL-specific attack surface: introspection exposure, sensitive field disclosure, alias / batch / directive / circular DoS, GraphiQL IDE exposure, GET-method CSRF, field suggestion leaks, and unhandled error disclosure. Pairs the native RedAmon GraphQL scanner with graphql-cop's 12 external checks for defense-in-depth cross-validation.

### Who is this for?
Pentesters and security engineers whose target is a GraphQL API (standalone or embedded in a web/mobile backend). Apollo / Hasura / graphql-yoga / Ruby-graphql / Python-graphene / any framework where GraphQL is the primary attack surface. Works equally well for:
- Pure GraphQL APIs (one endpoint, rich schema)
- Hybrid apps with a GraphQL sub-path alongside REST
- SPAs that route all data through a single GraphQL gateway
- Mobile backends whose client code references graphql endpoints in JS bundles

Use \`API Security Audit\` if you also need heavy REST endpoint discovery via Kiterunner + Arjun. Use this preset when GraphQL specifically is the target.

### What it enables
- Passive subdomain discovery (crt.sh + Subfinder + Amass + HackerTarget + PureDNS) finds \`api.*\`, \`graphql.*\`, \`gql.*\`, \`v1.*\`, \`v2.*\`, \`playground.*\`, \`admin-api.*\`
- **Naabu port scan** scoped to ~50 API ports (80/443 + 3000-3005 + 4000-4005 + 5000-5013 + 8000-8010 + 8080-8090 + 8443 + 9000-9010) -- catches Apollo Server (4000), graphql-yoga (4000), Hasura (8080), Flask-GraphQL (5000), Spring Boot (8080), DVGA (5013)
- httpx with Content-Type + response capture to detect \`application/graphql\` endpoints
- Wappalyzer for Apollo / Hasura / graphql-yoga / Relay framework detection (feeds Nuclei tag targeting)
- Katana depth 3 with JS crawl + Hakrawler to crawl frontend code for embedded GraphQL URLs
- jsluice + **JS Recon** to extract GraphQL endpoint references from JavaScript bundles (critical for SPAs / modern frameworks)
- GAU + ParamSpider for historical URL discovery -- often reveals old \`/graphql\`, \`/graphiql\` paths. GAU verify + method detection + dead-endpoint filtering enabled so results are live POSTable endpoints
- Arjun to detect GraphQL-like parameters (\`query\`, \`mutation\`, \`variables\`, \`operationName\`)
- **Native GraphQL scanner**: introspection extraction, schema fingerprinting, sensitive-field detection, mutation + proxy-path testing -- full coverage, safe mode off
- **graphql-cop** (external 12-check scanner): field suggestions, GraphiQL detection, GET-method CSRF, trace/debug disclosure, alias / array-batching / directive / circular DoS probes, unhandled-error leakage, introspection cross-validation
- Nuclei with GraphQL + CSRF + injection tags (apollo, hasura, graphql, csrf, injection) for framework CVEs + GraphQL-specific CSRF/injection vectors
- **MITRE enrichment** maps Nuclei-found CVEs (e.g. Apollo SSRF CVE-2023-37478) to ATT&CK techniques + CAPEC patterns
- Minimal security checks (HTTPS / TLS / basic headers) to catch transport-layer issues

### What it disables
- Knockpy (brute-force subdomain discovery) -- standard GraphQL subdomain names are already in Subfinder/crt.sh indexes; Knockpy adds 2-5 min for marginal gain
- Masscan, Nmap -- Naabu's scoped API-port scan is sufficient
- Kiterunner & ffuf -- GraphQL paths are well-known patterns our scanner already probes (\`/graphql\`, \`/api/graphql\`, \`/v1/graphql\`, \`/query\`, \`/graphiql\`, \`/playground\`, etc.); brute-forcing is redundant and noisy
- OSINT enrichment (Shodan, Censys, FOFA, OTX, Netlas, VirusTotal, ZoomEye, CriminalIP) -- not relevant for GraphQL-specific work
- Banner grabbing -- port banners aren't GraphQL signals (Wappalyzer covers framework detection instead)
- CVE lookup -- Nuclei + graphql-cop report framework CVEs directly
- URLScan, Uncover -- subdomain discovery is already comprehensive

### How it works
1. Subdomain discovery surfaces GraphQL-subdomain patterns (\`api.*\`, \`graphql.*\`, \`gql.*\`, \`admin.*\`, \`internal-api.*\`)
2. httpx probes every discovered host, captures response headers + body; \`Content-Type: application/graphql\` or GraphQL-shaped JSON responses are immediate candidates
3. Katana + Hakrawler crawl the frontend, discovering URLs referenced in HTML/JS/source maps
4. JS Recon + jsluice parse JavaScript bundles -- modern SPAs typically reference \`/graphql\` endpoints via Apollo Client / urql / Relay configs embedded in compiled JS
5. GAU + ParamSpider pull historical URLs from Wayback Machine -- catches \`/graphql\` paths from old deploys
6. Arjun tests for parameter names matching GraphQL signatures (\`query\`, \`mutation\`, \`variables\`, \`operationName\`) on discovered endpoints
7. Native GraphQL scanner runs against every confirmed + candidate endpoint: introspection query, full schema extraction (capped at 10 MB), operation enumeration (up to 50 queries / 50 mutations / 50 subscriptions), sensitive-field keyword match, optional mutation + REST-proxy testing
8. graphql-cop runs 12 external checks against each endpoint; findings dedupe against the native scanner via deterministic MERGE ids (same \`vulnerability_type\` on the same endpoint collapses to one Vulnerability node)
9. Nuclei runs with \`graphql\`, \`apollo\`, \`hasura\` tags to catch framework CVEs

### Expected findings (severity class)
- **Critical/High**: Alias overloading, array-based query batching, directive overloading, circular introspection DoS, sensitive-field exposure
- **Medium**: GET-method CSRF, POST url-encoded CSRF, GET-based mutations, graphql introspection enabled (in production)
- **Low/Info**: GraphiQL IDE exposed, field suggestions enabled, trace/debug mode, unhandled-error disclosure`,
  parameters: {
    // Modules: 5 phases. port_scan included to discover non-standard API ports
    // (Apollo=4000, graphql-yoga=4000, Hasura=8080, Flask=5000, dev=3000/5013/etc.)
    scanModules: ['domain_discovery', 'port_scan', 'http_probe', 'resource_enum', 'vuln_scan'],

    stealthMode: false,
    useTorForRecon: false,

    // --- Subdomain Discovery: passive tools only (crt.sh, Subfinder, Amass passive,
    //     HackerTarget already catch api.*, graphql.*, gql.* patterns). Knockpy
    //     disabled: brute-force adds 2-5 min for marginal gain on standard names. ---
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

    // --- Naabu: scoped to common API/GraphQL ports (fast, targeted) ---
    // Apollo Server, graphql-yoga, Hasura, Spring Boot, Flask-GraphQL, Strawberry,
    // Node dev, DVGA (5013), and common alt-HTTPS ports. ~50 ports, <30s per host.
    naabuEnabled: true,
    naabuScanType: 's',                  // SYN scan (fastest)
    naabuRateLimit: 500,
    naabuThreads: 25,
    naabuTimeout: 5000,
    naabuRetries: 1,
    naabuCustomPorts: '80,443,3000-3005,4000-4005,5000-5013,8000-8010,8080-8090,8443,9000-9010',
    naabuTopPorts: '',                   // Suppress top-N; use explicit list above
    naabuSkipHostDiscovery: true,
    naabuVerifyPorts: true,
    // Masscan & Nmap stay off (overkill for this scope)
    masscanEnabled: false,
    nmapEnabled: false,

    // --- httpx: aggressive tech + response capture for GraphQL detection ---
    httpxEnabled: true,
    httpxThreads: 50,
    httpxTimeout: 15,
    httpxRetries: 2,
    httpxRateLimit: 75,
    httpxFollowRedirects: true,
    httpxMaxRedirects: 10,
    httpxProbeStatusCode: true,
    httpxProbeContentLength: true,
    httpxProbeContentType: true,     // critical for detecting application/graphql
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
    httpxProbeCdn: false,
    httpxIncludeResponse: true,
    httpxIncludeResponseHeaders: true,

    // --- Wappalyzer: detects Apollo / Hasura / graphql-yoga / Relay frameworks --
    //     improves Nuclei tag targeting + decorates the graph with Technology nodes
    //     for easier Cypher querying (MATCH (t:Technology) WHERE t.name CONTAINS 'Apollo'). ---
    wappalyzerEnabled: true,
    wappalyzerMinConfidence: 50,
    // Banner grabbing stays off -- port banners aren't GraphQL signals
    bannerGrabEnabled: false,

    // --- Katana: deep crawl (GraphQL endpoints are often referenced deep in JS) ---
    katanaEnabled: true,
    katanaDepth: 3,
    katanaMaxUrls: 800,
    katanaRateLimit: 75,
    katanaTimeout: 2400,
    katanaJsCrawl: true,

    // --- Hakrawler: secondary crawler for corroboration ---
    hakrawlerEnabled: true,
    hakrawlerDepth: 2,
    hakrawlerThreads: 10,

    // --- GAU: historical URLs (catch old /graphql paths from deploys) ---
    gauEnabled: true,
    gauThreads: 5,
    gauProviders: ['wayback', 'commoncrawl', 'otx'],
    gauVerifyUrls: true,             // Filter dead historical URLs via httpx probe
    gauDetectMethods: true,          // GraphQL is POST-heavy; method detection matters
    gauFilterDeadEndpoints: true,    // Drop 404/410/500 historical noise

    // --- ParamSpider: historical parameter patterns ---
    paramspiderEnabled: true,
    paramspiderWorkers: 5,

    // --- jsluice: extract GraphQL URLs + API secrets from JS ---
    jsluiceEnabled: true,
    jsluiceMaxFiles: 300,
    jsluiceExtractSecrets: true,
    jsluiceExtractUrls: true,
    jsluiceConcurrency: 5,

    // --- JS Recon: CRITICAL for modern GraphQL SPAs (Apollo/urql/Relay configs) ---
    jsReconEnabled: true,
    jsReconMaxFiles: 500,
    jsReconTimeout: 900,
    jsReconConcurrency: 10,
    jsReconExtractEndpoints: true,   // extracts /graphql paths from compiled JS
    jsReconRegexPatterns: true,
    jsReconSourceMaps: true,         // exposed source maps may include full schema
    jsReconDependencyCheck: true,
    jsReconDomSinks: false,          // not GraphQL-relevant
    jsReconFrameworkDetect: true,    // Apollo/Relay/urql detection
    jsReconDevComments: true,
    jsReconIncludeChunks: true,
    jsReconIncludeFrameworkJs: true,
    jsReconMinConfidence: 'low',

    // --- DISABLE Kiterunner (GraphQL paths are known patterns, not fuzzable) ---
    kiterunnerEnabled: false,

    // --- DISABLE ffuf (same reason -- our scanner already probes 12 common GraphQL paths) ---
    ffufEnabled: false,

    // --- Arjun: find endpoints accepting GraphQL-like parameters ---
    arjunEnabled: true,
    arjunThreads: 5,
    arjunTimeout: 15,
    arjunScanTimeout: 600,
    arjunMethods: ['POST', 'GET'],  // GraphQL is predominantly POST; GET for CSRF testing
    arjunMaxEndpoints: 100,
    arjunChunkSize: 500,
    arjunPassive: false,

    // --- Nuclei: GraphQL + framework-specific tags + csrf + injection
    //     (Apollo / Hasura / graphql-yoga CVEs, CSRF vectors, GraphQL injection) ---
    nucleiEnabled: true,
    nucleiSeverity: ['critical', 'high', 'medium', 'low'],
    nucleiTags: ['graphql', 'apollo', 'hasura', 'exposure', 'csrf', 'injection'],
    nucleiRateLimit: 100,
    nucleiBulkSize: 25,
    nucleiConcurrency: 25,
    nucleiTimeout: 10,
    nucleiRetries: 2,
    nucleiDastMode: true,
    nucleiAutoUpdateTemplates: true,
    nucleiFollowRedirects: true,
    nucleiMaxRedirects: 10,
    nucleiScanAllIps: false,
    nucleiInteractsh: true,

    // --- Native GraphQL Security Scanner: FULL COVERAGE ---
    graphqlSecurityEnabled: true,
    graphqlIntrospectionTest: true,
    graphqlTimeout: 45,
    graphqlRateLimit: 10,
    graphqlConcurrency: 5,
    graphqlDepthLimit: 15,
    graphqlRetryCount: 3,
    graphqlVerifySsl: true,

    // --- graphql-cop: ALL 12 CHECKS (including DoS probes) for cross-validation ---
    graphqlCopEnabled: true,
    graphqlCopTimeout: 150,
    graphqlCopForceScan: false,
    graphqlCopDebug: false,
    graphqlCopTestFieldSuggestions: true,
    graphqlCopTestIntrospection: true,       // ENABLED here for native/cop cross-validation
    graphqlCopTestGraphiql: true,
    graphqlCopTestGetMethod: true,
    graphqlCopTestGetMutation: true,
    graphqlCopTestPostCsrf: true,
    graphqlCopTestTraceMode: true,
    graphqlCopTestUnhandledError: true,
    // DoS probes: ON (this is a focused GraphQL assessment, not a general scan)
    graphqlCopTestAliasOverloading: true,
    graphqlCopTestBatchQuery: true,
    graphqlCopTestDirectiveOverloading: true,
    graphqlCopTestCircularIntrospection: true,

    // --- Security checks: minimal (transport-layer only) ---
    securityCheckEnabled: true,
    securityCheckTlsExpiringSoon: true,
    securityCheckLoginNoHttps: true,
    securityCheckSessionNoSecure: true,
    securityCheckBasicAuthNoTls: true,
    // Not GraphQL-relevant:
    securityCheckDirectIpHttp: false,
    securityCheckIpApiExposed: false,
    securityCheckWafBypass: false,

    // --- DISABLE CVE lookup (Nuclei + graphql-cop surface CVEs directly) ---
    cveLookupEnabled: false,

    // --- MITRE: ENABLE to map Nuclei-found CVEs (e.g. Apollo CVE-2023-37478) to
    //     ATT&CK techniques + CAPEC patterns. Offline DB lookup, negligible cost. ---
    mitreEnabled: true,
    mitreAutoUpdateDb: true,
    mitreIncludeCwe: true,
    mitreIncludeCapec: true,
    mitreEnrichRecon: true,

    // --- DISABLE all OSINT (not GraphQL-relevant) ---
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
