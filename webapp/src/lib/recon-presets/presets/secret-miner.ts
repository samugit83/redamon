import type { ReconPreset } from '../types'

export const SECRET_MINER: ReconPreset = {
  id: 'secret-miner',
  name: 'JS Secret Miner',
  icon: 'FileCode2',
  image: '/preset-file-js.svg',
  shortDescription: 'Deep JS analysis pipeline. Maximize JS file discovery, extract secrets, endpoints, and source maps.',
  fullDescription: `### Pipeline Goal
Laser-focused JavaScript reconnaissance. This preset builds a minimal pipeline that discovers subdomains, probes HTTP, then crawls aggressively for JS files and analyzes them in depth.

### Who is this for?
Bug bounty hunters and pentesters targeting modern web applications built with React, Angular, Vue, or similar frameworks where business logic lives in the client-side JavaScript.

### What it enables
- JS Recon module (disabled by default) with all analysis features maxed out
- Katana with depth 3 and JS crawl enabled for discovering dynamically loaded scripts
- Hakrawler with depth 3 for complementary crawl coverage
- GAU enabled to pull historical JS files from Wayback Machine and other archives
- jsluice with 500 file limit and full secret/URL extraction
- JS Recon max files raised to 1000 for thorough analysis

### What it disables
- Port scanning (Naabu, Nmap, Masscan) - not needed, httpx falls back to common web ports
- Directory fuzzing (ffuf, Kiterunner) - noise for this use case
- Parameter discovery (Arjun, ParamSpider) - not relevant to JS hunting
- Vulnerability scanning (Nuclei) - removed from pipeline modules
- Security checks and MITRE enrichment - disabled to reduce noise
- OSINT enrichment - disabled for faster focused scans

### How it works
1. Subdomain discovery finds all subdomains
2. HTTP probing identifies live web servers (uses DNS fallback for port detection)
3. Katana + Hakrawler + GAU aggressively crawl for JS files
4. jsluice extracts secrets and URLs from discovered JS files
5. JS Recon runs deep analysis: source maps, dependency confusion, DOM sinks, framework detection, regex patterns, and key validation`,
  parameters: {
    // Pipeline modules: skip port_scan and vuln_scan
    scanModules: ['domain_discovery', 'http_probe', 'resource_enum', 'js_recon'],

    // JS Recon (the main feature - default is false)
    jsReconEnabled: true,
    jsReconMaxFiles: 1000,
    jsReconTimeout: 1800,
    jsReconConcurrency: 10,
    jsReconValidateKeys: true,
    jsReconValidationTimeout: 5,
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

    // Katana: deeper crawl for JS discovery
    katanaEnabled: true,
    katanaDepth: 3,
    katanaMaxUrls: 1000,
    katanaJsCrawl: true,

    // Hakrawler: complementary crawler
    hakrawlerEnabled: true,
    hakrawlerDepth: 3,
    hakrawlerIncludeSubs: true,

    // GAU: historical JS from Wayback (default is false)
    gauEnabled: true,

    // jsluice: increase limits for heavy JS analysis
    jsluiceEnabled: true,
    jsluiceMaxFiles: 500,
    jsluiceExtractSecrets: true,
    jsluiceExtractUrls: true,

    // Disable port scanning tools
    naabuEnabled: false,
    nmapEnabled: false,
    masscanEnabled: false,

    // Disable irrelevant resource enum tools
    ffufEnabled: false,
    kiterunnerEnabled: false,
    arjunEnabled: false,
    paramspiderEnabled: false,

    // --- GraphQL Security: JS-heavy crawl frequently surfaces /graphql endpoints in
    //     compiled SPA bundles (Apollo/urql/Relay configs). Enable introspection to
    //     extract the schema -- schemas commonly contain sensitive field names
    //     (password, apiKey, etc.) which is the preset's core mission. ---
    graphqlSecurityEnabled: true,
    graphqlIntrospectionTest: true,
    graphqlCopEnabled: true,
    // Info-leak + CSRF checks only (field suggestions, tracing, unhandled errors are
    // all secret-leaking). DoS probes off -- not the preset's focus.
    graphqlCopTestAliasOverloading: false,
    graphqlCopTestBatchQuery: false,
    graphqlCopTestDirectiveOverloading: false,
    graphqlCopTestCircularIntrospection: false,

    // Disable security/vuln modules via master switches
    cveLookupEnabled: false,
    securityCheckEnabled: false,
    nucleiEnabled: false,
    mitreEnabled: false,
    osintEnrichmentEnabled: false,
  },
}
