import type { ReconPreset } from '../types'

export const SUPPLY_CHAIN_AUDIT: ReconPreset = {
  id: 'supply-chain-audit',
  name: 'Supply Chain Audit',
  icon: '',
  image: '/preset-spider.svg',
  shortDescription: 'Laser-focused on malicious and vulnerable dependencies. Black-box harvest of the package set the target actually serves (source maps, imports, detected technologies), verdicted against the OFFLINE OSV database. No manifest needed, no extra traffic.',
  fullDescription: `### Pipeline Goal
Answer one question: **is the target shipping a malicious or known-vulnerable dependency?** The pipeline crawls the app, downloads its JavaScript, and infers the package set from what the live target leaks - source maps (\`node_modules/<pkg>\` paths), module imports, and the technology stack detected during HTTP probing. That set is turned into a CycloneDX SBOM and checked against a **local copy of the OSV database**, producing \`Package\` and \`MalPackageFinding\` nodes in the graph.

### Why it is safe to run
The verdict step is **fully offline** - it reads a local OSV database volume and makes zero network calls, so a client's dependency list is never sent to a third-party API. The harvest itself sends **no additional traffic to the target**: it re-uses the JavaScript and source maps JS Recon already downloaded. GuardDog behavioural analysis (which would download package tarballs) stays **off** by default.

### Who is this for?
- Anyone auditing a web app for **supply-chain risk** without access to its repository or manifests
- Pentesters who need dependency evidence (\`MAL-\` typosquats, vulnerable library versions) alongside the usual findings
- Teams checking exposure to a **newly published malicious package** across their externally-visible apps

### Prerequisite
The offline OSV database must be populated once on the host:

\`\`\`bash
./redamon.sh supply-chain-sync npm     # add PyPI, Go, ... as needed
\`\`\`

Without it the scan reports a clear error instead of a misleading clean result. After that, the feed auto-refreshes when it is older than 24h.

### What it enables
Discovery -> HTTP probing (technology detection) -> crawling (Katana + Hakrawler + GAU) -> **JS Recon with source maps** (the richest package-name source) -> **Supply Chain Recon** (harvest + offline OSV verdict). The JS Recon dependency-confusion check stays on because it complements the OSV verdict.

### What it disables
Port scanning (Naabu / Nmap / Masscan), directory and API fuzzing (FFuf / Kiterunner), parameter discovery (Arjun / ParamSpider), active vulnerability scanning (Nuclei), GraphQL testing, subdomain takeover, VHost/SNI, web cache poisoning, AI surface recon, OSINT enrichment, and brute force. Secret-oriented JS Recon sub-checks (regex patterns, key validation, DOM sinks, dev comments) are also off - this preset is about dependencies, not the network surface or secrets.

Use \`Full Pipeline - Maximum\` if you want supply-chain findings as one signal among many; use this preset when dependency risk is the objective.

### Interpreting the results
- **\`MAL-\` verdict = malicious**: the dependency itself is malware (typically a typosquat). Treat as critical.
- **CVE / GHSA**: a known-vulnerable version - normal vulnerability triage.
- A package with **no version** (harvested from a source-map path) is recorded for inventory but cannot be version-matched against an advisory.`,
  targetProfile: 'domain',
  environment: 'external',
  parameters: {
    scanModules: ['domain_discovery', 'http_probe', 'resource_enum', 'js_recon'],

    // -- The point of this preset --
    supplyChainReconEnabled: true,
    supplyChainReconEcosystems: 'npm',
    supplyChainReconDeepAnalysisEnabled: false,   // GuardDog downloads tarballs; opt-in only

    // -- JS Recon: the richest harvest source (source-map node_modules mining) --
    jsReconEnabled: true,
    jsReconMaxFiles: 1000,
    jsReconTimeout: 1800,
    jsReconConcurrency: 10,
    jsReconSourceMaps: true,          // primary input for package-name mining
    jsReconDependencyCheck: true,     // dependency-confusion signal, complements OSV
    jsReconFrameworkDetect: true,
    jsReconIncludeChunks: true,
    jsReconIncludeFrameworkJs: true,
    jsReconIncludeArchivedJs: true,
    jsReconRegexPatterns: false,      // not a secret hunt
    jsReconValidateKeys: false,
    jsReconExtractEndpoints: false,
    jsReconDomSinks: false,
    jsReconDevComments: false,
    jsReconMinConfidence: 'low',
    jsReconStandaloneCrawlDepth: 3,

    // -- Crawling: reach the JS bundles that carry the dependency evidence --
    katanaEnabled: true,
    katanaDepth: 3,
    katanaMaxUrls: 1000,
    katanaJsCrawl: true,
    hakrawlerEnabled: true,
    hakrawlerDepth: 3,
    hakrawlerIncludeSubs: true,
    gauEnabled: true,
    zapAjaxSpiderEnabled: false,
    jsluiceEnabled: false,

    // -- Everything not needed to answer the dependency question --
    naabuEnabled: false,
    nmapEnabled: false,
    masscanEnabled: false,
    ffufEnabled: false,
    kiterunnerEnabled: false,
    arjunEnabled: false,
    paramspiderEnabled: false,
    graphqlSecurityEnabled: false,
    nucleiEnabled: false,
    securityCheckEnabled: false,
    cveLookupEnabled: false,
    mitreEnabled: false,
    osintEnrichmentEnabled: false,
    subdomainTakeoverEnabled: false,
    vhostSniEnabled: false,
    webCachePoisonEnabled: false,
    aiSurfaceReconEnabled: false,
    useBruteforceForSubdomains: false,
    amassBrute: false,
  },
}
