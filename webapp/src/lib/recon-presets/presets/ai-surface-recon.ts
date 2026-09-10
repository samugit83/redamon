import type { ReconPreset } from '../types'

export const AI_SURFACE_RECON: ReconPreset = {
  id: 'ai-surface-recon',
  name: 'AI / LLM Surface Recon',
  icon: '',
  image: '/preset-radar.svg',
  shortDescription: 'Full pipeline with every AI/LLM/MCP signal turned on, plus the active AI Surface Recon module at full coverage. Maps the entire AI attack surface.',
  fullDescription: `### Pipeline Goal
Discover and fingerprint every AI / LLM / MCP / vector-DB surface a target exposes. This preset runs the complete active recon pipeline AND flips on every AI-awareness hook across the modules, then runs the dedicated **AI Surface Recon** module (active chat-shape probing, MCP handshake + tool-poisoning analysis, OpenAPI/manifest parsing, model-family fingerprinting, Julius service detection, and vector-DB confirmation) at full coverage.

### Who is this for?
Red-teamers and AI-security engineers scoping the adversarial-AI attack surface (OWASP LLM Top 10 / MITRE ATLAS): chat endpoints, RAG ingestion, exposed MCP servers with poisoned tools, vector databases, AI runtimes (Ollama / vLLM / TGI / LiteLLM), AI frontends, and leaked provider keys.

### What it enables
- Full discovery + active port scan (Naabu + Masscan + Nmap -sV/NSE) with the **AI port catalogue** (Ollama 11434, Qdrant/Weaviate/Milvus/Chroma, vLLM, ...) and the **Nmap AI version regex**
- httpx with the **AI header / favicon / title / Wappalyzer** signature passes (LangChain, vLLM, LiteLLM, Open WebUI, LibreChat, Gradio, ...)
- Domain recon **AI TXT/NS hints** (replicate.com, huggingface.co, anthropic.com, ...)
- Full crawl (Katana + Hakrawler + GAU + ParamSpider + Kiterunner + Arjun + jsluice) with the **Endpoint AI Classifier** at full coverage: path classifier, RAG-path flag, prompt-injectable parameter flag, and tool-arg-path resolver
- JS Recon with **AI SDK detection** (openai / @anthropic-ai/sdk / langchain / dangerouslyAllowBrowser / hard-coded sk- keys)
- Nuclei + GraphQL + Subdomain Takeover (with **AI takeover classifier**) + VHost/SNI
- WAF detection with the **AI classifier**
- **AI Surface Recon (active), every workload on:** chat-shape probes, MCP handshake, MCP tools/list enumeration, MCP tool-poisoning YARA scan, OpenAPI/ai-plugin discovery, model-family guess, vector-DB confirmation read, Julius fingerprint pack, latency baseline, and response caching, with a generous per-probe timeout and concurrency

### What it disables
- Stealth mode (would turn off MCP tools/list and the vector-DB read and throttle probing, defeating the purpose)

### How it works
Every AI signal is a property annotation on existing graph nodes (Endpoint, Technology, Parameter, Service) plus Vulnerability nodes for MCP tool poisoning. Run a full scan, then open the graph or the report's AI Surface section to review the discovered AI attack surface. The AI Surface Recon node also supports partial recon, so you can re-probe the AI surfaces after updating the probe packs without re-crawling.`,
  targetProfile: 'domain',
  environment: 'external',
  parameters: {
    stealthMode: false,

    // --- Discovery ---
    subdomainDiscoveryEnabled: true,
    crtshEnabled: true,
    hackerTargetEnabled: true,
    knockpyReconEnabled: true,
    subfinderEnabled: true,
    amassEnabled: true,
    whoisEnabled: true,
    dnsEnabled: true,
    // AI: domain_recon hints
    domainReconAiTxtHintEnabled: true,
    domainReconAiNsHintEnabled: true,

    // --- Port scanning ---
    naabuEnabled: true,
    naabuPassiveMode: false,
    masscanEnabled: true,
    nmapEnabled: true,
    nmapVersionDetection: true,
    nmapScriptScan: true,
    // AI: port catalogues + nmap version regex
    portScanAiPortCatalogEnabled: true,
    masscanAiPortCatalogEnabled: true,
    nmapAiVersionRegexEnabled: true,

    // --- HTTP probing ---
    httpxEnabled: true,
    httpxProbeTechDetect: true,
    httpxProbeFavicon: true,
    httpxProbeTlsInfo: true,
    httpxIncludeResponse: true,
    wappalyzerEnabled: true,
    bannerGrabEnabled: true,
    // AI: http_probe signature passes
    httpProbeAiHeaderScanEnabled: true,
    httpProbeAiFaviconHashEnabled: true,
    httpProbeAiTitleDetectionEnabled: true,
    httpProbeAiWappalyzerEnabled: true,

    // --- Resource enumeration (crawlers) ---
    katanaEnabled: true,
    katanaJsCrawl: true,
    hakrawlerEnabled: true,
    gauEnabled: true,
    paramspiderEnabled: true,
    jsluiceEnabled: true,
    kiterunnerEnabled: true,
    arjunEnabled: true,
    ffufEnabled: true,
    // AI: Endpoint AI Classifier (full coverage)
    resourceEnumAiClassifierEnabled: true,
    resourceEnumAiPathClassifierEnabled: true,
    resourceEnumAiRagPathFlagEnabled: true,
    resourceEnumAiParamInjectableFlagEnabled: true,
    resourceEnumAiToolArgPathEnabled: true,

    // --- JS recon ---
    jsReconEnabled: true,
    jsReconAiSdkDetectionEnabled: true,

    // --- Vuln / security ---
    nucleiEnabled: true,
    graphqlSecurityEnabled: true,
    subdomainTakeoverEnabled: true,
    vhostSniEnabled: true,
    cveLookupEnabled: true,
    mitreEnabled: true,
    // AI classifiers on takeover + WAF (LLM-assisted)
    takeoverAiClassifier: true,
    wafAiClassifier: true,

    // --- AI Surface Recon (central module): FULL coverage ---
    aiSurfaceReconEnabled: true,
    aiSurfaceReconTimeout: 15,
    aiSurfaceReconMaxWorkers: 8,
    aiSurfaceReconUserAgent: 'RedAmon-AISurfaceRecon/1.0',
    aiSurfaceReconChatShapeProbeEnabled: true,
    aiSurfaceReconMcpHandshakeEnabled: true,
    aiSurfaceReconMcpListToolsEnabled: true,
    aiSurfaceReconMcpYaraEnabled: true,
    aiSurfaceReconOpenapiDiscoveryEnabled: true,
    aiSurfaceReconModelListEnabled: true,
    aiSurfaceReconVectorDbReadEnabled: true,
    aiSurfaceReconJuliusProbePackEnabled: true,
    aiSurfaceReconLatencyBaselineEnabled: true,
    aiSurfaceReconCacheEnabled: true,
    aiSurfaceReconProbePackVersion: 'latest',
  },
}
