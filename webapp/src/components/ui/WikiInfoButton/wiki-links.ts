// Centralized map of every webapp section/tool to its wiki page (and optional anchor).
// Wiki source lives at https://github.com/samugit83/redamon/wiki and locally at
// `redamon.wiki/`. Page filenames there map 1:1 to URLs (without the `.md`).

const WIKI_BASE = 'https://github.com/samugit83/redamon/wiki'

/** Build the full wiki URL for a given page (and optional GitHub-slug anchor). */
export function buildWikiUrl(page: string, anchor?: string): string {
  const base = `${WIKI_BASE}/${page}`
  return anchor ? `${base}#${anchor}` : base
}

// ---- Top-level pages ----------------------------------------------------------------

export const PAGE_WIKI: Record<string, { page: string; anchor?: string }> = {
  graph:        { page: 'Red-Zone' },
  insights:     { page: 'Insights-Dashboard' },
  projects:     { page: 'Creating-a-Project' },
  projectsNew:  { page: 'Creating-a-Project' },
  projectSettings: { page: 'Project-Settings-Reference' },
  reports:      { page: 'Pentest-Reports' },
  settings:     { page: 'Global-Settings' },
  settingsUsers:{ page: 'User-Management' },
  cypherfix:    { page: 'CypherFix-Automated-Remediation' },
  login:        { page: 'Getting-Started' },
}

// ---- Recon Pipeline tools ----------------------------------------------------------
// Keys mirror the WORKFLOW_TOOLS ids in webapp/src/components/projects/ProjectForm/WorkflowView/workflowDefinition.ts
// Anchors use GitHub's auto-generated slug (lowercased, spaces -> '-', stripped of punctuation).

export const TOOL_WIKI: Record<string, { page: string; anchor?: string }> = {
  // Discovery
  SubdomainDiscovery: { page: 'Project-Settings-Reference', anchor: 'subdomain-discovery' },
  Urlscan:            { page: 'Project-Settings-Reference', anchor: 'urlscanio-enrichment' },
  Uncover:            { page: 'Project-Settings-Reference', anchor: 'uncover-multi-engine-search' },

  // OSINT
  Shodan:             { page: 'Project-Settings-Reference', anchor: 'shodan-osint-enrichment' },
  OsintEnrichment:    { page: 'Project-Settings-Reference', anchor: 'threat-intelligence-enrichment-7-osint-tools' },

  // Port Scanning
  Naabu:              { page: 'Project-Settings-Reference', anchor: 'port-scanner-naabu' },
  Masscan:            { page: 'Project-Settings-Reference', anchor: 'port-scanner-masscan' },
  Nmap:               { page: 'Project-Settings-Reference', anchor: 'nmap-service-detection' },

  // HTTP Probing
  Httpx:              { page: 'Project-Settings-Reference', anchor: 'http-prober-httpx' },

  // Resource Enumeration
  Katana:             { page: 'Project-Settings-Reference', anchor: 'web-crawler-katana' },
  ZapAjaxSpider:      { page: 'Project-Settings-Reference', anchor: 'web-crawler-zap-ajax-spider' },
  Hakrawler:          { page: 'Project-Settings-Reference', anchor: 'web-crawler-hakrawler' },
  Jsluice:            { page: 'Project-Settings-Reference', anchor: 'javascript-analysis-jsluice' },
  Ffuf:               { page: 'Project-Settings-Reference', anchor: 'directory-fuzzer-ffuf' },
  Gau:                { page: 'Project-Settings-Reference', anchor: 'passive-url-discovery-gau' },
  ParamSpider:        { page: 'Project-Settings-Reference', anchor: 'paramspider-passive-parameter-discovery' },
  Kiterunner:         { page: 'Project-Settings-Reference', anchor: 'api-discovery-kiterunner' },
  Arjun:              { page: 'Project-Settings-Reference', anchor: 'parameter-discovery-arjun' },

  // JS Recon
  JsRecon:            { page: 'JS-Reconnaissance' },

  // Supply-Chain Recon (GROUP 5.5)
  SupplyChainRecon:   { page: 'Supply-Chain-Scanning', anchor: 'layer-l2-supply-chain-recon-pipeline' },

  // AI Surface Recon (Phase 4.5)
  AiSurfaceRecon:     { page: 'Adversarial-AI-Recon', anchor: 'ai-surface-recon-active-probing' },

  // Vulnerability Scanning
  Nuclei:             { page: 'Project-Settings-Reference', anchor: 'vulnerability-scanner-nuclei' },
  GraphqlScan:        { page: 'GraphQL-Security-Testing' },
  SubdomainTakeover:  { page: 'Subdomain-Takeover-Detection' },
  VhostSni:           { page: 'VHost-and-SNI-Enumeration' },
  WebCachePoison:     { page: 'Web-Cache-Poisoning' },

  // CVE & MITRE
  CveLookup:          { page: 'Project-Settings-Reference', anchor: 'cve-enrichment' },
  Mitre:              { page: 'Project-Settings-Reference', anchor: 'mitre-mapping' },

  // Security Checks
  SecurityChecks:     { page: 'Project-Settings-Reference', anchor: 'security-checks' },
  OriginDiscovery:    { page: 'Origin-Discovery' },

  // Workflow input pseudo-tool
  input:              { page: 'Creating-a-Project' },
}

// ---- ProjectForm sections (per-section keys) ---------------------------------------
// These extend TOOL_WIKI with non-tool sections. Tool sections fall back to TOOL_WIKI.

export const SECTION_WIKI: Record<string, { page: string; anchor?: string }> = {
  Target:           { page: 'Creating-a-Project' },
  ScanModules:      { page: 'Recon-Pipeline-Workflow' },
  ReconPreset:      { page: 'Recon-Presets' },
  Roe:              { page: 'Rules-of-Engagement' },
  AgentBehaviour:   { page: 'AI-Agent-Guide' },
  ToolMatrix:       { page: 'AI-Agent-Guide' },
  AttackSkills:     { page: 'Agent-Skills' },
  CypherFixSettings:{ page: 'CypherFix-Automated-Remediation' },
  EndpointAiClassifier: { page: 'Adversarial-AI-Recon', anchor: 'endpoint-ai-classifier' },
  Github:           { page: 'GitHub-Secret-Hunting' },
  Trufflehog:       { page: 'Secret-Multiscanner' },
  // Supply-Chain L1 standalone scan (the Other Scans modal card). L2 recon uses SupplyChainRecon.
  SupplyChainScan:  { page: 'Supply-Chain-Scanning', anchor: 'layer-l1-the-supply-chain-scanner-other-scans' },
  GvmScan:          { page: 'GVM-Vulnerability-Scanning' },
  Fireteam:         { page: 'Fireteam-Parallel-Specialists' },
  Lats:             { page: 'Exploit-Path-Search-LATS' },
  // Scan Timeline (versioned recon graphs) - one page, three deep links.
  ScanTimeline:     { page: 'Scan-Timeline' },
  ReconDelta:       { page: 'Scan-Timeline', anchor: 'recon-delta-comparing-two-versions' },
  ScanSchedule:     { page: 'Scan-Timeline', anchor: 'scans' },
  // Priority Board (finding ranking + mute). One page; the settings section and
  // the Red Zone tab both point at it, so an operator reaches the same explanation.
  PriorityBoard:     { page: 'Priority-Board' },
  PriorityBoardMute: { page: 'Priority-Board', anchor: 'what-muted-actually-means' },
  VersionManager:   { page: 'Scan-Timeline', anchor: 'version-manager' },
  // Tool sections that have a TOOL_WIKI entry are also exposed here for convenience.
  ...({} as Record<string, { page: string; anchor?: string }>),
}

/** Resolve the wiki destination for any known key (page, tool, or section). */
export function resolveWikiTarget(key: string): { page: string; anchor?: string } | null {
  return PAGE_WIKI[key] ?? TOOL_WIKI[key] ?? SECTION_WIKI[key] ?? null
}

/** Build a wiki URL directly from a known key. Returns null if the key is unknown. */
export function getWikiUrl(key: string): string | null {
  const target = resolveWikiTarget(key)
  if (!target) return null
  return buildWikiUrl(target.page, target.anchor)
}
