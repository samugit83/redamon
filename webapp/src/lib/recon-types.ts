/**
 * Types for Recon Process Management
 */

export type ReconStatus = 'idle' | 'starting' | 'running' | 'paused' | 'pausing' | 'completed' | 'error' | 'stopping'

export interface ReconState {
  project_id: string
  status: ReconStatus
  current_phase: string | null
  phase_number: number | null
  total_phases: number
  started_at: string | null
  completed_at: string | null
  error: string | null
  container_id?: string | null
}

export interface ReconLogEvent {
  log: string
  timestamp: string
  phase?: string | null
  phaseNumber?: number | null
  isPhaseStart?: boolean
  level: 'info' | 'warning' | 'error' | 'success' | 'action'
}

export interface ReconSSEEvent {
  event: 'log' | 'error' | 'complete'
  data: ReconLogEvent | { error: string } | { status: string; completedAt?: string; error?: string }
}

export const RECON_PHASES = [
  'Domain Discovery',
  'Port Scanning',
  'HTTP Probing',
  'Resource Enumeration',
  'OpenAPI Ingestion',
  'Vulnerability Scanning',
  'MITRE Enrichment',
] as const

export type ReconPhase = typeof RECON_PHASES[number]

// =============================================================================
// GVM Vulnerability Scan Types
// =============================================================================

export type GvmStatus = 'idle' | 'starting' | 'running' | 'paused' | 'pausing' | 'completed' | 'error' | 'stopping'

export interface GvmState {
  project_id: string
  status: GvmStatus
  current_phase: string | null
  phase_number: number | null
  total_phases: number
  started_at: string | null
  completed_at: string | null
  error: string | null
  container_id?: string | null
}

export const GVM_PHASES = [
  'Loading Recon Data',
  'Connecting to GVM',
  'Scanning IPs',
  'Scanning Hostnames',
] as const

export type GvmPhase = typeof GVM_PHASES[number]

// =============================================================================
// GitHub Secret Hunt Types
// =============================================================================

export type GithubHuntStatus = 'idle' | 'starting' | 'running' | 'paused' | 'pausing' | 'completed' | 'error' | 'stopping'

export interface GithubHuntState {
  project_id: string
  status: GithubHuntStatus
  current_phase: string | null
  phase_number: number | null
  total_phases: number
  started_at: string | null
  completed_at: string | null
  error: string | null
  container_id?: string | null
}

export const GITHUB_HUNT_PHASES = [
  'Loading Settings',
  'Scanning Repositories',
  'Complete',
] as const

export type GithubHuntPhase = typeof GITHUB_HUNT_PHASES[number]

// =============================================================================
// TruffleHog Secret Scan Types
// =============================================================================

export type TrufflehogStatus = 'idle' | 'starting' | 'running' | 'paused' | 'pausing' | 'completed' | 'error' | 'stopping'

export interface TrufflehogState {
  project_id: string
  status: TrufflehogStatus
  /** The source id, which is ALSO the run key: one run per source, any number
   *  of distinct sources in parallel. */
  source?: string
  run_id?: string
  /** Human descriptor of what this run scans (org, image ref, bucket, URL). */
  target?: string
  current_phase: string | null
  phase_number: number | null
  total_phases: number
  started_at: string | null
  completed_at: string | null
  error: string | null
  container_id?: string | null
  /** Set once the clean ingest step has written the findings to the graph. */
  ingested?: boolean
  findings_count?: number
}

/** The /trufflehog/{projectId}/all payload. */
export interface TrufflehogListResponse {
  project_id: string
  runs: TrufflehogState[]
}

// Supply-Chain scan (L1 "Other Scans") - same lifecycle shape as trufflehog.
export type SupplyChainStatus = 'idle' | 'starting' | 'running' | 'paused' | 'pausing' | 'completed' | 'error' | 'stopping'

export interface SupplyChainState {
  project_id: string
  status: SupplyChainStatus
  current_phase: string | null
  phase_number: number | null
  total_phases: number
  started_at: string | null
  completed_at: string | null
  error: string | null
  container_id?: string | null
}

// Kept in step with TRUFFLEHOG_PHASE_PATTERNS in container_manager.py. The
// scanner reads a job file rather than fetching settings, and it scans far more
// than repositories, so the old labels described neither.
export const TRUFFLEHOG_PHASES = [
  'Preparing',
  'Scanning',
  'Complete',
] as const

export type TrufflehogPhase = typeof TRUFFLEHOG_PHASES[number]

// =============================================================================
// Partial Recon Types
// =============================================================================

export type PartialReconStatus = 'idle' | 'starting' | 'running' | 'completed' | 'error' | 'stopping'

export interface PartialReconState {
  project_id: string
  run_id: string
  tool_id: string
  status: PartialReconStatus
  container_id: string | null
  started_at: string | null
  completed_at: string | null
  error: string | null
  stats: Record<string, number> | null
}

export interface PartialReconListResponse {
  project_id: string
  runs: PartialReconState[]
}

export interface GraphInputs {
  domain: string | null
  existing_subdomains_count: number
  existing_subdomains?: string[]
  existing_ips_count?: number
  existing_ports_count?: number
  existing_baseurls_count?: number
  existing_baseurls?: string[]
  existing_endpoints_count?: number
  existing_graphql_endpoints_count?: number
  existing_ai_endpoints_count?: number
  existing_mcp_endpoints_count?: number
  existing_vector_db_services_count?: number
  existing_external_domains_count?: number
  source: 'graph' | 'settings'
}

export interface UserTargets {
  subdomains: string[]
  ips: string[]
  ip_attach_to: string | null
  ports?: number[]
  urls?: string[]
  url_attach_to?: string | null
}

export interface PartialReconParams {
  tool_id: string
  graph_inputs: Record<string, string>
  user_inputs: string[]
  user_targets?: UserTargets
  include_graph_targets?: boolean
  settings_overrides?: Record<string, unknown>
}

export const PARTIAL_RECON_SUPPORTED_TOOLS = new Set(['SubdomainDiscovery', 'Naabu', 'Masscan', 'Nmap', 'Httpx', 'Katana', 'OpenAPI', 'ZapAjaxSpider', 'Hakrawler', 'Jsluice', 'Gau', 'Kiterunner', 'ParamSpider', 'Arjun', 'Ffuf', 'EndpointAiClassifier', 'AiSurfaceRecon', 'JsRecon', 'SupplyChainRecon', 'GraphqlScan', 'Nuclei', 'SubdomainTakeover', 'VhostSni', 'WebCachePoison', 'SecurityChecks', 'Shodan', 'Urlscan', 'Uncover', 'OsintEnrichment'])

export const PARTIAL_RECON_PHASE_MAP: Record<string, readonly string[]> = {
  SubdomainDiscovery: ['Subdomain Discovery'],
  Naabu: ['Port Scanning'],
  Masscan: ['Port Scanning'],
  Nmap: ['Nmap Service Detection'],
  Httpx: ['HTTP Probing'],
  Katana: ['Resource Enumeration'],
  OpenAPI: ['OpenAPI Ingestion'],
  ZapAjaxSpider: ['Resource Enumeration'],
  Hakrawler: ['Resource Enumeration'],
  Jsluice: ['Resource Enumeration'],
  Gau: ['Resource Enumeration'],
  Kiterunner: ['Resource Enumeration'],
  ParamSpider: ['Resource Enumeration'],
  Arjun: ['Resource Enumeration'],
  Ffuf: ['Resource Enumeration'],
  EndpointAiClassifier: ['Endpoint AI Classification'],
  AiSurfaceRecon: ['AI Surface Recon'],
  JsRecon: ['JS Recon'],
  SupplyChainRecon: ['Package Harvest', 'Offline OSV Verdict'],
  GraphqlScan: ['Endpoint Discovery', 'Introspection Testing', 'Schema Analysis', 'Vulnerability Detection'],
  Nuclei: ['Vulnerability Scanning'],
  SubdomainTakeover: ['Subdomain Takeover Detection'],
  VhostSni: ['VHost & SNI Enumeration'],
  WebCachePoison: ['Cache Poisoning Detection'],
  SecurityChecks: ['Security Checks'],
  Shodan: ['Shodan Enrichment'],
  Urlscan: ['URLScan Enrichment'],
  Uncover: ['Uncover Expansion'],
  OsintEnrichment: ['OSINT Enrichment'],
}

// Backward-compatible default (SubdomainDiscovery phases)
export const PARTIAL_RECON_PHASES = PARTIAL_RECON_PHASE_MAP['SubdomainDiscovery']

export type PartialReconPhase = typeof PARTIAL_RECON_PHASES[number]
