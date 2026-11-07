import { SECTION_INPUT_MAP, SECTION_NODE_MAP, SECTION_ENRICH_MAP } from '../nodeMapping'
import { NODE_COLORS } from '@/app/graph/config/colors'

// ---- Tool definitions ----

export interface WorkflowToolDef {
  id: string
  label: string
  enabledField: string
  group: number
  badge?: 'active' | 'passive' | 'both'
  /** Recently shipped module: shows a "New!" badge on its node. */
  isNew?: boolean
  /** Enabled but given nothing to work on: shown as Idle, and not a source of its outputs. */
  idleWhen?: (formData: Record<string, unknown>) => boolean
}

function openApiIdle(d: Record<string, unknown>): boolean {
  const sources = Array.isArray(d.openapiSources) ? d.openapiSources as Array<Record<string, unknown> | null> : []
  return !d.openapiAutoDiscover && !sources.some(s => s?.enabled !== false && Boolean(s?.url))
}

export const WORKFLOW_TOOLS: WorkflowToolDef[] = [
  // Group 1 - Discovery & OSINT, stacked in one column.
  // Uncover has no node: its settings live inside OSINT Enrichment and the scan
  // runs it only while OSINT Enrichment is on, so a node of its own opened the
  // same dialog and could show it on while the scan skipped it.
  { id: 'SubdomainDiscovery', label: 'Subdomain Discovery', enabledField: 'subdomainDiscoveryEnabled', group: 1, badge: 'both' },
  { id: 'Urlscan',           label: 'URLScan',             enabledField: 'urlscanEnabled',             group: 1, badge: 'passive' },
  { id: 'Shodan',           label: 'Shodan',              enabledField: 'shodanEnabled',              group: 1, badge: 'passive' },
  { id: 'OsintEnrichment',  label: 'OSINT Enrichment',    enabledField: 'osintEnrichmentEnabled',     group: 1, badge: 'passive' },

  // Group 3 - Port Scanning
  { id: 'Naabu',   label: 'Naabu',   enabledField: 'naabuEnabled',   group: 3, badge: 'active' },
  { id: 'Masscan', label: 'Masscan', enabledField: 'masscanEnabled', group: 3, badge: 'active' },
  { id: 'Nmap',    label: 'Nmap',    enabledField: 'nmapEnabled',    group: 3, badge: 'active' },
  { id: 'Tlsx',    label: 'TLS Grab', enabledField: 'tlsxEnabled',   group: 3, badge: 'active' },

  // Group 4 - HTTP Probing
  { id: 'Httpx', label: 'Httpx', enabledField: 'httpxEnabled', group: 4, badge: 'active' },
  { id: 'IpAttribution', label: 'IP Attribution', enabledField: 'ipAttributionEnabled', group: 4, badge: 'both' },

  // Group 5 - Resource Enumeration
  { id: 'Katana',      label: 'Katana',      enabledField: 'katanaEnabled',      group: 5, badge: 'active' },
  { id: 'ZapAjaxSpider', label: 'ZAP Ajax Spider', enabledField: 'zapAjaxSpiderEnabled', group: 5, badge: 'active' },
  { id: 'Hakrawler',   label: 'Hakrawler',   enabledField: 'hakrawlerEnabled',   group: 5, badge: 'active' },
  { id: 'Jsluice',     label: 'jsluice',     enabledField: 'jsluiceEnabled',     group: 5, badge: 'both' },
  { id: 'Ffuf',        label: 'FFuf',        enabledField: 'ffufEnabled',        group: 5, badge: 'active' },
  { id: 'Gau',         label: 'GAU',         enabledField: 'gauEnabled',         group: 5, badge: 'passive' },
  { id: 'ParamSpider', label: 'ParamSpider', enabledField: 'paramspiderEnabled', group: 5, badge: 'passive' },
  { id: 'Kiterunner',  label: 'Kiterunner',  enabledField: 'kiterunnerEnabled',  group: 5, badge: 'active' },
  { id: 'Arjun',       label: 'Arjun',       enabledField: 'arjunEnabled',       group: 5, badge: 'active' },
  { id: 'OpenAPI',     label: 'OpenAPI',     enabledField: 'openapiEnabled',     group: 5, badge: 'active',
    idleWhen: openApiIdle },
  { id: 'EndpointAiClassifier', label: 'Endpoint AI Classifier',
    enabledField: 'resourceEnumAiClassifierEnabled', group: 5, badge: 'passive' },

  // Group 5.5 - JS Recon
  { id: 'JsRecon', label: 'JS Recon', enabledField: 'jsReconEnabled', group: 5.5, badge: 'both' },
  { id: 'SerializedScan', label: 'Serialized Objects', enabledField: 'serializedScanEnabled', group: 5.5, badge: 'passive' },
  { id: 'AiSurfaceRecon', label: 'AI Surface Recon', enabledField: 'aiSurfaceReconEnabled', group: 5.5, badge: 'active' },
  // Runs after JS Recon (consumes its source maps + the detected technologies);
  // the harvest sends no traffic of its own and the OSV verdict is offline.
  { id: 'SupplyChainRecon', label: 'Supply Chain', enabledField: 'supplyChainReconEnabled', group: 5.5, badge: 'passive' },

  // Group 6 - Vulnerability Scanning
  { id: 'Nuclei',             label: 'Nuclei',             enabledField: 'nucleiEnabled',               group: 6, badge: 'active' },
  { id: 'GraphqlScan',        label: 'GraphQL Scan',       enabledField: 'graphqlSecurityEnabled',     group: 6, badge: 'active' },
  { id: 'SubdomainTakeover',  label: 'Subdomain Takeover', enabledField: 'subdomainTakeoverEnabled',   group: 6, badge: 'active' },
  { id: 'VhostSni',           label: 'VHost & SNI',        enabledField: 'vhostSniEnabled',             group: 6, badge: 'active' },
  { id: 'WebCachePoison',     label: 'Cache Poisoning',    enabledField: 'webCachePoisonEnabled',       group: 6, badge: 'active' },
  { id: 'RouteExposure',      label: 'Route Exposure',     enabledField: 'routeExposureEnabled',        group: 6, badge: 'active', isNew: true },

  // Group 7 - CVE & MITRE
  { id: 'CveLookup', label: 'CVE Lookup', enabledField: 'cveLookupEnabled', group: 7 },
  { id: 'Mitre',     label: 'MITRE',      enabledField: 'mitreEnabled',     group: 7 },

  // Group 8 - Security Checks
  { id: 'SecurityChecks', label: 'Security Checks', enabledField: 'securityCheckEnabled', group: 8, badge: 'active' },
  { id: 'OriginDiscovery', label: 'Origin Discovery', enabledField: 'originDiscoveryEnabled', group: 8, badge: 'both' },
]

// ---- Data node definitions ----

export const UNIVERSAL_DATA_NODES = new Set(['Domain', 'Subdomain', 'IP'])

export const TRANSITIONAL_DATA_NODES = new Set([
  'DNSRecord',
  'Port', 'Service',
  'BaseURL', 'Endpoint', 'Parameter', 'Header', 'Certificate',
  'Technology',
  'Vulnerability', 'CVE', 'MitreData', 'Capec', 'Secret',
  'Package', 'MalPackageFinding',
  'ExternalDomain',
])

// All data nodes shown in the workflow
export const ALL_WORKFLOW_DATA_NODES = new Set([...UNIVERSAL_DATA_NODES, ...TRANSITIONAL_DATA_NODES])

export type DataNodeCategory = 'identity' | 'network' | 'web' | 'technology' | 'security' | 'external'

export const DATA_NODE_CATEGORIES: Record<string, DataNodeCategory> = {
  Domain: 'identity',
  Subdomain: 'identity',
  IP: 'identity',
  DNSRecord: 'network',
  Port: 'network',
  Service: 'network',
  BaseURL: 'web',
  Endpoint: 'web',
  Parameter: 'web',
  Header: 'web',
  Certificate: 'web',
  Technology: 'technology',
  Vulnerability: 'security',
  CVE: 'security',
  MitreData: 'security',
  Capec: 'security',
  Secret: 'security',
  Package: 'technology',
  MalPackageFinding: 'security',
  ExternalDomain: 'external',
}

export const CATEGORY_COLORS: Record<DataNodeCategory, string> = {
  identity: '#3b82f6',
  network: '#06b6d4',
  web: '#22c55e',
  technology: '#a855f7',
  security: '#f97316',
  external: '#eab308',
}

// Per-node color from the graph legend (falls back to category color)
export function getNodeColor(nodeType: string): string {
  return NODE_COLORS[nodeType] ?? CATEGORY_COLORS[DATA_NODE_CATEGORIES[nodeType] ?? 'identity'] ?? '#6b7280'
}

// Group stage metadata
export const WORKFLOW_GROUPS: { group: number; label: string; color: string }[] = [
  { group: 0,   label: 'Input',          color: '#6b7280' },
  { group: 1,   label: 'Discovery & OSINT', color: '#3b82f6' },
  { group: 3,   label: 'Port Scanning',  color: '#06b6d4' },
  { group: 4,   label: 'HTTP Probing',   color: '#22c55e' },
  { group: 5,   label: 'Resource Enum',  color: '#f59e0b' },
  { group: 5.5, label: 'JS Recon',       color: '#f59e0b' },
  { group: 6,   label: 'Vuln Scanning',  color: '#ef4444' },
  { group: 7,   label: 'CVE & MITRE',    color: '#f97316' },
  { group: 8,   label: 'Security',       color: '#ec4899' },
]

// Get the group color for a tool
export function getGroupColor(group: number): string {
  return WORKFLOW_GROUPS.find(g => g.group === group)?.color ?? '#6b7280'
}

// Filtered versions of nodeMapping that only include workflow data nodes
export function getToolProduces(toolId: string): string[] {
  return (SECTION_NODE_MAP[toolId] ?? []).filter(n => ALL_WORKFLOW_DATA_NODES.has(n))
}

export function getToolConsumes(toolId: string): string[] {
  return (SECTION_INPUT_MAP[toolId] ?? []).filter(n => ALL_WORKFLOW_DATA_NODES.has(n))
}

export function getToolEnriches(toolId: string): string[] {
  return (SECTION_ENRICH_MAP[toolId] ?? []).filter(n => ALL_WORKFLOW_DATA_NODES.has(n))
}
