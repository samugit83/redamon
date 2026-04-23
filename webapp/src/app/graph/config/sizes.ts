// Node size multipliers by type (1x = default size)
export const NODE_SIZES: Record<string, number> = {
  Domain: 4,
  Subdomain: 3,
  IP: 2,
  Port: 2,
  Service: 2,
  Traceroute: 1.5,
  BaseURL: 3,
  Technology: 2,
  ExploitGvm: 1.4, // GVM confirmed exploit - diamond shape
  GithubHunt: 2.5,          // Prominent scan node
  GithubRepository: 1.5,    // Medium repo nodes
  GithubPath: 1.2,          // File path nodes
  GithubSecret: 1,          // Leaf: leaked secret
  GithubSensitiveFile: 1,   // Leaf: sensitive file
  TrufflehogScan: 2.5,       // Prominent scan node (same as GithubHunt)
  TrufflehogRepository: 1.5, // Medium repo nodes
  TrufflehogFinding: 1,      // Leaf: secret finding
  Secret: 1.2,              // Slightly larger than default leaf nodes
  JsReconFinding: 1,        // Leaf: JS analysis finding
  ExternalDomain: 1.5,      // Small — informational
  // Attack Chain nodes (30% smaller than base)
  AttackChain: 1.4,            // Chain root
  ChainStep: 0.5,             // Individual steps (was 0.7)
  ChainFinding: 1.4,          // Findings
  ChainDecision: 0.5,         // Decision points (was 0.7)
  ChainFailure: 1,            // Failed attempts (was 1.5)
  Default: 1,
}

// Severity-based size multipliers
export const SEVERITY_SIZE_MULTIPLIERS: Record<string, number> = {
  critical: 1.0,
  high: 1.0,
  medium: 1.0,
  low: 0.7,
  info: 0.7,
  unknown: 0.7,
}

// Base sizes for rendering
export const BASE_SIZES = {
  node2D: 6,
  node3D: 5,
  label2D: { min: 2, divisor: 1 },
  label3D: 3,
} as const

// Link dimensions
export const LINK_SIZES = {
  defaultWidth2D: 1,
  highlightedWidth2D: 3,
  defaultWidth3D: 1.5,
  highlightedWidth3D: 3.5,
  arrowLength: 4,
  arrowLength3D: 3,
  particleWidth: 4,
  particleCount: 4,
} as const

// Drawer dimensions
export const DRAWER_WIDTH = 400

// Clustering: collapse >CLUSTER_THRESHOLD same-type leaf neighbors of a shared parent
export const CLUSTER_THRESHOLD = 30
export const CLUSTER_SIZE = {
  base: 2.5,        // base multiplier for a cluster node (vs 1x for a leaf)
  perDecade: 0.6,   // extra size per log10(childCount)
  max: 5,           // hard cap
} as const

