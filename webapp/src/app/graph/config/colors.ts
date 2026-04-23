// Node colors by type - semantic color mapping
export const NODE_COLORS: Record<string, string> = {
  // CRITICAL SECURITY (Red family) - Immediate attention needed
  Vulnerability: '#ef4444',  // Bright red - DANGER, highest priority
  CVE: '#dc2626',            // Deep red - Known vulnerabilities

  // THREAT INTELLIGENCE (Orange family) - Attack context
  MitreData: '#f97316',      // Orange - CWE/MITRE techniques
  Capec: '#eab308',          // Yellow - Attack patterns
  ThreatPulse: '#dc4a22',    // Red-orange - OTX threat intel pulses (adversary/campaign)
  Malware: '#991b1b',        // Deep red-800 - Malware file samples (confirmed indicators)

  // DOMAIN HIERARCHY (Blue family) - Recon foundation
  Domain: '#1e3a8a',         // Deep navy - Root/foundation (most important)
  Subdomain: '#2563eb',      // Royal blue - Children of domain

  // NETWORK LAYER (Cyan/Teal family) - Infrastructure
  IP: '#0d9488',             // Teal - Network addresses
  Port: '#0e7490',           // Dark cyan - Network ports
  Service: '#06b6d4',        // Cyan - Running services
  Traceroute: '#164e63',     // Dark cyan-900 - Network path/route data

  // WEB APPLICATION LAYER (Purple family) - Web-specific assets
  BaseURL: '#6366f1',        // Indigo - Web entry points
  Endpoint: '#8b5cf6',       // Purple - Paths/routes
  Parameter: '#c026d3',      // Fuchsia - Inputs (attack surface)
  Secret: '#e11d48',          // Rose-600 - Leaked secrets (danger, attention-grabbing)

  // EXPLOITATION RESULTS - Confirmed compromises
  ExploitGvm: '#ea580c',     // Orange-600 - GVM confirmed exploitation (active check)

  // CONTEXT & METADATA (Neutral family) - Supporting information
  Technology: '#22c55e',     // Green - Tech stack (good to know)
  Certificate: '#d97706',    // Amber - TLS/security context
  Header: '#78716c',         // Stone gray - HTTP metadata

  // GITHUB INTELLIGENCE (Gray family for hierarchy, distinct muted colors for leaf nodes)
  GithubHunt: '#4b5563',           // Gray-600 - scan container node
  GithubRepository: '#6b7280',     // Gray-500 - repository node
  GithubPath: '#9ca3af',           // Gray-400 - file path node
  GithubSecret: '#7c6f9b',        // Muted dusty purple - leaked secret (API key, credential)
  GithubSensitiveFile: '#5b8a72',  // Muted sage green - sensitive file (.env, config)

  // TRUFFLEHOG INTELLIGENCE (Teal-gray family - distinct from GitHub Hunt)
  TrufflehogScan: '#334155',       // Slate-700 - scan container node
  TrufflehogRepository: '#475569', // Slate-600 - repository node
  TrufflehogFinding: '#8b5e3c',    // Muted bronze - secret finding (warm, distinct from GithubSecret purple)

  // JS RECON SCANNER (Fuchsia - distinct from all other node families)
  JsReconFinding: '#c026d3',       // Fuchsia-600 - JS analysis finding

  // EXTERNAL / OUT-OF-SCOPE (informational, not a target)
  ExternalDomain: '#8b8178',       // Warm stone gray

  // ATTACK CHAIN (Amber family) — Agent execution history
  AttackChain: '#f59e0b',     // Amber - Chain root
  ChainStep: '#f59e0b',       // Amber - Execution steps
  ChainFinding: '#f59e0b',    // Amber - Findings
  ChainDecision: '#f59e0b',   // Amber - Decision points
  ChainFailure: '#f59e0b',    // Amber - Failed attempts

  Default: '#6b7280',        // Gray - Fallback
}

// Severity-based colors for Vulnerability nodes (pure red tonality)
export const SEVERITY_COLORS_VULN: Record<string, string> = {
  critical: '#ff3333',  // Brilliant red - brightest, vivid
  high: '#b91c1c',      // Medium red (red-700)
  medium: '#b91c1c',    // Medium red (red-700)
  low: '#7f1d1d',       // Dark red (red-900)
  info: '#7f1d1d',      // Dark red (red-900)
  unknown: '#6b7280',   // Grey for unknown
}

// Severity-based colors for CVE nodes (red-purple/magenta tonality)
export const SEVERITY_COLORS_CVE: Record<string, string> = {
  critical: '#ff3377',  // Brilliant magenta-red - brightest
  high: '#be185d',      // Medium pink-red (pink-700)
  medium: '#be185d',    // Medium pink-red (pink-700)
  low: '#831843',       // Dark pink-red (pink-900)
  info: '#831843',      // Dark pink-red (pink-900)
  unknown: '#831843',   // Dark pink-red - CVEs are always threats, even without severity data
}

// Link colors
export const LINK_COLORS = {
  default: '#9ca3af',
  highlighted: '#60a5fa',
  particle: '#60a5fa',
  chainParticle: '#f59e0b',   // Amber - animated flow on attack chain edges
  chainLink: '#2d3748',       // Gray-750 - attack chain edges (unselected, dark)
} as const

// Selection colors
export const SELECTION_COLORS = {
  ring: '#22c55e',
} as const

// Attack chain session colors
export const CHAIN_SESSION_COLORS = {
  inactive: '#6b7280',          // Grey-500 — chains not in active session
  inactiveSelected: '#f59e0b',  // Amber — inactive chain node when clicked/selected
  inactiveFinding: '#3d3107',   // Dark yellow — inactive non-goal ChainFinding diamonds
  activeRing: '#facc15',        // Yellow-400 — pulsing ring on active AttackChain node
} as const

// Goal/outcome finding types — these represent achieved attack objectives
export const GOAL_FINDING_TYPES = new Set([
  'exploit_success',
  'access_gained',
  'privilege_escalation',
  'credential_found',
  'data_exfiltration',
  'lateral_movement',
  'persistence_established',
  'denial_of_service_success',
  'social_engineering_success',
  'remote_code_execution',
  'session_hijacked',
])

// Colors for goal ChainFinding diamonds
export const GOAL_FINDING_COLORS = {
  active: '#4ade80',       // Green-400 — goal achieved (active chain)
  inactive: '#276d43',     // Dark green — goal achieved (inactive chain)
} as const

// Background colors by theme
export const BACKGROUND_COLORS = {
  dark: {
    graph: '#0a0a0a',
    label: '#ffffff',
  },
  light: {
    graph: '#ffffff',
    label: '#3f3f46', // gray-700
  },
} as const
