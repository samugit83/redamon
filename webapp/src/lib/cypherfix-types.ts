// =============================================================================
// CypherFix - TypeScript Types for WebSocket Messages & Payloads
// =============================================================================

// ── Triage Agent Messages ────────────────────────────────────────────────────

export enum CypherFixTriageMessageType {
  // Client → Server
  INIT = 'init',
  START_TRIAGE = 'start_triage',
  STOP = 'stop',
  PING = 'ping',

  // Server → Client
  CONNECTED = 'connected',
  TRIAGE_PHASE = 'triage_phase',
  TRIAGE_FINDING = 'triage_finding',
  THINKING = 'thinking',
  THINKING_CHUNK = 'thinking_chunk',
  TOOL_START = 'tool_start',
  TOOL_COMPLETE = 'tool_complete',
  TRIAGE_COMPLETE = 'triage_complete',
  ERROR = 'error',
  PONG = 'pong',
  STOPPED = 'stopped',
}

export type TriagePhase =
  | 'collecting_vulnerabilities'
  | 'collecting_cve_chains'
  | 'collecting_secrets'
  | 'collecting_exploits'
  | 'collecting_assets'
  | 'collecting_chain_findings'
  | 'collecting_attack_chains'
  | 'collecting_certificates'
  | 'collecting_security_checks'
  // Between collection and correlation: a real/noise verdict per finding,
  // written back onto the graph nodes.
  | 'classifying'
  | 'correlating'
  | 'prioritizing'
  | 'generating_remediations'
  | 'saving'

export interface TriagePhasePayload {
  phase: TriagePhase
  description: string
  progress: number
}

export interface TriageFindingPayload {
  title: string
  severity: string
  category: string
  cveIds: string[]
  affectedAssets: number
}

export interface TriageCompletePayload {
  total_remediations: number
  by_severity: Record<string, number>
  by_type: Record<string, number>
  summary: string
}

// ── CodeFix Agent Messages ───────────────────────────────────────────────────

export enum CypherFixCodeFixMessageType {
  // Client → Server
  INIT = 'init',
  START_FIX = 'start_fix',
  BLOCK_DECISION = 'block_decision',
  GUIDANCE = 'guidance',
  STOP = 'stop',
  PING = 'ping',

  // Server → Client
  CONNECTED = 'connected',
  CODEFIX_PHASE = 'codefix_phase',
  THINKING = 'thinking',
  THINKING_CHUNK = 'thinking_chunk',
  TOOL_START = 'tool_start',
  TOOL_COMPLETE = 'tool_complete',
  FIX_PLAN = 'fix_plan',
  DIFF_BLOCK = 'diff_block',
  BLOCK_STATUS = 'block_status',
  PR_CREATED = 'pr_created',
  CODEFIX_COMPLETE = 'codefix_complete',
  ERROR = 'error',
  PONG = 'pong',
  STOPPED = 'stopped',
}

export type CodeFixPhase =
  | 'cloning_repo'
  | 'exploring_codebase'
  | 'planning_fix'
  | 'implementing_fix'
  | 'awaiting_approval'
  | 'verifying_fix'
  | 'creating_pr'

export interface DiffBlockPayload {
  block_id: string
  file_path: string
  language: string
  old_code: string
  new_code: string
  context_before: string
  context_after: string
  start_line: number
  end_line: number
  description: string
  status: 'pending' | 'accepted' | 'rejected'
}

export interface FixPlanPayload {
  files: Array<{
    path: string
    action: 'edit' | 'create' | 'delete'
    description: string
  }>
  approach: string
  risks: string[]
  estimated_blocks: number
}

export interface BlockDecisionPayload {
  block_id: string
  decision: 'accept' | 'reject'
  reason?: string
}

export interface PRCreatedPayload {
  pr_url: string
  pr_number: number
  branch: string
  title: string
  files_changed: number
  additions: number
  deletions: number
}

// ── Shared / Remediation Types ───────────────────────────────────────────────

export type RemediationSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export type RemediationStatus =
  | 'pending'
  | 'in_progress'
  | 'no_fix'
  | 'code_review'
  | 'pr_created'
  | 'resolved'
  | 'dismissed'

export type RemediationType =
  | 'code_fix'
  | 'dependency_update'
  | 'config_change'
  | 'secret_rotation'
  | 'infrastructure'

export type FixComplexity = 'low' | 'medium' | 'high' | 'critical'

export interface Remediation {
  id: string
  projectId: string
  title: string
  description: string
  severity: RemediationSeverity
  priority: number
  category: string
  remediationType: RemediationType
  affectedAssets: Array<{ type: string; name: string; url?: string; ip?: string; port?: number }>
  cvssScore: number | null
  cveIds: string[]
  cweIds: string[]
  capecIds: string[]
  evidence: string
  attackChainPath: string
  exploitAvailable: boolean
  cisaKev: boolean
  solution: string
  fixComplexity: FixComplexity
  estimatedFiles: number
  targetRepo: string
  targetBranch: string
  fixBranch: string
  prUrl: string
  prStatus: string
  status: RemediationStatus
  agentSessionId: string
  agentNotes: string
  fileChanges: Array<{
    filePath: string
    language: string
    blocks: Array<{
      id: string
      oldCode: string
      newCode: string
      status: 'pending' | 'accepted' | 'rejected'
    }>
  }>
  createdAt: string
  updatedAt: string
}

// ── Severity helpers ─────────────────────────────────────────────────────────

export const SEVERITY_ORDER: Record<RemediationSeverity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
}

export const SEVERITY_COLORS: Record<RemediationSeverity, string> = {
  critical: 'var(--severity-critical, #dc2626)',
  high: 'var(--severity-high, #ea580c)',
  medium: 'var(--severity-medium, #ca8a04)',
  low: 'var(--severity-low, #2563eb)',
  info: 'var(--severity-info, #6b7280)',
}

export const STATUS_LABELS: Record<RemediationStatus, string> = {
  pending: 'Pending',
  in_progress: 'In Progress',
  no_fix: 'No Fix',
  code_review: 'Code Review',
  pr_created: 'PR Created',
  resolved: 'Resolved',
  dismissed: 'Dismissed',
}

// ── Activity Log Entry (CodeFix chronological event) ────────────────────────

export type ActivityEntry =
  | { id: string; type: 'phase'; ts: number; phase: CodeFixPhase; description: string }
  | { id: string; type: 'thinking'; ts: number; text: string }
  | { id: string; type: 'tool'; ts: number; name: string; args: Record<string, unknown>; status: 'running' | 'done' | 'error'; success?: boolean; output?: string }
  | { id: string; type: 'diff_block'; ts: number; block: DiffBlockPayload }
  | { id: string; type: 'fix_plan'; ts: number; plan: FixPlanPayload }
  | { id: string; type: 'pr_created'; ts: number; pr: PRCreatedPayload }
  | { id: string; type: 'error'; ts: number; message: string }
  | { id: string; type: 'complete'; ts: number; completionStatus: string }

export const REMEDIATION_TYPE_LABELS: Record<RemediationType, string> = {
  code_fix: 'Code Fix',
  dependency_update: 'Dependency Update',
  config_change: 'Config Change',
  secret_rotation: 'Secret Rotation',
  infrastructure: 'Infrastructure',
}
