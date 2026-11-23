/**
 * The webapp's copy of the per-user Kali sandbox contract.
 *
 * The contract lives in three copies: `recon_orchestrator/sandbox_contract.py` and
 * `agentic/sandbox_contract.py` (byte-identical), and this file, which carries the
 * constants and types the webapp uses. `tests/test_sandbox_contract.py` reads every
 * `export const` here and fails when one is missing or differs from the Python
 * copies, so change all three together. Prose: docs/readmes/README.KALI_SANDBOX.md.
 *
 * Every constant is a plain literal, never an expression, so that test can read it.
 */

export const CONTRACT_VERSION = 1

// `act_as` is the separate sandbox an admin acting as a person works in.
export const VIEWS = ['own', 'act_as'] as const

// Orchestrator routes (orchestrator key). `{user_id}` and `{lease_id}` are path
// segments the caller fills and encodes.
export const ROUTE_ENSURE = '/sandboxes/ensure'
export const ROUTE_LEASES = '/sandboxes/{user_id}/leases'
export const ROUTE_LEASE = '/sandboxes/{user_id}/leases/{lease_id}'
export const ROUTE_RECONCILE = '/sandboxes/{user_id}/reconcile'
export const ROUTE_STOP_USER = '/sandboxes/{user_id}/stop'
export const ROUTE_STOP_PROJECT = '/sandboxes/stop-project'
export const ROUTE_STOP_ALL = '/sandboxes/stop-all'
export const ROUTE_STATUS = '/sandboxes/{user_id}'
export const ROUTE_LIST = '/sandboxes'

// The keys of an `ensure` answer (EnsureRunning, EnsureStarting below). Both carry
// `fresh`: a non-waiting call (the warm-up) is often the one that creates the
// instance, and a fresh start writes `sandbox.started` and turns tunnels off.
export const ENSURE_RUNNING_KEYS = [
  'user_id',
  'view',
  'instance',
  'host',
  'token',
  'tunnel_token',
  'ports',
  'reverse_port',
  'projects',
  'state',
  'fresh',
  'stop_at',
  'stop_reason',
  'warn',
] as const
export const ENSURE_STARTING_KEYS = ['state', 'instance', 'fresh'] as const

// Agent -> webapp internal routes (master key), the browser's status route, and the
// agent routes the webapp calls (master key).
export const INTERNAL_ROUTE_ENSURE = '/api/internal/agent/sandbox/ensure'
export const INTERNAL_ROUTE_LEASE = '/api/internal/agent/sandbox/lease'
export const INTERNAL_ROUTE_RELEASE = '/api/internal/agent/sandbox/release'
export const INTERNAL_ROUTE_LIST = '/api/internal/agent/sandbox/list'
export const SESSION_ROUTE_STATUS = '/api/agent/sandbox/status'
export const AGENT_ROUTE_DROP = '/sandboxes/{user_id}/drop'
export const AGENT_ROUTE_TUNNEL = '/sandboxes/{user_id}/tunnel'

// Error codes: 400 for the three invalid ids, 403 for the gateway's two refusals,
// 404 unknown instance, 409 for the lease and governor refusals, 503 / 504 for starts.
export const ERR_INVALID_PROJECT_ID = 'invalid_project_id'
export const ERR_INVALID_USER_ID = 'invalid_user_id'
export const ERR_INVALID_VIEW = 'invalid_view'
export const ERR_IMAGE_MISSING = 'sandbox_image_missing'
export const ERR_START_FAILED = 'sandbox_start_failed'
export const ERR_START_TIMEOUT = 'sandbox_start_timeout'
export const ERR_UNKNOWN_INSTANCE = 'unknown_instance'
export const ERR_NOT_RUNNING = 'sandbox_not_running'
export const ERR_DRAINING = 'sandbox_draining'
export const ERR_RAM = 'sandbox_ram'
export const ERR_HARD = 'sandbox_hard'
export const ERR_USER_REFUSED = 'sandbox_user_refused'
export const ERR_PROJECT_REFUSED = 'sandbox_project_refused'

export const STATES = ['starting', 'running', 'draining', 'stopping'] as const
export const LEASE_KINDS = ['run', 'terminal', 'exec', 'job', 'triage', 'tradecraft', 'interact', 'hold'] as const
export const STOP_REASONS = [
  'idle',
  'hold_unused',
  'access_lost',
  'account_disabled',
  'account_deleted',
  'project_deleted',
  'last_project_deleted',
  'emergency',
  'operator',
  'replaced',
  'start_failed',
] as const

// The agent WebSocket event (also MessageType.SANDBOX_STATUS in websocket-types.ts).
export const SANDBOX_STATUS = 'sandbox_status'
export const SANDBOX_STATUS_STATES = ['starting', 'ready', 'unavailable'] as const
export const SANDBOX_STATUS_REASONS = ['ram', 'hard', 'error', 'refused', 'stopped'] as const

// MCP kali_exec / kali_output.
export const KALI_EXEC_STATUS_STARTING = 'starting'
export const KALI_EXEC_ERROR_CODES = ['ram', 'hard', 'sandbox_error', 'sandbox_refused', 'sandbox_stopped'] as const
export const SANDBOX_REFUSED = 'sandbox unavailable: this person may not use the Kali sandbox on this project'

// UI texts. A refused warm-up shows nothing.
export const MODAL_RAM_TITLE = 'Not enough memory'
export const MODAL_RAM_BODY =
  "Your Kali sandbox cannot start now: the instance's memory is in use by scans and other sandboxes."
export const MODAL_HARD_TITLE = 'Sandbox limit reached'
export const MODAL_HARD_BODY = "Your Kali sandbox cannot start now: the instance's sandbox limit is reached."
export const MODAL_REFUSED_TITLE = 'Kali sandbox not available'
export const MODAL_REFUSED_BODY =
  'You cannot use the Kali sandbox on this project. Ask its owner for Use AI agent or Exploitation & shells.'
export const MODAL_RETRY_LABEL = 'Retry'
export const MODAL_CLOSE_LABEL = 'Close'
export const PARTIAL_ANSWER_ONE = '1 sandbox did not answer; its sessions may be out of date or missing'
export const PARTIAL_ANSWER_MANY = '{n} sandboxes did not answer; their sessions may be out of date or missing'
export const SHARE_KEYS_LENT_TEXT =
  "This person's agent runs on this project use your WPScan, URLScan and ProjectDiscovery keys inside a Kali sandbox, where this person can read them while their runs use them."

// Timings, in seconds.
export const HOLD_WARN_BEFORE_S = 3_600
export const HOLD_MAX_NO_USE_S = 28_800
export const START_TIMEOUT_S = 300
// The webapp's wait on an `ensure` that waits: above the start, below the agent's
// own wait on the webapp.
export const ORCHESTRATOR_ENSURE_TIMEOUT_S = 315

export type SandboxView = (typeof VIEWS)[number]
export type SandboxState = (typeof STATES)[number]
export type LeaseKind = (typeof LEASE_KINDS)[number]
export type StopReason = (typeof STOP_REASONS)[number]
export type SandboxStatusState = (typeof SANDBOX_STATUS_STATES)[number]
export type SandboxStatusReason = (typeof SANDBOX_STATUS_REASONS)[number]
export type KaliExecErrorCode = (typeof KALI_EXEC_ERROR_CODES)[number]
export type SandboxErrorCode =
  | typeof ERR_INVALID_PROJECT_ID
  | typeof ERR_INVALID_USER_ID
  | typeof ERR_INVALID_VIEW
  | typeof ERR_IMAGE_MISSING
  | typeof ERR_START_FAILED
  | typeof ERR_START_TIMEOUT
  | typeof ERR_UNKNOWN_INSTANCE
  | typeof ERR_NOT_RUNNING
  | typeof ERR_DRAINING
  | typeof ERR_RAM
  | typeof ERR_HARD
  | typeof ERR_USER_REFUSED
  | typeof ERR_PROJECT_REFUSED

/** The governor's refusal payload (AdmissionResult.payload()), carried by a 409. */
export interface SandboxLimit {
  admitted: boolean
  limitType: 'ram' | 'hard' | null
  resource: string
  current: number
  ceiling: number
  settingName: string | null
  detail: string
}

/** The payload of a `sandbox_status` event. Sent, never persisted. */
export interface SandboxStatusPayload {
  state: SandboxStatusState
  reason?: SandboxStatusReason
  detail?: string
  limit?: SandboxLimit
}

export interface SandboxPorts {
  network_recon: number
  nuclei: number
  metasploit: number
  nmap: number
  playwright: number
  sessions: number
  hydra: number
  tunnel: number
  terminal: number
  ngrok_api: number
}

/** Orchestrator `ensure` bodies and answers. Times are epoch seconds. */
export interface EnsureRequest {
  user_id: string
  view: SandboxView
  projects: string[]
  need_project: string | null
  wait: boolean
  touch: boolean
}

export interface EnsureRunning {
  user_id: string
  view: SandboxView
  instance: string
  /** The container name; it resolves only on the person's sandbox network. */
  host: string
  token: string
  tunnel_token: string
  ports: SandboxPorts
  reverse_port: number
  projects: string[]
  state: 'running'
  fresh: boolean
  stop_at: number | null
  stop_reason: StopReason | null
  warn: boolean
}

/** The 202 of a call that did not wait (`wait: false` or `touch`). */
export interface EnsureStarting {
  state: 'starting'
  instance: string
  /** This call created the instance: the same rule as EnsureRunning.fresh. */
  fresh: boolean
}

export type EnsureAnswer = EnsureRunning | EnsureStarting

export interface LeaseRequest {
  instance: string
  lease_id: string
  kind: LeaseKind
}

export interface LeaseAnswer {
  expires_at: number
  state: SandboxState
  stop_at: number | null
  warn: boolean
}

/** One instance in `GET /sandboxes/{user_id}`: never a token. */
export interface SandboxInstanceStatus {
  instance: string
  view: SandboxView
  state: SandboxState
  projects_hash: string
  created_at: number
  last_used: number
  lease_kinds: LeaseKind[]
  stop_at: number | null
  stop_reason: StopReason | null
  warn: boolean
  reverse_port: number
}

export interface SandboxStatusAnswer {
  instances: SandboxInstanceStatus[]
}

/** One entry of `GET /sandboxes`. Carries tokens: strip them before any browser sees it. */
export interface SandboxListEntry {
  user_id: string
  view: SandboxView
  instance: string
  host: string
  token: string
  state: SandboxState
}

export interface SandboxListAnswer {
  sandboxes: SandboxListEntry[]
}

export interface StoppedAnswer {
  stopped: number
}

/** The partial-answer line of the Sessions panel and the Operations view. */
export function partialAnswerLine(unavailable: number): string {
  return unavailable === 1 ? PARTIAL_ANSWER_ONE : PARTIAL_ANSWER_MANY.replace('{n}', String(unavailable))
}
