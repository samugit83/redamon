/**
 * WebSocket Message Types and TypeScript Definitions
 *
 * Mirrors the backend Python definitions in agentic/websocket_api.py
 * Ensures type-safe communication between frontend and backend.
 */

// =============================================================================
// MESSAGE TYPES
// =============================================================================

export enum MessageType {
  // Client → Server
  INIT = 'init',
  QUERY = 'query',
  APPROVAL = 'approval',
  ANSWER = 'answer',
  TOOL_CONFIRMATION = 'tool_confirmation',
  FIRETEAM_MEMBER_CONFIRMATION = 'fireteam_member_confirmation',
  PING = 'ping',
  GUIDANCE = 'guidance',
  SKILL_INJECT = 'skill_inject',
  STOP = 'stop',
  RESUME = 'resume',
  TOOL_STOP = 'tool_stop',

  // Server → Client
  CONNECTED = 'connected',
  THINKING = 'thinking',
  THINKING_CHUNK = 'thinking_chunk',
  TOOL_START = 'tool_start',
  TOOL_OUTPUT_CHUNK = 'tool_output_chunk',
  TOOL_FINISHED = 'tool_finished',
  TOOL_COMPLETE = 'tool_complete',
  PHASE_UPDATE = 'phase_update',
  TODO_UPDATE = 'todo_update',
  APPROVAL_REQUEST = 'approval_request',
  QUESTION_REQUEST = 'question_request',
  RESPONSE = 'response',
  EXECUTION_STEP = 'execution_step',
  ERROR = 'error',
  PONG = 'pong',
  TASK_COMPLETE = 'task_complete',
  GUIDANCE_ACK = 'guidance_ack',
  SKILL_INJECT_ACK = 'skill_inject_ack',
  STOPPED = 'stopped',
  FILE_READY = 'file_ready',
  PLAN_START = 'plan_start',
  PLAN_COMPLETE = 'plan_complete',
  PLAN_ANALYSIS = 'plan_analysis',
  DEEP_THINK = 'deep_think',
  TOOL_CONFIRMATION_REQUEST = 'tool_confirmation_request',

  // Fireteam (multi-agent) events
  FIRETEAM_DEPLOYED = 'fireteam_deployed',
  FIRETEAM_MEMBER_STARTED = 'fireteam_member_started',
  FIRETEAM_THINKING = 'fireteam_thinking',
  FIRETEAM_TOOL_START = 'fireteam_tool_start',
  FIRETEAM_TOOL_OUTPUT_CHUNK = 'fireteam_tool_output_chunk',
  FIRETEAM_TOOL_COMPLETE = 'fireteam_tool_complete',
  FIRETEAM_PLAN_START = 'fireteam_plan_start',
  FIRETEAM_PLAN_COMPLETE = 'fireteam_plan_complete',
  FIRETEAM_MEMBER_COMPLETED = 'fireteam_member_completed',
  FIRETEAM_COMPLETED = 'fireteam_completed',
  FIRETEAM_MEMBER_AWAITING_CONFIRMATION = 'fireteam_member_awaiting_confirmation',

  // LATS (exploit-path tree search) events. String values MUST stay
  // byte-identical to the Python MessageType enum in agentic/websocket_api.py.
  LATS_START = 'lats_start',
  LATS_TREE_UPDATE = 'lats_tree_update',
  LATS_COMPLETE = 'lats_complete',

  // Background-job lifecycle (job_spawn / job_cancel), fanned out by
  // agentic/ws_job_emitter.py to every connection of the job's project.
  JOB_UPDATE = 'job_update',

  // Agent in the Loop: who answers the run's model calls right now. Sent only
  // for a run whose model is the loop model, never persisted.
  LOOP_STATUS = 'loop_status',

  // A model call waits for the provider's rate limit to clear before its next
  // try. Sent only, never persisted.
  RATE_LIMIT_WAIT = 'rate_limit_wait',
}

/**
 * Server messages the webapp receives and deliberately does nothing with, each
 * with the reason. Every other server message must have a handler:
 * websocket-types.parity.test.ts fails a value that has neither, so a message
 * the agent adds is a decision instead of a silent drop.
 */
export const IGNORED_SERVER_MESSAGES: Readonly<Partial<Record<MessageType, string>>> = {
  [MessageType.JOB_UPDATE]:
    'No webapp view lists agent background jobs; the agent reads a job through job_status / job_wait, whose output the drawer shows as a tool result.',
  [MessageType.THINKING_CHUNK]:
    'The drawer renders the complete thought from THINKING, not the streamed partials.',
  [MessageType.EXECUTION_STEP]:
    'The drawer builds its timeline from the tool and thinking events; the step record is not displayed.',
  [MessageType.SKILL_INJECT_ACK]:
    'The drawer shows an injected chat skill when it sends it; the queue position in the ack is not displayed.',
}

// ---------------------------------------------------------------------------
// LATS (exploit-path tree search) payloads (mirror ExploitTree.to_view, §17.4)
// ---------------------------------------------------------------------------

export type LatsNodeStatus = 'proposed' | 'executing' | 'evaluated' | 'pruned' | 'terminal'

export interface LatsNodeView {
  id: string
  parent_id: string | null
  depth: number
  label: string
  tool_name: string | null
  tool_args?: Record<string, unknown> | null
  status: LatsNodeStatus
  value: number
  local_value: number
  visits: number
  verdict: string
  error_class: string
  response_class: string
  finding_confidence: number
  exploit_succeeded: boolean
  duration_ms: number
  observation: string
  reflection: string
  is_dangerous: boolean
  step_id: string | null
}

export interface LatsTreeSnapshot {
  search_id: string
  objective: string
  phase: string
  shadow_mode: boolean
  rollouts: number
  budget: { max_rollouts: number; max_depth: number }
  active_id: string | null
  best_trajectory: string[]
  nodes: LatsNodeView[]
}

export interface LatsStartPayload {
  search_id: string
  objective: string
  phase: string
  budget: { max_rollouts: number; max_depth: number }
  shadow_mode: boolean
}

export interface LatsTreeUpdatePayload {
  search_id: string
  snapshot: LatsTreeSnapshot
}

export interface LatsCompletePayload {
  search_id: string
  best_trajectory: string[]
  outcome: string
  metrics?: Record<string, unknown>
}

export interface FireteamMemberAwaitingConfirmationPayload {
  fireteam_id: string
  wave_id: string
  member_id: string
  member_name?: string
  confirmation_id?: string
  mode?: 'single' | 'plan'
  tools: Array<{ tool_name: string; tool_args: Record<string, unknown> }>
  reasoning?: string
  iteration?: number
}

// =============================================================================
// FIRETEAM PAYLOADS (Server → Client)
// =============================================================================

export type FireteamMemberStatus =
  | 'running'
  | 'success'
  | 'partial'
  | 'timeout'
  | 'needs_confirmation'
  | 'cancelled'
  | 'error'

export interface FireteamMemberInfo {
  member_id: string
  name: string
  task: string
  // Agent canonical key is `tools` (the member's primary allowlist). The
  // legacy `skills` alias is kept optional for back-compat during rollout but
  // is no longer emitted by the agent.
  tools?: string[]
  skills?: string[]
  max_iterations: number
}

export interface FireteamDeployedPayload {
  fireteam_id: string
  iteration: number
  plan_rationale: string
  member_count: number
  members: FireteamMemberInfo[]
}

export interface FireteamMemberStartedPayload {
  fireteam_id: string
  member_id: string
  name: string
}

export interface FireteamThinkingPayload {
  fireteam_id: string
  member_id: string
  name: string
  iteration: number
  phase: string
  thought: string
  reasoning: string
  input_tokens?: number
  output_tokens?: number
}

export interface FireteamToolStartPayload {
  fireteam_id: string
  member_id: string
  tool_name: string
  tool_args: Record<string, unknown>
  wave_id?: string | null
  step_index?: number | null
}

export interface FireteamToolOutputChunkPayload {
  fireteam_id: string
  member_id: string
  tool_name: string
  chunk: string
  is_final: boolean
  wave_id?: string | null
  step_index?: number | null
}

export interface FireteamToolCompletePayload {
  fireteam_id: string
  member_id: string
  tool_name: string
  success: boolean
  duration_ms: number
  output_excerpt: string
  wave_id?: string | null
  step_index?: number | null
}

export interface FireteamPlanStartPayload {
  fireteam_id: string
  member_id: string
  wave_id: string
  plan_rationale: string
  tools: string[]
}

export interface FireteamPlanCompletePayload {
  fireteam_id: string
  member_id: string
  wave_id: string
  total_steps: number
  successful: number
  failed: number
}

export interface FireteamMemberCompletedPayload {
  fireteam_id: string
  member_id: string
  name: string
  status: FireteamMemberStatus
  iterations_used: number
  tokens_used: number
  input_tokens_used?: number
  output_tokens_used?: number
  findings_count: number
  wall_clock_seconds: number
  error_message?: string | null
}

export interface FireteamCompletedPayload {
  fireteam_id: string
  total: number
  status_counts: Record<string, number>
  wall_clock_seconds: number
}

// =============================================================================
// CLIENT MESSAGE PAYLOADS (Client → Server)
// =============================================================================

export interface InitPayload {
  user_id: string
  project_id: string
  session_id: string
  graph_view_cypher?: string
  // STRIDE S6: short-lived ticket minted by the webapp, verified by the agent.
  ticket?: string
}

export interface QueryPayload {
  question: string
}

export interface ApprovalPayload {
  decision: 'approve' | 'modify' | 'abort'
  modification?: string
}

export interface AnswerPayload {
  answer: string
}

export interface GuidancePayload {
  message: string
}

export interface GuidanceAckPayload {
  message: string
  queue_position: number
}

export interface SkillInjectPayload {
  skill_id: string
  skill_name: string
  content: string
}

export interface SkillInjectAckPayload {
  skill_id: string
  skill_name: string
  queue_position: number
}

export interface StoppedPayload {
  message: string
  iteration: number
  phase: string
}

export interface ToolStopPayload {
  tool_name: string
  wave_id?: string
  step_index?: number
}

export interface ToolConfirmationTool {
  tool_name: string
  tool_args: Record<string, unknown>
  rationale?: string
}

export interface ToolConfirmationRequestPayload {
  mode: 'single' | 'plan' | 'fireteam_escalation'
  tools: ToolConfirmationTool[]
  reasoning?: string
  phase?: string
  iteration?: number
  /** Non-null when a fireteam member escalated this request. */
  agent_id?: string | null
  agent_name?: string | null
}

// =============================================================================
// SERVER MESSAGE PAYLOADS (Server → Client)
// =============================================================================

export interface ConnectedPayload {
  session_id: string
  message: string
  timestamp: string
  /** Protocol version for forward/backward compatibility. Added in v2. */
  protocol_version?: number
  /** Server-advertised feature flags (e.g. "fireteam", "plan_tools"). */
  features?: string[]
  /** Whether this session's run is still going on the server. Events emitted
   *  while the socket was down are lost, so every (re)connect uses this to
   *  keep or clear the spinner. Absent from agents older than this field. */
  agent_running?: boolean
  /** Agent in the Loop: the live status, for a reconnecting browser of a loop run. */
  loop_state?: LoopStatusPayload
}

/**
 * Agent in the Loop status (master plan T6). Never carries prompt or answer
 * text: a step is named by id, purpose and iteration only.
 */
export interface LoopStatusPayload {
  state: 'thinking' | 'running_tool' | 'awaiting_human' | 'finished' | 'stopped' | 'error' | string
  detail: {
    tool?: string
    kind?: 'approval' | 'question' | 'tool_confirmation' | string
    code?: 'loop_step_not_answered' | 'loop_step_declined' | 'loop_no_driver' | string
    /** A decline's reason, sanitized by the agent (one line, at most 300 characters). */
    reason?: string
  }
  step?: { stepId: string; state: 'open' | 'claimed' | string; purpose: string; iteration?: number | null }
  driver: { connected: boolean; lastSeenSeconds: number | null }
  openSteps: number
  sinceSeconds: number
}

/** A rate-limit wait: `seconds` before retry number `retry` of a `purpose` call. */
export interface RateLimitWaitPayload {
  seconds: number
  retry: number
  purpose: string
}

export interface ThinkingPayload {
  iteration: number
  phase: string
  thought: string
  reasoning: string
  action?: string
  input_tokens?: number
  output_tokens?: number
  /** Agent in the Loop: the MCP token that supplied this decision (display prefix and name). */
  answeredBy?: { token_prefix?: string; token_name?: string }
}

export interface ThinkingChunkPayload {
  chunk: string
}

export interface ToolStartPayload {
  tool_name: string
  tool_args: Record<string, any>
  wave_id?: string
  /** Stable per-step id, repeated on this tool's chunk/finished/complete. */
  step_id?: string
}

export interface ToolOutputChunkPayload {
  tool_name: string
  chunk: string
  is_final: boolean
  wave_id?: string
  step_id?: string
}

/** The tool itself returned; its tool_complete follows after the next think turn. */
export interface ToolFinishedPayload {
  tool_name: string
  success: boolean
  duration_ms?: number
  step_id?: string
}

export interface ToolCompletePayload {
  tool_name: string
  success: boolean
  output_summary: string
  actionable_findings: string[]
  recommended_next_steps: string[]
  wave_id?: string
  step_index?: number
  duration_ms?: number
  step_id?: string
}

export interface PlanStartPayload {
  wave_id: string
  plan_rationale: string
  tool_count: number
  tools: string[]
}

export interface PlanCompletePayload {
  wave_id: string
  total_steps: number
  successful: number
  failed: number
}

export interface PhaseUpdatePayload {
  current_phase: string
  iteration_count: number
  attack_path_type?: string  // a KNOWN_ATTACK_PATHS id (agentic/state.py), "user_skill:<id>" or "<term>-unclassified"
}

export interface TodoItem {
  id?: string
  description?: string  // Backend uses 'description'
  content?: string      // Keep for backward compatibility
  status: 'pending' | 'in_progress' | 'completed'
  activeForm?: string
  priority?: string
}

export interface TodoUpdatePayload {
  todo_list: TodoItem[]
}

export interface ApprovalRequestPayload {
  from_phase: string
  to_phase: string
  reason: string
  planned_actions: string[]
  risks: string[]
}

export interface QuestionRequestPayload {
  question: string
  context: string
  format: 'text' | 'single_choice' | 'multi_choice'
  options: string[]
  default_value?: string
}

export interface ResponsePayload {
  answer: string
  iteration_count: number
  phase: string
  task_complete: boolean
  response_tier?: 'conversational' | 'summary' | 'full_report'
}

export interface ExecutionStepPayload {
  step: Record<string, any>
}

export interface ErrorPayload {
  message: string
  recoverable: boolean
  /** Why, as a fixed code: llm_setup_failed, ws_ticket_invalid, invalid_frame, persist_failed. */
  code?: string
  /** The exception class, never its text (it can quote provider errors or keys). */
  error_class?: string
  /** The model provider's HTTP status, when the failure came from it. */
  provider_status?: number
  /** A provider 429's kind: rate_limited, quota_exhausted or request_too_large. */
  provider_error_kind?: string
  /** Seconds the agent waited for the rate limit to clear before giving up. */
  rate_limit_waited_s?: number
  http_status?: number
  /** The invalid frame's field paths, never their values. */
  fields?: string[]
}

export interface TaskCompletePayload {
  message: string
  final_phase: string
  total_iterations: number
}

export interface DeepThinkPayload {
  trigger_reason: string
  analysis: string
  iteration: number
  phase: string
}

export interface FileReadyPayload {
  filepath: string
  filename: string
  source: string
  description: string
}

// =============================================================================
// MESSAGE STRUCTURE
// =============================================================================

export interface ClientMessage<T = any> {
  type: MessageType
  payload: T
}

export interface ServerMessage<T = any> {
  type: MessageType
  payload: T
  timestamp: string
}

// =============================================================================
// WEBSOCKET CONNECTION STATE
// =============================================================================

export enum ConnectionStatus {
  DISCONNECTED = 'disconnected',
  CONNECTING = 'connecting',
  CONNECTED = 'connected',
  RECONNECTING = 'reconnecting',
  FAILED = 'failed',
}

export interface WebSocketState {
  status: ConnectionStatus
  isConnected: boolean
  reconnectAttempt: number
  error: Error | null
}

// =============================================================================
// ACTIVE SESSIONS (REST polling, not WebSocket)
// =============================================================================

export interface MsfSession {
  id: number
  type: 'meterpreter' | 'shell' | 'unknown'
  info: string
  connection: string
  target_ip: string
  chat_session_id: string | null
}

export interface MsfJob {
  id: number
  name: string
  payload: string
  port: number
}

export interface NonMsfSession {
  id: string
  type: string
  tool: string
  command: string
  chat_session_id: string | null
}

export interface SessionsData {
  sessions: MsfSession[]
  jobs: MsfJob[]
  non_msf_sessions: NonMsfSession[]
  cache_age_seconds: number
  agent_busy: boolean
}

export interface SessionInteractResult {
  busy: boolean
  output?: string
  message?: string
}

// =============================================================================
// TYPE GUARDS (Runtime type checking)
// =============================================================================

export function isServerMessage(data: any): data is ServerMessage {
  return (
    typeof data === 'object' &&
    data !== null &&
    'type' in data &&
    'payload' in data &&
    'timestamp' in data
  )
}

export function isMessageType(type: string): type is MessageType {
  return Object.values(MessageType).includes(type as MessageType)
}
