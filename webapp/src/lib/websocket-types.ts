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
  skills: string[]
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
}

export interface ThinkingPayload {
  iteration: number
  phase: string
  thought: string
  reasoning: string
  action?: string
  input_tokens?: number
  output_tokens?: number
}

export interface ThinkingChunkPayload {
  chunk: string
}

export interface ToolStartPayload {
  tool_name: string
  tool_args: Record<string, any>
  wave_id?: string
}

export interface ToolOutputChunkPayload {
  tool_name: string
  chunk: string
  is_final: boolean
  wave_id?: string
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
  attack_path_type?: string  // "cve_exploit", "brute_force_credential_guess", "phishing_social_engineering", "denial_of_service", or "<term>-unclassified"
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
