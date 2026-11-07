/**
 * The MCP server's Agent in the Loop calls into the agent.
 *
 * Same shape as kaliClient.ts: the MCP layer resolves a personal access token
 * to ONE user (and that user's owned projects) and hands that identity to the
 * agent, whose step broker checks it on every operation. Every call carries an
 * explicit timeout; the wait is a long poll, so its timeout is the wait plus a
 * margin.
 */
import { agentBaseUrl } from '@/lib/agentFetch'
import { internalKeyHeaders } from '@/lib/agentAuth'
import { McpToolError } from '@/lib/mcp/errors'

const SHORT_TIMEOUT_MS = 15_000
const WAIT_MARGIN_S = 10

export interface LoopIdentity {
  userId: string
  /** The token id: the agent records driver activity per token. */
  driverId: string
  /** The client-chosen name that keys prompt dedup (two windows may share a token). */
  driverName?: string
  projectIds: string[]
}

export interface LoopWaitArgs extends LoopIdentity {
  sessionId?: string
  waitSeconds: number
  delivery: 'dedup' | 'full'
}

export interface LoopGetArgs extends LoopIdentity {
  stepId: string
  cursor: number
  full: boolean
}

export interface LoopAnswerArgs extends LoopIdentity {
  stepId: string
  answer?: string
  declined?: boolean
  reason?: string
  answeredBy: { tokenPrefix: string; tokenName: string }
}

/** The step a driver reads. Shape owned by agentic/agent_in_the_loop/broker.py. */
export interface LoopStepView {
  contractVersion: number
  stepId: string
  sessionId: string
  projectId: string
  purpose: string
  iteration?: number
  attempt: number
  member?: { id: string; name: string }
  answerFormat: string
  lastInstruction: string
  prompt: string
  page: { cursor: number; nextCursor: number | null; totalChars: number }
  leaseExpiresInSeconds: number
  deadlineInSeconds: number
  /** If no loop call of the driver reaches RedAmon for this long, the whole run ends. */
  runEndsIfSilentSeconds: number
}

export interface LoopSessionView {
  sessionId: string
  projectId: string
  state: string
  detail: Record<string, unknown>
  sinceSeconds: number
  openSteps: number
}

export interface LoopWaitResult {
  step: LoopStepView | null
  sessions: LoopSessionView[]
  hint: string
}

export interface LoopAnswerResult {
  ok: true
  projectId: string
  sessionId: string
  purpose: string
  iteration: number | null
}

const FIXED: Record<string, string> = {
  disabled: 'Agent in the Loop is turned off on this RedAmon deployment. An operator enables it ' +
    'with AGENT_IN_THE_LOOP_ENABLED=true.',
  agent_outdated: 'The RedAmon agent does not support Agent in the Loop yet: rebuild and ' +
    'restart the agent.',
  not_found: 'No such step is open for you. Call loop_wait_step for the next one.',
  step_closed: 'This step is already answered, expired or cancelled. If you did not answer it, ' +
    'RedAmon gave up on it, which can end the run: call loop_wait_step to see the session\'s ' +
    'state, and tell the person.',
  answer_too_large: 'The answer is larger than this RedAmon deployment accepts.',
  bad_args: 'The agent refused the request as invalid.',
  loop_too_many_steps: 'Too many steps are waiting. Answer the open ones first.',
  agent_refused: 'The agent refused the request.',
  agent_failed: 'The agent could not handle the request.',
  agent_unreachable: 'The RedAmon agent is unreachable.',
}

function fail(code: string): never {
  throw new McpToolError(FIXED[code] ?? FIXED.agent_failed, code)
}

/** Map an agent failure to a fixed sentence. The body's text is never quoted. */
async function failure(resp: Response): Promise<never> {
  let body: Record<string, unknown> = {}
  try {
    body = (await resp.json()) as Record<string, unknown>
  } catch {
    // Non-JSON: nothing to read.
  }
  const code = typeof body.code === 'string' ? body.code : ''
  if (resp.status === 404) {
    if (code === 'loop_disabled') fail('disabled')
    // FastAPI's own 404 ({"detail": "Not Found"}): an agent older than the feature.
    if (!code) fail('agent_outdated')
    fail(code === 'not_found' ? 'not_found' : 'agent_refused')
  }
  if (resp.status === 409) fail('step_closed')
  if (resp.status === 413) fail('answer_too_large')
  if (resp.status === 422) fail('bad_args')
  if (resp.status === 429) fail('loop_too_many_steps')
  if (resp.status < 500) {
    console.error(`[mcp] loop ${resp.status}${code ? ` (${code})` : ''}`)
    fail('agent_refused')
  }
  console.error(`[mcp] loop agent failed (${resp.status})`)
  fail('agent_failed')
}

async function post(path: string, body: Record<string, unknown>, timeoutMs: number): Promise<unknown> {
  let resp: Response
  try {
    resp = await fetch(`${agentBaseUrl()}${path}`, {
      method: 'POST',
      headers: internalKeyHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs),
    })
  } catch (err) {
    console.error('[mcp] loop transport error:', err instanceof Error ? err.name : 'unknown')
    fail('agent_unreachable')
  }
  if (!resp.ok) await failure(resp)
  return resp.json()
}

function identity(a: LoopIdentity): Record<string, unknown> {
  return {
    user_id: a.userId,
    driver_id: a.driverId,
    ...(a.driverName ? { driver_name: a.driverName } : {}),
    project_ids: a.projectIds,
  }
}

export async function loopWait(a: LoopWaitArgs): Promise<LoopWaitResult> {
  return (await post('/loop/steps/wait', {
    ...identity(a),
    ...(a.sessionId ? { session_id: a.sessionId } : {}),
    wait_seconds: a.waitSeconds,
    delivery: a.delivery,
  }, (a.waitSeconds + WAIT_MARGIN_S) * 1000)) as LoopWaitResult
}

export async function loopGet(a: LoopGetArgs): Promise<{ step: LoopStepView }> {
  return (await post(`/loop/steps/${a.stepId}/get`, {
    ...identity(a),
    cursor: a.cursor,
    full: a.full,
  }, SHORT_TIMEOUT_MS)) as { step: LoopStepView }
}

export async function loopAnswer(a: LoopAnswerArgs): Promise<LoopAnswerResult> {
  return (await post(`/loop/steps/${a.stepId}/answer`, {
    ...identity(a),
    ...(a.declined ? { declined: true, reason: a.reason ?? '' } : { answer: a.answer }),
    answered_by: { token_prefix: a.answeredBy.tokenPrefix, token_name: a.answeredBy.tokenName },
  }, SHORT_TIMEOUT_MS)) as LoopAnswerResult
}
