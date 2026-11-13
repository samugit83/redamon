/**
 * Is an agent session really running on this project?
 *
 * Conversation.agentRunning is set and cleared by fire-and-forget PATCHes from
 * the agent. An agent that is restarted or killed mid-run never sends the clear,
 * so the flag stays true and locks the project: preset apply, rescope, graph
 * activation and the queued-scan dispatcher all wait on it.
 *
 * There is deliberately no time-to-live. A run legitimately lasts hours, so an
 * age proves nothing. The agent's own task registry is the truth, and it is only
 * asked when a flag is set. A flag whose session the agent does not hold is
 * cleared, conditionally on the row being unchanged since it was read, so a run
 * that starts between the read and the clear keeps its flag.
 *
 * FAIL CLOSED: an agent that cannot answer leaves a set flag counting as running.
 * Server-side only.
 */
import prisma from '@/lib/prisma'
import { agentFetch } from '@/lib/agentFetch'
import { upstreamFailure } from '@/lib/routeErrors'

export type AgentSessionState = 'running' | 'idle' | 'unverified'

const LIVE_CHECK_TIMEOUT_MS = 5_000

/**
 * Why the agent could not say which sessions are live: `agent_unreachable` or
 * `agent_timeout` (with the errno as `cause`) when it never answered, `agent_error` with
 * its HTTP status when it answered with an error, `agent_bad_answer` when the answer had no
 * session list. Codes and a status only, safe to show.
 */
export interface LiveCheckFailure {
  code: 'agent_unreachable' | 'agent_timeout' | 'agent_error' | 'agent_bad_answer'
  upstreamStatus?: number
  cause?: string
}

async function liveSessions(
  projectId: string,
): Promise<{ ids: Set<string>; loopStates: Record<string, string> } | { failure: LiveCheckFailure }> {
  let res: Response
  try {
    res = await agentFetch(
      `/agent-sessions/live?project_id=${encodeURIComponent(projectId)}`,
      { method: 'GET' },
      { timeoutMs: LIVE_CHECK_TIMEOUT_MS },
    )
  } catch (err) {
    console.error('[agentSessions] live-session check failed (treating a set flag as running):', err)
    // AgentUnreachableError keeps the fetch failure, with its errno, in `cause_`.
    const { body } = upstreamFailure('agent', (err as { cause_?: unknown } | null)?.cause_ ?? err, '')
    return { failure: { code: body.code as LiveCheckFailure['code'], ...(body.cause ? { cause: body.cause } : {}) } }
  }
  if (!res.ok) {
    console.warn(`[agentSessions] live-session check: the agent answered HTTP ${res.status} (treating a set flag as running)`)
    return { failure: { code: 'agent_error', upstreamStatus: res.status } }
  }
  let ids: unknown
  let loopStates: unknown
  try {
    const body = await res.json()
    ids = body?.session_ids
    loopStates = body?.loop_states
  } catch {
    ids = undefined
  }
  if (!Array.isArray(ids)) {
    console.warn('[agentSessions] live-session check: the agent answered without a session list (treating a set flag as running)')
    return { failure: { code: 'agent_bad_answer', upstreamStatus: res.status } }
  }
  return {
    ids: new Set(ids.filter((id): id is string => typeof id === 'string')),
    // Agent in the Loop runs only, keyed by session id (absent from older agents).
    loopStates: loopStates && typeof loopStates === 'object' && !Array.isArray(loopStates)
      ? Object.fromEntries(Object.entries(loopStates).filter(([, v]) => typeof v === 'string')) as Record<string, string>
      : {},
  }
}

/**
 * Whether a live Agent in the Loop run of this project is waiting for its
 * external agent to answer a step. False when the agent could not be asked.
 */
export async function agentLoopWaiting(projectId: string): Promise<boolean> {
  const live = await liveSessions(projectId)
  return 'loopStates' in live && Object.values(live.loopStates).includes('waiting_for_agent')
}

/** Session ids the agent holds a running task for, or null when it could not say. */
async function liveSessionIds(projectId: string): Promise<Set<string> | null> {
  const live = await liveSessions(projectId)
  return 'ids' in live ? live.ids : null
}

/**
 * 'running' when the agent confirms a flagged session, 'idle' when no flag is
 * set or every set flag was stale (and is now cleared), 'unverified' when a flag
 * is set and the agent could not be asked. A database error propagates: each
 * caller already treats that as busy.
 */
export async function checkAgentSessions(projectId: string): Promise<AgentSessionState> {
  const flagged = await prisma.conversation.findMany({
    where: { projectId, agentRunning: true },
    select: { id: true, sessionId: true, updatedAt: true },
  })
  if (flagged.length === 0) return 'idle'

  const live = await liveSessionIds(projectId)
  if (!live) return 'unverified'
  if (flagged.some(c => live.has(c.sessionId))) return 'running'

  let cleared = 0
  for (const c of flagged) {
    const res = await prisma.conversation.updateMany({
      where: { id: c.id, agentRunning: true, updatedAt: c.updatedAt },
      data: { agentRunning: false },
    })
    cleared += res.count
  }
  console.warn(`[agentSessions] cleared ${cleared} stale agentRunning flag(s) on project ${projectId}`)
  // A row that changed since it was read may be a run that just started.
  return cleared === flagged.length ? 'idle' : 'running'
}

/**
 * Whether the agent is running ONE session: true or false, or 'unverified' when the agent
 * could not be asked. The agent's answer decides, not the flag: a live session whose flag
 * was never set (its PATCH lost) is running, and a set flag the agent does not hold is
 * stale and cleared, conditionally, as checkAgentSessions does. A flag that changed
 * between the read and the clear may be a run that just started: it counts as running.
 */
export async function sessionRunningState(conversation: SessionRow): Promise<boolean | 'unverified'> {
  return (await sessionRunningCheck(conversation)).running
}

interface SessionRow {
  id: string
  projectId: string
  sessionId: string
  agentRunning: boolean
  updatedAt: Date
}

/** `sessionRunningState`, plus why the agent could not be asked when it is 'unverified'. */
export async function sessionRunningCheck(
  conversation: SessionRow,
): Promise<{ running: boolean | 'unverified'; failure?: LiveCheckFailure }> {
  const live = await liveSessions(conversation.projectId)
  if (!('ids' in live)) return { running: 'unverified', failure: live.failure }
  if (live.ids.has(conversation.sessionId)) return { running: true }
  if (!conversation.agentRunning) return { running: false }
  const res = await prisma.conversation.updateMany({
    where: { id: conversation.id, agentRunning: true, updatedAt: conversation.updatedAt },
    data: { agentRunning: false },
  })
  if (res.count === 0) return { running: true }
  console.warn(`[agentSessions] cleared a stale agentRunning flag on session ${conversation.sessionId}`)
  return { running: false }
}

/**
 * Who is running an agent session on this project: the author (Conversation.userId, the ticket's
 * `sub`) of each flagged session the agent confirms live, for the second-writer check (step 5.11).
 * Read-only: a stale flag is left for checkAgentSessions to clear. With no flag set nobody is, and
 * the agent is not asked.
 */
export async function runningSessionAuthors(
  projectId: string,
): Promise<{ userIds: string[] } | { failure: LiveCheckFailure }> {
  const flagged = await prisma.conversation.findMany({
    where: { projectId, agentRunning: true },
    select: { userId: true, sessionId: true },
  })
  if (flagged.length === 0) return { userIds: [] }
  const live = await liveSessions(projectId)
  if (!('ids' in live)) return { failure: live.failure }
  return { userIds: [...new Set(flagged.filter(c => live.ids.has(c.sessionId)).map(c => c.userId))] }
}

/** The phrase describeLiveGraphWriters and the MCP busy messages use, or null when idle. */
export function describeAgentSessionState(state: AgentSessionState): string | null {
  if (state === 'running') return 'an agent session is running'
  if (state === 'unverified') return 'an agent session is marked running and the agent could not be reached to confirm it'
  return null
}
