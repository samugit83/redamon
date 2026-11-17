/**
 * Stopping an account's Tradecraft ingestion jobs when the account goes away or is disabled
 * (R-201, R-208, D-10), whatever the RBAC switches say: a job may still be running when its
 * account goes.
 *
 * The flag on each unfinished job is the cancel: whichever copy of the agent runs a job reads it
 * between pages. The agent call only makes it stop sooner, so a lost agent never blocks a delete;
 * a job that outlives the account finds no row to write to, since every agent write is keyed by
 * the resource and the user (T1.4) and the cascade removed both.
 */
import prisma from '@/lib/prisma'
import { agentFetch, AgentUnreachableError } from '@/lib/agentFetch'
import { safeErrorCode, upstreamFailure } from '@/lib/routeErrors'
import { AGENT_ROUTES, UNFINISHED_JOB_STATUSES, UserCancelAnswer } from './agentContract'

const CANCEL_TIMEOUT_MS = 5_000

export interface UserJobsCancelled {
  /** Unfinished jobs flagged, or the error code when the flag could not be written. */
  flagged: number | { error: string }
  /** What the agent stopped, or the error code when it could not be told. */
  agent: number | { error: string }
}

/** Never throws: each failure is logged with a fixed code and answered. */
export async function cancelUserTradecraftJobs(userId: string): Promise<UserJobsCancelled> {
  let flagged: UserJobsCancelled['flagged']
  try {
    const { count } = await prisma.tradecraftIngestionJob.updateMany({
      where: { userId, status: { in: [...UNFINISHED_JOB_STATUSES] } },
      data: { cancelRequested: true },
    })
    flagged = count
  } catch (err) {
    console.error(`[tradecraft] user_cancel_flag_failed user=${userId} code=${safeErrorCode(err)}`)
    flagged = { error: safeErrorCode(err) }
  }

  // Every job the agent runs has its row first, so the flag reaches every job there is; the call
  // only makes the agent see it sooner. With nothing flagged (none unfinished, or the write
  // failed and was reported) there is nothing for it to hurry.
  if (typeof flagged !== 'number' || flagged === 0) return { flagged, agent: 0 }
  let agent: UserJobsCancelled['agent']
  try {
    const res = await agentFetch(AGENT_ROUTES.cancelUser(userId), {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}',
    }, { timeoutMs: CANCEL_TIMEOUT_MS })
    const answer = res.ok ? UserCancelAnswer.safeParse(await res.json().catch(() => null)) : null
    agent = answer?.success ? answer.data.cancelled : { error: res.ok ? 'agent_bad_answer' : `agent_http_${res.status}` }
  } catch (err) {
    agent = { error: err instanceof AgentUnreachableError ? upstreamFailure('agent', err.cause_, '').body.code : safeErrorCode(err) }
  }
  if (typeof agent !== 'number') console.error(`[tradecraft] user_cancel_agent_failed user=${userId} code=${agent.error}`)
  return { flagged, agent }
}
