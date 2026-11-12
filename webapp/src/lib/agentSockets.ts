/**
 * Ends the agent sockets that rested on access someone just lost (DV-21), through the
 * agent's master-key POST /ws/close. A WebSocket ticket is checked only when its socket
 * opens, so refusing new tickets alone would leave an open Kali terminal running.
 *
 * `scope` is the agent's rule for an admin's act-as sockets: `access` (a grant the user's
 * own access gave) leaves open the sockets an admin opened acting as the user; `account`
 * (a disabled or deleted account) closes them too; `act_as` (one impersonation ended) closes
 * only what admin `actorId` opened acting as `userId`, and needs both. An agent from before
 * `act_as` refuses it (422), so it never closes wider than asked.
 *
 * Never throws: the change it follows is already committed and stands. A close the agent
 * did not confirm logs `[rbac] socket-close failed` with a fixed reason, and the caller
 * reports it. Server side only.
 */
import { AgentUnreachableError, agentFetch } from '@/lib/agentFetch'
import { safeErrorCode } from '@/lib/routeErrors'
import type { WsSocket } from '@/lib/wsTicket'

export interface CloseSocketsRequest {
  userId?: string
  projectId?: string
  /** The admin of the impersonation (`act_as` only). */
  actorId?: string
  kinds: WsSocket[]
  scope?: 'access' | 'account' | 'act_as'
}

export type CloseSocketsResult =
  | { ok: true; closed: number; stoppedRuns: number }
  | { ok: false; reason: string }

const CLOSE_TIMEOUT_MS = 10_000

const count = (v: unknown) => (typeof v === 'number' && Number.isFinite(v) ? v : 0)

function failed(req: CloseSocketsRequest, reason: string): CloseSocketsResult {
  console.error(
    `[rbac] socket-close failed user=${req.userId ?? '-'}${req.actorId ? ` actor=${req.actorId}` : ''} project=${req.projectId ?? '-'} `
    + `kinds=${req.kinds.join(',')}: ${reason}`,
  )
  return { ok: false, reason }
}

export async function closeAgentSockets(req: CloseSocketsRequest): Promise<CloseSocketsResult> {
  let res: Response
  try {
    res = await agentFetch('/ws/close', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ...(req.userId ? { user_id: req.userId } : {}),
        ...(req.actorId ? { actor_id: req.actorId } : {}),
        ...(req.projectId ? { project_id: req.projectId } : {}),
        kinds: req.kinds,
        scope: req.scope ?? 'access',
      }),
    }, { timeoutMs: CLOSE_TIMEOUT_MS })
  } catch (err) {
    return failed(req, err instanceof AgentUnreachableError ? 'agent_unreachable' : safeErrorCode(err))
  }
  if (!res.ok) return failed(req, `agent_http_${res.status}`)
  const body = await res.json().catch(() => null) as { closed?: unknown; stopped_runs?: unknown } | null
  return { ok: true, closed: count(body?.closed), stoppedRuns: count(body?.stopped_runs) }
}
