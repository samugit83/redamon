/**
 * The two agent routes the webapp calls for a person's Kali sandbox (group 1, B.10, B.12), with the
 * master key (`agentFetch`, as the agent proxy routes call it): forget a person's clients after
 * their sandboxes stopped, and push a person's tunnel configuration to their sandbox.
 *
 * Neither throws: the answer says whether the agent took it, so a stop or a settings save never
 * fails on the agent. The tunnel configuration holds the person's ngrok token and chisel secret: it
 * is sent, never logged.
 *
 * Server-side only.
 */
import { agentFetch, AgentUnreachableError } from '@/lib/agentFetch'
import { upstreamFailure } from '@/lib/routeErrors'
import { AGENT_ROUTE_DROP, AGENT_ROUTE_TUNNEL, type SandboxView } from './contract'
import { validUserId } from './orchestratorClient'

export interface AgentCallResult {
  ok: boolean
  /** The agent's HTTP status; 0 when it did not answer or was never asked. */
  status: number
  /** Why not: `invalid_user_id`, `agent_unreachable` / `agent_timeout`, or the agent's own `agent_<status>`. */
  code?: string
}

/** A person's tunnel settings (their own user_settings), pushed to their sandbox's tunnel manager. Empty stops it. */
export interface SandboxTunnelConfig {
  ngrokAuthtoken: string | null
  chiselServerUrl: string | null
  chiselAuth: string | null
}

async function callAgentRoute(route: string, userId: string, init: RequestInit): Promise<AgentCallResult> {
  if (!validUserId(userId)) return { ok: false, status: 0, code: 'invalid_user_id' }
  const path = route.replace('{user_id}', encodeURIComponent(userId))
  try {
    const res = await agentFetch(path, init)
    return res.ok ? { ok: true, status: res.status } : { ok: false, status: res.status, code: `agent_${res.status}` }
  } catch (err) {
    const cause = err instanceof AgentUnreachableError ? err.cause_ : err
    const { code } = upstreamFailure('agent', cause, '').body
    console.warn(`[sandbox] agent ${route} not reached: ${code}`)
    return { ok: false, status: 0, code }
  }
}

/**
 * POST /sandboxes/{user_id}/drop at the agent: forget every client and handle of the person, both
 * views or only `view`. A background job whose handle is forgotten ends, so a stop of one view
 * names it and leaves the other view's work alone.
 */
export function dropSandboxClient(userId: string, view?: SandboxView): Promise<AgentCallResult> {
  const route = view ? `${AGENT_ROUTE_DROP}?view=${encodeURIComponent(view)}` : AGENT_ROUTE_DROP
  return callAgentRoute(route, userId, { method: 'POST' })
}

/** POST /sandboxes/{user_id}/tunnel at the agent: the agent starts the person's own view and pushes the config. */
export function pushSandboxTunnel(userId: string, config: SandboxTunnelConfig): Promise<AgentCallResult> {
  return callAgentRoute(AGENT_ROUTE_TUNNEL, userId, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      ngrokAuthtoken: config.ngrokAuthtoken,
      chiselServerUrl: config.chiselServerUrl,
      chiselAuth: config.chiselAuth,
    }),
  })
}
