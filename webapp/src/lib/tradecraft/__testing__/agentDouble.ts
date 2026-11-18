/**
 * A double of the agent behind `agentFetch`: replaces global `fetch`, records every call (path
 * and parsed body) and answers the Tradecraft 2.0 routes as a healthy agent does, unless a test
 * sets its own answer. An answer may be a Response, or an Error the transport throws.
 */
import { vi } from 'vitest'

export interface AgentCall {
  path: string
  body: unknown
  headers: Record<string, string>
}

export type AgentAnswer = (path: string, body: unknown) => Response | Error | Promise<Response | Error>

export function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

/** The agent's default answers: every job accepted, every cancel acknowledged. */
export const healthyAgent: AgentAnswer = (path, body) => {
  if (path === '/tradecraft/v2/jobs') {
    const jobs = (body as { jobs: { job_id: string }[] }).jobs
    return json({ accepted: jobs.map(j => j.job_id), refused: [] }, 202)
  }
  if (/^\/tradecraft\/v2\/jobs\/[^/]+\/cancel$/.test(path)) return json({ ok: true })
  if (/^\/tradecraft\/v2\/users\/[^/]+\/cancel$/.test(path)) return json({ cancelled: 0 })
  return json({ detail: 'Not Found' }, 404)
}

/** A transport failure as Node's fetch throws it: `TypeError('fetch failed')` with the errno in `cause`. */
export function refused(code = 'ECONNREFUSED'): Error {
  return Object.assign(new TypeError('fetch failed'), { cause: Object.assign(new Error(`connect ${code}`), { code }) })
}

export function timedOut(): Error {
  return new DOMException('The operation was aborted due to timeout', 'TimeoutError')
}

export function stubAgent(answer: AgentAnswer = healthyAgent): { calls: AgentCall[]; setAnswer(a: AgentAnswer): void } {
  const calls: AgentCall[] = []
  let current = answer
  global.fetch = vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
    const path = new URL(String(url)).pathname
    const body = init?.body ? JSON.parse(String(init.body)) : null
    calls.push({ path, body, headers: (init?.headers ?? {}) as Record<string, string> })
    const a = await current(path, body)
    if (a instanceof Error) throw a
    return a
  }) as typeof fetch
  return { calls, setAnswer: (a) => { current = a } }
}
