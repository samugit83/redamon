/**
 * The agent's workspace-import routes answer a 4xx as `{error, code}` with a
 * fixed sentence per code, plus a few machine fields the browser acts on. Pass
 * those through; a 5xx keeps the route's own message.
 *
 * Server-side only.
 */
import { NextResponse } from 'next/server'
import { readUpstreamBody } from '@/lib/routeErrors'
import { agentErrorResponse } from '../agentProxy'

const PASSED_FIELDS = ['expectedOffset', 'jobId'] as const

export async function codedAgentError(res: Response, message: string): Promise<NextResponse> {
  if (res.status >= 500) return agentErrorResponse(res, message)
  const body = await readUpstreamBody(res)
  const extra: Record<string, unknown> = {}
  for (const key of PASSED_FIELDS) {
    const v = body.json?.[key]
    if (typeof v === 'number' || (typeof v === 'string' && /^[0-9a-f]{1,64}$/.test(v))) extra[key] = v
  }
  return NextResponse.json({
    error: body.text || message,
    code: body.code ?? 'agent_error',
    upstreamStatus: res.status,
    ...extra,
  }, { status: res.status })
}
