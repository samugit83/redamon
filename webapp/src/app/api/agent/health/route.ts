import { NextResponse } from 'next/server'
import { agentFetch, AgentUnreachableError } from '@/lib/agentFetch'
import { internalError, upstreamFailure } from '@/lib/routeErrors'
import { requireSession } from '@/lib/session'

export interface AgentHealthResponse {
  status: string
  version: string
  tools_loaded: number
  active_sessions: number
}

export async function GET() {
  const session = await requireSession()
  if (session instanceof NextResponse) return session
  try {
    // Short budget: this is the preflight the settings UI uses to decide
    // whether to offer a Test button, so it must fail fast rather than make
    // the operator wait out a full request timeout.
    const response = await agentFetch('/health', {}, { timeoutMs: 5_000 })

    if (!response.ok) {
      return NextResponse.json(
        { error: `Health check failed: ${response.status}` },
        { status: response.status }
      )
    }

    const data: AgentHealthResponse = await response.json()
    return NextResponse.json(data)
  } catch (error) {
    if (error instanceof AgentUnreachableError) {
      console.error('Agent health check: agent unreachable:', error.message, error.cause_)
      // describeAgentFailure's sentence names the service and what to run; the
      // code says refused/unresolved/timeout for a screenshot.
      const { code, cause } = upstreamFailure('agent', error.cause_, error.message).body
      return NextResponse.json({ error: error.message, code, ...(cause ? { cause } : {}) }, { status: 503 })
    }
    return internalError(error, 'Health check failed', { log: 'Agent health check error' })
  }
}
