import { NextResponse } from 'next/server'
import { agentFetch, AgentUnreachableError } from '@/lib/agentFetch'

export interface AgentHealthResponse {
  status: string
  version: string
  tools_loaded: number
  active_sessions: number
}

export async function GET() {
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
      return NextResponse.json({ error: error.message }, { status: 503 })
    }
    console.error('Agent health check error:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Health check failed' },
      { status: 500 }
    )
  }
}
