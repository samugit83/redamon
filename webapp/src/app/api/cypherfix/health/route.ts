import { NextResponse } from 'next/server'
import { requireSession } from '@/lib/session'

const AGENT_API_URL = process.env.AGENT_API_URL || 'http://agent:8080'

// GET /api/cypherfix/health - Check triage + codefix agent health
export async function GET() {
  const session = await requireSession()
  if (session instanceof NextResponse) return session
  try {
    const agentHealth = await fetch(`${AGENT_API_URL}/health`, {
      signal: AbortSignal.timeout(5000),
    })

    if (!agentHealth.ok) {
      return NextResponse.json(
        { status: 'unhealthy', agent: 'unreachable' },
        { status: 503 }
      )
    }

    const agentData = await agentHealth.json()

    return NextResponse.json({
      status: 'healthy',
      agent: agentData,
      cypherfix: {
        triage: 'available',
        codefix: 'available',
      },
    })
  } catch (error) {
    console.error('CypherFix health check failed:', error)
    return NextResponse.json(
      { status: 'unhealthy', error: 'Agent unreachable' },
      { status: 503 }
    )
  }
}
