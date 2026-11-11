import { NextResponse } from 'next/server'
import { fetchAgentDefaults, fetchReconDefaults } from '@/lib/reconPresets/server'
import { requireSession } from '@/lib/session'

// GET /api/projects/defaults - Get default project settings from recon + agent backends
export async function GET() {
  const session = await requireSession()
  if (session instanceof NextResponse) return session
  // Fetched in parallel. The recon half is required; the agent half is not: the
  // form falls back to the Prisma defaults for the agent settings. The MCP
  // preset apply calls the same fetchers and fails closed on either instead.
  const [reconResult, agentResult] = await Promise.allSettled([fetchReconDefaults(), fetchAgentDefaults()])

  if (reconResult.status === 'rejected') {
    console.error('Failed to fetch defaults from recon orchestrator:', reconResult.reason)
    return NextResponse.json(
      { error: 'Failed to fetch defaults from recon backend', code: 'recon_defaults_unavailable' },
      { status: 503 }
    )
  }

  let agentDefaults = {}
  if (agentResult.status === 'fulfilled') {
    agentDefaults = agentResult.value
  } else {
    console.warn('Agent API defaults unavailable, using recon/Prisma defaults for agent settings')
  }

  // Merge: recon defaults + agent defaults (agent overrides any overlapping keys)
  return NextResponse.json({ ...reconResult.value, ...agentDefaults })
}
