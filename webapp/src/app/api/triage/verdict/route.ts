import { NextRequest, NextResponse } from 'next/server'
import { requireProjectOwner, callGraphTriage } from '@/lib/triageClient'

const VALID = ['confirmed', 'likely_noise', 'needs_verification', 'unreviewed']

/**
 * POST /api/triage/verdict - record the operator's own judgement on a finding.
 *
 * Body: { projectId, nodeId, status, reason? }
 *
 * Stamps `triage_source = 'human'`, which is what makes a later AI triage run
 * skip the row instead of overwriting the decision.
 */
export async function POST(request: NextRequest) {
  const body = await request.json().catch(() => ({}))
  const { projectId, nodeId, status, reason } = body ?? {}

  const caller = await requireProjectOwner(projectId)
  if (caller instanceof NextResponse) return caller
  if (!nodeId || typeof nodeId !== 'string') {
    return NextResponse.json({ error: 'nodeId is required' }, { status: 400 })
  }
  if (!VALID.includes(status)) {
    return NextResponse.json(
      { error: `status must be one of ${VALID.join(', ')}` },
      { status: 400 },
    )
  }

  return callGraphTriage('human_verdict', caller, {
    node_id: nodeId,
    status,
    reason: typeof reason === 'string' ? reason.slice(0, 500) : '',
  })
}
