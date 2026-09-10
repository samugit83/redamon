import { NextRequest, NextResponse } from 'next/server'
import { requireProjectOwner, callGraphTriage } from '@/lib/triageClient'

/**
 * POST /api/triage/unmute - restore a suppressed finding.
 *
 * Body: { projectId, nodeId }
 *
 * Lossless: the finding keeps every relationship and property it had. The triage
 * VERDICT is deliberately left in place -- unmuting means "show me this again",
 * not "forget the analysis".
 */
export async function POST(request: NextRequest) {
  const body = await request.json().catch(() => ({}))
  const { projectId, nodeId } = body ?? {}

  const caller = await requireProjectOwner(projectId)
  if (caller instanceof NextResponse) return caller
  if (!nodeId || typeof nodeId !== 'string') {
    return NextResponse.json({ error: 'nodeId is required' }, { status: 400 })
  }

  return callGraphTriage('unmute', caller, { node_id: nodeId })
}
