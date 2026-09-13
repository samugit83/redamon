/**
 * POST /api/internal/triage-runs/[runId]/publish — claim the right to write.
 *
 * Steps A to D are entirely in memory; this is the gate between them and the
 * only step that touches the graph. The transition is a conditional update, so
 * a run that lost its claim while it was thinking writes NOTHING rather than
 * writing part of a result onto a graph somebody else has since replaced.
 */
import { NextRequest, NextResponse } from 'next/server'
import { isInternalRequest } from '@/lib/session'
import { claimPublish } from '@/lib/triageRun'

interface RouteParams {
  params: Promise<{ runId: string }>
}

export async function POST(request: NextRequest, { params }: RouteParams) {
  if (!isInternalRequest(request)) {
    return NextResponse.json({ error: 'Not found' }, { status: 404 })
  }

  const { runId } = await params
  const claim = await claimPublish(runId)
  if (!claim.ok) {
    return NextResponse.json(
      { error: claim.reason, errorClass: claim.errorClass },
      { status: claim.errorClass === 'unknown_run' ? 404 : 409 }
    )
  }
  return NextResponse.json({ status: 'publishing' })
}
