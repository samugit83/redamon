/**
 * POST /api/internal/triage-runs/[runId]/heartbeat — "still here", and "should I stop?".
 *
 * The agent calls this every 30 seconds. The reply carries `abort`, which is
 * how the run learns that something outside it changed: an operator pressed
 * Stop, the project was deleted, or a version activation started. The agent
 * treats two consecutive failures as an abort, so a webapp it cannot reach
 * stops the run rather than letting it publish blind.
 */
import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { isInternalRequest } from '@/lib/session'
import { isActivationInProgress } from '@/lib/activationLock'

interface RouteParams {
  params: Promise<{ runId: string }>
}

export async function POST(request: NextRequest, { params }: RouteParams) {
  if (!isInternalRequest(request)) {
    return NextResponse.json({ error: 'Not found' }, { status: 404 })
  }

  const { runId } = await params
  const run = await prisma.triageRun.findUnique({
    where: { id: runId },
    select: { id: true, projectId: true, status: true },
  })

  // A missing run means the project was deleted (the relation cascades), which
  // is exactly the case the agent must stop for.
  if (!run) {
    return NextResponse.json(
      { status: 'gone', abort: true, reason: 'the run no longer exists' },
      { status: 404 }
    )
  }

  if (run.status !== 'running') {
    return NextResponse.json({
      status: run.status,
      abort: true,
      reason: `the run is ${run.status}`,
    })
  }

  if (await isActivationInProgress(run.projectId)) {
    return NextResponse.json({
      status: run.status,
      abort: true,
      reason: 'a version activation started',
    })
  }

  await prisma.triageRun.update({
    where: { id: runId },
    data: { heartbeatAt: new Date() },
  })

  return NextResponse.json({ status: 'running', abort: false })
}
