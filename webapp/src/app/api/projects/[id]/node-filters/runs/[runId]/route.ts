/**
 * GET /api/projects/[id]/node-filters/runs/[runId] — one apply's progress and result.
 *
 * Polled by the Mute Rules page while an apply runs. Scoped to the project:
 * a run id from another project is a 404 like any other miss.
 */
import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import { triageCaller } from '@/lib/triage/routeCaller'
import prisma from '@/lib/prisma'
import { RUN_SELECT } from '@/lib/nodeFilters/server'
import { findLiveNodeFilterRun } from '@/lib/nodeFilterRun'

interface RouteParams {
  params: Promise<{ id: string; runId: string }>
}

export async function GET(request: NextRequest, { params }: RouteParams) {
  const { id, runId } = await params
  const auth = await requirePermission(request, 'triage:read', { projectId: id })
  if (auth instanceof NextResponse) return auth
  const caller = triageCaller(auth)
  // Sweeps a run whose agent died, so polling a lost run ends in `failed`
  // instead of spinning for ever.
  await findLiveNodeFilterRun(caller.projectId).catch(() => null)
  const run = await prisma.nodeFilterRun.findFirst({
    where: { id: runId, projectId: caller.projectId },
    select: RUN_SELECT,
  })
  if (!run) return NextResponse.json({ error: 'Not found' }, { status: 404 })
  return NextResponse.json(run)
}
