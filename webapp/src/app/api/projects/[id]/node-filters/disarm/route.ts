/**
 * POST /api/projects/[id]/node-filters/disarm — stop applying the rules to new scans.
 *
 * Changes nothing already muted; to undo mutes, disable the rules and apply to
 * the current graph.
 */
import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import { triageCaller } from '@/lib/triage/routeCaller'
import prisma from '@/lib/prisma'
import { writeAudit } from '@/lib/audit'
import { readJsonBody } from '@/lib/jsonBody'
import { realActorUserId } from '@/lib/triageClient'

interface RouteParams {
  params: Promise<{ id: string }>
}

export async function POST(request: NextRequest, { params }: RouteParams) {
  const { id } = await params
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const auth = await requirePermission(request, 'node_filters:manage', { projectId: id })
  if (auth instanceof NextResponse) return auth
  const caller = triageCaller(auth)

  const updated = await prisma.projectNodeFilter.updateMany({
    where: { projectId: caller.projectId, applyToScans: true },
    data: { applyToScans: false },
  })
  if (updated.count > 0) {
    await writeAudit({
      actorId: caller.userId,
      action: 'node_filters.disarmed',
      targetType: 'project',
      targetId: caller.projectId,
      after: { realActorUserId: await realActorUserId() },
      source: 'ui',
    })
  }
  return NextResponse.json({ armed: false })
}
