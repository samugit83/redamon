/**
 * DELETE /api/projects/[id]/node-filters/exemptions?label= — let rules mute these again.
 *
 * An exemption is recorded whenever an operator unmutes a finding, so no rule
 * mutes it again. Clearing them hands those findings back to the rules at the
 * next sweep. `label` narrows the clear to one finding label (a kind panel
 * passes its own); without it every exemption in the project goes.
 */
import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import { triageCaller } from '@/lib/triage/routeCaller'
import prisma from '@/lib/prisma'
import { writeAudit } from '@/lib/audit'
import { realActorUserId } from '@/lib/triageClient'
import { MUTEABLE_FINDING_LABELS } from '@/lib/mcp/findingLabels'

interface RouteParams {
  params: Promise<{ id: string }>
}

export async function DELETE(request: NextRequest, { params }: RouteParams) {
  const { id } = await params
  const auth = await requirePermission(request, 'node_filters:manage', { projectId: id })
  if (auth instanceof NextResponse) return auth
  const caller = triageCaller(auth)

  const label = request.nextUrl.searchParams.get('label')
  if (label && !(MUTEABLE_FINDING_LABELS as readonly string[]).includes(label)) {
    return NextResponse.json({ error: 'unknown label' }, { status: 400 })
  }
  const deleted = await prisma.nodeFilterExemption.deleteMany({
    where: { projectId: caller.projectId, ...(label ? { label } : {}) },
  })
  if (deleted.count > 0) {
    await writeAudit({
      actorId: caller.userId,
      action: 'node_filters.exemptions_cleared',
      targetType: 'project',
      targetId: caller.projectId,
      after: { label: label ?? 'all', count: deleted.count, realActorUserId: await realActorUserId() },
      source: 'ui',
    })
  }
  return NextResponse.json({ cleared: deleted.count })
}
