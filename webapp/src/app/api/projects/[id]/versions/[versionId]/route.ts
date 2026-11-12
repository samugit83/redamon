/**
 * Scan Timeline - Version Manager operations on one version (Section 5).
 *
 * PATCH  /api/projects/[id]/versions/[versionId]   rename / pin / unpin
 * DELETE /api/projects/[id]/versions/[versionId]   delete the row + its bytes
 *
 * Delete rules (the current version IS the live graph, so it has no bytes to
 * delete and removing its row would leave the project with no identity for the
 * graph): the current version cannot be deleted, and a pinned version must be
 * unpinned first. Both are destructive-confirmed in the UI and audited here.
 */
import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import prisma from '@/lib/prisma'
import { requireVersionInProject } from '@/lib/scanVersionAccess'
import { sanitizeVersionLabel } from '@/lib/scanVersionLabel'
import { writeAudit } from '@/lib/audit'
import { internalError, withRouteErrors } from '@/lib/routeErrors'

interface RouteParams {
  params: Promise<{ id: string; versionId: string }>
}

export const PATCH = withRouteErrors('Failed to update version', async (request: NextRequest, { params }: RouteParams) => {
  const { id, versionId } = await params

  const auth = await requirePermission(request, 'scan:versions', { projectId: id })
  if (auth instanceof NextResponse) return auth
  const eff = auth.effective
  const version = await requireVersionInProject(id, versionId)
  if (version instanceof NextResponse) return version

  const body = await request.json().catch(() => ({})) as { label?: unknown; pinned?: unknown }

  const data: { label?: string; pinned?: boolean } = {}

  if (body.label !== undefined) {
    const label = sanitizeVersionLabel(body.label)
    if (label instanceof Error) {
      return NextResponse.json({ error: label.message }, { status: 400 })
    }
    if (label) data.label = label
  }

  if (body.pinned !== undefined) {
    if (typeof body.pinned !== 'boolean') {
      return NextResponse.json({ error: 'pinned must be a boolean' }, { status: 400 })
    }
    data.pinned = body.pinned
  }

  if (Object.keys(data).length === 0) {
    return NextResponse.json({ error: 'Nothing to update (expected label and/or pinned)' }, { status: 400 })
  }

  try {
    const updated = await prisma.scanVersion.update({
      where: { id: versionId },
      data,
      select: { id: true, seq: true, label: true, pinned: true, isCurrent: true },
    })

    await writeAudit({
      actorId: eff.userId,
      action: 'scan-version.update',
      targetType: 'scanVersion',
      targetId: versionId,
      before: { label: version.label, pinned: version.pinned },
      after: { label: updated.label, pinned: updated.pinned },
    })

    return NextResponse.json({ version: updated })
  } catch (error) {
    return internalError(error, 'Failed to update version', { log: '[scanTimeline] version update failed' })
  }
})

export const DELETE = withRouteErrors('Failed to delete version', async (request: NextRequest, { params }: RouteParams) => {
  const { id, versionId } = await params

  const auth = await requirePermission(request, 'scan:versions_delete', { projectId: id })
  if (auth instanceof NextResponse) return auth
  const eff = auth.effective
  const version = await requireVersionInProject(id, versionId)
  if (version instanceof NextResponse) return version

  if (version.isCurrent) {
    return NextResponse.json(
      {
        error: 'The current version is the live graph and cannot be deleted. ' +
          'Activate another version or run a new scan instead.',
        isCurrent: true,
      },
      { status: 409 }
    )
  }

  if (version.pinned) {
    return NextResponse.json(
      { error: 'This version is pinned. Unpin it before deleting.', pinned: true },
      { status: 409 }
    )
  }

  // C-3: a version referenced by a NON-TERMINAL ScanJob must not be deleted - the
  // ScanJob FK is onDelete: Cascade, so deleting it would take a queued/running
  // job's history row with it.
  const liveJob = await prisma.scanJob.findFirst({
    where: { versionId, status: { in: ['queued', 'running'] } },
    select: { id: true },
  })
  if (liveJob) {
    return NextResponse.json(
      { error: 'A queued or running scan still references this version. Wait for it to finish before deleting.', hasLiveJob: true },
      { status: 409 }
    )
  }

  try {
    // The row owns its snapshot bytes; its ScanJob history cascades with it.
    await prisma.scanVersion.delete({ where: { id: versionId } })

    await writeAudit({
      actorId: eff.userId,
      action: 'scan-version.delete',
      targetType: 'scanVersion',
      targetId: versionId,
      before: {
        projectId: id,
        seq: version.seq,
        label: version.label,
        nodeCount: version.nodeCount,
        hadSnapshot: version.hasSnapshot,
      },
    })

    return NextResponse.json({ ok: true, deletedVersionId: versionId, seq: version.seq })
  } catch (error) {
    return internalError(error, 'Failed to delete version', { log: '[scanTimeline] version delete failed' })
  }
})
