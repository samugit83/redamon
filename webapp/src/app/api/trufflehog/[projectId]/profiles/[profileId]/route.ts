import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import prisma from '@/lib/prisma'
import { Prisma } from '@prisma/client'
import { getTrufflehogSource, rejectTrufflehogSecretFields } from '@/lib/trufflehogSources'
import { internalError } from '@/lib/routeErrors'

interface RouteParams {
  params: Promise<{ projectId: string; profileId: string }>
}

export async function PATCH(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId, profileId } = await params
    const auth = await requirePermission(request, 'scan:secrets', { projectId })
    if (auth instanceof NextResponse) return auth

    // Scoped to the project, not just the id: a profile id from another project
    // must 404, not update.
    const profile = await prisma.trufflehogScanProfile.findFirst({
      where: { id: profileId, projectId },
      select: { id: true, source: true },
    })
    if (!profile) return NextResponse.json({ error: 'Profile not found' }, { status: 404 })

    const body = await request.json().catch(() => ({}))
    const data: { label?: string; config?: Prisma.InputJsonValue } = {}

    if (typeof body.label === 'string') data.label = body.label.slice(0, 200)
    if (body.config && typeof body.config === 'object') {
      const config = body.config as Record<string, unknown>
      const rejected = rejectTrufflehogSecretFields(profile.source, config)
      if (rejected) return NextResponse.json({ error: rejected }, { status: 400 })
      data.config = config as Prisma.InputJsonValue
    }

    // The source is the run key and the unique-constraint half; changing it
    // would silently re-point history, findings and the queued job's identity.
    if (body.source && getTrufflehogSource(String(body.source))?.id !== profile.source) {
      return NextResponse.json(
        { error: 'A profile\'s source cannot be changed. Delete it and add the other source.' },
        { status: 400 },
      )
    }

    const updated = await prisma.trufflehogScanProfile.update({
      where: { id: profileId },
      data,
    })
    return NextResponse.json({ profile: updated })
  } catch (error) {
    return internalError(error, 'Failed to save the source', { log: 'Error updating TruffleHog profile' })
  }
}

export async function DELETE(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId, profileId } = await params
    const auth = await requirePermission(request, 'scan:secrets', { projectId })
    if (auth instanceof NextResponse) return auth

    const profile = await prisma.trufflehogScanProfile.findFirst({
      where: { id: profileId, projectId },
      select: { id: true },
    })
    if (!profile) return NextResponse.json({ error: 'Profile not found' }, { status: 404 })

    await prisma.trufflehogScanProfile.delete({ where: { id: profileId } })
    return NextResponse.json({ ok: true })
  } catch (error) {
    return internalError(error, 'Failed to delete the source', { log: 'Error deleting TruffleHog profile' })
  }
}
