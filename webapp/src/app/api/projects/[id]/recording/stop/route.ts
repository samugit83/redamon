import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import prisma from '@/lib/prisma'
import { internalError } from '@/lib/routeErrors'
import { publicRecordingSession, summarizeMaterial } from '@/lib/recordingSession'
import type { RecordingMaterial } from '@/lib/recordingSession'

interface RouteParams {
  params: Promise<{ id: string }>
}

// POST /api/projects/[id]/recording/stop — auth_profile:manage (the owner, or a co-owner with Manage). Ends the active recording
// (best-effort immediate; the injected tag also drops within one reconcile of
// expiry). Returns the masked summary of what was captured so the operator can
// confirm before committing it to the profile (G3).
export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const auth = await requirePermission(request, 'auth_profile:manage', { projectId: id })
    if (auth instanceof NextResponse) return auth

    const session = await prisma.recordingSession.findFirst({
      where: { projectId: id, state: 'active' },
      orderBy: { startedAt: 'desc' },
    })
    if (!session) {
      return NextResponse.json({ session: null, summary: summarizeMaterial(null) })
    }

    const stopped = await prisma.recordingSession.update({
      where: { id: session.id },
      data: { state: 'stopped', stoppedAt: new Date() },
    })
    return NextResponse.json({
      session: publicRecordingSession(stopped),
      summary: summarizeMaterial(stopped.pendingMaterial as RecordingMaterial | null),
    })
  } catch (error) {
    return internalError(error, 'Failed to stop recording')
  }
}
