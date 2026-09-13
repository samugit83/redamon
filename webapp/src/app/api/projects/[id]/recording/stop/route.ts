import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { requireEffectiveUser, requireProjectAccess } from '@/lib/access'
import { publicRecordingSession, summarizeMaterial } from '@/lib/recordingSession'
import type { RecordingMaterial } from '@/lib/recordingSession'

interface RouteParams {
  params: Promise<{ id: string }>
}

// POST /api/projects/[id]/recording/stop — owner-only. Ends the active recording
// (best-effort immediate; the injected tag also drops within one reconcile of
// expiry). Returns the masked summary of what was captured so the operator can
// confirm before committing it to the profile (G3).
export async function POST(_request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const eff = await requireEffectiveUser()
    if (eff instanceof NextResponse) return eff
    const access = await requireProjectAccess(eff, id)
    if (access instanceof NextResponse) return access

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
    console.error('Failed to stop recording:', error)
    return NextResponse.json({ error: 'Failed to stop recording' }, { status: 500 })
  }
}
