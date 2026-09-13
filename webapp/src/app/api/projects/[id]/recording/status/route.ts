import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { requireEffectiveUser, requireProjectAccess } from '@/lib/access'
import { publicRecordingSession, summarizeMaterial } from '@/lib/recordingSession'
import type { RecordingMaterial } from '@/lib/recordingSession'

interface RouteParams {
  params: Promise<{ id: string }>
}

// GET /api/projects/[id]/recording/status — owner-only. The RecordingModal polls
// this for the live observed counter (G4) and, once stopped, the masked summary.
// Also reports whether ANOTHER project holds the single global slot (G10).
export async function GET(_request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const eff = await requireEffectiveUser()
    if (eff instanceof NextResponse) return eff
    const access = await requireProjectAccess(eff, id)
    if (access instanceof NextResponse) return access

    const now = new Date()
    const session = await prisma.recordingSession.findFirst({
      where: { projectId: id, state: { in: ['active', 'stopped'] } },
      orderBy: { startedAt: 'desc' },
    })

    const otherActive = await prisma.recordingSession.findFirst({
      where: { state: 'active', expiresAt: { gt: now }, projectId: { not: id } },
      select: { id: true },
    })

    return NextResponse.json({
      session: session ? publicRecordingSession(session) : null,
      summary: session ? summarizeMaterial(session.pendingMaterial as RecordingMaterial | null) : null,
      otherProjectRecording: !!otherActive,
    })
  } catch (error) {
    console.error('Failed to read recording status:', error)
    return NextResponse.json({ error: 'Failed to read recording status' }, { status: 500 })
  }
}
