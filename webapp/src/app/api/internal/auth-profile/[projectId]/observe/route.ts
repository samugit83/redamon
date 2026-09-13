import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { isInternalRequest } from '@/lib/session'
import { mergeMaterial, OBSERVE_GRACE_MS } from '@/lib/recordingSession'
import { parseObservedMaterial } from '@/lib/observeMaterial'

interface RouteParams {
  params: Promise<{ projectId: string }>
}

// POST /api/internal/auth-profile/[projectId]/observe — INTERNAL only.
// The ingest worker POSTs login material extracted (pre-redaction) from an
// operator-recorded transaction. We accumulate it on the active RecordingSession
// (never straight onto the profile — the operator confirms on stop, G3), bump
// the observed counter (G4) and record any error. The corpus row stays redacted.
export async function POST(request: NextRequest, { params }: RouteParams) {
  if (!isInternalRequest(request)) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }
  try {
    const { projectId } = await params
    let body: unknown
    try {
      body = await request.json()
    } catch {
      return NextResponse.json({ error: 'Invalid JSON' }, { status: 400 })
    }
    const b = (body || {}) as Record<string, unknown>

    // G6: the tenant is the recording's owner, resolved server-side from the
    // session row — never a body-supplied user id. Bind the observation to the
    // named session when given, else the project's active one.
    const sessionId = typeof b.sessionId === 'string' ? b.sessionId : undefined
    const now = new Date()
    const session = await prisma.recordingSession.findFirst({
      where: {
        projectId,
        // Expiry closes the window, but a STOPPED session still accepts records
        // for a short grace period: the ingest worker polls the spool on a ~1s
        // loop, so the last response of a login (the Set-Cookie — the single
        // most valuable record) routinely arrives after the operator has already
        // clicked Stop. Requiring 'active' silently discarded exactly that
        // record and reported "no login detected".
        OR: [
          { state: 'active', expiresAt: { gt: now } },
          { state: 'stopped', stoppedAt: { gt: new Date(now.getTime() - OBSERVE_GRACE_MS) } },
        ],
        ...(sessionId ? { id: sessionId } : {}),
      },
      orderBy: { startedAt: 'desc' },
    })
    if (!session) {
      // No active recording (expired/stopped between capture and ingest): drop
      // quietly so a late spool record cannot revive a window or write anywhere.
      return NextResponse.json({ ok: true, applied: false })
    }

    const material = parseObservedMaterial(b.material, b.host)
    if (!material) {
      await prisma.recordingSession.update({
        where: { id: session.id },
        data: { lastError: 'observation carried no usable session material' },
      })
      return NextResponse.json({ ok: true, applied: false })
    }

    const merged = mergeMaterial(session.pendingMaterial as Record<string, unknown> | null, material)
    await prisma.recordingSession.update({
      where: { id: session.id },
      data: {
        pendingMaterial: merged as object,
        observedCount: { increment: 1 },
        lastError: null,
      },
    })
    return NextResponse.json({ ok: true, applied: true })
  } catch (error) {
    console.error('observe write failed:', error)
    return NextResponse.json({ error: 'observe failed' }, { status: 500 })
  }
}
