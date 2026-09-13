import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { requireEffectiveUser, requireProjectAccess } from '@/lib/access'
import { assertGraphNotActivating } from '@/lib/activationLock'
import { defaultRecordingScope, publicRecordingSession, RECORDING_TTL_MS } from '@/lib/recordingSession'
import { isCaptureGloballyEnabled } from '@/lib/captureStatus'

interface RouteParams {
  params: Promise<{ id: string }>
}

// POST /api/projects/[id]/recording/start — owner-only. Begins an operator login
// recording: gated on global proxy enabled AND per-project captureProxyEnabled,
// single-active across all projects (G10), max-TTL bounded (G2), and refused mid
// graph-activation (G11).
export async function POST(_request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const eff = await requireEffectiveUser()
    if (eff instanceof NextResponse) return eff
    const access = await requireProjectAccess(eff, id)
    if (access instanceof NextResponse) return access

    // G11: never begin a recording while the live graph is being swapped. Fail
    // closed — a lock-check error refuses rather than proceeds.
    let activating: NextResponse | null
    try {
      activating = await assertGraphNotActivating(id)
    } catch {
      return NextResponse.json({ error: 'activation check failed; try again' }, { status: 409 })
    }
    if (activating) return activating

    const project = await prisma.project.findUnique({
      where: { id },
      select: {
        userId: true, captureProxyEnabled: true, ipMode: true, targetDomain: true,
        subdomainList: true, targetIps: true, roeEnabled: true, roeExcludedHosts: true,
      },
    })
    if (!project) return NextResponse.json({ error: 'Project not found' }, { status: 404 })

    if (!(await isCaptureGloballyEnabled())) {
      return NextResponse.json(
        { error: 'The capture proxy is disabled. An admin must enable it in Global Settings → TrafficMind.' },
        { status: 409 })
    }
    if (!project.captureProxyEnabled) {
      return NextResponse.json(
        { error: 'Enable HTTP capture for this project before recording a login.' },
        { status: 409 })
    }

    const now = new Date()
    const scopeHosts = defaultRecordingScope(project)

    // G10: single active recording across ALL projects (the capture-config is
    // admin-global, one slot). Check-and-set: reject if another is live.
    const existing = await prisma.recordingSession.findFirst({
      where: { state: 'active', expiresAt: { gt: now } },
      select: { id: true, projectId: true },
    })
    if (existing) {
      if (existing.projectId !== id) {
        return NextResponse.json(
          { error: 'A recording is already active for another project.' }, { status: 409 })
      }
      // Same project: treat start as extend — refresh the window.
      const refreshed = await prisma.recordingSession.update({
        where: { id: existing.id },
        data: { expiresAt: new Date(now.getTime() + RECORDING_TTL_MS), scopeHosts, lastError: null },
      })
      return NextResponse.json({ session: publicRecordingSession(refreshed) })
    }

    const session = await prisma.recordingSession.create({
      data: {
        projectId: id, userId: project.userId, state: 'active', scopeHosts,
        startedAt: now, expiresAt: new Date(now.getTime() + RECORDING_TTL_MS),
      },
    })

    // The check above is not atomic: two concurrent starts can both pass it and
    // create a session, leaving two "active" recordings while the capture-config
    // only ever emits one tag — the loser would show "Recording…" and capture
    // nothing. Resolve deterministically after the fact: the oldest session wins
    // (id breaks a tie), any later duplicate discards itself and reports 409.
    const rival = await prisma.recordingSession.findFirst({
      where: { state: 'active', expiresAt: { gt: now }, id: { not: session.id } },
      orderBy: { startedAt: 'asc' },
      select: { id: true, projectId: true, startedAt: true },
    })
    if (rival && (rival.startedAt < session.startedAt
        || (rival.startedAt.getTime() === session.startedAt.getTime() && rival.id < session.id))) {
      await prisma.recordingSession.update({
        where: { id: session.id }, data: { state: 'discarded', stoppedAt: new Date() },
      })
      return NextResponse.json({
        error: rival.projectId === id
          ? 'A recording is already active for this project.'
          : 'A recording is already active for another project.',
      }, { status: 409 })
    }

    return NextResponse.json({ session: publicRecordingSession(session) })
  } catch (error) {
    console.error('Failed to start recording:', error)
    return NextResponse.json({ error: 'Failed to start recording' }, { status: 500 })
  }
}
