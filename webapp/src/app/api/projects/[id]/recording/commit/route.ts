import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { requireEffectiveUser, requireProjectAccess } from '@/lib/access'
import { toAuthProfileMetadata } from '@/lib/authProfile'
import {
  deriveProfileFromMaterial,
  materialIsEmpty,
  summarizeMaterial,
} from '@/lib/recordingSession'
import type { RecordingMaterial } from '@/lib/recordingSession'

interface RouteParams {
  params: Promise<{ id: string }>
}

// POST /api/projects/[id]/recording/commit — owner-only. body { save: boolean }.
// save=true saves the recorded session into the ProjectAuthProfile (source
// "recorded"); save=false discards it. Refuses to overwrite a profile with an
// EMPTY capture (G3). Never echoes the value back — returns metadata only.
export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const eff = await requireEffectiveUser()
    if (eff instanceof NextResponse) return eff
    const access = await requireProjectAccess(eff, id)
    if (access instanceof NextResponse) return access

    let body: unknown = {}
    try { body = await request.json() } catch { /* empty body allowed */ }
    const save = (body as Record<string, unknown>)?.save === true

    // An ABANDONED recording (never stopped) must not stay committable forever:
    // its material is a long-dead session that would be saved as status "active".
    // A stopped one is fine — the operator ended it deliberately.
    const now = new Date()
    const session = await prisma.recordingSession.findFirst({
      where: {
        projectId: id,
        OR: [
          { state: 'stopped' },
          { state: 'active', expiresAt: { gt: now } },
        ],
      },
      orderBy: { startedAt: 'desc' },
    })
    if (!session) return NextResponse.json({ error: 'No recording to commit' }, { status: 404 })

    const material = session.pendingMaterial as RecordingMaterial | null

    if (!save) {
      await prisma.recordingSession.update({ where: { id: session.id }, data: { state: 'discarded', stoppedAt: new Date() } })
      return NextResponse.json({ committed: false, discarded: true })
    }

    // G3: never overwrite a working profile with a login that captured nothing.
    if (materialIsEmpty(material)) {
      return NextResponse.json(
        { error: 'No login detected — nothing was captured, so the existing profile is unchanged.' },
        { status: 422 })
    }

    const project = await prisma.project.findUnique({ where: { id }, select: { userId: true } })
    if (!project) return NextResponse.json({ error: 'Project not found' }, { status: 404 })

    const derived = deriveProfileFromMaterial(material!)
    const data = {
      authType: derived.authType,
      authHeaderName: derived.authHeaderName,
      authValue: derived.authValue,
      extraHeaders: derived.extraHeaders,
      // Deliberately NOT session.scopeHosts. The recording scope bounds what the
      // proxy TAGS; pinning it here as the profile's explicit scope froze auth to
      // the apex and excluded every discovered subdomain. Leaving it alone keeps
      // any operator-set scope and otherwise falls back to the project default.
      source: 'recorded',
      status: 'active',
      lastValidatedAt: new Date(),
    }
    const profile = await prisma.projectAuthProfile.upsert({
      where: { projectId: id },
      create: { projectId: id, userId: project.userId, ...data },
      update: data,
    })
    await prisma.recordingSession.update({ where: { id: session.id }, data: { state: 'committed', stoppedAt: new Date() } })

    return NextResponse.json({
      committed: true,
      summary: summarizeMaterial(material),
      authProfile: toAuthProfileMetadata(profile),
    })
  } catch (error) {
    console.error('Failed to commit recording:', error)
    return NextResponse.json({ error: 'Failed to commit recording' }, { status: 500 })
  }
}
