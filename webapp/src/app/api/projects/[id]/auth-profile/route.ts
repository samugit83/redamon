import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { requireEffectiveUser, requireProjectAccess } from '@/lib/access'
import { parseAuthProfileInput, toAuthProfileMetadata } from '@/lib/authProfile'

interface RouteParams {
  params: Promise<{ id: string }>
}

// Browser-facing and write-only: every response is metadata + hasValue. The
// stored value is served only to recon/the agent via GET /api/projects/[id].

async function authorize(id: string) {
  const eff = await requireEffectiveUser()
  if (eff instanceof NextResponse) return eff
  const access = await requireProjectAccess(eff, id)
  if (access instanceof NextResponse) return access
  return eff
}

export async function GET(_request: NextRequest, { params }: RouteParams) {
  const { id } = await params
  const denied = await authorize(id)
  if (denied instanceof NextResponse) return denied

  const profile = await prisma.projectAuthProfile.findUnique({ where: { projectId: id } })
  return NextResponse.json({ authProfile: toAuthProfileMetadata(profile) })
}

export async function PUT(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const denied = await authorize(id)
    if (denied instanceof NextResponse) return denied

    let body: unknown
    try {
      body = await request.json()
    } catch {
      return NextResponse.json({ error: 'Invalid JSON body' }, { status: 400 })
    }
    if (!body || typeof body !== 'object') {
      return NextResponse.json({ error: 'Invalid body' }, { status: 400 })
    }
    const { patch, error } = parseAuthProfileInput(body as Record<string, unknown>)
    if (error) return NextResponse.json({ error }, { status: 400 })

    // The row's tenant is the project OWNER, never a body field or the admin
    // simulating them.
    const project = await prisma.project.findUnique({ where: { id }, select: { userId: true } })
    if (!project) return NextResponse.json({ error: 'Project not found' }, { status: 404 })

    const identityChanged = patch.authValue !== undefined || patch.extraHeaders !== undefined
      || patch.authType !== undefined || patch.authHeaderName !== undefined
    const data = {
      ...patch,
      // A hand edit replaces whatever was recorded and has not been validated.
      ...(identityChanged ? { source: 'manual', status: 'unknown', lastValidatedAt: null } : {}),
    }
    const profile = await prisma.projectAuthProfile.upsert({
      where: { projectId: id },
      create: { projectId: id, userId: project.userId, ...data },
      update: data,
    })
    return NextResponse.json({ authProfile: toAuthProfileMetadata(profile) })
  } catch (error) {
    console.error('Failed to save auth profile:', error)
    return NextResponse.json({ error: 'Failed to save auth profile' }, { status: 500 })
  }
}

export async function DELETE(_request: NextRequest, { params }: RouteParams) {
  const { id } = await params
  const denied = await authorize(id)
  if (denied instanceof NextResponse) return denied

  await prisma.projectAuthProfile.deleteMany({ where: { projectId: id } })
  return NextResponse.json({ authProfile: null })
}
