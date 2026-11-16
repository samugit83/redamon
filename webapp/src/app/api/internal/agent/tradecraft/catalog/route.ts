import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { isInternalRequest } from '@/lib/session'
import { internalError } from '@/lib/routeErrors'
import { runCatalog } from '@/lib/tradecraft/catalog'

/**
 * GET /api/internal/agent/tradecraft/catalog?projectId=&personId=&actorId=
 *
 * The tradecraft resources one run may use (lib/tradecraft/catalog.ts), read by the agent when a
 * run starts. The key is checked here: the middleware allowlist is not the control while
 * INTERNAL_KEY_ALLOWLIST_ENFORCE is off, and a session or the scanner key reads nothing. The
 * owner comes from the project row, never from the query. An unknown project answers its own
 * coded 404, which the agent tells apart from an older webapp's page 404 (that one falls back to
 * the 1.x route; this one must not, D-53).
 */
export async function GET(request: NextRequest) {
  if (!isInternalRequest(request)) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }
  try {
    const params = request.nextUrl.searchParams
    const projectId = params.get('projectId') ?? ''
    const personId = params.get('personId') ?? ''
    const actorId = params.get('actorId') || null
    if (!projectId) return NextResponse.json({ error: 'projectId is required', code: 'project_required' }, { status: 400 })
    // Without the person the login rule cannot be decided: the agent always has the run's person.
    if (!personId) return NextResponse.json({ error: 'personId is required', code: 'person_required' }, { status: 400 })

    const project = await prisma.project.findUnique({ where: { id: projectId }, select: { userId: true } })
    if (!project) return NextResponse.json({ error: 'Project not found', code: 'project_not_found' }, { status: 404 })

    return NextResponse.json(await runCatalog({ ownerId: project.userId, projectId, personId, actorId }))
  } catch (error) {
    return internalError(error, 'Failed to build the tradecraft run catalog')
  }
}
