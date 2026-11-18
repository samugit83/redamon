import { NextRequest, NextResponse } from 'next/server'
import { requireUserAccess } from '@/lib/session'
import { internalError } from '@/lib/routeErrors'
import { requireSelfPermission } from '@/lib/authz/selfService'
import { auditActor } from '@/lib/auditActor'
import { readJsonBody } from '@/lib/jsonBody'
import { jobActorOf } from '@/lib/tradecraft/jobs'
import { resourceViewOf } from '@/lib/tradecraft/v2/list'
import { updateResourceV2 } from '@/lib/tradecraft/v2/update'
import { removeResourceV2 } from '@/lib/tradecraft/v2/remove'

interface RouteParams {
  params: Promise<{ id: string; resourceId: string }>
}

// GET /api/users/[id]/tradecraft-resources/[resourceId]
// Every caller gets the masked 2.0 view (T9.3: no unmasked read exists any more).
export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { id, resourceId } = await params
    const denied = await requireUserAccess(request, id, { mode: 'read' })
    if (denied) return denied
    const selfRefused = await requireSelfPermission(request, id, 'self:tradecraft')
    if (selfRefused) return selfRefused
    const view = await resourceViewOf(id, resourceId)
    if (!view) return NextResponse.json({ error: 'Resource not found' }, { status: 404 })
    return NextResponse.json(view)
  } catch (error) {
    return internalError(error, 'Failed to fetch tradecraft resource')
  }
}

// PUT /api/users/[id]/tradecraft-resources/[resourceId]
export async function PUT(request: NextRequest, { params }: RouteParams) {
  try {
    const { id, resourceId } = await params
    const denied = await requireUserAccess(request, id, { mode: 'write' })
    if (denied) return denied
    const selfRefused = await requireSelfPermission(request, id, 'self:tradecraft')
    if (selfRefused) return selfRefused
    // A URL change starts a job, which names the person: the internal key alone edits nothing.
    const actor = jobActorOf(await auditActor())
    if (!actor) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    const parsed = await readJsonBody(request)
    if (parsed instanceof NextResponse) return parsed
    return await updateResourceV2({ ownerId: id, resourceId, body: parsed.body, actor })
  } catch (error) {
    return internalError(error, 'Failed to update tradecraft resource')
  }
}

// DELETE /api/users/[id]/tradecraft-resources/[resourceId]
export async function DELETE(request: NextRequest, { params }: RouteParams) {
  try {
    const { id, resourceId } = await params
    const denied = await requireUserAccess(request, id, { mode: 'write' })
    if (denied) return denied
    const selfRefused = await requireSelfPermission(request, id, 'self:tradecraft')
    if (selfRefused) return selfRefused
    return await removeResourceV2({ ownerId: id, resourceId })
  } catch (error) {
    return internalError(error, 'Failed to delete tradecraft resource')
  }
}
