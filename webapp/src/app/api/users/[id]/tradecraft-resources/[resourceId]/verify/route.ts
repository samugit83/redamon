import { NextRequest, NextResponse } from 'next/server'
import { requireUserAccess } from '@/lib/session'
import { internalError } from '@/lib/routeErrors'
import { requireSelfPermission } from '@/lib/authz/selfService'
import { auditActor } from '@/lib/auditActor'
import { jobActorOf } from '@/lib/tradecraft/jobs'
import { refreshResourceV2 } from '@/lib/tradecraft/v2/refresh'

interface RouteParams {
  params: Promise<{ id: string; resourceId: string }>
}

// POST /api/users/[id]/tradecraft-resources/[resourceId]/verify
// The 1.x name of Refresh, kept for older clients: the same background job (R-097).
export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { id, resourceId } = await params
    const denied = await requireUserAccess(request, id, { mode: 'write' })
    if (denied) return denied
    const selfRefused = await requireSelfPermission(request, id, 'self:tradecraft')
    if (selfRefused) return selfRefused
    const actor = jobActorOf(await auditActor())
    if (!actor) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    return await refreshResourceV2({ ownerId: id, resourceId, actor })
  } catch (error) {
    return internalError(error, 'Failed to verify tradecraft resource')
  }
}
