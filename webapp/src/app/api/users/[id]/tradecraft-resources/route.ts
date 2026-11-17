import { NextRequest, NextResponse } from 'next/server'
import { requireUserAccess } from '@/lib/session'
import { internalError } from '@/lib/routeErrors'
import { requireSelfPermission } from '@/lib/authz/selfService'
import { auditActor } from '@/lib/auditActor'
import { readJsonBody } from '@/lib/jsonBody'
import { jobActorOf } from '@/lib/tradecraft/jobs'
import { listResourcesV2 } from '@/lib/tradecraft/v2/list'
import { createResourceV2 } from '@/lib/tradecraft/v2/create'

interface RouteParams {
  params: Promise<{ id: string }>
}

// GET /api/users/[id]/tradecraft-resources
// Every caller gets the masked 2.0 view: the agent reads its run catalog
// (/api/internal/agent/tradecraft/catalog), so no unmasked list exists (T9.3).
export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const denied = await requireUserAccess(request, id, { mode: 'read' })
    if (denied) return denied
    const selfRefused = await requireSelfPermission(request, id, 'self:tradecraft')
    if (selfRefused) return selfRefused
    return NextResponse.json(await listResourcesV2(id))
  } catch (error) {
    return internalError(error, 'Failed to fetch tradecraft resources')
  }
}

// POST /api/users/[id]/tradecraft-resources
//   Body: the 2.0 resource fields (v2/fields.ts)
//   Query: ?skipVerify=true saves without starting the add job
export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const denied = await requireUserAccess(request, id, { mode: 'write' })
    if (denied) return denied
    const selfRefused = await requireSelfPermission(request, id, 'self:tradecraft')
    if (selfRefused) return selfRefused
    const skipVerify = request.nextUrl.searchParams.get('skipVerify') === 'true'
    // A job names the person who started it: the internal key alone starts none.
    const actor = jobActorOf(await auditActor())
    if (!actor) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    const parsed = await readJsonBody(request)
    if (parsed instanceof NextResponse) return parsed
    return await createResourceV2({ ownerId: id, body: parsed.body, actor, skipVerify })
  } catch (error: unknown) {
    return internalError(error, 'Failed to create tradecraft resource')
  }
}
