import { NextRequest, NextResponse } from 'next/server'
import { requireUserAccess } from '@/lib/session'
import { requireSelfPermission } from '@/lib/authz/selfService'
import { auditActor } from '@/lib/auditActor'
import { internalError } from '@/lib/routeErrors'
import { readJsonBody } from '@/lib/jsonBody'
import { setTradecraftV2, tradecraftV2Enabled } from '@/lib/tradecraft/switch'

interface RouteParams {
  params: Promise<{ id: string }>
}

const BAD_BODY = 'Body must be {"v2Enabled": true} or {"v2Enabled": false}'

// GET /api/users/[id]/tradecraft-settings
export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const denied = await requireUserAccess(request, id, { mode: 'read' })
    if (denied) return denied
    const selfRefused = await requireSelfPermission(request, id, 'self:tradecraft')
    if (selfRefused) return selfRefused
    return NextResponse.json({ v2Enabled: await tradecraftV2Enabled(id) })
  } catch (error) {
    return internalError(error, 'Failed to read the Tradecraft settings')
  }
}

// PUT /api/users/[id]/tradecraft-settings   Body: { v2Enabled: boolean }
export async function PUT(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const denied = await requireUserAccess(request, id, { mode: 'write' })
    if (denied) return denied
    const selfRefused = await requireSelfPermission(request, id, 'self:tradecraft')
    if (selfRefused) return selfRefused
    // The internal key passes the account rule, but the switch is a person's choice and
    // its audit row names that person: a request without one changes nothing.
    const actor = await auditActor()
    if (!actor.actorId) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    const parsed = await readJsonBody(request)
    if (parsed instanceof NextResponse) return parsed
    const { body } = parsed
    if (Object.keys(body).length !== 1 || typeof body.v2Enabled !== 'boolean') {
      return NextResponse.json({ error: BAD_BODY }, { status: 400 })
    }
    await setTradecraftV2(actor, id, body.v2Enabled)
    return NextResponse.json({ v2Enabled: body.v2Enabled })
  } catch (error) {
    return internalError(error, 'Failed to save the Tradecraft settings')
  }
}
