import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { requireUserAccess } from '@/lib/session'
import { internalError } from '@/lib/routeErrors'
import { requireSelfPermission } from '@/lib/authz/selfService'
import { loadOwnResource } from '@/lib/tradecraft/resourceAccess'
import { enabledImpact } from '@/lib/tradecraft/projectChoices'

interface RouteParams {
  params: Promise<{ id: string; resourceId: string }>
}

// GET /api/users/[id]/tradecraft-resources/[resourceId]/enabled-impact?next=true|false
// The numbers of the alert shown before a change of Enabled is saved (R-062): every project of the
// account follows the change, and the projects where the resource is turned off lose that choice.
export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { id, resourceId } = await params
    const denied = await requireUserAccess(request, id, { mode: 'read' })
    if (denied) return denied
    const selfRefused = await requireSelfPermission(request, id, 'self:tradecraft')
    if (selfRefused) return selfRefused

    const next = request.nextUrl.searchParams.get('next')
    if (next !== 'true' && next !== 'false') {
      return NextResponse.json({ error: 'next must be true or false', code: 'bad_request' }, { status: 400 })
    }
    if (!(await loadOwnResource(id, resourceId))) {
      return NextResponse.json({ error: 'Resource not found' }, { status: 404 })
    }
    return NextResponse.json({ next: next === 'true', ...(await enabledImpact(prisma, id, resourceId)) })
  } catch (error) {
    return internalError(error, 'Failed to read what the change of Enabled affects')
  }
}
