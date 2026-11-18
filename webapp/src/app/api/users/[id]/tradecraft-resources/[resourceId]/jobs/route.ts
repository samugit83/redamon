import { NextRequest, NextResponse } from 'next/server'
import { requireUserAccess } from '@/lib/session'
import { internalError } from '@/lib/routeErrors'
import { requireSelfPermission } from '@/lib/authz/selfService'
import { cancelJob, latestJob } from '@/lib/tradecraft/jobs'
import { loadOwnResource } from '@/lib/tradecraft/resourceAccess'

interface RouteParams {
  params: Promise<{ id: string; resourceId: string }>
}

// Reading and cancelling a job work whatever its state; a converted 1.x resource may have none.

// GET /api/users/[id]/tradecraft-resources/[resourceId]/jobs   The resource's latest job, or null.
export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { id, resourceId } = await params
    const denied = await requireUserAccess(request, id, { mode: 'read' })
    if (denied) return denied
    const selfRefused = await requireSelfPermission(request, id, 'self:tradecraft')
    if (selfRefused) return selfRefused

    if (!(await loadOwnResource(id, resourceId))) {
      return NextResponse.json({ error: 'Resource not found' }, { status: 404 })
    }
    return NextResponse.json({ job: await latestJob(id, resourceId) })
  } catch (error) {
    return internalError(error, 'Failed to read the tradecraft job')
  }
}

// DELETE /api/users/[id]/tradecraft-resources/[resourceId]/jobs   Cancels the running job.
export async function DELETE(request: NextRequest, { params }: RouteParams) {
  try {
    const { id, resourceId } = await params
    const denied = await requireUserAccess(request, id, { mode: 'write' })
    if (denied) return denied
    const selfRefused = await requireSelfPermission(request, id, 'self:tradecraft')
    if (selfRefused) return selfRefused

    const { found, job } = await cancelJob(id, resourceId)
    if (!found) return NextResponse.json({ error: 'Resource not found' }, { status: 404 })
    return NextResponse.json({ job })
  } catch (error) {
    return internalError(error, 'Failed to cancel the tradecraft job')
  }
}
