/**
 * Scan Queue - enqueue a scan for this project (Scan Queue plan Phase 3).
 *
 * The refusal modal calls this when the operator chooses "Add to queue" after a
 * temporary start failure. Project-scoped, so the project check runs FIRST (Section 4:
 * a JobQueue id must never be sufficient; object-level authz is the guard, not the
 * row): recon:schedule, plus the permission that starts the queued kind
 * (queuedJobPermissions). Queueing is always the operator's explicit choice (R3).
 */
import { NextRequest, NextResponse } from 'next/server'
import { requireAlso, requirePermission } from '@/lib/authz/guards'
import { queuedJobPermissions } from '@/lib/authz/queuedJobPermissions'
import { getEffectiveUser } from '@/lib/session'
import { enqueueJob } from '@/lib/enqueueJob'
import { internalError } from '@/lib/routeErrors'

export const runtime = 'nodejs'

interface RouteParams {
  params: Promise<{ id: string }>
}

export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { id: projectId } = await params
    const auth = await requirePermission(request, 'recon:schedule', { projectId })
    if (auth instanceof NextResponse) return auth

    const eff = await getEffectiveUser()
    if (!eff?.userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    const body = await request.json().catch(() => ({}))
    const kind = typeof body?.kind === 'string' ? body.kind : ''
    const payload = body?.payload && typeof body.payload === 'object' ? body.payload : {}
    for (const permission of queuedJobPermissions(kind, payload)) {
      const refused = requireAlso(auth, permission)
      if (refused) return refused
    }

    const result = await enqueueJob({
      projectId,
      userId: eff.userId,
      kind,
      payload,
      priority: 10, // manual
    })

    if (!result.ok) {
      return NextResponse.json({ error: result.error }, { status: result.status })
    }
    return NextResponse.json({ ok: true, id: result.id }, { status: 201 })
  } catch (error) {
    return internalError(error, 'Could not add this scan to the queue', { log: '[jobQueue] enqueue failed' })
  }
}
