import { NextRequest, NextResponse } from 'next/server'
import { internalError } from '@/lib/routeErrors'
import prisma from '@/lib/prisma'
import { isInternalRequest } from '@/lib/session'
import { requireEffectiveUser, requireConversationAccessBySession } from '@/lib/access'
import { requirePermission } from '@/lib/authz/guards'

// PATCH /api/conversations/by-session/[sessionId]/fireteams/[fireteamIdKey]
// Update a fireteam's status and final stats. Called by the agent (carve-out);
// browser callers must own the session.
export async function PATCH(
  request: NextRequest,
  { params }: { params: Promise<{ sessionId: string; fireteamIdKey: string }> }
) {
  try {
    const { sessionId, fireteamIdKey } = await params

    if (!isInternalRequest(request)) {
      const eff = await requireEffectiveUser()
      if (eff instanceof NextResponse) return eff
      const guard = await requireConversationAccessBySession(eff, sessionId)
      if (guard instanceof NextResponse) return guard
      const auth = await requirePermission(request, 'agent:chat', { projectId: guard.conversation.projectId })
      if (auth instanceof NextResponse) return auth
    }

    const body = await request.json()
    const updates: Record<string, unknown> = {}
    if (typeof body.status === 'string') updates.status = body.status
    if (body.statusCounts !== undefined) updates.statusCounts = body.statusCounts
    if (typeof body.wallClockSeconds === 'number') updates.wallClockSeconds = body.wallClockSeconds
    if (body.completedAt === undefined && updates.status && updates.status !== 'running' && updates.status !== 'pending') {
      updates.completedAt = new Date()
    }
    const fireteam = await prisma.fireteam.update({
      where: { fireteamIdKey },
      data: updates,
    })
    return NextResponse.json({ id: fireteam.id, status: fireteam.status })
  } catch (error: any) {
    if (error?.code === 'P2025') {
      return NextResponse.json({ error: 'Fireteam not found' }, { status: 404 })
    }
    return internalError(error, 'Failed to patch fireteam')
  }
}
