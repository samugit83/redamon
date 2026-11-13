import { NextRequest, NextResponse } from 'next/server'
import { internalError } from '@/lib/routeErrors'
import prisma from '@/lib/prisma'
import { isInternalRequest } from '@/lib/session'
import { requireEffectiveUser, requireConversationAccessBySession } from '@/lib/access'
import { requirePermission } from '@/lib/authz/guards'
import { readOnlyConversationRefusal, requireConversationRead, type ConversationView } from '@/lib/authz/conversationAccess'

// GET /api/conversations/by-session/[sessionId] - Lookup by session.
// The agent persists chat via this route with X-Internal-Key (carve-out); a browser caller reaches a
// session they (effectively) own, or another person's read-only under step 5.8's rules.
export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ sessionId: string }> }
) {
  try {
    const { sessionId } = await params

    let view: ConversationView | null = null
    if (!isInternalRequest(request)) {
      const eff = await requireEffectiveUser()
      if (eff instanceof NextResponse) return eff
      const read = await requireConversationRead(request, eff, { sessionId })
      if (read instanceof NextResponse) return read
      view = read.view
    }

    const conversation = await prisma.conversation.findUnique({
      where: { sessionId },
      include: {
        messages: {
          orderBy: { sequenceNum: 'asc' },
        },
      },
    })

    if (!conversation) {
      return NextResponse.json(
        { error: 'Conversation not found' },
        { status: 404 }
      )
    }

    return NextResponse.json(view ? { ...conversation, access: view } : conversation)
  } catch (error) {
    return internalError(error, 'Failed to fetch conversation', { log: 'Failed to fetch conversation by session' })
  }
}

// PATCH /api/conversations/by-session/[sessionId] - Update by session
export async function PATCH(
  request: NextRequest,
  { params }: { params: Promise<{ sessionId: string }> }
) {
  try {
    const { sessionId } = await params

    if (!isInternalRequest(request)) {
      const eff = await requireEffectiveUser()
      if (eff instanceof NextResponse) return eff
      const guard = await requireConversationAccessBySession(eff, sessionId)
      if (guard instanceof NextResponse) return guard
      const auth = await requirePermission(request, 'agent:chat', { projectId: guard.conversation.projectId })
      if (auth instanceof NextResponse) return auth
      const readOnly = await readOnlyConversationRefusal(guard.conversation.id)
      if (readOnly) return readOnly
    }

    const body = await request.json()

    const allowedFields = ['title', 'status', 'agentRunning', 'currentPhase', 'iterationCount']
    const data: Record<string, unknown> = {}
    for (const field of allowedFields) {
      if (body[field] !== undefined) {
        data[field] = body[field]
      }
    }

    const conversation = await prisma.conversation.update({
      where: { sessionId },
      data,
    })

    return NextResponse.json(conversation)
  } catch (error) {
    return internalError(error, 'Failed to update conversation', { log: 'Failed to update conversation by session' })
  }
}
