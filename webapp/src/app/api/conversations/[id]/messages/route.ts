import { NextRequest, NextResponse } from 'next/server'
import { internalError } from '@/lib/routeErrors'
import prisma from '@/lib/prisma'
import { requireEffectiveUser, requireConversationAccess } from '@/lib/access'
import { requirePermission } from '@/lib/authz/guards'
import { readOnlyConversationRefusal } from '@/lib/authz/conversationAccess'

// POST /api/conversations/[id]/messages - Append messages
export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id: conversationId } = await params

    const eff = await requireEffectiveUser()
    if (eff instanceof NextResponse) return eff
    const guard = await requireConversationAccess(eff, conversationId)
    if (guard instanceof NextResponse) return guard
    const auth = await requirePermission(request, 'agent:chat', { projectId: guard.conversation.projectId })
    if (auth instanceof NextResponse) return auth
    const readOnly = await readOnlyConversationRefusal(conversationId)
    if (readOnly) return readOnly

    const body = await request.json()

    // Support single or batch messages
    const items: Array<{ type: string; data: unknown }> = body.messages
      ? body.messages
      : [{ type: body.type, data: body.data }]

    // Get current max sequence number
    const maxSeq = await prisma.chatMessage.aggregate({
      where: { conversationId },
      _max: { sequenceNum: true },
    })
    let nextSeq = (maxSeq._max.sequenceNum ?? -1) + 1

    const created = await prisma.chatMessage.createMany({
      data: items.map((item) => ({
        conversationId,
        sequenceNum: nextSeq++,
        type: item.type,
        data: item.data as any,
      })),
    })

    // Touch the conversation's updatedAt
    await prisma.conversation.update({
      where: { id: conversationId },
      data: { updatedAt: new Date() },
    })

    return NextResponse.json({ count: created.count }, { status: 201 })
  } catch (error) {
    return internalError(error, 'Failed to save messages')
  }
}
