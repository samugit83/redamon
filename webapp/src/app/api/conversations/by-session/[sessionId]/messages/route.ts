import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'

// POST /api/conversations/by-session/[sessionId]/messages
// Append messages by session ID (used by agent backend)
// Auto-creates conversation if body includes projectId + userId
export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ sessionId: string }> }
) {
  try {
    const { sessionId } = await params
    const body = await request.json()

    // Find or create conversation
    let conversation = await prisma.conversation.findUnique({
      where: { sessionId },
    })

    if (!conversation) {
      const { projectId, userId } = body
      if (!projectId || !userId) {
        return NextResponse.json(
          { error: 'Conversation not found. Provide projectId and userId to auto-create.' },
          { status: 404 }
        )
      }
      conversation = await prisma.conversation.create({
        data: { projectId, userId, sessionId },
      })
    }

    // Support single or batch messages. Each item may carry optional
    // memberIdKey / fireteamIdKey to attribute the row to a Fireteam member.
    type ItemInput = {
      type: string
      data: unknown
      memberIdKey?: string | null
      fireteamIdKey?: string | null
    }
    const items: Array<ItemInput> = body.messages
      ? body.messages
      : [{
          type: body.type,
          data: body.data,
          memberIdKey: body.memberIdKey ?? null,
          fireteamIdKey: body.fireteamIdKey ?? null,
        }]

    // Get current max sequence number
    const maxSeq = await prisma.chatMessage.aggregate({
      where: { conversationId: conversation.id },
      _max: { sequenceNum: true },
    })
    let nextSeq = (maxSeq._max.sequenceNum ?? -1) + 1

    const created = await prisma.chatMessage.createMany({
      data: items.map((item) => ({
        conversationId: conversation.id,
        sequenceNum: nextSeq++,
        type: item.type,
        data: item.data as any,
        memberIdKey: item.memberIdKey ?? null,
        fireteamIdKey: item.fireteamIdKey ?? null,
      })),
    })

    // Auto-set title from first user message if title is empty
    if (!conversation.title && items.some(i => i.type === 'user_message')) {
      const firstUserMsg = items.find(i => i.type === 'user_message')
      if (firstUserMsg && typeof (firstUserMsg.data as any)?.content === 'string') {
        const title = (firstUserMsg.data as any).content.substring(0, 100)
        await prisma.conversation.update({
          where: { id: conversation.id },
          data: { title },
        })
      }
    }

    // Touch updatedAt
    await prisma.conversation.update({
      where: { id: conversation.id },
      data: { updatedAt: new Date() },
    })

    return NextResponse.json({ count: created.count, conversationId: conversation.id }, { status: 201 })
  } catch (error) {
    console.error('Failed to save messages by session:', error)
    return NextResponse.json(
      { error: 'Failed to save messages' },
      { status: 500 }
    )
  }
}
