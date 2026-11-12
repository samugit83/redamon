import { NextRequest, NextResponse } from 'next/server'
import { internalError } from '@/lib/routeErrors'
import prisma from '@/lib/prisma'
import { requirePermission } from '@/lib/authz/guards'

// GET /api/conversations?projectId=X (conversations are scoped to the effective
// user; the client-supplied userId is ignored as an auth input).
export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url)
    const projectId = searchParams.get('projectId')

    if (!projectId) {
      return NextResponse.json(
        { error: 'projectId is required' },
        { status: 400 }
      )
    }

    const auth = await requirePermission(request, 'agent:chat', { projectId })
    if (auth instanceof NextResponse) return auth
    const eff = auth.effective

    const conversations = await prisma.conversation.findMany({
      where: { projectId, userId: eff.userId },
      orderBy: { updatedAt: 'desc' },
      select: {
        id: true,
        sessionId: true,
        title: true,
        status: true,
        agentRunning: true,
        currentPhase: true,
        iterationCount: true,
        activeSkillId: true,
        createdAt: true,
        updatedAt: true,
        _count: { select: { messages: true } },
      },
    })

    return NextResponse.json(conversations)
  } catch (error) {
    return internalError(error, 'Failed to fetch conversations')
  }
}

// POST /api/conversations - Create a new conversation
export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { projectId, sessionId } = body

    if (!projectId || !sessionId) {
      return NextResponse.json(
        { error: 'projectId and sessionId are required' },
        { status: 400 }
      )
    }

    const auth = await requirePermission(request, 'agent:chat', { projectId })
    if (auth instanceof NextResponse) return auth
    const eff = auth.effective

    // Owner is the effective user, never a client-supplied body value.
    const conversation = await prisma.conversation.create({
      data: { projectId, userId: eff.userId, sessionId },
    })

    return NextResponse.json(conversation, { status: 201 })
  } catch (error) {
    return internalError(error, 'Failed to create conversation')
  }
}
