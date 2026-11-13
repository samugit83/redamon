import { NextRequest, NextResponse } from 'next/server'
import { internalError } from '@/lib/routeErrors'
import prisma from '@/lib/prisma'
import { requirePermission } from '@/lib/authz/guards'
import { conversationListScope } from '@/lib/authz/conversationAccess'

// GET /api/conversations?projectId=X: the effective user's own conversations (the client-supplied userId
// is ignored as an auth input) and, with write sharing in force, the others' they may read, each with its
// `access` view (step 5.8, conversationAccess.ts).
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
    const scope = await conversationListScope(request, projectId, auth)
    if (scope instanceof NextResponse) return scope

    const conversations = await prisma.conversation.findMany({
      where: scope.where,
      orderBy: { updatedAt: 'desc' },
      select: {
        ...scope.select,
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

    return NextResponse.json(scope.present(conversations))
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
