import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'

// GET /api/conversations?projectId=X&userId=Y
export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url)
    const projectId = searchParams.get('projectId')
    const userId = searchParams.get('userId')

    if (!projectId || !userId) {
      return NextResponse.json(
        { error: 'projectId and userId are required' },
        { status: 400 }
      )
    }

    const conversations = await prisma.conversation.findMany({
      where: { projectId, userId },
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
    console.error('Failed to fetch conversations:', error)
    return NextResponse.json(
      { error: 'Failed to fetch conversations' },
      { status: 500 }
    )
  }
}

// POST /api/conversations - Create a new conversation
export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { projectId, userId, sessionId } = body

    if (!projectId || !userId || !sessionId) {
      return NextResponse.json(
        { error: 'projectId, userId, and sessionId are required' },
        { status: 400 }
      )
    }

    const conversation = await prisma.conversation.create({
      data: { projectId, userId, sessionId },
    })

    return NextResponse.json(conversation, { status: 201 })
  } catch (error) {
    console.error('Failed to create conversation:', error)
    return NextResponse.json(
      { error: 'Failed to create conversation' },
      { status: 500 }
    )
  }
}
