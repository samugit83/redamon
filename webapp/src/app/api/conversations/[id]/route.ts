import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { getSession } from '../../graph/neo4j'

// GET /api/conversations/[id] - Get conversation with all messages
export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params

    const conversation = await prisma.conversation.findUnique({
      where: { id },
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

    return NextResponse.json(conversation)
  } catch (error) {
    console.error('Failed to fetch conversation:', error)
    return NextResponse.json(
      { error: 'Failed to fetch conversation' },
      { status: 500 }
    )
  }
}

// PATCH /api/conversations/[id] - Update conversation metadata
export async function PATCH(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params
    const body = await request.json()

    const allowedFields = ['title', 'status', 'agentRunning', 'currentPhase', 'iterationCount', 'activeSkillId']
    const data: Record<string, unknown> = {}
    for (const field of allowedFields) {
      if (body[field] !== undefined) {
        data[field] = body[field]
      }
    }

    const conversation = await prisma.conversation.update({
      where: { id },
      data,
    })

    return NextResponse.json(conversation)
  } catch (error) {
    console.error('Failed to update conversation:', error)
    return NextResponse.json(
      { error: 'Failed to update conversation' },
      { status: 500 }
    )
  }
}

// DELETE /api/conversations/[id] - Delete conversation, messages (cascade), and attack chain nodes
export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params

    // Fetch conversation to get sessionId (= chain_id in Neo4j)
    const conversation = await prisma.conversation.findUnique({
      where: { id },
      select: { sessionId: true, userId: true, projectId: true },
    })

    if (!conversation) {
      return NextResponse.json({ error: 'Conversation not found' }, { status: 404 })
    }

    // Delete attack chain nodes from Neo4j (fire-and-forget — don't block on failure)
    try {
      const neo4jSession = getSession()
      try {
        await neo4jSession.run(
          `MATCH (n)
           WHERE n.chain_id = $chainId
             AND n.user_id = $userId
             AND n.project_id = $projectId
             AND (n:AttackChain OR n:ChainStep OR n:ChainFinding OR n:ChainDecision OR n:ChainFailure)
           DETACH DELETE n`,
          {
            chainId: conversation.sessionId,
            userId: conversation.userId,
            projectId: conversation.projectId,
          }
        )
      } finally {
        await neo4jSession.close()
      }
    } catch (neo4jError) {
      console.error('Failed to delete attack chain nodes from Neo4j (continuing):', neo4jError)
    }

    // Delete conversation + cascaded messages from Postgres
    await prisma.conversation.delete({ where: { id } })

    return NextResponse.json({ success: true })
  } catch (error) {
    console.error('Failed to delete conversation:', error)
    return NextResponse.json(
      { error: 'Failed to delete conversation' },
      { status: 500 }
    )
  }
}
