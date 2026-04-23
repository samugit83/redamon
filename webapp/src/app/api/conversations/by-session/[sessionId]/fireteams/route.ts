import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'

// POST /api/conversations/by-session/[sessionId]/fireteams
// Create a new Fireteam row and its FireteamMember rows. Called by agent.
// Requires body.userId + body.projectId to auto-create conversation if missing.
export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ sessionId: string }> }
) {
  try {
    const { sessionId } = await params
    const body = await request.json()
    const {
      fireteamIdKey,
      fireteamNumber,
      iteration,
      memberCount,
      planRationale,
      members,
      userId,
      projectId,
    } = body

    if (!fireteamIdKey || !Array.isArray(members)) {
      return NextResponse.json({ error: 'fireteamIdKey and members[] required' }, { status: 400 })
    }

    let conversation = await prisma.conversation.findUnique({ where: { sessionId } })
    if (!conversation) {
      if (!userId || !projectId) {
        return NextResponse.json(
          { error: 'Conversation not found. Provide userId and projectId to auto-create.' },
          { status: 404 }
        )
      }
      conversation = await prisma.conversation.create({
        data: { userId, projectId, sessionId },
      })
    }

    const fireteam = await prisma.fireteam.create({
      data: {
        parentConversationId: conversation.id,
        parentSessionId: sessionId,
        fireteamIdKey,
        fireteamNumber: fireteamNumber ?? 0,
        iteration: iteration ?? 0,
        memberCount: memberCount ?? members.length,
        planRationale: planRationale ?? '',
        status: 'running',
        members: {
          create: members.map((m: any) => ({
            memberIdKey: m.memberIdKey,
            name: m.name,
            task: m.task ?? '',
            skills: m.skills ?? [],
            status: 'running',
          })),
        },
      },
      include: { members: true },
    })

    return NextResponse.json({ id: fireteam.id, members: fireteam.members.map(m => ({ id: m.id })) }, { status: 201 })
  } catch (error) {
    console.error('Failed to create fireteam:', error)
    return NextResponse.json({ error: 'Failed to create fireteam' }, { status: 500 })
  }
}

// GET /api/conversations/by-session/[sessionId]/fireteams
// List all fireteams for a session. Used by frontend session resume.
export async function GET(
  _request: NextRequest,
  { params }: { params: Promise<{ sessionId: string }> }
) {
  try {
    const { sessionId } = await params
    const conversation = await prisma.conversation.findUnique({ where: { sessionId } })
    if (!conversation) {
      return NextResponse.json({ fireteams: [] })
    }
    const fireteams = await prisma.fireteam.findMany({
      where: { parentConversationId: conversation.id },
      orderBy: { fireteamNumber: 'asc' },
      include: { members: { orderBy: { startedAt: 'asc' } } },
    })
    return NextResponse.json({ fireteams })
  } catch (error) {
    console.error('Failed to list fireteams:', error)
    return NextResponse.json({ error: 'Failed to list fireteams' }, { status: 500 })
  }
}
