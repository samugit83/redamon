import { NextRequest, NextResponse } from 'next/server'
import { internalError } from '@/lib/routeErrors'
import prisma from '@/lib/prisma'
import { isInternalRequest } from '@/lib/session'
import { requireEffectiveUser, requireConversationAccessBySession } from '@/lib/access'
import { requirePermission } from '@/lib/authz/guards'

// POST /api/conversations/by-session/[sessionId]/fireteams
// Create a new Fireteam row and its FireteamMember rows. Called by the agent with
// X-Internal-Key (carve-out); browser callers must own the session.
export async function POST(
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
    }

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
            // Agent now emits the primary toolbox under `tools` (canonical).
            // The DB column is still called `skills` (legacy, internal - UI's
            // `member.tools` already means executed tool calls, so renaming
            // the column would force a wider refactor). Map across boundary:
            // accept `tools` from the agent, fall back to `skills` if some
            // legacy payload sneaks in.
            skills: m.tools ?? m.skills ?? [],
            status: 'running',
          })),
        },
      },
      include: { members: true },
    })

    return NextResponse.json({ id: fireteam.id, members: fireteam.members.map(m => ({ id: m.id })) }, { status: 201 })
  } catch (error) {
    return internalError(error, 'Failed to create fireteam')
  }
}

// GET /api/conversations/by-session/[sessionId]/fireteams
// List all fireteams for a session. Used by frontend session resume.
export async function GET(
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
    }

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
    return internalError(error, 'Failed to list fireteams')
  }
}
