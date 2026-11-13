import { NextRequest, NextResponse } from 'next/server'
import { internalError, safeErrorCode, upstreamFailure } from '@/lib/routeErrors'
import prisma from '@/lib/prisma'
import { getGraphSession } from '../../graph/neo4j'
import { requireEffectiveUser, requireConversationAccess } from '@/lib/access'
import { requirePermission } from '@/lib/authz/guards'
import { agentFetch, AgentUnreachableError } from '@/lib/agentFetch'

/** A cleanup step that failed while the conversation itself was deleted. */
interface DeleteWarning {
  step: 'agent_stop' | 'graph_cleanup'
  code: string
  /** The agent's HTTP status, when it answered. */
  status?: number
}

// GET /api/conversations/[id] - Get conversation with all messages
export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params

    const eff = await requireEffectiveUser()
    if (eff instanceof NextResponse) return eff
    const guard = await requireConversationAccess(eff, id)
    if (guard instanceof NextResponse) return guard
    const auth = await requirePermission(request, 'agent:chat', { projectId: guard.conversation.projectId })
    if (auth instanceof NextResponse) return auth

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
    return internalError(error, 'Failed to fetch conversation')
  }
}

// PATCH /api/conversations/[id] - Update conversation metadata
export async function PATCH(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params

    const eff = await requireEffectiveUser()
    if (eff instanceof NextResponse) return eff
    const guard = await requireConversationAccess(eff, id)
    if (guard instanceof NextResponse) return guard
    const auth = await requirePermission(request, 'agent:chat', { projectId: guard.conversation.projectId })
    if (auth instanceof NextResponse) return auth

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
    return internalError(error, 'Failed to update conversation')
  }
}

// DELETE /api/conversations/[id] - Delete conversation, messages (cascade), and attack chain nodes
export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params

    const eff = await requireEffectiveUser()
    if (eff instanceof NextResponse) return eff
    const guard = await requireConversationAccess(eff, id)
    if (guard instanceof NextResponse) return guard
    const auth = await requirePermission(request, 'agent:chat', { projectId: guard.conversation.projectId })
    if (auth instanceof NextResponse) return auth

    // Fetch conversation to get sessionId (= chain_id in Neo4j)
    const conversation = await prisma.conversation.findUnique({
      where: { id },
      select: { sessionId: true, userId: true, projectId: true },
    })

    if (!conversation) {
      return NextResponse.json({ error: 'Conversation not found' }, { status: 404 })
    }

    // The graph tenant: the project's owner, whose id every chain node carries whoever ran it
    // (step 5.3), from the access the guard read. The agent's run is keyed on its person, the
    // author, so the stop below names them. Without an owner, the author: what it deleted before.
    const tenantUserId = auth.access?.project.userId || conversation.userId

    // STOP the running agent task for this session FIRST. Deleting a conversation
    // used to leave its agent loop running headlessly: it kept iterating and
    // re-MERGEing its AttackChain into Neo4j, so the graph repopulated moments
    // after we cleared it (and it kept burning LLM tokens). Cancelling the task
    // before the graph/DB delete makes the cleanup stick. Best-effort.
    // Each failed step is reported with the success: the agent may still be
    // running, or chain nodes may remain in the graph.
    const warnings: DeleteWarning[] = []
    try {
      const stop = await agentFetch('/agent-session/stop', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          user_id: conversation.userId,
          project_id: conversation.projectId,
          session_id: conversation.sessionId,
        }),
      })
      if (!stop.ok) {
        console.error(`Failed to stop agent session before delete (continuing): HTTP ${stop.status}`)
        warnings.push({ step: 'agent_stop', code: 'agent_error', status: stop.status })
      }
    } catch (stopError) {
      console.error('Failed to stop agent session before delete (continuing):', stopError)
      const code = stopError instanceof AgentUnreachableError
        ? upstreamFailure('agent', stopError.cause_, '').body.code
        : safeErrorCode(stopError)
      warnings.push({ step: 'agent_stop', code })
    }

    // Delete attack chain nodes from Neo4j (fire-and-forget - don't block on failure)
    try {
      const neo4jSession = getGraphSession()
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
            userId: tenantUserId,
            projectId: conversation.projectId,
          }
        )
      } finally {
        await neo4jSession.close()
      }
    } catch (neo4jError) {
      console.error('Failed to delete attack chain nodes from Neo4j (continuing):', neo4jError)
      warnings.push({ step: 'graph_cleanup', code: safeErrorCode(neo4jError) })
    }

    // Delete conversation + cascaded messages from Postgres
    await prisma.conversation.delete({ where: { id } })

    return NextResponse.json(warnings.length ? { success: true, warnings } : { success: true })
  } catch (error) {
    return internalError(error, 'Failed to delete conversation')
  }
}
