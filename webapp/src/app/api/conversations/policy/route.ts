import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { writeAuditTx } from '@/lib/audit'
import { auditedTransaction } from '@/lib/auditForward'
import { auditActorOf, sessionActor } from '@/lib/auditActor'
import { readJsonBody } from '@/lib/jsonBody'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { withRouteErrors } from '@/lib/routeErrors'
import { routeNotFound } from '@/lib/authz/accountStatus'
import { refuseWhileActingAs } from '@/lib/authz/actAsRefusals'
import { requireLevel, requirePermission } from '@/lib/authz/guards'
import {
  conversationSharingInForce, managersSeeAllConversations, writeManagersSeeAll,
} from '@/lib/authz/conversationAccess'

const projectIdOf = (request: NextRequest) => new URL(request.url).searchParams.get('projectId')

/**
 * GET /api/conversations/policy?projectId= (step 5.8, SH-22, OQ-07): whether the project's owner lets the
 * co-owners read every conversation of the project, for anyone who chats there (agent:chat), so a
 * collaborator knows who may read their conversations. Write sharing in force only (404 otherwise,
 * nothing read).
 */
export const GET = withRouteErrors('Could not read the conversations policy', async (request: NextRequest) => {
  if (!(await conversationSharingInForce())) return routeNotFound()
  const projectId = projectIdOf(request)
  const auth = await requirePermission(request, 'agent:chat', { projectId })
  if (auth instanceof NextResponse) return auth
  return NextResponse.json({ managersSeeAllConversations: await managersSeeAllConversations(auth.access!.project.id) })
})

/**
 * POST /api/conversations/policy?projectId= `{managersSeeAllConversations: boolean}` (step 5.8, OQ-07): the
 * owner, and only the owner (agent:conversations_share at the owner level), turns the co-owners' view of
 * every conversation on or off. Same-origin JSON; refused while an admin acts as the owner. Audited in the
 * change's transaction (`project.conversations_policy`), so it shows in the project's activity. Write
 * sharing in force only (404 otherwise, nothing read).
 */
export const POST = withRouteErrors('Could not change the conversations policy', async (request: NextRequest) => {
  if (!(await conversationSharingInForce({ fresh: true }))) return routeNotFound()
  const projectId = projectIdOf(request)
  const auth = await requirePermission(request, 'agent:conversations_share', { projectId, fresh: true })
  if (auth instanceof NextResponse) return auth
  if (!sameOrigin(request)) return crossOriginResponse(request)
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const ownerOnly = requireLevel(auth, 'O')
  if (ownerOnly) return ownerOnly
  const project = auth.access!.project
  const acting = await refuseWhileActingAs({ session: auth.session, targetUserId: project.userId }, 'change_shares')
  if (acting) return acting
  const wanted = parsed.body.managersSeeAllConversations
  if (typeof wanted !== 'boolean') {
    return NextResponse.json(
      { error: 'managersSeeAllConversations must be true or false', code: 'invalid_field', field: 'managersSeeAllConversations' },
      { status: 400 },
    )
  }

  const actor = auditActorOf(sessionActor(auth.session), auth.effective.userId)
  const changed = await auditedTransaction(prisma, async (tx) => {
    if (!(await writeManagersSeeAll(tx, project.id, wanted))) return false
    await writeAuditTx(tx, {
      actorId: actor.actorId,
      ...(actor.actorEmail ? { actorEmail: actor.actorEmail } : {}),
      projectId: project.id,
      permission: auth.permission,
      action: 'project.conversations_policy',
      targetType: 'project',
      targetId: project.id,
      before: { managersSeeAllConversations: !wanted },
      after: { managersSeeAllConversations: wanted },
      source: 'api',
    })
    return true
  })
  return NextResponse.json({ managersSeeAllConversations: wanted, changed })
})
