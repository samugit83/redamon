import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { writeAuditTx } from '@/lib/audit'
import { auditedTransaction } from '@/lib/auditForward'
import { auditActorOf, sessionActor } from '@/lib/auditActor'
import { readJsonBody } from '@/lib/jsonBody'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { withRouteErrors } from '@/lib/routeErrors'
import { requireConversationAccess, requireEffectiveUser } from '@/lib/access'
import { routeNotFound } from '@/lib/authz/accountStatus'
import { refuseWhileActingAs } from '@/lib/authz/actAsRefusals'
import { requirePermission } from '@/lib/authz/guards'
import { conversationSharingInForce, writeConversationShare } from '@/lib/authz/conversationAccess'

interface RouteParams {
  params: Promise<{ id: string }>
}

/**
 * POST /api/conversations/[id]/share `{shared: boolean}` (step 5.8, SH-22): the author shares the
 * conversation, read-only, with everyone on its project, or stops sharing it. Its author only (anyone
 * else gets the conversation guard's 404), with agent:conversations_share (W+A) on the project. Same-origin
 * JSON; refused while an admin acts as the author, since sharing is the person's own choice. Audited in the
 * change's transaction (`conversation.share` / `conversation.unshare`): no row, no change. With write sharing
 * not in force (the switch, sharing and Root's Read + Write) it does not exist: 404, nothing read.
 */
export const POST = withRouteErrors('Could not change the conversation share', async (request: NextRequest, { params }: RouteParams) => {
  if (!(await conversationSharingInForce({ fresh: true }))) return routeNotFound()
  const { id } = await params
  const eff = await requireEffectiveUser()
  if (eff instanceof NextResponse) return eff
  const guard = await requireConversationAccess(eff, id)
  if (guard instanceof NextResponse) return guard
  const projectId = guard.conversation.projectId
  const auth = await requirePermission(request, 'agent:conversations_share', { projectId, fresh: true })
  if (auth instanceof NextResponse) return auth
  if (!sameOrigin(request)) return crossOriginResponse(request)
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const acting = await refuseWhileActingAs({ session: auth.session, targetUserId: eff.userId }, 'change_shares')
  if (acting) return acting
  const shared = parsed.body.shared
  if (typeof shared !== 'boolean') {
    return NextResponse.json({ error: 'shared must be true or false', code: 'invalid_field', field: 'shared' }, { status: 400 })
  }

  const actor = auditActorOf(sessionActor(auth.session), auth.effective.userId)
  const changed = await auditedTransaction(prisma, async (tx) => {
    if (!(await writeConversationShare(tx, id, shared ? eff.userId : null))) return false
    await writeAuditTx(tx, {
      actorId: actor.actorId,
      ...(actor.actorEmail ? { actorEmail: actor.actorEmail } : {}),
      projectId,
      permission: auth.permission,
      action: shared ? 'conversation.share' : 'conversation.unshare',
      targetType: 'conversation',
      targetId: id,
      before: { shared: !shared },
      after: { shared },
      source: 'api',
    })
    return true
  })
  return NextResponse.json({ shared, changed })
})
