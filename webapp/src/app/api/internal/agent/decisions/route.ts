/**
 * POST /api/internal/agent/decisions: the audit row of an answer the agent accepted (step 3.9b;
 * AU-02, IM-09).
 *
 * The agent refuses an approval, a dangerous-tool confirmation or a Fireteam member confirmation
 * the answering person's ticket does not allow (`cap`), and posts each one it accepts here
 * (agentic/orchestrator_helpers/chat_persistence.py `post_agent_decision`). The row names the real
 * person: under act-as the admin (`actorId`, the ticket's `act`) is the actor and the account acted
 * as (`userId`, the ticket's `sub`) goes in `onBehalfOfUserId`.
 *
 * The internal key is the only way in, and it is global, so this route decides nothing: it writes
 * what the agent, which verified the ticket, reports. The decision is already applied, so a failed
 * write answers a coded 500 and the agent logs `[rbac] decision audit failed`.
 */
import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { isInternalRequest } from '@/lib/session'
import { writeAuditTx } from '@/lib/audit'
import { withRouteErrors } from '@/lib/routeErrors'
import type { PermissionId } from '@/lib/authz/permissions'

export const runtime = 'nodejs'

const KINDS: Record<string, { action: string; permission: PermissionId }> = {
  approval: { action: 'agent.approval', permission: 'agent:approve_phase' },
  tool_confirmation: { action: 'agent.tool_confirmation', permission: 'agent:approve_dangerous' },
  // A per-member dangerous-tool escalation (websocket_api.py handle_fireteam_member_confirmation).
  fireteam_member_confirmation: { action: 'agent.tool_confirmation', permission: 'agent:approve_dangerous' },
}

// The agent's decisions are short words ('approve', 'modify', 'abort', 'reject'): only a word, never
// text the person typed (a modification can quote target data), reaches the row.
const DECISION = /^[a-z_]{1,32}$/
const MAX_ID = 200

interface Decision {
  kind: keyof typeof KINDS
  sessionId: string
  projectId: string
  userId: string
  actorId: string | null
  decision: string
  fireteam: { waveId: string; memberId: string } | null
}

const id = (v: unknown): v is string => typeof v === 'string' && v.length > 0 && v.length <= MAX_ID

function parse(body: unknown): Decision | null {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return null
  const b = body as Record<string, unknown>
  if (typeof b.kind !== 'string' || !Object.hasOwn(KINDS, b.kind)) return null
  if (!id(b.sessionId) || !id(b.projectId) || !id(b.userId)) return null
  if (b.actorId !== undefined && b.actorId !== null && !id(b.actorId)) return null
  if (typeof b.decision !== 'string' || !DECISION.test(b.decision)) return null
  const fireteam = b.kind === 'fireteam_member_confirmation'
  if (fireteam ? !id(b.waveId) || !id(b.memberId) : b.waveId !== undefined || b.memberId !== undefined) return null
  return {
    kind: b.kind,
    sessionId: b.sessionId,
    projectId: b.projectId,
    userId: b.userId,
    actorId: (b.actorId as string | null | undefined) ?? null,
    decision: b.decision,
    fireteam: fireteam ? { waveId: b.waveId as string, memberId: b.memberId as string } : null,
  }
}

export const POST = withRouteErrors('Could not record the agent decision', async (request: NextRequest) => {
  if (!isInternalRequest(request)) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }
  const decision = parse(await request.json().catch(() => null))
  if (!decision) {
    return NextResponse.json({ error: 'Not an agent decision', code: 'invalid_decision' }, { status: 400 })
  }
  const { action, permission } = KINDS[decision.kind]
  const actorId = decision.actorId ?? decision.userId
  // The address is a snapshot, so the row still names a person after the account is deleted.
  const actor = await prisma.user.findUnique({ where: { id: actorId }, select: { email: true } })
  // Through writeAuditTx, which throws: the row is the route's only effect, so a lost row must
  // answer 500 rather than the silent success writeAudit gives.
  await writeAuditTx(prisma, {
    actorId,
    onBehalfOfUserId: decision.actorId && decision.actorId !== decision.userId ? decision.userId : null,
    actorEmail: actor?.email ?? null,
    projectId: decision.projectId,
    permission,
    action,
    targetType: 'agent_session',
    targetId: decision.sessionId,
    after: { decision: decision.decision, ...(decision.fireteam ? { fireteam: decision.fireteam } : {}) },
    source: 'ui',
  })
  return NextResponse.json({ recorded: true })
})
