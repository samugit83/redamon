import { NextRequest, NextResponse } from 'next/server'
import { requireAdmin, type Session } from '@/lib/session'
import { withRouteErrors } from '@/lib/routeErrors'
import { readJsonBody } from '@/lib/jsonBody'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { actingAsUserId } from '@/lib/userAudit'
import { closeAgentSockets } from '@/lib/agentSockets'
import {
  decideAllLegacyGrants, decideLegacyGrant, isLegacyGrant, listLegacyHolders, type DecisionActor,
} from '@/lib/authz/updateReview'

/**
 * The admin review of the shared tools members kept at the RBAC upgrade (HD-29). GET lists
 * them; POST `{userId, grant, action: 'keep' | 'remove'}` or `{action: 'keep_all' |
 * 'remove_all'}` decides. No request can add a grant. Removing the Kali terminal grant
 * also closes that member's open terminals (the agent's POST /ws/close, scope `access`, so
 * an admin acting as the member keeps theirs); the sessions console and the tunnel need no
 * close, since each request re-reads the grant.
 */

const PERMISSION = 'users:assign_permissions'

async function reviewer(): Promise<Session | NextResponse> {
  const session = await requireAdmin()
  if (session instanceof NextResponse && session.status === 403) {
    return NextResponse.json(
      { error: 'Only an administrator reviews legacy access.', code: 'forbidden', permission: PERMISSION },
      { status: 403 },
    )
  }
  return session
}

export const GET = withRouteErrors('Could not read the legacy access review', async () => {
  const session = await reviewer()
  if (session instanceof NextResponse) return session
  const holders = await listLegacyHolders()
  const pending = holders.reduce((n, h) => n + h.grants.filter(g => g.state === 'pending').length, 0)
  return NextResponse.json({ holders, pending })
})

const invalid = (code: string, error: string) => NextResponse.json({ error, code }, { status: 400 })

export const POST = withRouteErrors('Could not record the legacy access decision', async (request: NextRequest) => {
  const session = await reviewer()
  if (session instanceof NextResponse) return session
  if (!sameOrigin(request)) return crossOriginResponse(request)
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const { action, userId, grant } = parsed.body

  const actor: DecisionActor = { actorId: session.userId, actingAsUserId: await actingAsUserId(request, session) }

  if (action === 'keep_all' || action === 'remove_all') {
    const result = await decideAllLegacyGrants(actor, action)
    if (action === 'keep_all') return NextResponse.json({ action, changed: result.changed })
    let closed = 0
    let failed = 0
    for (const id of result.terminalLost) {
      const close = await closeAgentSockets({ userId: id, kinds: ['kali-terminal'], scope: 'access' })
      if (close.ok) closed += close.closed
      else failed++
    }
    return NextResponse.json({ action, changed: result.changed, terminals: { closed, failed } })
  }

  if (action !== 'keep' && action !== 'remove') {
    return invalid('invalid_action', 'action must be keep, remove, keep_all or remove_all; a grant is never added.')
  }
  if (typeof userId !== 'string' || userId === '') return invalid('invalid_user', 'userId is required.')
  if (!isLegacyGrant(grant)) return invalid('invalid_grant', 'grant must be kali_terminal, shell_sessions or tunnels.')

  const result = await decideLegacyGrant(actor, userId, grant, action)
  if (!result.ok) return NextResponse.json({ error: result.error, code: result.code }, { status: result.status })
  const answer: Record<string, unknown> = { action, userId, grant, changed: result.changed }
  if (action === 'remove' && result.changed && grant === 'kali_terminal') {
    const close = await closeAgentSockets({ userId, kinds: ['kali-terminal'], scope: 'access' })
    answer.terminal = close.ok ? { closed: close.closed } : { error: close.reason }
  }
  return NextResponse.json(answer)
})
