import { NextRequest, NextResponse } from 'next/server'
import { requireAdmin, type Session, type SessionOptions } from '@/lib/session'
import { withRouteErrors } from '@/lib/routeErrors'
import { readJsonBody } from '@/lib/jsonBody'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { actingAsUserId } from '@/lib/userAudit'
import { sessionActor } from '@/lib/auditActor'
import { closeAgentSockets } from '@/lib/agentSockets'
import {
  decideAllLegacyGrants, decideLegacyGrant, isLegacyGrant, listLegacyHolders, type DecisionActor,
} from '@/lib/authz/updateReview'
import { rbacFlags } from '@/lib/authz/flags'
import { LEGACY_KEEP_DAYS } from '@/lib/authz/legacyOverrides'
import { writeLegacyOverrides } from '@/lib/authz/legacyOverrideDecisions'

/**
 * The admin review of the shared tools members kept at the RBAC upgrade (HD-29). GET lists
 * them; POST `{userId, grant, action: 'keep' | 'remove'}` or `{action: 'keep_all' |
 * 'remove_all'}` decides. No request can add a grant. Removing the Kali terminal grant
 * also closes that member's open terminals (the agent's POST /ws/close, scope `access`, so
 * an admin acting as the member keeps theirs); the sessions console and the tunnel need no
 * close, since each request re-reads the grant.
 *
 * With RBAC_PERMISSIONS_ENABLED on (step 3.15) a grant is kept by an expiring override: each
 * decision first changes the member's overrides through the account permission writer
 * (legacyOverrideDecisions.ts: its rules, its step-up `stepUpPassword` for a Keep, its audit row
 * and its sign-out on a removal), then is recorded as above, the column included, so a roll-back
 * (the switch off) keeps every removal and every Keep. A refusal of the writer is the answer, and
 * nothing of that account is recorded.
 */

const PERMISSION = 'users:assign_permissions'

async function reviewer(opts: SessionOptions = {}): Promise<Session | NextResponse> {
  const session = await requireAdmin(opts)
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
  if (!rbacFlags().permissions) return NextResponse.json({ holders, pending })
  return NextResponse.json({ holders, pending, overrides: true, keepDays: LEGACY_KEEP_DAYS })
})

const invalid = (code: string, error: string) => NextResponse.json({ error, code }, { status: 400 })

export const POST = withRouteErrors('Could not record the legacy access decision', async (request: NextRequest) => {
  // A decision changes another account's grants and may close its terminals: a stale admin never makes it.
  const session = await reviewer({ fresh: true })
  if (session instanceof NextResponse) return session
  if (!sameOrigin(request)) return crossOriginResponse(request)
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const { action, userId, grant, stepUpPassword } = parsed.body
  const overrides = rbacFlags().permissions

  const actor: DecisionActor = {
    actorId: session.userId, actingAsUserId: await actingAsUserId(request, session), actorEmail: sessionActor(session).email,
  }

  if (action === 'keep_all' || action === 'remove_all') {
    if (overrides) {
      let changed = 0
      for (const holder of await listLegacyHolders()) {
        const grants = holder.grants.filter(g => action === 'remove_all' || g.state === 'pending').map(g => g.grant)
        if (grants.length === 0) continue
        const refused = await writeLegacyOverrides(request, session, holder.id, grants, action === 'keep_all' ? 'keep' : 'remove', stepUpPassword)
        if (refused) return refused
        if (action === 'keep_all') {
          for (const g of grants) await decideLegacyGrant(actor, holder.id, g, 'keep')
          changed += grants.length
        }
      }
      if (action === 'keep_all') return NextResponse.json({ action, changed })
    }
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

  if (overrides) {
    const refused = await writeLegacyOverrides(request, session, userId, [grant], action, stepUpPassword)
    if (refused) return refused
  }
  const result = await decideLegacyGrant(actor, userId, grant, action)
  if (!result.ok) return NextResponse.json({ error: result.error, code: result.code }, { status: result.status })
  const answer: Record<string, unknown> = { action, userId, grant, changed: result.changed }
  if (action === 'remove' && result.changed && grant === 'kali_terminal') {
    const close = await closeAgentSockets({ userId, kinds: ['kali-terminal'], scope: 'access' })
    answer.terminal = close.ok ? { closed: close.closed } : { error: close.reason }
  }
  return NextResponse.json(answer)
})
