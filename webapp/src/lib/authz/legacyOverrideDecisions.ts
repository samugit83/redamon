/**
 * The legacy access review with RBAC_PERMISSIONS_ENABLED on (step 3.15, HD-02): before the
 * review records a decision (updateReview.ts), the member's overrides change through the account
 * permission writer (userPermissionAdmin.ts, step 3.11), with its rules: the person must be able
 * to assign the member's permissions and hold what they give (PE-03), giving a platform tool
 * takes their password (ID-25), the change commits with its `user.permissions_changed` row, and
 * a removal that takes a permission the member held signs them out (ID-21).
 *
 * - Keep: an override grant of the grant's platform permission with the reason "kept from 7.7.x"
 *   and a 90-day end (legacyOverrides.ts). A grant override in force is left as it is; a deny in
 *   force refuses (a person chose it on the account).
 * - Remove: every grant override of that permission goes; a deny stays.
 *
 * Overrides past their end are dropped from the list the writer receives (it accepts no past end
 * date): they give and take nothing.
 */
import { NextResponse, type NextRequest } from 'next/server'
import type { Session } from '@/lib/session'
import { now } from './clock'
import { KEPT_LEGACY_REASON, LEGACY_GRANT_PERMISSION, legacyKeepExpiry } from './legacyOverrides'
import { managedOf } from './permissionAdmin'
import type { PermissionOverrideRow } from './principal'
import type { LegacyGrant } from './updateReview'
import { changeUserPermissions } from './userPermissionAdmin'

const inForce = (o: PermissionOverrideRow, at: number) => o.expiresAt === null || o.expiresAt.getTime() > at
const asBody = (o: PermissionOverrideRow) => ({
  permission: o.permission, effect: o.effect, expiresAt: o.expiresAt ? o.expiresAt.toISOString() : null, reason: o.reason,
})

/**
 * Writes the overrides that keep (or stop giving) `grants` to the member `userId`. Null when they
 * are written or nothing had to change; else the answer refusing it, nothing written.
 */
export async function writeLegacyOverrides(
  request: NextRequest,
  session: Session,
  userId: string,
  grants: readonly LegacyGrant[],
  action: 'keep' | 'remove',
  stepUpPassword: unknown,
): Promise<NextResponse | null> {
  const target = await managedOf(userId)
  if (!target) return NextResponse.json({ error: 'Account not found', code: 'not_found' }, { status: 404 })
  const permissions = new Set<string>(grants.map(g => LEGACY_GRANT_PERMISSION.get(g)!))
  const current = target.principal.permissionOverrides ?? []
  const at = now().getTime()
  const live = current.filter(o => inForce(o, at))
  let next: PermissionOverrideRow[]
  if (action === 'keep') {
    if (grants.some(g => !target.principal.legacyGrants.includes(g))) {
      return NextResponse.json({ error: 'This account no longer holds that grant.', code: 'not_held' }, { status: 409 })
    }
    const denied = live.find(o => permissions.has(o.permission) && o.effect === 'deny')
    if (denied) {
      return NextResponse.json({
        error: `A deny override of ${denied.permission} stands on this account; change it on the account's permissions.`,
        code: 'overridden',
        permission: denied.permission,
      }, { status: 409 })
    }
    const missing = [...permissions].filter(p => !live.some(o => o.permission === p && o.effect === 'grant'))
    if (missing.length === 0) return null
    const expiresAt = legacyKeepExpiry()
    next = [...live, ...missing.map(permission => ({ permission, effect: 'grant', expiresAt, reason: KEPT_LEGACY_REASON }))]
  } else {
    if (!current.some(o => permissions.has(o.permission) && o.effect === 'grant')) return null
    next = live.filter(o => !(permissions.has(o.permission) && o.effect === 'grant'))
  }
  const answer = await changeUserPermissions(request, session, userId, { overrides: next.map(asBody), stepUpPassword })
  return answer.ok ? null : answer
}
