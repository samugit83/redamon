import type { NextResponse } from 'next/server'
import { meetsLevel, projectAccess } from '@/lib/authz/projectAccess'
import { ownsRow } from '@/lib/authz/rowOwner'
import { requireAccountWrite } from '@/lib/session'
import type { OverrideScope } from './overrides'

/**
 * Who may act on a change set (OQ-08, X9). The effective user must own its scope — a user
 * scope they ARE (`ownsRow`), a project scope `projectAccess()` gives them at the owner level.
 * An admin acting as the owner passes because the effective user is the owner; the audit
 * records the real session user.
 *
 * A user-scope write also carries `scopeOwnerId` in its body, which must equal the effective
 * user: the act-as cookie is site-wide, so a second tab could have switched it between the
 * page load and the click (RV-33). This is the extra body check callers apply on top.
 */
export async function ownsScope(scope: OverrideScope, effectiveUserId: string): Promise<boolean> {
  const subject = { userId: effectiveUserId }
  if (scope.type === 'user') return ownsRow(subject, scope.id)
  if (typeof scope.id !== 'string' || !scope.id) return false
  const access = await projectAccess(subject, scope.id)
  return access !== null && meetsLevel(access, 'O')
}

/** For a user-scope write: the body's scopeOwnerId must be the effective user and the owner. */
export function bodyOwnerMatches(scope: OverrideScope, effectiveUserId: string, scopeOwnerId: unknown): boolean {
  if (scope.type !== 'user') return true
  return typeof scopeOwnerId === 'string' && scopeOwnerId === effectiveUserId && scopeOwnerId === scope.id
}

/**
 * A user scope is that account's own catalog and prompt: approving, rejecting, deleting or
 * resetting one of its versions follows the account write rule (HD-23, OQ-49), so an admin
 * acting as a member who can sign in is refused, and an admin acting as a passwordless
 * managed account is not. A project scope keeps the owner check of `ownsScope`. Call it
 * after `ownsScope`, so another account's set stays a 404. Null when allowed.
 */
export async function userScopeWriteRefusal(scope: OverrideScope): Promise<NextResponse | null> {
  if (scope.type !== 'user') return null
  return requireAccountWrite(scope.id)
}
