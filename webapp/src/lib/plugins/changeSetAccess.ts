import { NextResponse } from 'next/server'
import { meetsLevel, projectAccess } from '@/lib/authz/projectAccess'
import { ownsRow } from '@/lib/authz/rowOwner'
import { requireAccountWrite } from '@/lib/session'
import type { OverrideScope } from './overrides'

/**
 * Who may act on a change set (OQ-08, X9). A user scope is that account's own (`ownsRow`): only the
 * effective user who IS it. A project scope is decided at Manage (step 5.10, SH-35): the owner, or a
 * co-owner whose share holds Manage, as `projectAccess()` answers; a collaborator without it may
 * run a plugin that proposes, never approve, reject, delete or reset what it proposed. An admin
 * acting as the owner passes because the effective user is the owner; one acting as a collaborator
 * reaches the share at read (D-22) and never decides. The audit records the real session user.
 *
 * A user-scope write also carries `scopeOwnerId` in its body, which must equal the effective
 * user: the act-as cookie is site-wide, so a second tab could have switched it between the
 * page load and the click (RV-33). This is the extra body check callers apply on top.
 */
export interface ScopeAccessOptions {
  /** The effective user is the account an admin acts as (the guard's `actingAs`). */
  actingAs?: boolean
}

/**
 * Why the effective user may not act on the scope: `not_found` when it is not theirs to see (another
 * account, a project they cannot reach), `level` when they reach the project below Manage; null when
 * they may.
 */
export async function scopeRefusal(
  scope: OverrideScope,
  effectiveUserId: string,
  opts: ScopeAccessOptions = {},
): Promise<'not_found' | 'level' | null> {
  const subject = { userId: effectiveUserId }
  if (scope.type === 'user') return ownsRow(subject, scope.id) ? null : 'not_found'
  if (typeof scope.id !== 'string' || !scope.id) return 'not_found'
  const access = opts.actingAs === true
    ? await projectAccess(subject, scope.id, { actingAs: true })
    : await projectAccess(subject, scope.id)
  if (access === null) return 'not_found'
  if (meetsLevel(access, 'M')) return null
  // Oversight and break-glass are no collaborators: the project's sets stay out of their sight.
  return access.via === 'share' ? 'level' : 'not_found'
}

/** Whether the effective user may read and decide the scope's change sets (`scopeRefusal` is null). */
export async function ownsScope(scope: OverrideScope, effectiveUserId: string, opts: ScopeAccessOptions = {}): Promise<boolean> {
  return (await scopeRefusal(scope, effectiveUserId, opts)) === null
}

/**
 * The answer to a refused scope: 404 for a scope that is not the caller's to see, 403 naming Manage
 * for a collaborator below it (§9.8).
 */
export function scopeRefusalResponse(refusal: 'not_found' | 'level', permission: string): NextResponse {
  if (refusal === 'not_found') return NextResponse.json({ error: 'Not found', code: 'not_found' }, { status: 404 })
  return NextResponse.json(
    { error: `Deciding this project's plugin proposals needs Manage on the project (${permission}, level M).`, code: 'forbidden', permission, level: 'M' },
    { status: 403 },
  )
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
 * managed account is not. A project scope keeps the Manage check of `scopeRefusal`. Call it
 * after `scopeRefusal`, so another account's set stays a 404. Null when allowed.
 */
export async function userScopeWriteRefusal(scope: OverrideScope): Promise<NextResponse | null> {
  if (scope.type !== 'user') return null
  return requireAccountWrite(scope.id)
}
