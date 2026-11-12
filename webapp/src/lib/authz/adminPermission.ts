/**
 * The administration and platform permissions (§5.1, §5.2) of the signed-in person, for a route that
 * already holds its session: managing users, plugins, the instance traffic capture. Asked through
 * `can()`, so the person's admin profile decides with RBAC_PERMISSIONS_ENABLED on, and with it off
 * the account type's default, which is what an admin and a member can do today (Root and admins
 * every one but Root's own, members none but a legacy grant's shared tool).
 *
 * The real person decides, never the account acted as (§4.7: user administration and the platform
 * read the real session), so only `admin`-kind permissions are asked here; a member permission acts
 * on the effective user's data and goes through `requirePermission` (guards.ts).
 *
 * The account is the one `getSession()` read (its remembered principal). A session object it did
 * not build (a copy, a test double) carries only the id and role getSession read: with the
 * permissions switch off they are the whole answer but for a member's legacy grants, which are not
 * on it (so a shared tool reads as not held: fail closed); with the switch on the account is read.
 */
import type { NextResponse } from 'next/server'
import type { Session } from '@/lib/session'
import { can } from './can'
import type { CapabilityPrincipal } from './capabilities'
import { rbacFlags } from './flags'
import { forbiddenResponse } from './guards'
import { PERMISSIONS, assertKnownPermission, type PermissionId } from './permissions'
import { loadPrincipal } from './principal'
import { sessionPrincipal } from './sessionPrincipal'

export interface AdminPermissionOptions {
  /** A critical path: the account (when not already read fresh), the Root and the sets read again. */
  fresh?: boolean
}

function assertAdministration(permission: PermissionId): void {
  assertKnownPermission(permission)
  if (PERMISSIONS[permission].kind !== 'admin') {
    throw new Error(`adminPermission: ${permission} is a member permission; check it with requirePermission`)
  }
}

async function principalOf(session: Session, fresh: boolean): Promise<CapabilityPrincipal | null> {
  const read = sessionPrincipal(session)
  if (read) return read
  if (!rbacFlags().permissions) {
    return { id: session.userId, role: session.role, status: 'active', adminProfileId: null, legacyGrants: [] }
  }
  return loadPrincipal(session.userId, { fresh })
}

async function decide(principal: CapabilityPrincipal | null, permission: PermissionId, fresh: boolean): Promise<boolean> {
  if (!principal) return false
  return (await can(principal, permission, { fresh })).allowed
}

/** Whether the signed-in person holds this administration or platform permission. A failed read throws. */
export async function sessionHolds(session: Session, permission: PermissionId, { fresh = false }: AdminPermissionOptions = {}): Promise<boolean> {
  assertAdministration(permission)
  return decide(await principalOf(session, fresh), permission, fresh)
}

/** Null when the signed-in person holds the permission, else the 403 naming it (master §9.8). */
export async function requireSessionPermission(
  session: Session,
  permission: PermissionId,
  opts: AdminPermissionOptions = {},
): Promise<NextResponse | null> {
  return (await sessionHolds(session, permission, opts)) ? null : forbiddenResponse(permission)
}

/**
 * Whether the account `userId` names holds this administration or platform permission, read from
 * the database (`fresh` for a gate the account's last change must reach at once). An account that
 * does not exist holds nothing.
 */
export async function accountHolds(userId: string, permission: PermissionId, { fresh = false }: AdminPermissionOptions = {}): Promise<boolean> {
  assertAdministration(permission)
  return decide(await loadPrincipal(userId, { fresh }), permission, fresh)
}
