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
 * With the permissions switch off, capabilities.ts gives every admin *Full admin* (every
 * administration permission but Root's own), Root everything, and a member none but the shared
 * tool of a legacy grant: so for any other permission the account type getSession read is the whole
 * answer, and nothing more is read (no Root, no account: the switch-off product reads what it read
 * before, DV-30). adminPermission.test.ts holds this equal to can() for every such permission.
 * Otherwise can() decides, on the account getSession read (its remembered principal), or on the
 * account read again for a session object getSession did not build (a copy, a test double).
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

/**
 * The shared tools a member holds through a legacy grant (§14.7), `platform:<grant>` of
 * updateReview.ts LEGACY_GRANTS (adminPermission.test.ts holds them equal). Written out: this
 * module loads with the session helpers, so it imports nothing a route test may mock away.
 */
export const LEGACY_GRANTED: ReadonlySet<PermissionId> = new Set<PermissionId>(['platform:kali_terminal', 'platform:shell_sessions', 'platform:tunnels'])

/** Whether the switch-off answer for `permission` is the account type alone (see the header). */
export function decidedByAccountType(permission: PermissionId): boolean {
  return !rbacFlags().permissions && !PERMISSIONS[permission].rootOnly && !LEGACY_GRANTED.has(permission)
}

async function decide(principal: CapabilityPrincipal | null, permission: PermissionId, fresh: boolean): Promise<boolean> {
  if (!principal) return false
  return (await can(principal, permission, { fresh })).allowed
}

/** Whether the signed-in person holds this administration or platform permission. A failed read throws. */
export async function sessionHolds(session: Session, permission: PermissionId, { fresh = false }: AdminPermissionOptions = {}): Promise<boolean> {
  assertAdministration(permission)
  if (decidedByAccountType(permission)) return session.role === 'admin'
  return decide(sessionPrincipal(session) ?? await loadPrincipal(session.userId, { fresh }), permission, fresh)
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
  const principal = await loadPrincipal(userId, { fresh })
  if (principal && decidedByAccountType(permission)) return principal.role === 'admin'
  return decide(principal, permission, fresh)
}
