/**
 * Who may manage whom, and what they may give (step 3.11; feature document §4.5, §4.8; PE-03,
 * PE-08, PE-09, PE-10). Root > admin > member:
 *
 *   - an admin acts on members, with the permission of the action (`users:disable`, ...);
 *   - another admin is Root's; with `admins:manage` (D-02: in no built-in profile, only Root puts
 *     it in a custom one) an admin also manages an admin whose profile sits STRICTLY inside its own
 *     admin side, so two peers with one profile can never take each other over (F-08), and promotes
 *     only to such a profile; even then a reset, an impersonation and a creation stay Root's;
 *   - nobody acts on Root (rootProtection.ts answers it first in the routes);
 *   - nobody gives a permission they do not hold (`unheld`).
 *
 * Root's powers here are an account type `root` holding `admins:manage`: a confirmed Root holds
 * every permission, an unconfirmed one none of the Root-only ones (step 2.6), so it manages
 * members like an admin and no admin.
 *
 * Pure rules over what capabilities.ts resolved; the routes read the accounts. With
 * RBAC_PERMISSIONS_ENABLED off nothing calls them: Phase 2's Root-only gates answer (rootPowers.ts).
 */
import { PERMISSIONS, PERMISSION_IDS, isPermissionId, type PermissionId } from './permissions'
import type { AccountType } from './root'

export type ManageAction =
  | 'create' | 'edit' | 'assign_permissions' | 'disable' | 'enable'
  | 'reset_credentials' | 'revoke_sessions' | 'impersonate' | 'delete'

/** The §5.1 permission each row of the §4.8 table needs on a member. */
export const MANAGE_PERMISSION: Readonly<Record<ManageAction, PermissionId>> = Object.freeze({
  create: 'users:create',
  edit: 'users:edit',
  assign_permissions: 'users:assign_permissions',
  disable: 'users:disable',
  enable: 'users:disable',
  reset_credentials: 'users:reset_credentials',
  revoke_sessions: 'users:revoke_sessions',
  impersonate: 'users:impersonate',
  delete: 'users:delete',
})

export const MANAGE_ACTIONS: readonly ManageAction[] = Object.freeze(Object.keys(MANAGE_PERMISSION) as ManageAction[])

/**
 * On another admin these stay Root's even for an `admins:manage` holder: a reset and an
 * impersonation are takeovers (§4.5), and admins are created by Root or promoted (D-02).
 */
export const ROOT_ONLY_ON_ADMINS: ReadonlySet<ManageAction> = new Set<ManageAction>(['create', 'reset_credentials', 'impersonate'])

/**
 * Giving any of these takes the giver's password (ID-25): the cross-tenant platform tools, and the
 * agent's exploitation approvals, shell sessions and Kali commands.
 */
export const STEP_UP_PERMISSIONS: readonly PermissionId[] = Object.freeze(PERMISSION_IDS.filter((p) =>
  PERMISSIONS[p].crossTenant
  || p === 'agent:approve_phase' || p === 'agent:approve_dangerous' || p === 'agent:sessions' || p === 'agent:kali_exec'))

export interface Manager {
  id: string
  accountType: AccountType
  /** What the actor holds now (capabilities.ts `held`). */
  held: readonly PermissionId[]
}

export interface Managed {
  id: string
  accountType: AccountType
  /** An admin target's profile as stored (not narrowed by denies or status); [] for anyone else. */
  profile: readonly PermissionId[]
}

export type ManageDecision =
  | { allowed: true }
  | { allowed: false; reason: 'own_account' | 'root_protected' | 'root_only' | 'not_a_subset' }
  | { allowed: false; reason: 'forbidden'; permission: PermissionId }

const ALLOWED: ManageDecision = Object.freeze({ allowed: true })
const refused = (reason: 'own_account' | 'root_protected' | 'root_only' | 'not_a_subset'): ManageDecision =>
  Object.freeze({ allowed: false, reason })

function holds(actor: Manager, permission: PermissionId): boolean {
  return actor.held.includes(permission)
}

function hasRootPowers(actor: Manager): boolean {
  return actor.accountType === 'root' && holds(actor, 'admins:manage')
}

/** The administration and platform permissions among `held`, in registry order. */
export function adminSide(held: readonly PermissionId[]): PermissionId[] {
  const set = new Set(held)
  return PERMISSION_IDS.filter((p) => set.has(p) && PERMISSIONS[p].kind === 'admin')
}

/** Every id of `inner` is in `outer`, and `outer` holds at least one more. */
export function isStrictSubset(inner: readonly string[], outer: readonly string[]): boolean {
  const out = new Set(outer)
  const inn = new Set(inner)
  for (const p of inn) if (!out.has(p)) return false
  return out.size > inn.size
}

/** May `actor` take `action` on `target` (§4.8)? */
export function canManage(actor: Manager, target: Managed, action: ManageAction): ManageDecision {
  if (actor.id === target.id) return refused('own_account')
  if (target.accountType === 'root') return refused('root_protected')
  const permission = MANAGE_PERMISSION[action]
  if (target.accountType === 'admin') {
    if (hasRootPowers(actor)) return ALLOWED
    if (ROOT_ONLY_ON_ADMINS.has(action) || !holds(actor, 'admins:manage')) return refused('root_only')
    if (!holds(actor, permission)) return Object.freeze({ allowed: false, reason: 'forbidden', permission })
    return isStrictSubset(target.profile, adminSide(actor.held)) ? ALLOWED : refused('not_a_subset')
  }
  return holds(actor, permission) ? ALLOWED : Object.freeze({ allowed: false, reason: 'forbidden', permission })
}

/** May `actor` give an admin this profile (a promotion or a profile change)? Only a strict subset of its own. */
export function canAssignProfile(actor: Manager, profile: readonly PermissionId[]): ManageDecision {
  if (hasRootPowers(actor)) return ALLOWED
  if (!holds(actor, 'admins:manage')) return refused('root_only')
  return isStrictSubset(profile, adminSide(actor.held)) ? ALLOWED : refused('not_a_subset')
}

/** What of `permissions` the actor does not hold (PE-10, PE-11), in registry order; an unknown id is never held. */
export function unheld(actor: Manager, permissions: readonly string[]): string[] {
  const wanted = new Set(permissions)
  const known = PERMISSION_IDS.filter((p) => wanted.has(p) && !holds(actor, p))
  const unknown = [...wanted].filter((p) => !isPermissionId(p))
  return [...known, ...unknown]
}

/** The permissions among `permissions` whose giving takes a step-up, in registry order. */
export function stepUpPermissionsIn(permissions: readonly string[]): PermissionId[] {
  const wanted = new Set(permissions)
  return STEP_UP_PERMISSIONS.filter((p) => wanted.has(p))
}

/**
 * Whether an override (grant or deny) may name this permission on an account of this type (D-20,
 * PE-30): any member permission; a §5.2 platform tool on a member only (the §14.7 shared tools,
 * step 3.15); never a §5.1 administration permission, nothing on an admin's admin side (its one
 * profile states it whole), nothing on Root (Root never depends on stored data).
 */
export function overrideAllowed(permission: PermissionId, accountType: AccountType): boolean {
  if (accountType === 'root') return false
  const meta = PERMISSIONS[permission]
  return meta.kind === 'member' || (accountType === 'member' && meta.crossTenant)
}
