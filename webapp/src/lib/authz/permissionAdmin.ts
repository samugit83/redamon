/**
 * What the permission-management writers share (step 3.11): the lock every writer of a set, an
 * admin profile, an assignment, an override or the instance default set takes; the signed-in
 * person and a target as hierarchy.ts sees them; a set's contents as stored; the audit entry of a
 * set or profile change; and ending the sessions of accounts that lost a permission.
 *
 * Every read here is fresh: these are the critical checks of master plan §9.6 (a revoked admin
 * never changes another account's rights on a cached answer).
 */
import { NextResponse, type NextRequest } from 'next/server'
import type { Prisma } from '@prisma/client'
import prisma from '@/lib/prisma'
import type { AuditEntry } from '@/lib/audit'
import { actorFields, auditActorOf, sessionActor } from '@/lib/auditActor'
import { actingAsUserId } from '@/lib/userAudit'
import type { Session } from '@/lib/session'
import { endAgentWork } from './accountStatus'
import { builtinSet, FULL_ADMIN_PROFILE_ID } from './builtinSets'
import { resolveCapabilities, type Capabilities } from './capabilities'
import { forbiddenResponse } from './guards'
import type { Managed, Manager } from './hierarchy'
import { PERMISSIONS, isPermissionId, type PermissionId } from './permissions'
import { invalidatePrincipal, loadPrincipal, type Principal } from './principal'
import { accountTypeOf, loadInstanceRoot } from './root'
import { sessionPrincipal } from './sessionPrincipal'

/**
 * Taken first by every writer of permission data, `hashtext('rbac.permissions')` per database: a
 * set is never deleted while an assignment of it commits, and two admins editing one account
 * serialize, on every webapp copy.
 */
export const PERMISSIONS_LOCK = 'rbac.permissions'

export type Tx = Prisma.TransactionClient
type Db = Pick<Prisma.TransactionClient, 'permissionSet'>

export async function lockPermissions(tx: Tx): Promise<void> {
  await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${PERMISSIONS_LOCK}))`
}

export type SetKind = 'member' | 'admin'

export interface SetContents {
  id: string
  kind: SetKind
  name: string
  permissions: PermissionId[]
  builtin: boolean
}

/**
 * The permissions a custom row of this kind can carry: known ids of its kind; of the Root-only ones
 * only `admins:manage`, in an admin profile (OQ-02). capabilities.ts reads a row the same way.
 */
export function keptPermissions(permissions: readonly string[], kind: SetKind): PermissionId[] {
  return permissions.filter((p): p is PermissionId =>
    isPermissionId(p) && PERMISSIONS[p].kind === kind && (!PERMISSIONS[p].rootOnly || p === 'admins:manage'))
}

/** A built-in or stored set of `kind`, or null when `id` names none of that kind. */
export async function setOfKind(db: Db, id: string, kind: SetKind): Promise<SetContents | null> {
  const builtin = builtinSet(id)
  if (builtin) return builtin.kind === kind ? { id, kind, name: builtin.name, permissions: [...builtin.permissions], builtin: true } : null
  if (id.startsWith('builtin:')) return null
  const row = await db.permissionSet.findUnique({ where: { id }, select: { kind: true, name: true, permissions: true } })
  if (!row || row.kind !== kind) return null
  return { id, kind, name: row.name, permissions: keptPermissions(row.permissions, kind), builtin: false }
}

/** An admin's profile as stored: none recorded = *Full admin*; a profile that is gone gives nothing. */
export async function profileContents(db: Db, adminProfileId: string | null): Promise<PermissionId[]> {
  const set = await setOfKind(db, adminProfileId ?? FULL_ADMIN_PROFILE_ID, 'admin')
  return set ? set.permissions : []
}

export interface Acting {
  manager: Manager
  principal: Principal
  capabilities: Capabilities
}

/**
 * What a person may give: what they hold, counting what only an instance cap removes
 * (`MCP_SERVER_ENABLED`, `AGENT_IN_THE_LOOP_ENABLED`). A cap removes the permission from every
 * account alike, the target's too, so it must not stop an admin assigning *Default member*.
 */
export function givable(capabilities: Capabilities): PermissionId[] {
  return capabilities.explainAll()
    .filter((e) => e.held || (e.reasons.some((r) => r.effect === 'grant')
      && e.reasons.every((r) => r.effect === 'grant' || r.kind === 'instance_cap')))
    .map((e) => e.permission)
}

function managerFrom(capabilities: Capabilities): Manager {
  return { id: capabilities.userId, accountType: capabilities.accountType, held: givable(capabilities) }
}

/** The signed-in person, read fresh, as hierarchy.ts sees them. A failed read throws. */
export async function managerOf(session: Session): Promise<Acting> {
  const principal = sessionPrincipal(session) ?? await loadPrincipal(session.userId, { fresh: true })
  if (!principal) throw new Error('permissionAdmin: the signed-in account is gone')
  const capabilities = await resolveCapabilities(principal, { fresh: true })
  return { manager: managerFrom(capabilities), principal, capabilities }
}

export interface Target {
  principal: Principal
  managed: Managed
}

/** The account `targetId` names, read fresh, as a target; null when it does not exist. */
export async function managedOf(targetId: string): Promise<Target | null> {
  const principal = await loadPrincipal(targetId, { fresh: true })
  if (!principal) return null
  const root = principal.role === 'admin' ? await loadInstanceRoot({ fresh: true }) : null
  const accountType = accountTypeOf(principal, root)
  const profile = accountType === 'admin' ? await profileContents(prisma, principal.adminProfileId) : []
  return { principal, managed: { id: principal.id, accountType, profile } }
}

/** Null when the person holds one of `permissions`; else the 403 naming the first. */
export async function requireAnyPermission(session: Session, permissions: readonly [PermissionId, ...PermissionId[]]): Promise<NextResponse | null> {
  const { capabilities } = await managerOf(session)
  return permissions.some((p) => capabilities.has(p)) ? null : forbiddenResponse(permissions[0])
}

/** 403 `not_held`: the change would give what the person does not hold (PE-03). */
export function notHeldResponse(permissions: readonly string[]): NextResponse {
  return NextResponse.json({
    error: `You can give only permissions you hold yourself; you do not hold: ${permissions.join(', ')}.`,
    code: 'not_held',
    permissions,
  }, { status: 403 })
}

/** The audit entry of a change a person made, with the real person and the account acted as. */
export async function personAuditEntry(
  request: NextRequest,
  session: Session,
  entry: Omit<AuditEntry, 'actorId' | 'onBehalfOfUserId' | 'actorEmail' | 'source'>,
): Promise<AuditEntry> {
  const actingAs = await actingAsUserId(request, session)
  return { ...actorFields(auditActorOf(sessionActor(session), actingAs)), ...entry, source: 'api' }
}

/**
 * Ends what the accounts that lost a permission still hold (ID-21): their session version was
 * raised in the change's transaction; here, after the commit, this process forgets them and the
 * agent closes their sockets. Never throws; a refused agent call is logged by `endAgentWork`
 * (`[rbac] socket-close failed`) and counted.
 */
export async function endSessionsOf(userIds: readonly string[]): Promise<{ closed: number; failed: number }> {
  let closed = 0
  let failed = 0
  for (const id of userIds) invalidatePrincipal(id)
  for (const id of userIds) {
    const ended = await endAgentWork(id, { stopRuns: false })
    if ('closed' in ended.sockets) closed += ended.sockets.closed
    else failed += 1
  }
  return { closed, failed }
}
