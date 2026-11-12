/**
 * The instance's Root (step 2.5, ID-02, ID-03, ID-10; feature document §4.4): the one
 * account the instance settings row names (`rootUserId`, a single row, so one Root by
 * construction), while that account exists and is an admin. A Root id that names no account
 * (deleted while the identity switch was off) or an account demoted then is no Root; the boot
 * backfill (scripts/backfill-rbac-root.mjs) chooses again.
 *
 * Confirmed or not: an automatic choice is unconfirmed until the host confirms it, and an
 * unconfirmed Root has Root's protections (rootProtection.ts) but not the Root-only powers
 * (step 2.6 checks `confirmed`).
 *
 * Read only with RBAC_IDENTITY_ENABLED on; off, there is no Root and nothing is read. The row
 * is one for the whole process, so it is cached apart from the accounts for the same bound
 * (RBAC_AUTHZ_CACHE_MS): a request's account read stays one query (DV-25). A protection or a
 * Root-only power reads it `fresh`.
 */
import prisma from '@/lib/prisma'
import type { Prisma } from '@prisma/client'
import { rbacFlags } from './flags'
import { now } from './clock'
import { principalCacheTtl } from './principal'

export const INSTANCE_SETTINGS_ROW = 'instance'

/**
 * The advisory lock every writer of the Root takes: the boot backfill, the host's set-root and
 * create-admin, the Root transfer, and (switch on) every write that could leave the Root naming
 * an account that is no longer an active admin. `hashtext('rbac-root')`, per database.
 */
export const ROOT_LOCK = 'rbac-root'

export interface InstanceRoot {
  userId: string
  email: string
  /** Set by the install, the host (update, set-root) or a transfer; an automatic choice is not. */
  confirmed: boolean
  /** automatic | install | host | transfer */
  assignedBy: string | null
}

export type AccountType = 'root' | 'admin' | 'member'

let cached: { root: InstanceRoot | null; expiresAt: number } | null = null
// Raised by every invalidation: a read that started before one is returned but not kept.
let generation = 0

/** The Root, or null (none, or the identity switch is off). A failed read throws. */
export async function loadInstanceRoot({ fresh = false }: { fresh?: boolean } = {}): Promise<InstanceRoot | null> {
  if (!rbacFlags().identity) return null
  const ttl = principalCacheTtl()
  if (!fresh && ttl > 0 && cached && cached.expiresAt > now().getTime()) return cached.root
  const startedAt = generation
  const root = await readInstanceRoot()
  if (ttl > 0 && startedAt === generation) cached = { root, expiresAt: now().getTime() + ttl }
  return root
}

type RootReader = Pick<Prisma.TransactionClient, 'instanceSettings' | 'user'>

async function readInstanceRoot(db: RootReader = prisma): Promise<InstanceRoot | null> {
  const row = await db.instanceSettings.findUnique({
    where: { id: INSTANCE_SETTINGS_ROW },
    select: { rootUserId: true, rootConfirmedAt: true, rootAssignedBy: true },
  })
  if (!row?.rootUserId) return null
  const account = await db.user.findUnique({ where: { id: row.rootUserId }, select: { email: true, role: true } })
  if (!account || account.role !== 'admin') return null
  return Object.freeze({
    userId: row.rootUserId,
    email: account.email,
    confirmed: row.rootConfirmedAt !== null,
    assignedBy: row.rootAssignedBy ?? null,
  })
}

/**
 * Inside a transaction: takes the Root lock, then reads the Root as committed now (never the
 * cache), so no other writer of the Root can move it before this transaction ends.
 */
export async function lockedInstanceRoot(tx: Prisma.TransactionClient): Promise<InstanceRoot | null> {
  await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${ROOT_LOCK}))`
  return readInstanceRoot(tx)
}

/** Whether `userId` is the Root (always false with the identity switch off). */
export async function isRootAccount(userId: string, opts: { fresh?: boolean } = {}): Promise<boolean> {
  const root = await loadInstanceRoot(opts)
  return root !== null && root.userId === userId
}

/** root for the account the instance names, admin for another admin, member for the rest. */
export function accountTypeOf(account: { id: string; role: string }, root: InstanceRoot | null): AccountType {
  if (root && root.userId === account.id) return 'root'
  return account.role === 'admin' ? 'admin' : 'member'
}

/** A writer of the Root in this process (a transfer, step 2.6): the next read goes to the database. */
export function invalidateInstanceRoot(): void {
  generation += 1
  cached = null
}

/** Tests only. */
export function clearInstanceRootCacheForTests(): void {
  invalidateInstanceRoot()
}
