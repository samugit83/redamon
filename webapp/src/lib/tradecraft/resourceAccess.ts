/**
 * The one lookup of a tradecraft resource by its id and its account (D-27): every route of
 * `/api/users/[id]/tradecraft-resources/[resourceId]/**` reads the row here, after
 * `requireUserAccess` and `requireSelfPermission` decided the path's account may be reached.
 * authzStaticGuard.test.ts allows this statement alone.
 *
 * A 1.x answer reads the 1.x columns by name: an answer that spread a whole row would carry
 * every 2.0 column, `credentials` above all, to the browser and to the 1.x agent (D-44).
 */
import type { Prisma, UserTradecraftResource } from '@prisma/client'
import prisma from '@/lib/prisma'
import { LEGACY_RESOURCE_COLUMNS } from './agentContract'

type Db = Prisma.TransactionClient | typeof prisma

export type LegacyColumn = (typeof LEGACY_RESOURCE_COLUMNS)[number]
export type LegacyResourceRow = Pick<UserTradecraftResource, LegacyColumn>

/** The 7.7.2 columns of `user_tradecraft_resources`, for every 1.x read and every 1.x answer. */
export const LEGACY_SELECT: Readonly<Record<LegacyColumn, true>> = Object.freeze(
  Object.fromEntries(LEGACY_RESOURCE_COLUMNS.map(c => [c, true])) as Record<LegacyColumn, true>,
)

async function findOwn(db: Db, accountId: string, resourceId: string, select?: Prisma.UserTradecraftResourceSelect) {
  return db.userTradecraftResource.findFirst({ where: { id: resourceId, userId: accountId }, ...(select ? { select } : {}) })
}

/** The whole row, for server-side use only: it holds the secrets. */
export async function loadOwnResource(accountId: string, resourceId: string, db: Db = prisma): Promise<UserTradecraftResource | null> {
  return findOwn(db, accountId, resourceId)
}

/** The 1.x columns of the row, for the 1.x routes. */
export async function loadOwnLegacyResource(accountId: string, resourceId: string): Promise<LegacyResourceRow | null> {
  return (await findOwn(prisma, accountId, resourceId, LEGACY_SELECT)) as LegacyResourceRow | null
}

/**
 * Locks the account's resource row until the transaction ends and answers whether it exists.
 * Every writer that decides on the row's claim (a job start, an edit that a running job would
 * undo, a cancel) takes it first, so their reads inside the transaction see each other's commits.
 */
export async function lockOwnResource(tx: Prisma.TransactionClient, accountId: string, resourceId: string): Promise<boolean> {
  const rows = await tx.$queryRaw<{ id: string }[]>`SELECT id FROM user_tradecraft_resources WHERE id = ${resourceId} AND user_id = ${accountId} FOR UPDATE`
  return rows.length > 0
}

/**
 * lockOwnResource, answering the live generation the lock found, or null when there is no such
 * row. A writer that acts on the live map uses this one: a generation read before the lock may be
 * the one a refresh's swap replaced while the writer waited (the swap takes the same lock).
 */
export async function lockOwnResourceGeneration(tx: Prisma.TransactionClient, accountId: string, resourceId: string): Promise<number | null> {
  const rows = await tx.$queryRaw<{ id: string; generation: number }[]>`SELECT id, generation FROM user_tradecraft_resources WHERE id = ${resourceId} AND user_id = ${accountId} FOR UPDATE`
  return rows.length > 0 ? rows[0].generation : null
}

/** The live generation of the account's resource, read through `db` (a snapshot's transaction), or null. */
export async function ownGeneration(accountId: string, resourceId: string, db: Db = prisma): Promise<number | null> {
  return ((await findOwn(db, accountId, resourceId, { generation: true })) as { generation: number } | null)?.generation ?? null
}
