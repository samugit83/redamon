/**
 * The one lookup of a tradecraft resource by its id and its account (D-27): every route of
 * `/api/users/[id]/tradecraft-resources/[resourceId]/**` reads the row here, after
 * `requireUserAccess` and `requireSelfPermission` decided the path's account may be reached.
 * authzStaticGuard.test.ts allows this statement alone.
 */
import type { Prisma, UserTradecraftResource } from '@prisma/client'
import prisma from '@/lib/prisma'

type Db = Prisma.TransactionClient | typeof prisma

async function findOwn(db: Db, accountId: string, resourceId: string, select?: Prisma.UserTradecraftResourceSelect) {
  return db.userTradecraftResource.findFirst({ where: { id: resourceId, userId: accountId }, ...(select ? { select } : {}) })
}

/** The whole row, for server-side use only: it holds the secrets. */
export async function loadOwnResource(accountId: string, resourceId: string, db: Db = prisma): Promise<UserTradecraftResource | null> {
  return findOwn(db, accountId, resourceId)
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
