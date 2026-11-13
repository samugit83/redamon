import type { Prisma } from '@prisma/client'
import prisma from '@/lib/prisma'
import type { InstanceLlmProviderRecord, PermissionSetProviderRow } from './rows'

/**
 * Where instance providers, their assignments to permission sets and `byoLlmForbidden` live
 * (step 6.11): the `InstanceLlmProvider` and `PermissionSetProvider` tables and an `InstanceSettings`
 * column. `PermissionSetProvider.setId` names a stored set or a built-in one (`builtin:<slug>`), so
 * it carries no foreign key; `deleteSet` refuses a set a row still names, and a provider's rows go
 * with it (cascade).
 *
 * The writers run inside the caller's transaction, which holds the permissions lock (the one
 * deleteSet takes, so an assignment cannot name a set being deleted) and the audit row. A failed
 * read throws, never reads as "no provider".
 */

/**
 * Kept for the routes' 503 while a webapp runs on a database the boot `db push` has not given the
 * tables yet (a rolling deploy's first seconds): Prisma's P2021 "table does not exist" maps to it.
 */
export class InstanceProvidersNotReady extends Error {
  readonly code = 'instance_providers_not_ready'
  constructor() {
    super('Instance LLM providers are not stored yet on this database: the schema has no table for them.')
    this.name = 'InstanceProvidersNotReady'
  }
}

const MISSING_TABLE = 'P2021'

async function tables<T>(read: () => Promise<T>): Promise<T> {
  try {
    return await read()
  } catch (err) {
    if ((err as { code?: unknown })?.code === MISSING_TABLE) throw new InstanceProvidersNotReady()
    throw err
  }
}

type Tx = Prisma.TransactionClient
type ProviderDb = Pick<Tx, 'instanceLlmProvider'>
type AssignmentDb = Pick<Tx, 'permissionSetProvider'>

/** Every instance provider, or those of `ids`, by creation date. */
export async function readInstanceProviders(ids?: readonly string[], db: ProviderDb = prisma): Promise<InstanceLlmProviderRecord[]> {
  if (ids !== undefined && ids.length === 0) return []
  return tables(() => db.instanceLlmProvider.findMany({
    where: ids === undefined ? {} : { id: { in: [...ids] } },
    orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
  }))
}

/** One provider, or null. */
export async function readInstanceProvider(id: string, db: ProviderDb = prisma): Promise<InstanceLlmProviderRecord | null> {
  return tables(() => db.instanceLlmProvider.findUnique({ where: { id } }))
}

/** Every assignment, or those of the providers in `providerIds`. */
export async function readProviderAssignments(providerIds?: readonly string[], db: AssignmentDb = prisma): Promise<PermissionSetProviderRow[]> {
  return tables(() => db.permissionSetProvider.findMany({
    where: providerIds === undefined ? {} : { providerId: { in: [...providerIds] } },
    select: { setId: true, providerId: true },
    orderBy: [{ providerId: 'asc' }, { setId: 'asc' }],
  }))
}

/** The instance providers assigned to this set, by id. */
export async function providersAssignedToSet(setId: string, db: AssignmentDb = prisma): Promise<string[]> {
  const rows = await tables(() => db.permissionSetProvider.findMany({ where: { setId }, select: { providerId: true } }))
  return rows.map((r) => r.providerId).sort()
}

/** Whether Root hides bring-your-own providers from the accounts lacking self:llm_providers. */
export async function readByoLlmForbidden(db: Pick<Tx, 'instanceSettings'> = prisma): Promise<boolean> {
  const row = await db.instanceSettings.findUnique({ where: { id: 'instance' }, select: { byoLlmForbidden: true } })
  return row?.byoLlmForbidden === true
}

export type InstanceProviderData = Omit<InstanceLlmProviderRecord, 'id' | 'createdAt' | 'updatedAt' | 'createdById' | 'updatedById'>

export interface ProviderWrite {
  data: InstanceProviderData
  setIds: readonly string[]
  actorId: string
}

const stored = (data: InstanceProviderData) => ({ ...data, defaultHeaders: (data.defaultHeaders ?? {}) as Prisma.InputJsonValue })

/** Makes the provider's assignments exactly `setIds`, leaving the kept rows (their author and date) untouched. */
async function replaceSets(tx: Tx, providerId: string, setIds: readonly string[], actorId: string): Promise<string[]> {
  const before = (await readProviderAssignments([providerId], tx)).map((a) => a.setId).sort()
  const removed = before.filter((id) => !setIds.includes(id))
  const added = setIds.filter((id) => !before.includes(id))
  if (removed.length > 0) await tx.permissionSetProvider.deleteMany({ where: { providerId, setId: { in: removed } } })
  if (added.length > 0) await tx.permissionSetProvider.createMany({ data: added.map((setId) => ({ setId, providerId, createdById: actorId })) })
  return before
}

/** Creates the provider with its assignments. */
export async function createInstanceProvider(tx: Tx, write: ProviderWrite): Promise<InstanceLlmProviderRecord> {
  const provider = await tables(() => tx.instanceLlmProvider.create({ data: { ...stored(write.data), createdById: write.actorId } }))
  await replaceSets(tx, provider.id, write.setIds, write.actorId)
  return provider
}

/** Replaces the provider's settings and makes its assignments exactly `setIds`. */
export async function updateInstanceProvider(
  tx: Tx,
  id: string,
  write: ProviderWrite,
): Promise<{ provider: InstanceLlmProviderRecord; setIdsBefore: string[] }> {
  const provider = await tables(() => tx.instanceLlmProvider.update({ where: { id }, data: { ...stored(write.data), updatedById: write.actorId } }))
  const setIdsBefore = await replaceSets(tx, id, write.setIds, write.actorId)
  return { provider, setIdsBefore }
}

/** Deletes the provider (its assignments go with it); answers its assignments before. */
export async function deleteInstanceProvider(tx: Tx, id: string): Promise<string[]> {
  const before = (await readProviderAssignments([id], tx)).map((a) => a.setId).sort()
  await tables(() => tx.instanceLlmProvider.delete({ where: { id } }))
  return before
}

/** Sets the policy on the instance row, which the boot backfill creates. */
export async function writeByoLlmForbidden(tx: Tx, value: boolean): Promise<void> {
  await tx.instanceSettings.update({ where: { id: 'instance' }, data: { byoLlmForbidden: value } })
}
