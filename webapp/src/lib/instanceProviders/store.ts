import type { Prisma } from '@prisma/client'
import type { InstanceLlmProviderRecord, PermissionSetProviderRow } from './rows'

/**
 * Where instance providers, their assignments to permission sets and `byoLlmForbidden` live
 * (step 6.11): the `InstanceLlmProvider` and `PermissionSetProvider` tables and an `InstanceSettings`
 * column. `PermissionSetProvider.setId` names a stored set or a built-in one (`builtin:<slug>`), so
 * it carries no foreign key; `deleteSet` refuses a set a row still names.
 *
 * The tables are not in the schema yet. Until they are, no instance provider exists and none is
 * assigned, so nobody is offered or resolved one, and bring-your-own providers are never hidden:
 * every switch state behaves as before 6.11. The writes refuse with `InstanceProvidersNotReady`.
 */

/** A write reached a store whose tables are not in the schema yet (the route answers 503). */
export class InstanceProvidersNotReady extends Error {
  readonly code = 'instance_providers_not_ready'
  constructor() {
    super('Instance LLM providers are not stored yet on this version: the schema has no table for them.')
    this.name = 'InstanceProvidersNotReady'
  }
}

/** Every instance provider, or those of `ids`, by creation date. A failed read throws. */
export async function readInstanceProviders(ids?: readonly string[]): Promise<InstanceLlmProviderRecord[]> {
  void ids
  return []
}

/** One provider, or null. */
export async function readInstanceProvider(id: string): Promise<InstanceLlmProviderRecord | null> {
  void id
  return null
}

/** Every assignment, or those of the providers in `providerIds`. */
export async function readProviderAssignments(providerIds?: readonly string[]): Promise<PermissionSetProviderRow[]> {
  void providerIds
  return []
}

/** The instance providers assigned to this set, by id. */
export async function providersAssignedToSet(setId: string): Promise<string[]> {
  void setId
  return []
}

/** Whether Root hides bring-your-own providers from the accounts lacking self:llm_providers. */
export async function readByoLlmForbidden(): Promise<boolean> {
  return false
}

export type InstanceProviderData = Omit<InstanceLlmProviderRecord, 'id' | 'createdAt' | 'updatedAt' | 'createdById' | 'updatedById'>

export interface ProviderWrite {
  data: InstanceProviderData
  setIds: readonly string[]
  actorId: string
}

type Tx = Prisma.TransactionClient

/**
 * The writes run in the caller's transaction, which holds the permissions lock (the one deleteSet
 * takes, so an assignment cannot name a set being deleted) and the audit row.
 */
export async function createInstanceProvider(tx: Tx, write: ProviderWrite): Promise<InstanceLlmProviderRecord> {
  void tx
  void write
  throw new InstanceProvidersNotReady()
}

/** Replaces the provider's settings and makes its assignments exactly `setIds`. */
export async function updateInstanceProvider(
  tx: Tx,
  id: string,
  write: ProviderWrite,
): Promise<{ provider: InstanceLlmProviderRecord; setIdsBefore: string[] }> {
  void tx
  void id
  void write
  throw new InstanceProvidersNotReady()
}

/** Deletes the provider and its assignments; answers its assignments before. */
export async function deleteInstanceProvider(tx: Tx, id: string): Promise<string[]> {
  void tx
  void id
  throw new InstanceProvidersNotReady()
}

export async function writeByoLlmForbidden(tx: Tx, value: boolean): Promise<void> {
  void tx
  void value
  throw new InstanceProvidersNotReady()
}
