/**
 * Whether a person may use AI Navigator on a project (D3 of the AI Navigator plan, §5.4).
 *
 * The Navigator runs on the person's own model, so on a shared project the owner's data goes to the
 * provider the collaborator chose. RedAmon's rule is that the owner decides where their data and
 * keys go (ownerCredentials.ts, instanceProviders/entitlement.ts), so a collaborator reaches the
 * Navigator only once the owner turned on "AI Navigator for collaborators". The owner needs nothing.
 *
 * The one reader and writer of `navigator_project_policies`, apart from the ownership transfer's
 * reset (ownershipTransfer.ts). A failed read throws: the caller answers a coded 500 or refuses the
 * tool call, never a pass.
 */
import type { Prisma } from '@prisma/client'
import prisma from '@/lib/prisma'
import type { ProjectAccess } from './projectAccess'

type Db = Pick<Prisma.TransactionClient, 'navigatorProjectPolicy'>

/** The owner's toggle; no row is off. */
export async function navigatorCollaboratorsAllowed(projectId: string, db: Db = prisma): Promise<boolean> {
  const row = await db.navigatorProjectPolicy.findUnique({ where: { projectId }, select: { collaboratorsAllowed: true } })
  return row?.collaboratorsAllowed === true
}

/**
 * The decision for an access the policy already made: the owner always (by the level the access
 * answered, never by comparing ids), a share only when the owner allowed it, oversight and
 * break-glass never (D12).
 */
export async function navigatorAllowedFor(access: ProjectAccess, db: Db = prisma): Promise<boolean> {
  if (access.level === 'owner') return true
  if (access.via !== 'share') return false
  return navigatorCollaboratorsAllowed(access.project.id, db)
}

/** Sets the owner's toggle through `tx` (the transaction of its audit row); answers whether it changed. */
export async function writeNavigatorPolicy(tx: Db, projectId: string, value: boolean, byId: string): Promise<boolean> {
  const before = await navigatorCollaboratorsAllowed(projectId, tx)
  if (before === value) return false
  await tx.navigatorProjectPolicy.upsert({
    where: { projectId },
    create: { projectId, collaboratorsAllowed: value, updatedById: byId },
    update: { collaboratorsAllowed: value, updatedById: byId },
  })
  return true
}
