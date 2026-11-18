/**
 * Per-project choices (`TradecraftProjectChoice`): a row means "turned off in this project", no
 * row means on (R-059, R-228). The project's save writes them (T4.4); a change of a resource's
 * global Enabled clears them (R-062).
 *
 * A project can only turn a resource off (R-061): a resource disabled in Global Settings keeps
 * whatever row it has (none, since its Enabled change cleared them), and a save neither adds
 * nor removes one for it. A resource with a login is the owner's alone (§6.6): only the owner's
 * own session changes its choice, so a collaborator's save, or an administrator acting as the
 * owner, leaves it as it is.
 */
import type { Prisma } from '@prisma/client'
import { SETTINGS_CONSTANTS } from './settingsSpec'
import { hasStoredLogin } from './masking'
import { isOwnerRun } from './catalog'

type Db = Pick<Prisma.TransactionClient, 'tradecraftProjectChoice' | 'userTradecraftResource'>

/**
 * Forgets every project's choice for a resource. A change of the resource's global Enabled
 * resets them in the same transaction (R-062): after it, the resource is on in every project
 * when enabled and off everywhere when disabled.
 */
export async function clearChoicesForResource(tx: Prisma.TransactionClient, resourceId: string): Promise<number> {
  const { count } = await tx.tradecraftProjectChoice.deleteMany({ where: { resourceId } })
  return count
}

/** The longest `tradecraftOff` a save may send: one id per resource an account may have. */
export const MAX_TRADECRAFT_OFF = SETTINGS_CONSTANTS.maxResourcesPerUser

/** `tradecraftOff` as a save sends it: distinct non-empty ids, or null when it is not a list of ids. */
export function parseTradecraftOff(value: unknown): string[] | null {
  if (!Array.isArray(value) || value.length > MAX_TRADECRAFT_OFF) return null
  if (!value.every(v => typeof v === 'string' && v.length > 0 && v.length <= 200)) return null
  return [...new Set(value as string[])]
}

export interface ChoiceViewer {
  /** The person the request acts for. */
  personId: string
  /** The administrator acting as that person, or null. */
  actorId: string | null
}

const RESOURCE_SELECT = { id: true, enabled: true, hasLogin: true, credentials: true } as const

/** Whether the viewer may turn this resource on or off in a project of `ownerId` (R-061, §6.6). */
export function choiceChangeable(
  r: { enabled: boolean; hasLogin: boolean; credentials: unknown }, ownerId: string, viewer: ChoiceViewer,
): boolean {
  return r.enabled && (!hasStoredLogin(r) || isOwnerRun({ ownerId, personId: viewer.personId, actorId: viewer.actorId }))
}

/**
 * Makes the project's choices say `off` for the resources the viewer may change: a changeable
 * resource listed is turned off, one not listed is turned on. Ids that are not the owner's
 * resources are dropped; locked resources keep their row. Runs in the caller's transaction, the
 * one that writes the project row, so a save and its choices commit together (R-064).
 * Answers the project's off ids after the write.
 */
export async function writeProjectChoices(tx: Db, opts: {
  projectId: string
  ownerId: string
  off: readonly string[]
  viewer: ChoiceViewer
}): Promise<string[]> {
  const { projectId, ownerId, viewer } = opts
  const [resources, rows] = await Promise.all([
    tx.userTradecraftResource.findMany({ where: { userId: ownerId }, select: RESOURCE_SELECT }),
    tx.tradecraftProjectChoice.findMany({ where: { projectId }, select: { resourceId: true } }),
  ])
  const requested = new Set(opts.off)
  const current = new Set(rows.map(r => r.resourceId))
  const changeable = resources.filter(r => choiceChangeable(r, ownerId, viewer)).map(r => r.id)
  const turnOff = changeable.filter(id => requested.has(id) && !current.has(id))
  const turnOn = changeable.filter(id => !requested.has(id) && current.has(id))
  if (turnOn.length) await tx.tradecraftProjectChoice.deleteMany({ where: { projectId, resourceId: { in: turnOn } } })
  // Two saves at once may both turn the same resource off: the second insert is a no-op.
  if (turnOff.length) {
    await tx.tradecraftProjectChoice.createMany({
      data: turnOff.map(resourceId => ({ projectId, resourceId, createdById: viewer.personId })),
      skipDuplicates: true,
    })
  }
  const after = new Set([...current].filter(id => !turnOn.includes(id)))
  for (const id of turnOff) after.add(id)
  return [...after].sort()
}

/** The ids turned off in a project: the rows, whatever the resource's state. */
export async function offIdsForProject(db: Pick<Db, 'tradecraftProjectChoice'>, projectId: string): Promise<string[]> {
  const rows = await db.tradecraftProjectChoice.findMany({ where: { projectId }, select: { resourceId: true } })
  return rows.map(r => r.resourceId).sort()
}

/**
 * What a change of the resource's global Enabled reaches (R-062, §3.4): the account's projects,
 * all of which follow it, and the projects where it is turned off today, whose choice it clears.
 */
export async function enabledImpact(db: Pick<Prisma.TransactionClient, 'project' | 'tradecraftProjectChoice'>, accountId: string, resourceId: string): Promise<{
  projects: number
  turnedOffIn: number
}> {
  const [projects, turnedOffIn] = await Promise.all([
    db.project.count({ where: { userId: accountId } }),
    db.tradecraftProjectChoice.count({ where: { resourceId } }),
  ])
  return { projects, turnedOffIn }
}
