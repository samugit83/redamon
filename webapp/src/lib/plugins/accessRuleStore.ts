import type { Prisma } from '@prisma/client'
import prisma from '@/lib/prisma'

/**
 * Where the per-plugin allowlist rules live (GV-16): one `PluginAccessRule {pluginId, setId}` row
 * per permission set a plugin is limited to. `pluginId` is the catalog id and `setId` a permission
 * set row id or a built-in id (`builtin:<slug>`), neither a foreign key: a plugin uninstalled keeps
 * its rules for a reinstall, and built-in sets are code.
 *
 * The writers run inside a transaction holding the permissions lock (accessRuleAdmin.ts and
 * permissionSetAdmin.ts deleteSet), so a rule cannot name a set being deleted.
 */
export interface PluginAccessRule {
  pluginId: string
  setId: string
}

type RuleDb = Pick<Prisma.TransactionClient, 'pluginAccessRule'>

/** The rules of one plugin, or of every plugin when `pluginId` is left out. A failed read throws. */
export async function readAccessRules(pluginId?: string, db: RuleDb = prisma): Promise<PluginAccessRule[]> {
  return db.pluginAccessRule.findMany({
    where: pluginId === undefined ? {} : { pluginId },
    select: { pluginId: true, setId: true },
    orderBy: [{ pluginId: 'asc' }, { setId: 'asc' }],
  })
}

/** The plugins a rule limits to this set, in id order. */
export async function pluginsLimitedToSet(db: RuleDb, setId: string): Promise<string[]> {
  const rows = await db.pluginAccessRule.findMany({ where: { setId }, select: { pluginId: true } })
  return rows.map((r) => r.pluginId).sort()
}

/**
 * Makes the plugin's rules exactly these sets (an empty list removes them all), leaving the rows of
 * the sets kept untouched so their author and date stay. Answers the set ids before and after.
 */
export async function replaceAccessRules(
  db: RuleDb,
  pluginId: string,
  setIds: readonly string[],
  createdById: string,
): Promise<{ before: string[]; after: string[] }> {
  const before = (await readAccessRules(pluginId, db)).map((r) => r.setId).sort()
  const removed = before.filter((id) => !setIds.includes(id))
  const added = setIds.filter((id) => !before.includes(id))
  if (removed.length > 0) await db.pluginAccessRule.deleteMany({ where: { pluginId, setId: { in: removed } } })
  if (added.length > 0) await db.pluginAccessRule.createMany({ data: added.map((setId) => ({ pluginId, setId, createdById })) })
  return { before, after: [...setIds].sort() }
}
