/**
 * The checks and the audit every route that writes project settings shares.
 *
 * Per-field validation (the registry validators) runs before this, in each
 * caller, because what a caller may write differs: the settings form writes any
 * settable column, a RoE document only what the registry lets a document write.
 * What must NOT differ is what comes after: the rules over several fields, the
 * owner-owned Jev provider a switch onto the Jev engine needs, and the fireteam audit.
 * They lived inline in the PUT, so a second writer that forgot one of them was
 * a way around it; `projectWriteGuards.test.ts` holds every caller to this file.
 */
import { validateCrossFieldRules, writeFireteamAudit } from '@/lib/reconSettings/crossField'
import { JEV_ENGINE_SELECT, validateJevEngineChange } from '@/lib/reconSettings/jevEngine'
import { IP_HOSTNAME_FIELDS } from '@/lib/scopeGroups'

export { JEV_ENGINE_SELECT }

/**
 * The first rule `updateData` breaks, or null. `existing` is the stored row
 * (with at least `userId` and JEV_ENGINE_SELECT, plus every column a rule the
 * write can touch reads: the PUT selects the hostname policy, `ipMode` and
 * `engagementKind`), or null for a project the caller could not load.
 *
 * The rules judge the EFFECTIVE row, the stored row with `updateData` applied: a
 * partial save cannot otherwise tell "only in IP mode" or "scan_all needs its
 * confirmation". `updateData` may be normalized in place (`attackSkillConfig`,
 * the hostname policy), including a policy field it did not carry, such as the
 * scan_all confirmation a mode change resets.
 */
export async function guardProjectWrite(args: {
  existing: ({ userId: string } & Record<string, unknown>) | null
  updateData: Record<string, unknown>
  actorUserId: string
}): Promise<string | null> {
  const { existing, updateData, actorUserId } = args
  const effective: Record<string, unknown> = existing ? { ...existing, ...updateData } : updateData
  const crossFieldError = await validateCrossFieldRules(effective, Object.keys(updateData), actorUserId, {
    ownerUserId: existing ? existing.userId : undefined,
  })
  if (crossFieldError) return crossFieldError
  if (existing) {
    if ('attackSkillConfig' in updateData) updateData.attackSkillConfig = effective.attackSkillConfig
    for (const key of IP_HOSTNAME_FIELDS) {
      if (effective[key] === undefined) continue
      if (key in updateData || JSON.stringify(effective[key]) !== JSON.stringify(existing[key])) {
        updateData[key] = effective[key]
      }
    }
  }

  // A switch onto the Jev engine needs a selected Jev provider on the OWNER's account.
  if (existing) {
    const jevError = await validateJevEngineChange(existing as never, updateData, existing.userId)
    if (jevError) return jevError
  }
  return null
}

/** The audit rows a settings write owes beyond its own. Best-effort; never throws. */
export async function recordProjectWrite(
  projectId: string,
  before: Record<string, unknown>,
  updateData: Record<string, unknown>,
  actor: { userId: string | null; source: string },
): Promise<void> {
  await writeFireteamAudit(projectId, before, updateData, actor)
}
