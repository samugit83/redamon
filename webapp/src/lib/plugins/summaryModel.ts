import { BUILTIN_SKILLS } from './builtinSkills'
import { ownsScope, type ScopeAccessOptions } from './changeSetAccess'
import * as ov from './overrides'
import { dormantReason, findInstall, type DormantReason } from './registry'

/**
 * The per-skill plugin summary for a project's Agent Skills settings (design §6, GET
 * /api/plugins/overrides/summary). For each built-in skill it names the version that governs
 * THIS project (its own, else the owner's user-scope version; effectiveForProject), whether it
 * applies, why not if not, and how many proposals are pending across the two scopes — so the
 * section can show a chip, a Versions button and an "N pending" link only where something
 * applies. The agent is not called here (every settings open would pay for it); the review and
 * versions modals do the authoritative agent check.
 */
export const POINT = 'skill.text'

export interface SkillSummary {
  skillId: string
  applies: {
    pluginId: string
    pluginDisplayName: string
    scope: ov.ScopeType
    revision: number | null
    status: ov.OverrideStatus
    staleReason: ov.StaleReason | null
    /** True when it actually reaches the agent (active and the plugin qualifies). */
    applied: boolean
    /** Why it does not reach the agent, if it does not. */
    dormantReason: DormantReason | null
  } | null
  pending: number
}

export interface SummaryModel {
  projectId: string
  skills: SkillSummary[]
}

/** The summary for one project, or null when the caller does not decide its proposals (changeSetAccess.ts). */
export async function buildSummaryModel(
  effectiveUserId: string,
  projectId: string,
  opts: ScopeAccessOptions = {},
): Promise<SummaryModel | null> {
  if (!(await ownsScope({ type: 'project', id: projectId }, effectiveUserId, opts))) return null
  const env = { agentSupportsSeam: true }
  const names = new Map<string, Promise<string>>()
  const nameOf = (pluginId: string) => {
    if (!names.has(pluginId)) {
      names.set(
        pluginId,
        findInstall(pluginId).then((r) => {
          const m = r?.manifest
          return m && typeof m === 'object' && !Array.isArray(m) && typeof (m as { displayName?: unknown }).displayName === 'string'
            ? ((m as { displayName: string }).displayName || pluginId)
            : pluginId
        }),
      )
    }
    return names.get(pluginId)!
  }

  const skills = await Promise.all(
    BUILTIN_SKILLS.map(async ({ id }) => {
      const [set, projectPending, userPending] = await Promise.all([
        ov.effectiveForProject(projectId, id),
        ov.pendingCount({ type: 'project', id: projectId }, POINT, id),
        ov.pendingCount({ type: 'user', id: effectiveUserId }, POINT, id),
      ])
      const applies: SkillSummary['applies'] = set
        ? {
            pluginId: set.pluginId,
            pluginDisplayName: await nameOf(set.pluginId),
            scope: set.scope.type,
            revision: set.revision,
            status: set.status,
            staleReason: set.staleReason,
            applied: set.applies,
            dormantReason: set.applies ? null : dormantReason(set.plugin, env),
          }
        : null
      return { skillId: id, applies, pending: projectPending + userPending }
    }),
  )

  return { projectId, skills }
}
