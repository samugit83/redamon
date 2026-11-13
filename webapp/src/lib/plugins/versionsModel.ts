import type { PluginInstall } from '@prisma/client'
import { isBuiltinSkill } from './builtinSkills'
import { ownsScope, type ScopeAccessOptions } from './changeSetAccess'
import { skillDisplayName } from './overrideOps'
import * as ov from './overrides'
import { dormantReason, findInstall, type DormantReason } from './registry'
import { SkillPartsRegistryError, clearSkillPartsCache, registryFailureText, registrySkill } from './skillPartsRegistry'

/**
 * What the core versions modal shows for one built-in skill (design §6 SkillVersionsModal):
 * the versions of the viewer's user scope, and of a project they own when a projectId is
 * given. Another user's scope is never listed. The factory row is implicit (v1); factory text
 * runs when nothing is active or the active version is dormant.
 */
export const POINT = 'skill.text'

export interface VersionRow {
  changeSetId: string
  revision: number | null
  status: ov.OverrideStatus
  staleReason: ov.StaleReason | null
  pluginId: string
  pluginDisplayName: string
  createdAt: string
  decidedAt: string | null
  note: string | null
  parts: { partId: string; value: string }[]
  /** Active AND reaching the agent (not dormant). */
  applied: boolean
}

export interface ScopeVersions {
  scopeType: ov.ScopeType
  scopeOwnerId: string
  /** Factory text runs for this skill: no active version, or the active one is dormant. */
  factoryInUse: boolean
  /** Why the active version is not applied, if there is an active version that is dormant. */
  dormantReason: DormantReason | null
  /** The highest number handed out, so the modal can explain gaps after deletions (TD-19). */
  lastRevision: number
  versions: VersionRow[]
}

export interface VersionsModel {
  skillId: string
  skillDisplayName: string
  /** Factory text per part now, for the read-only "View" diff; null if the agent can't answer. */
  factoryText: Record<string, string> | null
  registryError: 'agent_unreachable' | 'agent_outdated' | null
  /** With a registryError: why, in words (the agent's HTTP status, or the errno of no answer). */
  registryErrorText?: string
  scopes: ScopeVersions[]
}

function toRow(set: ov.ChangeSet, displayName: string): VersionRow {
  return {
    changeSetId: set.changeSetId,
    revision: set.revision,
    status: set.status,
    staleReason: set.staleReason,
    pluginId: set.pluginId,
    pluginDisplayName: displayName,
    createdAt: set.createdAt.toISOString(),
    decidedAt: set.decidedAt ? set.decidedAt.toISOString() : null,
    note: set.note,
    parts: set.parts.map((p) => ({ partId: p.partId, value: p.value })),
    applied: false,
  }
}

async function scopeVersions(
  scope: ov.OverrideScope,
  group: string,
  env: { agentSupportsSeam: boolean },
  names: Map<string, Promise<string>>,
): Promise<ScopeVersions> {
  const [list, last] = await Promise.all([ov.listVersions(scope, POINT, group), ov.lastRevision(scope, POINT, group)])
  const nameOf = (pluginId: string) => {
    if (!names.has(pluginId)) {
      names.set(
        pluginId,
        findInstall(pluginId).then((r) => {
          const m = r?.manifest
          return m && typeof m === 'object' && !Array.isArray(m) && typeof (m as PluginInstall['manifest'] & { displayName?: string }).displayName === 'string'
            ? ((m as { displayName: string }).displayName || pluginId)
            : pluginId
        }),
      )
    }
    return names.get(pluginId)!
  }

  const versions = await Promise.all(list.sets.map(async (set) => toRow(set, await nameOf(set.pluginId))))
  const active = list.sets.find((s) => s.status === 'active') ?? null
  let dormant: DormantReason | null = null
  if (active) {
    const install = await findInstall(active.pluginId)
    dormant = dormantReason(install, env)
    const row = versions.find((v) => v.changeSetId === active.changeSetId)
    if (row) row.applied = dormant === null
  }
  return {
    scopeType: scope.type,
    scopeOwnerId: scope.id,
    factoryInUse: !active || dormant !== null,
    dormantReason: dormant,
    lastRevision: last,
    versions,
  }
}

/** The versions model, or null for an unknown skill. `projectId` is listed only when the caller decides its proposals. */
export async function buildVersionsModel(
  effectiveUserId: string,
  group: string,
  projectId?: string | null,
  opts: ScopeAccessOptions = {},
): Promise<VersionsModel | null> {
  if (!isBuiltinSkill(group)) return null

  let factoryText: Record<string, string> | null = null
  let registryError: VersionsModel['registryError'] = null
  let registryErrorText: string | null = null
  try {
    clearSkillPartsCache()
    const skill = await registrySkill(group)
    factoryText = skill ? Object.fromEntries(skill.parts.map((p) => [p.partId, p.text])) : null
  } catch (e) {
    if (e instanceof SkillPartsRegistryError && (e.code === 'agent_unreachable' || e.code === 'agent_outdated')) {
      registryError = e.code
      registryErrorText = registryFailureText(e)
    } else throw e
  }

  const env = { agentSupportsSeam: registryError !== 'agent_outdated' }
  const names = new Map<string, Promise<string>>()
  const scopes: ScopeVersions[] = [await scopeVersions({ type: 'user', id: effectiveUserId }, group, env, names)]
  if (projectId && (await ownsScope({ type: 'project', id: projectId }, effectiveUserId, opts))) {
    scopes.push(await scopeVersions({ type: 'project', id: projectId }, group, env, names))
  }

  return {
    skillId: group,
    skillDisplayName: skillDisplayName(group),
    factoryText,
    registryError,
    ...(registryErrorText ? { registryErrorText } : {}),
    scopes,
  }
}
