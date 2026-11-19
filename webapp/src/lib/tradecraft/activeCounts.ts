/**
 * What the next message in a project will use, counted for the person chatting (§3.4, R-054,
 * R-055): the project's Agent Skills & Tradecraft accordion and the counter badge of the chat's
 * top bar both read these numbers, so they must follow the agent's own rules:
 *
 *   - a built-in skill counts when its switch is true (`get_enabled_builtin_skills` keeps a key
 *     only when its value is truthy; a missing key is off);
 *   - a user skill counts as the agent payload builds it (`userSkillsForAgent`): toggled true,
 *     the owner's, not quarantined, at most MAX_ENABLED_USER_SKILLS_PER_PROJECT by name;
 *   - a tradecraft resource counts when the run catalog lists it for this person
 *     (`catalog.activeResourcesFor`, the one policy).
 */
import prisma from '@/lib/prisma'
import { MAX_ENABLED_USER_SKILLS_PER_PROJECT } from '@/lib/userSkills'
import { enabledUserSkillIds } from '@/lib/userSkillAgentPayload'
import { activeResourcesFor, isOwnerRun, type RunParties } from './catalog'
import { hasStoredLogin } from './masking'
import { TOPICS } from './vocab'

export interface ActiveCounts {
  builtIn: { active: number; total: number; names: string[] }
  user: { active: number; names: string[] }
  tradecraft: {
    active: number
    total: number
    names: string[]
    offInProject: number
    disabledGlobally: number
    /** The owner's resources with a login, left out of this person's chats (§6.6). */
    ownerOnlyHidden: number
  }
}

/** The built-in skills, as the vocabulary's skill topics name them (their ids are the agent's KNOWN_ATTACK_PATHS). */
const BUILT_IN = TOPICS.filter(t => t.source === 'skill')

function builtInMap(config: unknown): Record<string, unknown> {
  if (!config || typeof config !== 'object' || Array.isArray(config)) return {}
  const builtIn = (config as Record<string, unknown>).builtIn
  return builtIn && typeof builtIn === 'object' && !Array.isArray(builtIn) ? builtIn as Record<string, unknown> : {}
}

export function builtInCounts(attackSkillConfig: unknown): ActiveCounts['builtIn'] {
  const map = builtInMap(attackSkillConfig)
  const on = BUILT_IN.filter(t => Boolean(map[t.id]))
  return { active: on.length, total: BUILT_IN.length, names: on.map(t => t.label) }
}

export async function userSkillCounts(ownerId: string, attackSkillConfig: unknown): Promise<ActiveCounts['user']> {
  const ids = enabledUserSkillIds(attackSkillConfig)
  if (ids.length === 0) return { active: 0, names: [] }
  const skills = await prisma.userAttackSkill.findMany({
    where: { userId: ownerId, id: { in: ids }, quarantinedAt: null },
    select: { name: true },
    orderBy: [{ name: 'asc' }, { id: 'asc' }],
    take: MAX_ENABLED_USER_SKILLS_PER_PROJECT,
  })
  return { active: skills.length, names: skills.map(s => s.name) }
}

export async function tradecraftCounts(parties: RunParties): Promise<ActiveCounts['tradecraft']> {
  const [active, all, choices] = await Promise.all([
    activeResourcesFor(parties),
    prisma.userTradecraftResource.findMany({
      where: { userId: parties.ownerId },
      select: { id: true, enabled: true, hasLogin: true, credentials: true },
    }),
    prisma.tradecraftProjectChoice.findMany({ where: { projectId: parties.projectId }, select: { resourceId: true } }),
  ])
  const off = new Set(choices.map(c => c.resourceId))
  const ownerRun = isOwnerRun(parties)
  let offInProject = 0
  let disabledGlobally = 0
  let ownerOnlyHidden = 0
  for (const r of all) {
    if (!r.enabled) disabledGlobally++
    else if (off.has(r.id)) offInProject++
    else if (!ownerRun && hasStoredLogin(r)) ownerOnlyHidden++
  }
  return { active: active.length, total: all.length, names: active.map(r => r.name), offInProject, disabledGlobally, ownerOnlyHidden }
}

export async function activeCounts(parties: RunParties, attackSkillConfig: unknown): Promise<ActiveCounts> {
  const [user, tradecraft] = await Promise.all([
    userSkillCounts(parties.ownerId, attackSkillConfig),
    tradecraftCounts(parties),
  ])
  return { builtIn: builtInCounts(attackSkillConfig), user, tradecraft }
}
