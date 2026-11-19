/**
 * The counts of the accordion and the chat's counter badge follow the agent's own rules (R-054,
 * R-055, AC-29): on one shared fixture they equal what the run catalog lists, what the agent's
 * user-skill payload holds and what the agent's built-in rule keeps, for the owner and for anyone
 * else.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { createTradecraftDb, type TradecraftDb } from './__testing__/tradecraftDb'

const h = vi.hoisted(() => ({ db: null as unknown as TradecraftDb }))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => (h.db.prisma as Record<string | symbol, unknown>)[k] }) }))

import { activeCounts, builtInCounts } from './activeCounts'
import { activeResourcesFor, type RunParties } from './catalog'
import { userSkillsForAgent } from '@/lib/userSkillAgentPayload'
import { MAX_ENABLED_USER_SKILLS_PER_PROJECT } from '@/lib/userSkills'
import { skillTopicIds } from './vocab'

const OWNER = 'owner-1'
const PROJECT = 'p1'
const CONFIG = {
  builtIn: { sql_injection: true, xss: true, rce: false, cve_exploit: false, not_a_skill: true },
  user: {} as Record<string, boolean>,
}
const parties = (personId: string | null, actorId: string | null = null): RunParties => ({ ownerId: OWNER, projectId: PROJECT, personId, actorId })

beforeEach(() => {
  h.db = createTradecraftDb()
  // Resources: active, off here, disabled, a login (stored flag), a login (credentials only), another project's choice.
  const resources: [string, boolean, boolean, Record<string, unknown>][] = [
    ['HackTricks', true, false, {}], ['PayloadsAllTheThings', true, false, {}], ['Sigma rules', false, false, {}],
    ['Company wiki', true, true, {}], ['Paid KB', true, false, { cookie: 'fake-session' }], ['GTFOBins', true, false, {}],
  ]
  resources.forEach(([name, enabled, hasLogin, credentials], i) => {
    h.db.seed('userTradecraftResource', {
      id: `r${i}`, userId: OWNER, name, slug: `r${i}`, url: `https://r${i}.tc-fixture.test/`, enabled, hasLogin, credentials,
      createdAt: new Date(Date.UTC(2026, 0, i + 1)),
    })
  })
  h.db.seed('tradecraftProjectChoice', { projectId: PROJECT, resourceId: 'r1' })
  h.db.seed('tradecraftProjectChoice', { projectId: 'p2', resourceId: 'r5' })
  // 25 user skills toggled on: the agent takes 20 by name; one quarantined, one another account's.
  const user: Record<string, boolean> = {}
  for (let i = 0; i < 25; i++) {
    const id = `s${String(i).padStart(2, '0')}`
    h.db.seed('userAttackSkill', { id, userId: OWNER, name: `Skill ${String(25 - i).padStart(2, '0')}`, content: '# x' })
    user[id] = true
  }
  h.db.seed('userAttackSkill', { id: 'quarantined', userId: OWNER, name: 'AAA quarantined', content: '# x', quarantinedAt: new Date() })
  h.db.seed('userAttackSkill', { id: 'foreign', userId: 'someone-else', name: 'AAA foreign', content: '# x' })
  CONFIG.user = { ...user, quarantined: true, foreign: true, off: false }
})

describe('matches_agent_rules', () => {
  test.each([
    ['the owner', parties(OWNER)],
    ['a collaborator', parties('collab-1')],
    ['an administrator acting as the owner', parties(OWNER, 'admin-1')],
    ['a run whose person is unknown', parties(null)],
  ])('%s: the numbers equal the catalog, the agent payload and the built-in rule', async (_who, p) => {
    const counts = await activeCounts(p, CONFIG)
    const catalog = await activeResourcesFor(p)
    expect(counts.tradecraft.active).toBe(catalog.length)
    expect(counts.tradecraft.names).toEqual(catalog.map(r => r.name))
    const payload = await userSkillsForAgent(h.db.prisma as never, OWNER, CONFIG)
    expect(counts.user).toEqual({ active: payload.length, names: payload.map(s => s.name) })
    expect(counts.user.active).toBe(MAX_ENABLED_USER_SKILLS_PER_PROJECT)
    // agentic/project_settings.py get_enabled_builtin_skills: {k for k, v in builtIn.items() if v}, of the known skills.
    const agentBuiltIns = Object.entries(CONFIG.builtIn).filter(([k, v]) => v && skillTopicIds().includes(k)).map(([k]) => k)
    expect(counts.builtIn.active).toBe(agentBuiltIns.length)
    expect(counts.builtIn.total).toBe(14)
  })

  test('the owner: every category, adding up to the total', async () => {
    const t = (await activeCounts(parties(OWNER), CONFIG)).tradecraft
    expect(t).toEqual({
      active: 4, total: 6, names: ['HackTricks', 'Company wiki', 'Paid KB', 'GTFOBins'],
      offInProject: 1, disabledGlobally: 1, ownerOnlyHidden: 0,
    })
  })

  test('collaborator_excludes_logins: the two login resources are counted as owner-only, not active', async () => {
    for (const p of [parties('collab-1'), parties(OWNER, 'admin-1')]) {
      const t = (await activeCounts(p, CONFIG)).tradecraft
      expect(t).toEqual({
        active: 2, total: 6, names: ['HackTricks', 'GTFOBins'], offInProject: 1, disabledGlobally: 1, ownerOnlyHidden: 2,
      })
    }
  })

  test('a resource turned off here and disabled globally counts once, as disabled', async () => {
    h.db.seed('tradecraftProjectChoice', { projectId: PROJECT, resourceId: 'r2' })
    const t = (await activeCounts(parties(OWNER), CONFIG)).tradecraft
    expect(t.disabledGlobally).toBe(1)
    expect(t.offInProject).toBe(1)
    expect(t.active + t.offInProject + t.disabledGlobally + t.ownerOnlyHidden).toBe(t.total)
  })
})

describe('builtInCounts', () => {
  test('a missing key is off; only true counts; names from the vocabulary; an unknown key is not a skill', () => {
    expect(builtInCounts(CONFIG)).toEqual({ active: 2, total: 14, names: ['SQL injection', 'XSS'] })
    expect(builtInCounts({ builtIn: {} })).toEqual({ active: 0, total: 14, names: [] })
    expect(builtInCounts(null)).toEqual({ active: 0, total: 14, names: [] })
    expect(builtInCounts({ user: {} })).toEqual({ active: 0, total: 14, names: [] })
  })
})
