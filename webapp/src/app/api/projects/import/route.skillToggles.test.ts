/**
 * Project import and the user-skill toggles (D10, §9 row 10).
 *
 * A bundle's `attackSkillConfig` names the EXPORTING account's skills. Import never
 * refuses over them: ids the importing account does not have are dropped first (they
 * would count toward 20, invisible and impossible to turn off), then the importer's own
 * skills beyond 20 on (by name, then id) and quarantined ones are turned off, and
 * `warnings` says what changed. The same applies to the user presets the bundle carries.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { NextRequest } from 'next/server'
import JSZip from 'jszip'

const h = vi.hoisted(() => ({
  createProject: vi.fn(),
  createPreset: vi.fn(),
  skillFindMany: vi.fn(),
  skills: [] as { id: string; userId: string; name: string; quarantinedAt: Date | null }[],
}))

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: vi.fn().mockResolvedValue({ userId: 'importer', role: 'user' }),
}))
vi.mock('@/lib/prisma', () => ({
  default: {
    project: { create: (...a: unknown[]) => h.createProject(...a) },
    engagementAuthorization: { create: vi.fn() },
    userLlmProvider: { count: async () => 0 },
    userAttackSkill: { findMany: (...a: unknown[]) => h.skillFindMany(...a) },
    userProjectPreset: { create: (...a: unknown[]) => h.createPreset(...a) },
  },
}))
vi.mock('@/app/api/graph/neo4j', () => ({ getGraphSession: vi.fn() }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: vi.fn() }))

import { POST } from './route'

const BUILT_IN = { sql_injection: true, xss: false }
const QUARANTINED_AT = new Date('2026-10-01T00:00:00Z')

async function bundle(project: Record<string, unknown>, presets?: unknown[]): Promise<NextRequest> {
  const zip = new JSZip()
  zip.file('manifest.json', JSON.stringify({ version: '1', projectName: 'imported' }))
  zip.file('project.json', JSON.stringify({
    id: 'old', userId: 'exporter', name: 'imported', targetDomain: 'example.invalid',
    createdAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:00.000Z',
    ...project,
  }))
  if (presets) zip.file('presets/user_project_presets.json', JSON.stringify(presets))
  const buf = await zip.generateAsync({ type: 'arraybuffer' })
  const fd = new FormData()
  fd.set('file', new File([buf], 'p.zip', { type: 'application/zip' }))
  return new NextRequest('http://localhost:3000/api/projects/import', { method: 'POST', body: fd })
}

const created = () => h.createProject.mock.calls[0][0].data
const skillWarnings = (warnings: string[]) => warnings.filter((w) => /skill/i.test(w))

/** The importer's own skills: `n` of them, whose NAME order is the reverse of their id order. */
function importerSkills(n: number) {
  return Array.from({ length: n }, (_, i) => ({
    id: `id${String(n - 1 - i).padStart(2, '0')}`,
    userId: 'importer',
    name: `flow ${String(i).padStart(2, '0')}`,
    quarantinedAt: null as Date | null,
  }))
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  h.skills = [
    ...importerSkills(25),
    { id: 'exporterSkill', userId: 'exporter', name: 'their flow', quarantinedAt: null },
  ]
  h.skillFindMany.mockImplementation(async ({ where }: { where: { userId: string; id: { in: string[] } } }) =>
    h.skills.filter((s) => s.userId === where.userId && where.id.in.includes(s.id)))
  h.createProject.mockResolvedValue({ id: 'new', name: 'imported' })
  h.createPreset.mockResolvedValue({ id: 'preset' })
})

describe('the imported project\'s toggles', () => {
  test('within the rules and all the importer\'s own: imported as is, no warning', async () => {
    const config = { builtIn: BUILT_IN, user: { id00: true, id01: false } }
    const res = await POST(await bundle({ attackSkillConfig: config }))
    expect(res.status).toBe(200)
    expect(created().attackSkillConfig).toEqual(config)
    expect(skillWarnings((await res.json()).warnings)).toEqual([])
    expect(h.skillFindMany.mock.calls[0][0].where.userId).toBe('importer')
  })

  test('ids the importer does not have are dropped, and the warning says so', async () => {
    const res = await POST(await bundle({
      attackSkillConfig: { builtIn: BUILT_IN, user: { id00: true, exporterSkill: true, ghost: true } },
    }))
    expect(res.status).toBe(200)
    expect(created().attackSkillConfig).toEqual({ builtIn: BUILT_IN, user: { id00: true } })
    expect(skillWarnings((await res.json()).warnings)).toEqual([
      'The project turned on 2 user skill(s) this account does not have; they were left out.',
    ])
  })

  test('the "turned on ... left out" count is the foreign ids that were ON, not every foreign id', async () => {
    const res = await POST(await bundle({
      attackSkillConfig: { builtIn: BUILT_IN, user: { exporterSkill: true, ghostOff: false, ghostOff2: false } },
    }))
    expect(created().attackSkillConfig).toEqual({ builtIn: BUILT_IN, user: {} })
    expect(skillWarnings((await res.json()).warnings)).toEqual([
      'The project turned on 1 user skill(s) this account does not have; they were left out.',
    ])
  })

  test('foreign ids are dropped BEFORE the cut: 20 own plus foreign trues keeps all 20 own on', async () => {
    const own = Object.fromEntries(importerSkills(20).map((s) => [s.id, true]))
    const res = await POST(await bundle({ attackSkillConfig: { builtIn: BUILT_IN, user: { ...own, exporterSkill: true } } }))
    expect(created().attackSkillConfig.user).toEqual(own)
    const warnings = skillWarnings((await res.json()).warnings)
    expect(warnings).toHaveLength(1)
    expect(warnings[0]).toContain('does not have')
  })

  test('more than 20 of the importer\'s skills on: the first 20 BY NAME stay on, the rest are turned off', async () => {
    const all = importerSkills(25)
    const res = await POST(await bundle({
      attackSkillConfig: { builtIn: BUILT_IN, user: Object.fromEntries(all.map((s) => [s.id, true])) },
    }))
    expect(res.status).toBe(200)
    const user = created().attackSkillConfig.user as Record<string, boolean>
    const byName = [...all].sort((a, b) => a.name.localeCompare(b.name))
    for (const s of byName.slice(0, 20)) expect(user[s.id], s.name).toBe(true)
    for (const s of byName.slice(20)) expect(user[s.id], s.name).toBe(false)
    expect(Object.keys(user)).toHaveLength(25)
    expect(skillWarnings((await res.json()).warnings)).toEqual([
      'The project had more of your skills on than a project may use (20), or a quarantined one; 5 were turned off.',
    ])
  })

  test('equal names are ordered by id', async () => {
    h.skills = Array.from({ length: 21 }, (_, i) => ({
      id: `same${String(20 - i).padStart(2, '0')}`, userId: 'importer', name: 'same name', quarantinedAt: null,
    }))
    await POST(await bundle({
      attackSkillConfig: { builtIn: BUILT_IN, user: Object.fromEntries(h.skills.map((s) => [s.id, true])) },
    }))
    const user = created().attackSkillConfig.user as Record<string, boolean>
    expect(user.same20).toBe(false)
    expect(user.same00).toBe(true)
    expect(Object.values(user).filter(Boolean)).toHaveLength(20)
  })

  test('a quarantined skill is turned off and does not take one of the 20 places', async () => {
    const all = importerSkills(21)
    const first = [...all].sort((a, b) => a.name.localeCompare(b.name))[0]
    first.quarantinedAt = QUARANTINED_AT
    h.skills = all
    const res = await POST(await bundle({
      attackSkillConfig: { builtIn: BUILT_IN, user: Object.fromEntries(all.map((s) => [s.id, true])) },
    }))
    const user = created().attackSkillConfig.user as Record<string, boolean>
    expect(user[first.id]).toBe(false)
    expect(Object.values(user).filter(Boolean)).toHaveLength(20)
    expect(skillWarnings((await res.json()).warnings)[0]).toContain('1 were turned off')
  })

  test('an unreadable config is left out (the column default applies) with a warning', async () => {
    const res = await POST(await bundle({ attackSkillConfig: { user: { id00: true } } }))
    expect(res.status).toBe(200)
    expect(created()).not.toHaveProperty('attackSkillConfig')
    expect(skillWarnings((await res.json()).warnings)).toEqual([
      "The project's skill toggles were unreadable; the defaults are used.",
    ])
  })

  test('a bundle without the config reads no skills and warns about none', async () => {
    const res = await POST(await bundle({}))
    expect(res.status).toBe(200)
    expect(created()).not.toHaveProperty('attackSkillConfig')
    expect(h.skillFindMany).not.toHaveBeenCalled()
    expect(skillWarnings((await res.json()).warnings)).toEqual([])
  })
})

describe('the imported user presets\' toggles', () => {
  test('a preset\'s foreign ids are dropped and its trues cut to 20, with a warning naming the preset', async () => {
    const own = importerSkills(22)
    const res = await POST(await bundle({}, [{
      name: 'Shared preset',
      description: '',
      settings: {
        katanaDepth: 3,
        attackSkillConfig: {
          builtIn: BUILT_IN,
          user: { ...Object.fromEntries(own.map((s) => [s.id, true])), exporterSkill: true },
        },
      },
    }]))
    expect(res.status).toBe(200)
    const settings = h.createPreset.mock.calls[0][0].data.settings
    expect(settings.katanaDepth).toBe(3)
    expect(settings.attackSkillConfig.user).not.toHaveProperty('exporterSkill')
    expect(Object.values(settings.attackSkillConfig.user).filter(Boolean)).toHaveLength(20)
    expect(Object.keys(settings.attackSkillConfig.user)).toHaveLength(22)
    expect(skillWarnings((await res.json()).warnings)).toEqual([
      'The preset "Shared preset" turned on 1 user skill(s) this account does not have; they were left out.',
      'The preset "Shared preset" had more of your skills on than a project may use (20), or a quarantined one; 2 were turned off.',
    ])
  })

  test('a preset with an unreadable config is stored without it', async () => {
    const res = await POST(await bundle({}, [{ name: 'Bad', settings: { katanaDepth: 2, attackSkillConfig: [] } }]))
    expect(res.status).toBe(200)
    const settings = h.createPreset.mock.calls[0][0].data.settings
    expect(settings).toEqual({ katanaDepth: 2 })
    expect(skillWarnings((await res.json()).warnings)).toEqual([
      'The preset "Bad"\'s skill toggles were unreadable; the defaults are used.',
    ])
  })
})
