/**
 * PUT /api/projects/[id] and the user-skill toggles (D9, D10).
 *
 * The form PUTs the whole row, `attackSkillConfig` included, and an admin may save a
 * project they do not own. What is WRITTEN must name only the project OWNER's skills
 * (foreign ids dropped), with at most 20 of them on and none quarantined; anything else
 * is a 400 and nothing is written. The row is held by an in-memory Prisma double, so the
 * assertions read what was stored, not what a mock was called with.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  db: null as unknown as Record<string, unknown>,
  actor: { userId: 'owner', isAdmin: false } as { userId: string; isAdmin: boolean },
}))

vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => h.db[k as string] }) }))
vi.mock('@/lib/audit', () => ({ writeAudit: vi.fn() }))
vi.mock('@/app/api/graph/neo4j', () => ({ getGraphSession: () => ({ run: vi.fn(), close: vi.fn() }) }))
vi.mock('@/lib/graphSeedDomains', async orig => ({
  ...(await orig<typeof import('@/lib/graphSeedDomains')>()),
  seedProjectDomains: vi.fn(async () => true),
}))
vi.mock('@/lib/graphWriters', () => ({ describeScanWriters: async () => null }))
vi.mock('@/lib/graphRestore', () => ({ clearProjectGraph: vi.fn() }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: vi.fn() }))
vi.mock('@/lib/session', () => ({ isInternalRequest: () => false, isScannerRequest: () => false }))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', async () => {
  const actual = await vi.importActual<typeof import('@/lib/access')>('@/lib/access')
  return {
    ...actual,
    requireEffectiveUser: async () => h.actor,
    requireProjectAccess: async () => ({ project: { id: 'proj-1', userId: 'owner' } }),
  }
})

import { createFakePrisma, type FakePrisma } from '@/lib/plugins/__testing__/fakePrisma'
import { PUT } from './route'

const BUILT_IN = { sql_injection: true, xss: true, rce: false }
const READ_AT = new Date('2026-10-01T10:00:00.000Z')
const ownerIds = (n: number) => Array.from({ length: n }, (_, i) => `own${String(i).padStart(2, '0')}`)
const allOn = (ids: string[]) => Object.fromEntries(ids.map((id) => [id, true]))

let db: FakePrisma

function put(body: Record<string, unknown>) {
  return PUT(
    new NextRequest('http://localhost/api/projects/proj-1', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),
    { params: Promise.resolve({ id: 'proj-1' }) },
  )
}

const stored = () => db.rows('project')[0]
const storedConfig = () => stored().attackSkillConfig as { builtIn: Record<string, boolean>; user: Record<string, boolean> }

beforeEach(() => {
  db = createFakePrisma()
  h.db = db as unknown as Record<string, unknown>
  h.actor = { userId: 'owner', isAdmin: false }
  vi.spyOn(console, 'error').mockImplementation(() => {})
  db.seed('project', [{
    id: 'proj-1', userId: 'owner', name: 'p', targetDomain: 'example.invalid',
    ipMode: false, domainBatchMode: false, katanaDepth: 2,
    attackSkillConfig: { builtIn: BUILT_IN, user: { own00: true } },
    updatedAt: READ_AT,
  }])
  db.seed('userAttackSkill', [
    ...ownerIds(25).map((id) => ({ id, userId: 'owner', name: `flow ${id}`, content: '# x' })),
    { id: 'adminSkill', userId: 'admin', name: 'admin flow', content: '# x' },
    { id: 'otherSkill', userId: 'other', name: 'other flow', content: '# x' },
  ])
})

describe('toggles sent unchanged with a whole-row save', () => {
  test('a stored config the rules now refuse does not block an unrelated edit, and is left as stored', async () => {
    // Saved before the rules: no builtIn, and a 21st skill on.
    const legacy = { user: allOn(ownerIds(21)) }
    await db.project.update({ where: { id: 'proj-1' }, data: { attackSkillConfig: legacy } })
    const res = await put({ katanaDepth: 5, attackSkillConfig: legacy })
    expect(res.status).toBe(200)
    expect(stored().katanaDepth).toBe(5)
    expect(stored().attackSkillConfig).toEqual(legacy)
  })

  test('a changed config is still validated', async () => {
    const res = await put({ katanaDepth: 5, attackSkillConfig: { user: { own00: true } } })
    expect(res.status).toBe(400)
    expect(stored().katanaDepth).toBe(2)
  })
})

describe('PUT writes only the owner\'s skills', () => {
  test('foreign and unknown ids are dropped from what is written; the owner\'s on and off are kept', async () => {
    const res = await put({
      name: 'p',
      attackSkillConfig: { builtIn: BUILT_IN, user: { own01: true, own02: false, otherSkill: true, ghost: true } },
    })
    expect(res.status).toBe(200)
    expect(storedConfig()).toEqual({ builtIn: BUILT_IN, user: { own01: true, own02: false } })
    expect((await res.json()).attackSkillConfig).toEqual({ builtIn: BUILT_IN, user: { own01: true, own02: false } })
  })

  test('an admin saving someone else\'s project is judged on the OWNER\'s skills, not their own', async () => {
    h.actor = { userId: 'admin', isAdmin: true }
    const res = await put({
      name: 'p',
      attackSkillConfig: { builtIn: BUILT_IN, user: { own03: true, adminSkill: true } },
    })
    expect(res.status).toBe(200)
    expect(storedConfig().user).toEqual({ own03: true })
  })

  test('the whole-row save with updatedAt (the compare-and-swap path) writes the normalized value too', async () => {
    const res = await put({
      name: 'p', updatedAt: READ_AT.toISOString(),
      attackSkillConfig: { builtIn: BUILT_IN, user: { own04: true, otherSkill: true } },
    })
    expect(res.status).toBe(200)
    expect(storedConfig().user).toEqual({ own04: true })
  })

  test('exactly 20 of the owner\'s skills on is saved', async () => {
    const res = await put({ name: 'p', attackSkillConfig: { builtIn: BUILT_IN, user: allOn(ownerIds(20)) } })
    expect(res.status).toBe(200)
    expect(storedConfig().user).toEqual(allOn(ownerIds(20)))
  })
})

describe('PUT refuses, and writes nothing', () => {
  test('21 of the owner\'s skills on: 400 with the limit message', async () => {
    const res = await put({ name: 'renamed', attackSkillConfig: { builtIn: BUILT_IN, user: allOn(ownerIds(21)) } })
    expect(res.status).toBe(400)
    expect((await res.json()).error).toBe(
      'A project can use at most 20 of your skills; this turns on 21. Turn some off first.')
    expect(stored().name).toBe('p')
    expect(storedConfig().user).toEqual({ own00: true })
  })

  test('true on a quarantined skill: 400 naming it', async () => {
    db.seed('userAttackSkill', [{ id: 'quar', userId: 'owner', name: 'Revoked flow', content: '# x', quarantinedAt: new Date() }])
    const res = await put({ name: 'p', attackSkillConfig: { builtIn: BUILT_IN, user: { quar: true } } })
    expect(res.status).toBe(400)
    expect((await res.json()).error).toContain('"Revoked flow" is quarantined')
    expect(storedConfig().user).toEqual({ own00: true })
  })

  test('a config without builtIn: 400, never filled in', async () => {
    const res = await put({ name: 'p', attackSkillConfig: { user: { own01: true } } })
    expect(res.status).toBe(400)
    expect((await res.json()).error).toContain('must carry builtIn')
    expect(storedConfig()).toEqual({ builtIn: BUILT_IN, user: { own00: true } })
  })

  test('an array: 400', async () => {
    const res = await put({ name: 'p', attackSkillConfig: [] })
    expect(res.status).toBe(400)
    expect(storedConfig()).toEqual({ builtIn: BUILT_IN, user: { own00: true } })
  })
})

describe('a PUT that does not carry the toggles leaves them as stored', () => {
  test('a single-field autosave keeps even a legacy map the normalizer would refuse', async () => {
    const legacy = { builtIn: BUILT_IN, user: { ...allOn(ownerIds(25)), otherSkill: true } }
    db.tables.project.get('proj-1')!.attackSkillConfig = legacy
    const res = await put({ katanaDepth: 4 })
    expect(res.status).toBe(200)
    expect(stored().katanaDepth).toBe(4)
    expect(stored().attackSkillConfig).toEqual(legacy)
  })
})
