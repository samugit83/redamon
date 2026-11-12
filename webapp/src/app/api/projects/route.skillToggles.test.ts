/**
 * POST /api/projects and the user-skill toggles (D10, §9 row 11).
 *
 * A new project's `attackSkillConfig` may name only the CREATOR's own skills: ids the
 * creator does not have are dropped from the create call, more than 20 on is a 400 and
 * no project is created. The value may arrive as an object or as a JSON string (the
 * multipart create form and an LLM-parsed body send strings); both are judged after the
 * route's own coercion.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  userFindUnique: vi.fn(),
  projectCreate: vi.fn(),
  skillFindMany: vi.fn(),
  skills: [] as { id: string; userId: string; name: string; quarantinedAt: Date | null }[],
}))

vi.mock('@/lib/prisma', () => ({
  default: {
    user: { findUnique: (...a: unknown[]) => h.userFindUnique(...a) },
    project: { create: (...a: unknown[]) => h.projectCreate(...a), update: vi.fn() },
    userLlmProvider: { count: async () => 0 },
    userAttackSkill: { findMany: (...a: unknown[]) => h.skillFindMany(...a) },
  },
}))
vi.mock('@/app/api/graph/neo4j', () => ({
  getGraphSession: () => ({ run: vi.fn().mockResolvedValue({ records: [] }), close: vi.fn() }),
}))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: vi.fn().mockResolvedValue({ userId: 'creator' }),
  ownerScope: (eff: { userId: string }) => ({ userId: eff.userId }),
}))

import { NextRequest } from 'next/server'
import { POST } from './route'

const BUILT_IN = { sql_injection: true, xss: false }
const ids = (n: number) => Array.from({ length: n }, (_, i) => `own${String(i).padStart(2, '0')}`)
const allOn = (list: string[]) => Object.fromEntries(list.map((id) => [id, true]))

const postReq = (body: Record<string, unknown>) =>
  new NextRequest('http://localhost:3000/api/projects', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  })

// The soft guardrail is off so no request leaves the test; the hard one still runs.
const base = { name: 'test', targetDomain: 'example.invalid', targetGuardrailEnabled: false }
const created = () => h.projectCreate.mock.calls[0][0].data

beforeEach(() => {
  vi.clearAllMocks()
  h.skills = [
    ...ids(25).map((id) => ({ id, userId: 'creator', name: `flow ${id}`, quarantinedAt: null })),
    { id: 'otherSkill', userId: 'other', name: 'other flow', quarantinedAt: null },
    { id: 'quar', userId: 'creator', name: 'Revoked flow', quarantinedAt: new Date('2026-10-01T00:00:00Z') },
  ]
  // Prisma's `{ userId, id: { in } }` filter, applied to the rows above.
  h.skillFindMany.mockImplementation(async ({ where }: { where: { userId: string; id: { in: string[] } } }) =>
    h.skills.filter((s) => s.userId === where.userId && where.id.in.includes(s.id)))
  h.userFindUnique.mockResolvedValue({ id: 'creator' })
  h.projectCreate.mockResolvedValue({ id: 'p1', name: 'test', userId: 'creator', targetDomain: 'example.invalid' })
})

describe('POST: the create call names only the creator\'s skills', () => {
  test('ids the creator does not have are dropped; the creator\'s on and off are kept', async () => {
    const res = await POST(postReq({
      ...base,
      attackSkillConfig: { builtIn: BUILT_IN, user: { own00: true, own01: false, otherSkill: true, ghost: true } },
    }))
    expect(res.status).toBeLessThan(400)
    expect(created().attackSkillConfig).toEqual({ builtIn: BUILT_IN, user: { own00: true, own01: false } })
    expect(h.skillFindMany.mock.calls[0][0].where.userId).toBe('creator')
  })

  test('a JSON-string config (multipart / LLM-parsed body) is parsed, then normalized', async () => {
    const res = await POST(postReq({
      ...base, attackSkillConfig: JSON.stringify({ builtIn: BUILT_IN, user: { own02: true, otherSkill: true } }),
    }))
    expect(res.status).toBeLessThan(400)
    expect(created().attackSkillConfig).toEqual({ builtIn: BUILT_IN, user: { own02: true } })
  })

  test('20 on is created', async () => {
    const res = await POST(postReq({ ...base, attackSkillConfig: { builtIn: BUILT_IN, user: allOn(ids(20)) } }))
    expect(res.status).toBeLessThan(400)
    expect(created().attackSkillConfig.user).toEqual(allOn(ids(20)))
  })

  test('a body without the config leaves the column to its default and reads no skills', async () => {
    const res = await POST(postReq(base))
    expect(res.status).toBeLessThan(400)
    expect(created()).not.toHaveProperty('attackSkillConfig')
    expect(h.skillFindMany).not.toHaveBeenCalled()
  })
})

describe('POST: refused, and no project is created', () => {
  test('21 of the creator\'s skills on: 400 with the limit message and its code', async () => {
    const res = await POST(postReq({ ...base, attackSkillConfig: { builtIn: BUILT_IN, user: allOn(ids(21)) } }))
    expect(res.status).toBe(400)
    expect(await res.json()).toEqual({
      error: 'A project can use at most 20 of your skills; this turns on 21. Turn some off first.',
      code: 'too_many_enabled_skills',
    })
    expect(h.projectCreate).not.toHaveBeenCalled()
  })

  test('a quarantined skill on: 400', async () => {
    const res = await POST(postReq({ ...base, attackSkillConfig: { builtIn: BUILT_IN, user: { quar: true } } }))
    expect(res.status).toBe(400)
    expect((await res.json()).code).toBe('skill_quarantined')
    expect(h.projectCreate).not.toHaveBeenCalled()
  })

  test.each([
    ['a missing builtIn', { user: { own00: true } }],
    ['an array', [{ builtIn: BUILT_IN }]],
    ['an unknown key', { builtIn: BUILT_IN, user: {}, x: 1 }],
    ['a non-boolean toggle', { builtIn: BUILT_IN, user: { own00: 1 } }],
  ])('%s: 400 invalid_attack_skill_config', async (_label, value) => {
    const res = await POST(postReq({ ...base, attackSkillConfig: value }))
    expect(res.status).toBe(400)
    expect((await res.json()).code).toBe('invalid_attack_skill_config')
    expect(h.projectCreate).not.toHaveBeenCalled()
  })
})
