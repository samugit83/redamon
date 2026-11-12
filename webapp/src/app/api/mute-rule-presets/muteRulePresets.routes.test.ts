/**
 * The Mute Rules preset routes: whose presets a caller sees, and what they refuse.
 *
 * A preset belongs to a user. Another user's preset must answer exactly like a
 * missing one (404, never 403), the owner comes from the session and never
 * from the body, mutations are JSON-only (415), and rules the engine would not
 * run are refused at save time so a preset always loads.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const h = vi.hoisted(() => ({
  eff: vi.fn(),
  findMany: vi.fn(),
  findUnique: vi.fn(),
  create: vi.fn(),
  update: vi.fn(),
  del: vi.fn(),
}))

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: () => h.eff(),
  ownerScope: (eff: { userId: string }) => ({ userId: eff.userId }),
}))
vi.mock('@/lib/prisma', () => ({
  default: {
    userMuteRulesPreset: {
      findMany: (...a: unknown[]) => h.findMany(...a),
      findUnique: (...a: unknown[]) => h.findUnique(...a),
      create: (...a: unknown[]) => h.create(...a),
      update: (...a: unknown[]) => h.update(...a),
      delete: (...a: unknown[]) => h.del(...a),
    },
  },
}))

import { GET as listPresets, POST as createPreset } from './route'
import { GET as getPreset, PATCH as patchPreset, DELETE as deletePreset } from './[id]/route'

const ME = 'user-me'
const OTHER = 'user-other'
const RULE = { id: 'k3f9a2', name: 'Informational templates', enabled: true,
               all: [{ field: 'severity', op: 'in', value: ['info'] }] }
const RULES = { version: 1, kinds: { 'vuln.nuclei': { enabled: true, action: 'mute', rules: [RULE] } } }
const when = new Date('2026-09-24T10:00:00Z')
const row = (over: Record<string, unknown> = {}) => ({
  id: 'p1', userId: ME, name: 'Quiet perimeter', description: 'why', mode: 'denylist',
  rules: RULES, createdAt: when, updatedAt: when, ...over,
})
const params = (id = 'p1') => ({ params: Promise.resolve({ id }) })

function json(url: string, method: string, body: unknown) {
  return new NextRequest(url, { method, headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
}

beforeEach(() => {
  vi.clearAllMocks()
  h.eff.mockResolvedValue({ userId: ME })
})

describe('GET /api/mute-rule-presets', () => {
  test('lists only the caller\'s presets, with counts and without the rules', async () => {
    h.findMany.mockResolvedValue([row()])
    const res = await listPresets(new NextRequest('http://x/api/mute-rule-presets'))
    expect(res.status).toBe(200)
    expect(h.findMany.mock.calls[0][0].where).toEqual({ userId: ME })
    const [item] = await res.json()
    expect(item).toMatchObject({ id: 'p1', name: 'Quiet perimeter', mode: 'denylist', counts: { rules: 1, kinds: 1 } })
    expect(item).not.toHaveProperty('rules')
    expect(item).not.toHaveProperty('userId')
  })

  test('an anonymous caller is refused before the database is read', async () => {
    h.eff.mockResolvedValue(NextResponse.json({ error: 'Unauthorized' }, { status: 401 }))
    expect((await listPresets(new NextRequest('http://x/api/mute-rule-presets'))).status).toBe(401)
    expect(h.findMany).not.toHaveBeenCalled()
  })
})

describe('POST /api/mute-rule-presets', () => {
  const URL_ = 'http://x/api/mute-rule-presets'

  test('saves the caller\'s preset under the session user, never a user named in the body', async () => {
    h.create.mockImplementation(({ data }: { data: Record<string, unknown> }) => Promise.resolve(row(data)))
    const res = await createPreset(json(URL_, 'POST', {
      name: '  Quiet perimeter ', description: 'why', mode: 'denylist', rules: RULES, userId: OTHER,
    }))
    expect(res.status).toBe(201)
    const data = h.create.mock.calls[0][0].data
    expect(data.userId).toBe(ME)
    expect(data.name).toBe('Quiet perimeter')
    expect(data.rules).toEqual(RULES)
  })

  test('refuses rules the engine would not run, and saves nothing', async () => {
    const bad = { version: 1, kinds: { 'vuln.nuclei': { enabled: true, action: 'mute',
      rules: [{ ...RULE, all: [{ field: 'no_such_field', op: 'in', value: ['x'] }] }] } } }
    const res = await createPreset(json(URL_, 'POST', { name: 'Broken', mode: 'denylist', rules: bad }))
    expect(res.status).toBe(400)
    expect((await res.json()).errors.join(' ')).toMatch(/no_such_field/)
    expect(h.create).not.toHaveBeenCalled()
  })

  test('refuses a blank name and an unknown mode', async () => {
    expect((await createPreset(json(URL_, 'POST', { name: '  ', mode: 'denylist', rules: RULES }))).status).toBe(400)
    expect((await createPreset(json(URL_, 'POST', { name: 'Q', mode: 'maybe', rules: RULES }))).status).toBe(400)
    expect(h.create).not.toHaveBeenCalled()
  })

  test('refuses a body that is not JSON (415): a plain form post cannot create one', async () => {
    const req = new NextRequest(URL_, { method: 'POST', headers: { 'content-type': 'text/plain' }, body: 'name=x' })
    expect((await createPreset(req)).status).toBe(415)
  })
})

describe('GET /api/mute-rule-presets/[id]', () => {
  test('returns the owner\'s preset with its rules, for a load', async () => {
    h.findUnique.mockResolvedValue(row())
    const res = await getPreset(new NextRequest('http://x'), params())
    expect(res.status).toBe(200)
    expect((await res.json()).rules).toEqual(RULES)
  })

  test('someone else\'s preset answers 404, exactly like a missing one', async () => {
    h.findUnique.mockResolvedValue(row({ userId: OTHER }))
    const other = await getPreset(new NextRequest('http://x'), params())
    h.findUnique.mockResolvedValue(null)
    const missing = await getPreset(new NextRequest('http://x'), params())
    expect(other.status).toBe(404)
    expect(missing.status).toBe(404)
    expect(await other.json()).toEqual(await missing.json())
  })
})

describe('PATCH /api/mute-rule-presets/[id]', () => {
  test('renames the owner\'s preset and keeps its description when none is sent', async () => {
    h.findUnique.mockResolvedValue(row())
    h.update.mockImplementation(({ data }: { data: Record<string, unknown> }) => Promise.resolve(row(data)))
    const res = await patchPreset(json('http://x', 'PATCH', { name: 'Renamed' }), params())
    expect(res.status).toBe(200)
    expect(h.update.mock.calls[0][0].data).toEqual({ name: 'Renamed', description: 'why' })
  })

  test('cannot rename someone else\'s preset', async () => {
    h.findUnique.mockResolvedValue(row({ userId: OTHER }))
    expect((await patchPreset(json('http://x', 'PATCH', { name: 'Mine now' }), params())).status).toBe(404)
    expect(h.update).not.toHaveBeenCalled()
  })

  test('a rename never touches the rules, even when the body sends some', async () => {
    h.findUnique.mockResolvedValue(row())
    h.update.mockImplementation(({ data }: { data: Record<string, unknown> }) => Promise.resolve(row(data)))
    await patchPreset(json('http://x', 'PATCH', { name: 'R', rules: { version: 1, kinds: {} }, mode: 'allowlist' }), params())
    expect(Object.keys(h.update.mock.calls[0][0].data).sort()).toEqual(['description', 'name'])
  })

  test('refuses a blank name', async () => {
    h.findUnique.mockResolvedValue(row())
    expect((await patchPreset(json('http://x', 'PATCH', { name: ' ' }), params())).status).toBe(400)
    expect(h.update).not.toHaveBeenCalled()
  })
})

describe('DELETE /api/mute-rule-presets/[id]', () => {
  test('deletes the owner\'s preset', async () => {
    h.findUnique.mockResolvedValue(row())
    h.del.mockResolvedValue(row())
    expect((await deletePreset(new NextRequest('http://x'), params())).status).toBe(200)
    expect(h.del).toHaveBeenCalledWith({ where: { id: 'p1' } })
  })

  test('cannot delete someone else\'s preset', async () => {
    h.findUnique.mockResolvedValue(row({ userId: OTHER }))
    expect((await deletePreset(new NextRequest('http://x'), params())).status).toBe(404)
    expect(h.del).not.toHaveBeenCalled()
  })
})

describe('a database that is down', () => {
  const down = () => Object.assign(new Error('Invalid `prisma.userMuteRulesPreset` invocation: "SECRET-RULE"'), {
    name: 'PrismaClientKnownRequestError', code: 'P1001',
  })
  const CASES: [string, () => Promise<Response>, string][] = [
    ['GET the list', () => listPresets(new NextRequest('http://x/api/mute-rule-presets')), 'Failed to load the presets'],
    ['POST a preset', () => createPreset(json('http://x/api/mute-rule-presets', 'POST',
      { name: 'Quiet', mode: 'denylist', rules: RULES })), 'Failed to save the preset'],
    ['GET one preset', () => getPreset(new NextRequest('http://x/api/mute-rule-presets/p1'), params()), 'Failed to read the preset'],
    ['PATCH one preset', () => patchPreset(json('http://x/api/mute-rule-presets/p1', 'PATCH', { name: 'New' }), params()),
      'Failed to rename the preset'],
    ['DELETE one preset', () => deletePreset(new NextRequest('http://x/api/mute-rule-presets/p1', { method: 'DELETE' }), params()),
      'Failed to delete the preset'],
  ]

  test.each(CASES)('%s: 500 with the fixed sentence and the Prisma code, never a bodiless 500', async (_name, call, error) => {
    for (const fn of [h.findMany, h.findUnique, h.create, h.update, h.del]) fn.mockRejectedValue(down())
    const log = vi.spyOn(console, 'error').mockImplementation(() => {})
    const res = await call()
    const text = await res.text()
    expect(res.status).toBe(500)
    expect(JSON.parse(text)).toEqual({ error, code: 'P1001' })
    expect(text).not.toContain('SECRET-RULE')
    log.mockRestore()
  })
})
