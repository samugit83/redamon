/**
 * GET /api/users/[id]/tradecraft-resources/[resourceId]/enabled-impact: the numbers of the alert
 * shown before a change of Enabled is saved (R-062, R-140).
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'
import { createTradecraftDb, type TradecraftDb } from '@/lib/tradecraft/__testing__/tradecraftDb'

const h = vi.hoisted(() => ({ db: null as unknown as TradecraftDb, denied: null as Response | null }))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => (h.db.prisma as Record<string | symbol, unknown>)[k] }) }))
vi.mock('@/lib/authz/selfService', () => ({ requireSelfPermission: vi.fn(async () => null) }))
vi.mock('@/lib/session', () => ({ requireUserAccess: vi.fn(async () => h.denied), isInternalRequest: vi.fn(() => false) }))

import { GET } from './route'
import { requireUserAccess } from '@/lib/session'
import { requireSelfPermission } from '@/lib/authz/selfService'

const PR = (id = 'owner', resourceId = 'r1') => ({ params: Promise.resolve({ id, resourceId }) })
const req = (next: string | null = 'false') =>
  new NextRequest(`http://webapp.test/api/users/owner/tradecraft-resources/r1/enabled-impact${next === null ? '' : `?next=${next}`}`)
async function answer(res: Response) {
  return { status: res.status, body: await res.json() }
}

beforeEach(() => {
  h.db = createTradecraftDb()
  h.denied = null
  h.db.seed('userTradecraftResource', { id: 'r1', userId: 'owner', name: 'HackTricks', slug: 'hacktricks', url: 'https://wiki.tc-fixture.test/' })
  h.db.seed('userTradecraftResource', { id: 'r-x', userId: 'other', name: 'X', slug: 'x', url: 'https://x.tc-fixture.test/' })
  for (const id of ['p1', 'p2', 'p3', 'p4', 'p5', 'p6', 'p7']) h.db.seed('project', { id, userId: 'owner' })
  h.db.seed('project', { id: 'p-other', userId: 'other' })
  h.db.seed('tradecraftProjectChoice', { projectId: 'p1', resourceId: 'r1' })
  h.db.seed('tradecraftProjectChoice', { projectId: 'p2', resourceId: 'r1' })
  vi.spyOn(console, 'error').mockImplementation(() => {})
})
afterEach(() => { vi.restoreAllMocks() })

describe('enabled-impact', () => {
  test('enabled-impact numbers: every project of the account, and the projects where it is turned off', async () => {
    expect(await answer(await GET(req('false'), PR()))).toEqual({ status: 200, body: { next: false, projects: 7, turnedOffIn: 2 } })
    expect(await answer(await GET(req('true'), PR()))).toEqual({ status: 200, body: { next: true, projects: 7, turnedOffIn: 2 } })
  })

  test('reads only: nothing is written', async () => {
    await GET(req('true'), PR())
    expect(h.db.calls.filter(c => !/\.(findFirst|findUnique|findMany|count)$/.test(c))).toEqual([])
    expect(h.db.rows('tradecraftProjectChoice')).toHaveLength(2)
  })

  test('next must be true or false', async () => {
    for (const next of [null, '', 'yes', '1']) expect((await GET(req(next), PR())).status).toBe(400)
  })

  test("another account's resource or an unknown one: 404", async () => {
    expect((await GET(req(), PR('owner', 'r-x'))).status).toBe(404)
    expect((await GET(req(), PR('owner', 'ghost'))).status).toBe(404)
  })

  test('the account rule and self:tradecraft run first; a refusal reads nothing', async () => {
    h.denied = NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    expect((await GET(req(), PR())).status).toBe(403)
    expect(h.db.calls).toEqual([])
    expect(vi.mocked(requireUserAccess).mock.calls.at(-1)![2]).toEqual({ mode: 'read' })
    h.denied = null
    await GET(req(), PR())
    expect(vi.mocked(requireSelfPermission).mock.calls.at(-1)!.slice(1)).toEqual(['owner', 'self:tradecraft'])
  })

  test('a database failure answers its code', async () => {
    h.db.failNext('project.count', Object.assign(new Error('timeout at db-host'), { code: 'P2024' }))
    expect(await answer(await GET(req(), PR()))).toEqual({
      status: 500, body: { error: 'Failed to read what the change of Enabled affects', code: 'P2024' },
    })
  })
})
