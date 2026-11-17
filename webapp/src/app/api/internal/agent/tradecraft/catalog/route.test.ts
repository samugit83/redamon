/**
 * GET /api/internal/agent/tradecraft/catalog: the internal key checked in the route, the owner
 * from the project row, the coded 404, and one 2.0 catalog for every account (T9.3: the switch
 * and the 1.x payload are gone).
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterAll } from 'vitest'
import { NextRequest } from 'next/server'
import { createTradecraftDb, type TradecraftDb } from '@/lib/tradecraft/__testing__/tradecraftDb'

vi.stubEnv('INTERNAL_API_KEY', 'ik-test-catalog-0001')
vi.stubEnv('SCANNER_API_KEY', 'sk-test-catalog-0001')
vi.stubEnv('AUTH_SECRET', 't'.repeat(64))

const h = vi.hoisted(() => ({ db: null as unknown as TradecraftDb }))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => (h.db.prisma as Record<string | symbol, unknown>)[k] }) }))
vi.mock('@/lib/authz/selfService', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overSelfService()))
vi.mock('next/headers', () => ({ cookies: vi.fn(async () => ({ get: () => ({ value: 'a-session-cookie' }) })) }))

import { GET } from './route'

const KEY = { 'x-internal-key': 'ik-test-catalog-0001' }
const get = (query: string, headers: Record<string, string> = KEY) =>
  GET(new NextRequest(`http://webapp.test/api/internal/agent/tradecraft/catalog${query}`, { headers }))

beforeEach(() => {
  h.db = createTradecraftDb()
  h.db.seed('project', { id: 'p1', userId: 'owner' })
  h.db.seed('userTradecraftResource', {
    id: 'r1', userId: 'owner', name: 'Wiki', slug: 'wiki', url: 'https://wiki.example.test/', githubTokenOverride: 'ghp_fake_1',
    hasLogin: true, credentials: { cookie: 'session=fake-session' }, sitemap: { nav: [1] },
  })
  h.db.seed('userTradecraftResource', { id: 'r2', userId: 'owner', name: 'Docs', slug: 'docs', url: 'https://docs.example.test/', createdAt: new Date('2026-11-16T11:00:00Z') })
  h.db.seed('userTradecraftResource', { id: 'r-evil', userId: 'evil', name: 'E', slug: 'e', url: 'https://e.example.test/' })
})
afterAll(() => vi.unstubAllEnvs())

describe('catalog route', () => {
  test.each([
    ['no key', {}],
    ['the scanner key', { 'x-internal-key': 'sk-test-catalog-0001' }],
    ['a wrong key', { 'x-internal-key': 'nope' }],
    ['a session cookie and no key', { cookie: 'redamon-auth=a-session-cookie' }],
  ])('requires_internal_key: %s is refused, nothing read', async (_name, headers) => {
    const res = await get('?projectId=p1&personId=owner', headers)
    expect(res.status).toBe(401)
    expect(h.db.calls).toEqual([])
  })

  test('owner_read_from_project: the project row names whose library it is; the query cannot', async () => {
    h.db.seed('tradecraftUserSettings', { userId: 'owner', v2Enabled: true })
    const body = await (await get('?projectId=p1&personId=owner&ownerId=evil&userId=evil')).json()
    expect(body).toMatchObject({ v2: true, owner_id: 'owner' })
    expect(body.resources.map((r: { id: string }) => r.id)).toEqual(['r1', 'r2'])
  })

  test('unknown_project_404_code: a coded 404 the agent never falls back on (D-53)', async () => {
    const res = await get('?projectId=nope&personId=owner')
    expect(res.status).toBe(404)
    expect(await res.json()).toEqual({ error: 'Project not found', code: 'project_not_found' })
  })

  test('the project is required', async () => {
    expect(await (await get('?personId=owner')).json()).toEqual({ error: 'projectId is required', code: 'project_required' })
  })

  test.each([false, true, null])('no person (a request outside a run), old switch row %s: the 2.0 catalog without the login resource (R-155)', async (on) => {
    if (on !== null) h.db.seed('tradecraftUserSettings', { userId: 'owner', v2Enabled: on })
    const res = await get('?projectId=p1')
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.resources.map((r: { id: string }) => r.id)).toEqual(['r2'])
    expect(body).toMatchObject({ v2: true, person_id: null })
    expect(body).not.toHaveProperty('legacy')
    expect(JSON.stringify(body)).not.toMatch(/fake-session|ghp_fake_1/)
  })

  test("a collaborator's run: the login resource is not listed", async () => {
    h.db.seed('tradecraftUserSettings', { userId: 'owner', v2Enabled: true })
    const body = await (await get('?projectId=p1&personId=collab')).json()
    expect(body).toMatchObject({ v2: true, person_id: 'collab' })
    expect(body.resources.map((r: { id: string }) => r.id)).toEqual(['r2'])
  })

  test('the acting administrator is carried and closes the login rule', async () => {
    h.db.seed('tradecraftUserSettings', { userId: 'owner', v2Enabled: true })
    const body = await (await get('?projectId=p1&personId=owner&actorId=admin-1')).json()
    expect(body).toMatchObject({ actor_id: 'admin-1' })
    expect(body.resources.map((r: { id: string }) => r.id)).toEqual(['r2'])
  })

  test("an old switch row off changes nothing: the owner's own run lists the login resource, the others' runs do not", async () => {
    h.db.seed('tradecraftUserSettings', { userId: 'owner', v2Enabled: false })
    expect((await (await get('?projectId=p1&personId=owner')).json()).resources.map((r: { id: string }) => r.id)).toEqual(['r1', 'r2'])
    expect((await (await get('?projectId=p1&personId=collab')).json()).resources.map((r: { id: string }) => r.id)).toEqual(['r2'])
  })

  test('a database failure answers its code', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    h.db.failNext('project.findUnique', Object.assign(new Error('down'), { code: 'P1001' }))
    const res = await get('?projectId=p1&personId=owner')
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Failed to build the tradecraft run catalog', code: 'P1001' })
  })
})
