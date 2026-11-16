/**
 * GET /api/projects/[id]/tradecraft: the project's Tradecraft Resources accordion (§3.4, T4.4).
 * The owner gets every resource with read-only details; an administrator acting as the owner gets
 * no text of a resource with a login; anyone else gets names and on/off only, a login resource as
 * "Owner only" (R-066, D-07, §6.6). The owner comes from the access the guard answered.
 *
 * The guard is a double that answers the context a test sets (the real one is proved by the
 * permission tests and the route manifest); Prisma is the in-memory tradecraft double.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'
import { createTradecraftDb, type TradecraftDb } from '@/lib/tradecraft/__testing__/tradecraftDb'

const h = vi.hoisted(() => ({
  db: null as unknown as TradecraftDb,
  ctx: null as null | Record<string, unknown>,
  refusal: null as null | number,
  asked: [] as { permission: string; opts: unknown }[],
}))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => (h.db.prisma as Record<string | symbol, unknown>)[k] }) }))
vi.mock('@/lib/authz/guards', () => ({
  requirePermission: async (_req: unknown, permission: string, opts: unknown) => {
    h.asked.push({ permission, opts })
    if (h.refusal) return NextResponse.json({ error: 'Not found' }, { status: h.refusal })
    return h.ctx
  },
}))

import { GET } from './route'
import { activeCounts } from '@/lib/tradecraft/activeCounts'

const OWNER = 'owner-1'
const P = 'proj-1'

type Ctx = { person: string; actor?: string; via?: 'owner' | 'share' | 'oversight'; level?: string }
function as({ person, actor, via = 'owner', level = via === 'owner' ? 'owner' : 'write' }: Ctx) {
  h.ctx = {
    principal: { id: actor ?? person }, actingAs: actor ? { id: person } : null, effective: { userId: person },
    access: { project: { id: P, userId: OWNER }, level, via, toggles: { rawData: true } },
  }
}
async function get() {
  const res = await GET(new NextRequest(`http://localhost/api/projects/${P}/tradecraft`), { params: Promise.resolve({ id: P }) })
  return { status: res.status, body: await res.json() }
}

beforeEach(() => {
  h.db = createTradecraftDb()
  h.refusal = null
  h.asked = []
  as({ person: OWNER })
  h.db.seed('tradecraftUserSettings', { userId: OWNER, v2Enabled: true })
  h.db.seed('project', { id: P, userId: OWNER, attackSkillConfig: { builtIn: { xss: true, sql_injection: true }, user: {} } })
  h.db.seed('userTradecraftResource', {
    id: 'r1', userId: OWNER, name: 'HackTricks', slug: 'hacktricks', url: 'https://wiki.tc-fixture.test/', resourceType: 'mkdocs-wiki',
    storageMode: 'stored', mapVersion: 3, summary: 'PUBLIC-SUMMARY', settingsSnapshot: { values: { 'crawl.maxPages': 90 } },
    ingestionReport: { visited: 40, kept: 31 }, lastRefreshedAt: new Date('2026-11-10T00:00:00Z'), createdAt: new Date(1),
  })
  h.db.seed('userTradecraftResource', {
    id: 'r2', userId: OWNER, name: 'Company wiki', slug: 'company-wiki', url: 'https://private.tc-fixture.test/', hasLogin: true,
    credentials: { cookie: 'session=fake-session' }, summary: 'PRIVATE-SUMMARY', createdAt: new Date(2),
  })
  h.db.seed('userTradecraftResource', {
    id: 'r3', userId: OWNER, name: 'Sigma rules', slug: 'sigma', url: 'https://sigma.tc-fixture.test/', enabled: false, createdAt: new Date(3),
  })
  h.db.seed('userTradecraftResource', { id: 'r9', userId: 'someone-else', name: 'Theirs', slug: 'theirs', url: 'https://theirs.tc-fixture.test/' })
  h.db.seed('tradecraftProjectChoice', { projectId: P, resourceId: 'r1' })
})

describe('GET /api/projects/[id]/tradecraft', () => {
  test('asks recon:read on the project, and a refusal reads nothing', async () => {
    await get()
    expect(h.asked).toEqual([{ permission: 'recon:read', opts: { projectId: P } }])
    h.refusal = 404
    h.db.calls.length = 0
    expect((await get()).status).toBe(404)
    expect(h.db.calls).toEqual([])
  })

  test('v2 off: the tab and the drawer stay as they were', async () => {
    h.db.tables.tradecraftUserSettings[0].v2Enabled = false
    expect(await get()).toEqual({ status: 200, body: { v2: false, viewerIsOwner: true, resources: [], counts: null } })
  })

  test('the owner: every resource of the owner, oldest first, with the switch state and read-only details', async () => {
    const { body } = await get()
    expect(body.v2).toBe(true)
    expect(body.viewerIsOwner).toBe(true)
    expect(body.resources.map((r: { id: string }) => r.id)).toEqual(['r1', 'r2', 'r3'])
    expect(body.resources[0]).toMatchObject({
      name: 'HackTricks', type: 'mkdocs-wiki', storageMode: 'stored', pages: 0, lastRefreshedAt: '2026-11-10T00:00:00.000Z',
      enabledGlobally: true, offInProject: true, ownerOnly: false, locked: false,
      details: {
        url: 'https://wiki.tc-fixture.test/', mapVersion: 3, summary: 'PUBLIC-SUMMARY', hasLogin: false,
        ingestedWith: { 'crawl.maxPages': 90 }, report: expect.objectContaining({ visited: 40, kept: 31 }),
      },
    })
    expect(body.resources[1]).toMatchObject({ ownerOnly: false, locked: false, details: { hasLogin: true, summary: 'PRIVATE-SUMMARY' } })
    expect(body.resources[2]).toMatchObject({ enabledGlobally: false, offInProject: false, locked: true })
    // The values of a login never leave; the map never leaves.
    expect(JSON.stringify(body)).not.toMatch(/fake-session|credentials|sitemap/)
  })

  test("last refreshed: the card's rule; a failed ingestion's 1.x verification time is no refresh", async () => {
    const row = (id: string) => h.db.rows('userTradecraftResource', { id })[0]
    // Its only 2.0 ingestion failed: the failure set the 1.x time (TD-18), and the card says "never".
    Object.assign(row('r2'), { mapVersion: 3, lastRefreshedAt: null, lastVerifiedAt: new Date('2026-11-15T00:00:00Z'), lastError: 'fetch_failed' })
    // A 1.x map verified without an error is a refresh, as on the card.
    Object.assign(row('r3'), { mapVersion: 1, lastRefreshedAt: null, lastVerifiedAt: new Date('2026-11-14T00:00:00Z'), lastError: '' })
    const { body } = await get()
    expect(body.resources.map((r: { lastRefreshedAt: string | null }) => r.lastRefreshedAt))
      .toEqual(['2026-11-10T00:00:00.000Z', null, '2026-11-14T00:00:00.000Z'])
  })

  test('missing_row_means_on: a resource with no choice row is on in the project', async () => {
    const { body } = await get()
    expect(body.resources.find((r: { id: string }) => r.id === 'r2').offInProject).toBe(false)
  })

  test('collaborator_view: names and on/off only; the login resource is Owner only, locked; no detail of any kind', async () => {
    as({ person: 'collab-1', via: 'share' })
    const { body } = await get()
    expect(body.viewerIsOwner).toBe(false)
    expect(body.resources).toEqual([
      { id: 'r1', name: 'HackTricks', type: null, storageMode: null, pages: null, lastRefreshedAt: null, enabledGlobally: true, offInProject: true, ownerOnly: false, locked: false },
      { id: 'r2', name: 'Company wiki', type: null, storageMode: null, pages: null, lastRefreshedAt: null, enabledGlobally: true, offInProject: false, ownerOnly: true, locked: true },
      { id: 'r3', name: 'Sigma rules', type: null, storageMode: null, pages: null, lastRefreshedAt: null, enabledGlobally: false, offInProject: false, ownerOnly: false, locked: true },
    ])
    expect(JSON.stringify(body)).not.toMatch(/SUMMARY|tc-fixture\.test|hasLogin|fake-session/)
  })

  test('oversight reads like a collaborator: no details', async () => {
    as({ person: 'admin-2', via: 'oversight', level: 'read' })
    const { body } = await get()
    expect(body.viewerIsOwner).toBe(false)
    expect(body.resources.every((r: Record<string, unknown>) => !('details' in r))).toBe(true)
  })

  test('act_as_owner_details_without_text: details, but no summary of a resource with a login; it is Owner only here', async () => {
    as({ person: OWNER, actor: 'admin-1' })
    const { body } = await get()
    expect(body.viewerIsOwner).toBe(true)
    expect(body.resources[0].details.summary).toBe('PUBLIC-SUMMARY')
    expect(body.resources[1]).toMatchObject({ ownerOnly: true, locked: true, details: { summary: null, hasLogin: true } })
    expect(JSON.stringify(body)).not.toContain('PRIVATE-SUMMARY')
  })

  test('the counts are the viewer\'s, by the agent\'s rules', async () => {
    const owner = (await get()).body.counts
    expect(owner).toEqual(await activeCounts({ ownerId: OWNER, projectId: P, personId: OWNER, actorId: null }, { builtIn: { xss: true, sql_injection: true }, user: {} }))
    expect(owner.tradecraft).toMatchObject({ active: 1, total: 3, offInProject: 1, disabledGlobally: 1, ownerOnlyHidden: 0 })
    as({ person: 'collab-1', via: 'share' })
    expect((await get()).body.counts.tradecraft).toMatchObject({ active: 0, ownerOnlyHidden: 1 })
    expect((await get()).body.counts.builtIn).toMatchObject({ active: 2, total: 14 })
  })

  test('whose resources: the owner of the access, never another account', async () => {
    as({ person: 'someone-else', via: 'share' })
    const { body } = await get()
    expect(body.resources.map((r: { id: string }) => r.id)).toEqual(['r1', 'r2', 'r3'])
  })

  test('a failure answers a fixed message with its code', async () => {
    h.db.failNext('userTradecraftResource.findMany', Object.assign(new Error('db at 10.0.0.5 refused user secret_user'), { code: 'P1001' }))
    const r = await get()
    expect(r.status).toBe(500)
    expect(r.body).toEqual({ error: "Could not read the project's tradecraft resources", code: 'P1001' })
  })
})
