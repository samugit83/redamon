/**
 * The project's tradecraft switches in GET and PUT /api/projects/[id] (§3.4, T4.4).
 *
 * `tradecraftOff` (the owner's resources turned off here) is read with the project and saved
 * with it: one save, one version (R-064). The choices commit in the project update's transaction,
 * so a stale form changes no choice and a failed choice write leaves the row as it was; the ids
 * are judged against the owner the access names (foreign ids dropped, a globally disabled resource
 * and, for anyone but the owner, a resource with a login left as they are).
 *
 * The core rows are the plugin platform's in-memory Prisma, the tradecraft rows the tradecraft
 * double; one `$transaction` spans both and rolls both back. The guard is a double answering the
 * context a test sets and recording the permission asked.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  client: null as unknown as Record<string | symbol, unknown>,
  ctx: null as null | Record<string, unknown>,
  asked: [] as { permission: string; opts: unknown }[],
  internal: false,
}))

vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => h.client[k] }) }))
vi.mock('@/lib/audit', () => ({ writeAudit: vi.fn() }))
vi.mock('@/app/api/graph/neo4j', () => ({ getGraphSession: () => ({ run: vi.fn(), close: vi.fn() }) }))
vi.mock('@/lib/graphSeedDomains', async orig => ({
  ...(await orig<typeof import('@/lib/graphSeedDomains')>()),
  seedProjectDomains: vi.fn(async () => true),
}))
vi.mock('@/lib/graphWriters', () => ({ describeScanWriters: async () => null }))
vi.mock('@/lib/graphRestore', () => ({ clearProjectGraph: vi.fn() }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: vi.fn() }))
vi.mock('@/lib/session', () => ({ isInternalRequest: () => h.internal, isScannerRequest: () => false }))
vi.mock('@/lib/authz/guards', async () => ({
  ...(await vi.importActual<typeof import('@/lib/authz/guards')>('@/lib/authz/guards')),
  requirePermission: async (_req: unknown, permission: string, opts: unknown) => {
    h.asked.push({ permission, opts })
    return { ...h.ctx, permission }
  },
}))

import { createFakePrisma, type FakePrisma } from '@/lib/plugins/__testing__/fakePrisma'
import { createTradecraftDb, type TradecraftDb } from '@/lib/tradecraft/__testing__/tradecraftDb'
import { GET, PUT } from './route'
import { writeAudit } from '@/lib/audit'

const OWNER = 'owner-1'
const P = 'proj-1'
const READ_AT = new Date('2026-11-01T10:00:00.000Z')
const TRADECRAFT = new Set(['userTradecraftResource', 'tradecraftProjectChoice', 'tradecraftUserSettings'])

let fake: FakePrisma
let tc: TradecraftDb

let tick = 0

/**
 * The project delegate, answering `include: { tradecraftChoices }` from the tradecraft rows and
 * moving `updatedAt` on every update, as Prisma's @updatedAt does (the plugin double leaves it).
 */
function projectDelegate(delegate: Record<string, unknown>, tcClient: Record<string, unknown>) {
  return new Proxy(delegate, {
    get: (d, op) => {
      if (op === 'update' || op === 'updateMany') {
        return (args: { data: Record<string, unknown> } & Record<string, unknown>) =>
          (d[op] as (a: unknown) => Promise<unknown>)({ ...args, data: { updatedAt: new Date(READ_AT.getTime() + ++tick * 1000), ...args.data } })
      }
      if (op !== 'findUnique') return d[op as string]
      return async (args: { include?: Record<string, unknown> } & Record<string, unknown>) => {
        const { tradecraftChoices, ...include } = args.include ?? {}
        const row = await (d.findUnique as (a: unknown) => Promise<Record<string, unknown> | null>)({
          ...args, include: Object.keys(include).length ? include : undefined,
        })
        if (row && tradecraftChoices) {
          row.tradecraftChoices = await (tcClient.tradecraftProjectChoice as { findMany: (a: unknown) => Promise<unknown> })
            .findMany({ where: { projectId: row.id }, select: { resourceId: true } })
        }
        return row
      }
    },
  })
}

function combined(f: Record<string, unknown>, t: Record<string, unknown>): Record<string | symbol, unknown> {
  return new Proxy({}, {
    get: (_x, k) => {
      if (typeof k === 'string' && TRADECRAFT.has(k)) return t[k]
      if (k === 'project') return projectDelegate(f.project as Record<string, unknown>, t)
      if (k === '$transaction') {
        return async (fn: (tx: unknown) => Promise<unknown>) =>
          (f.$transaction as (g: (ftx: unknown) => Promise<unknown>) => Promise<unknown>)(async ftx =>
            (t.$transaction as (g: (ttx: unknown) => Promise<unknown>) => Promise<unknown>)(async ttx =>
              fn(combined(ftx as Record<string, unknown>, ttx as Record<string, unknown>))))
      }
      return f[k as string]
    },
  })
}

function as(person: string, opts: { actor?: string; via?: 'owner' | 'share' } = {}) {
  const via = opts.via ?? (person === OWNER ? 'owner' : 'share')
  h.ctx = {
    session: { userId: opts.actor ?? person }, principal: { id: opts.actor ?? person, role: 'standard' },
    actingAs: opts.actor ? { id: person } : null, effective: { userId: person },
    capabilities: { has: () => true },
    access: { project: { id: P, userId: OWNER }, level: via === 'owner' ? 'owner' : 'write', via, toggles: { rawData: true } },
  }
}

function put(body: Record<string, unknown>) {
  return PUT(new NextRequest(`http://localhost/api/projects/${P}`, {
    method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  }), { params: Promise.resolve({ id: P }) })
}
async function get() {
  const res = await GET(new NextRequest(`http://localhost/api/projects/${P}`), { params: Promise.resolve({ id: P }) })
  return { status: res.status, body: await res.json() }
}
const project = () => fake.rows('project')[0]
const off = (projectId = P) => tc.rows('tradecraftProjectChoice', { projectId }).map(c => c.resourceId).sort()

beforeEach(() => {
  fake = createFakePrisma()
  tc = createTradecraftDb()
  h.client = combined(fake as unknown as Record<string, unknown>, tc.prisma)
  h.asked = []
  h.internal = false
  as(OWNER)
  vi.spyOn(console, 'error').mockImplementation(() => {})
  fake.seed('project', [{
    id: P, userId: OWNER, name: 'p', targetDomain: 'example.invalid', ipMode: false, domainBatchMode: false, katanaDepth: 2,
    attackSkillConfig: { builtIn: { xss: true }, user: {} }, updatedAt: READ_AT,
  }])
  for (const [id, userId, enabled, hasLogin] of [
    ['r1', OWNER, true, false], ['r2', OWNER, true, false], ['r3', OWNER, false, false], ['r4', OWNER, true, true], ['foreign', 'other', true, false],
  ] as const) {
    tc.seed('userTradecraftResource', { id, userId, name: id, slug: id, url: `https://${id}.tc-fixture.test/`, enabled, hasLogin })
  }
  tc.seed('tradecraftProjectChoice', { projectId: P, resourceId: 'r2' })
  tc.seed('tradecraftProjectChoice', { projectId: 'proj-2', resourceId: 'r1' })
})

describe('GET carries the switches', () => {
  test('a browser reads tradecraftOff with the project; the agent and the scanners do not', async () => {
    const { body } = await get()
    expect(body.tradecraftOff).toEqual(['r2'])
    expect(body).not.toHaveProperty('tradecraftChoices')
    expect(h.asked).toEqual([{ permission: 'recon:read', opts: { projectId: P } }])
    h.internal = true
    const internal = await get()
    expect(internal.status).toBe(200)
    expect(internal.body).not.toHaveProperty('tradecraftOff')
    expect(internal.body).not.toHaveProperty('tradecraftChoices')
  })

  test('missing_row_means_on: a project with no row reads an empty list', async () => {
    tc.tables.tradecraftProjectChoice = tc.tables.tradecraftProjectChoice.filter(c => c.projectId !== P)
    expect((await get()).body.tradecraftOff).toEqual([])
  })
})

describe('PUT saves the switches with the project', () => {
  test('permission: the save asks project:settings on the project, as the skill switches (R-065)', async () => {
    await put({ name: 'p', tradecraftOff: ['r1'] })
    expect(h.asked).toEqual([{ permission: 'project:settings', opts: { projectId: P } }])
  })

  test('the listed changeable resources go off, the others back on, and the answer carries the result', async () => {
    const res = await put({ name: 'p', tradecraftOff: ['r1'] })
    expect(res.status).toBe(200)
    expect(off()).toEqual(['r1'])
    expect((await res.json()).tradecraftOff).toEqual(['r1'])
    expect(off('proj-2')).toEqual(['r1'])
  })

  test('drops_foreign_ids: another account\'s resource and an unknown id are not written', async () => {
    await put({ name: 'p', tradecraftOff: ['foreign', 'ghost', 'r2'] })
    expect(off()).toEqual(['r2'])
  })

  test('cannot_turn_on_globally_disabled: a disabled resource is neither added nor removed', async () => {
    tc.seed('tradecraftProjectChoice', { projectId: P, resourceId: 'r3' })
    await put({ name: 'p', tradecraftOff: [] })
    expect(off()).toEqual(['r3'])
    await put({ name: 'p', tradecraftOff: ['r3', 'r1'] })
    expect(off()).toEqual(['r1', 'r3'])
  })

  test('a collaborator changes the public resources; the owner\'s login resource stays as it is', async () => {
    as('collab-1')
    await put({ name: 'p', tradecraftOff: ['r1', 'r4'] })
    expect(off()).toEqual(['r1'])
    as(OWNER)
    await put({ name: 'p', tradecraftOff: ['r1', 'r4'] })
    expect(off()).toEqual(['r1', 'r4'])
    as(OWNER, { actor: 'admin-1' })
    await put({ name: 'p', tradecraftOff: ['r1'] })
    expect(off()).toEqual(['r1', 'r4'])
  })

  test('same_transaction_and_stale: a PUT with an old updatedAt changes no choice and no column (409)', async () => {
    // Another writer saved meanwhile.
    await (h.client.project as FakePrisma['project']).update({ where: { id: P }, data: { katanaDepth: 3 } })
    const res = await put({ name: 'renamed', updatedAt: READ_AT.toISOString(), tradecraftOff: ['r1'] })
    expect(res.status).toBe(409)
    expect((await res.json()).code).toBe('stale_save')
    expect(off()).toEqual(['r2'])
    expect(project().name).toBe('p')
  })

  test('same_transaction_and_stale: a choice save moves updatedAt, so a form read before it is refused (AC-27)', async () => {
    const drawer = await put({ updatedAt: READ_AT.toISOString(), tradecraftOff: ['r1'] })
    expect(drawer.status).toBe(200)
    expect((project().updatedAt as Date).getTime()).not.toBe(READ_AT.getTime())
    const form = await put({ name: 'from the form', updatedAt: READ_AT.toISOString(), tradecraftOff: [] })
    expect(form.status).toBe(409)
    expect(off()).toEqual(['r1'])
    expect(project().name).toBe('p')
  })

  test('same_transaction_and_stale: a choice write that fails rolls the project update back', async () => {
    tc.failNext('tradecraftProjectChoice.createMany', Object.assign(new Error('write failed'), { code: 'P2034' }))
    const res = await put({ name: 'renamed', updatedAt: READ_AT.toISOString(), tradecraftOff: ['r1'] })
    expect(res.status).toBe(500)
    expect(project().name).toBe('p')
    expect((project().updatedAt as Date).getTime()).toBe(READ_AT.getTime())
    expect(off()).toEqual(['r2'])
  })

  test('a save without tradecraftOff (a single-field autosave) leaves the choices as they are', async () => {
    const res = await put({ katanaDepth: 4 })
    expect(res.status).toBe(200)
    expect(project().katanaDepth).toBe(4)
    expect(off()).toEqual(['r2'])
    expect(await res.json()).not.toHaveProperty('tradecraftOff')
  })

  test.each([
    ['a string', 'r1'],
    ['a list with a number', ['r1', 2]],
    ['an object', { r1: true }],
    ['null', null],
  ])('tradecraftOff that is %s: 400, nothing written', async (_name, value) => {
    const res = await put({ name: 'renamed', tradecraftOff: value })
    expect(res.status).toBe(400)
    expect((await res.json()).code).toBe('invalid_tradecraft_off')
    expect(project().name).toBe('p')
    expect(off()).toEqual(['r2'])
  })

  test('a change of the switches is in the save\'s audit row, before and after; an unchanged list is not', async () => {
    vi.mocked(writeAudit).mockClear()
    await put({ tradecraftOff: ['r1'] })
    expect(writeAudit).toHaveBeenCalledWith(expect.objectContaining({
      action: 'project.update',
      before: expect.objectContaining({ tradecraftOff: ['r2'] }),
      after: expect.objectContaining({ changed: expect.arrayContaining(['tradecraftOff']), values: expect.objectContaining({ tradecraftOff: ['r1'] }) }),
    }))
    vi.mocked(writeAudit).mockClear()
    await put({ tradecraftOff: ['r1'] })
    const rows = vi.mocked(writeAudit).mock.calls.map(c => c[0] as { after: { changed: string[] } })
    expect(rows.every(r => !r.after.changed.includes('tradecraftOff'))).toBe(true)
  })
})
