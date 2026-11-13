/**
 * Insights on a shared project (step 4.6; SH-07, NF-10): every analytics route (`graph:read`, `R`)
 * answers a read collaborator exactly what it answers the owner, reading the owner's project: each
 * graph query binds the shared project's id and never the collaborator's, the pipeline status asks
 * the orchestrator about that project, and the activity counts read its rows. An overseer reads the
 * same; someone the project is not shared with, or anyone with sharing not in force, gets 404 before
 * any read.
 *
 * Real guard, can(), projectAccess(), sharing policy reader and capabilities; the session, Prisma,
 * the graph session and the orchestrator are doubles (sharedReads.ts). The graph answers no rows:
 * what is compared is who was let through, what each route asked for, and that both got one answer.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  identity: vi.fn(), shares: new Map(), policy: { enabled: true } as unknown, models: {} as Record<string, unknown>, refused: vi.fn(),
  queries: [] as Array<{ query: string; params: unknown }>,
  orchestrator: [] as string[],
}))
// A whole-module double: session.ts imports guards.ts, so a partial one (importOriginal) would
// leave the guard holding the real getAuthzIdentity. Nobody acts as anyone here.
vi.mock('@/lib/session', () => ({
  getAuthzIdentity: (...a: unknown[]) => h.identity(...a),
  getEffectiveUser: async () => {
    const id = await h.identity()
    return id ? { userId: (id.actingAs ?? id.principal).id } : null
  },
  mayActAs: async () => false,
}))
vi.mock('@/lib/prisma', async () => ({ default: (await import('@/lib/authz/__testing__/sharedReads')).sharedReadPrisma(h as never) }))
vi.mock('@/app/api/graph/neo4j', () => ({
  getGraphSession: () => ({
    run: async (query: string, params?: unknown) => {
      h.queries.push({ query, params })
      return { records: [] }
    },
    close: async () => undefined,
  }),
}))
vi.mock('@/lib/orchestrator', () => ({
  orchestratorFetch: async (url: string) => {
    h.orchestrator.push(url)
    return new Response(JSON.stringify({ status: 'idle' }), { status: 200, headers: { 'content-type': 'application/json' } })
  },
}))

import { ROUTE_MANIFEST } from '@/lib/authz/routeManifest'
import { BADGED_TABS } from '@/app/graph/unseen/registry'
import {
  COLLABORATOR, OVERSEER, OWNER, RAW_COLLABORATOR, SHARED_PROJECT, STRANGER,
  endSharedReads, mentions, queriedProject, resetSharedReads, setFlags, signInAs,
} from '@/lib/authz/__testing__/sharedReads'

type Handler = (request: NextRequest) => Promise<Response>
const MODULES = import.meta.glob<Record<string, unknown>>('./**/route.ts')

const ANALYTICS = ROUTE_MANIFEST.filter(r => r.path.startsWith('/api/analytics/'))
const fileOf = (path: string) => `.${path.slice('/api/analytics'.length)}/route.ts`

// The activity counts: the route's own Prisma reads, keyed on the project.
const prismaReads: Array<{ model: string; args: unknown }> = []
function activityModels(): void {
  const rec = (model: string, value: unknown) => async (args: unknown) => { prismaReads.push({ model, args }); return value }
  h.models.conversation = {
    aggregate: rec('conversation', { _count: { id: 2 }, _sum: { iterationCount: 7 }, _avg: { iterationCount: 3.5 } }),
    groupBy: rec('conversation', []),
    findMany: rec('conversation', [{ createdAt: new Date('2026-11-03T00:00:00Z'), iterationCount: 3 }]),
  }
  h.models.remediation = { groupBy: rec('remediation', []), count: rec('remediation', 1), findMany: rec('remediation', []) }
  h.models.chatMessage = { count: rec('chatMessage', 5) }
}

const LONG_AGO = '2026-01-01T00:00:00.000Z'
function requestFor(path: string, projectId: string): NextRequest {
  if (path === '/api/analytics/unseen') {
    // Every badged tab with a watermark, so the route fans out to each tab's own route as the caller.
    const marks = Object.fromEntries(BADGED_TABS.map(t => [t, LONG_AGO]))
    return new NextRequest('http://localhost:3000/api/analytics/unseen', {
      method: 'POST', headers: { 'content-type': 'application/json', origin: 'http://localhost:3000' },
      body: JSON.stringify({ projectId, marks }),
    })
  }
  return new NextRequest(`http://localhost:3000${path}?projectId=${projectId}`)
}

async function callAs(who: string, path: string, projectId = SHARED_PROJECT) {
  signInAs(h as never, who)
  h.queries.length = 0
  h.orchestrator.length = 0
  prismaReads.length = 0
  const entry = ANALYTICS.find(r => r.path === path)!
  const method = entry.methods[0]
  const mod = await MODULES[fileOf(path)]()
  const res = await (mod[method] as Handler)(requestFor(path, projectId))
  return {
    status: res.status,
    body: await res.json(),
    queries: [...h.queries],
    orchestrator: [...h.orchestrator],
    prismaReads: [...prismaReads],
  }
}

beforeEach(async () => {
  await resetSharedReads(h as never)
  activityModels()
  vi.spyOn(console, 'error').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})
afterEach(async () => {
  await endSharedReads()
  vi.restoreAllMocks()
})

describe('the Insights routes, as the manifest lists them', () => {
  test('25 analytics routes, every one at graph:read, each with its route file', () => {
    expect(ANALYTICS).toHaveLength(25)
    for (const r of ANALYTICS) {
      expect([r.path, r.permission]).toEqual([r.path, 'graph:read'])
      expect(Object.keys(MODULES)).toContain(fileOf(r.path))
    }
  })
})

describe('a read collaborator gets the owner data on every Insights route (step 4.6)', () => {
  test.each(ANALYTICS.map(r => [r.path]))('%s', async (path) => {
    const owner = await callAs(OWNER, path)
    const reader = await callAs(COLLABORATOR, path)
    expect(owner.status).toBe(200)
    expect(reader.status).toBe(200)
    expect(reader.body).toEqual(owner.body)

    // The reads are the owner's project's, and none is keyed on the person reading.
    expect(reader.queries.length + reader.orchestrator.length + reader.prismaReads.length).toBeGreaterThan(0)
    expect(reader.queries.map(q => q.query)).toEqual(owner.queries.map(q => q.query))
    for (const q of reader.queries) {
      if (/\$(pid|projectId)\b/.test(q.query)) expect(queriedProject(q.params)).toBe(SHARED_PROJECT)
      expect(mentions(q.params, COLLABORATOR)).toBe(false)
    }
    for (const url of reader.orchestrator) expect(url).toContain(`/${SHARED_PROJECT}/`)
    for (const read of reader.prismaReads) {
      expect(mentions(read.args, SHARED_PROJECT)).toBe(true)
      expect(mentions(read.args, COLLABORATOR)).toBe(false)
    }
    expect(h.refused).not.toHaveBeenCalled()
  })
})

describe('who else reads Insights on the shared project', () => {
  const PATH = '/api/analytics/graph-overview'

  test('a collaborator with Raw data & files and an overseer get the same answer as the owner', async () => {
    const owner = await callAs(OWNER, PATH)
    for (const who of [RAW_COLLABORATOR, OVERSEER]) {
      const other = await callAs(who, PATH)
      expect([who, other.status]).toEqual([who, 200])
      expect(other.body).toEqual(owner.body)
    }
  })

  test.each(ANALYTICS.map(r => [r.path]))('%s: someone the project is not shared with gets 404 before any read', async (path) => {
    const res = await callAs(STRANGER, path)
    expect(res.status).toBe(404)
    expect(res.queries).toEqual([])
    expect(res.orchestrator).toEqual([])
    expect(res.prismaReads).toEqual([])
  })

  test('an expired share or a disabled collaborator: 404', async () => {
    h.shares.set(`${SHARED_PROJECT}|${COLLABORATOR}`, { access: 'read', rawData: false, expiresAt: new Date('2020-01-01T00:00:00Z'), user: { status: 'active' } })
    expect((await callAs(COLLABORATOR, PATH)).status).toBe(404)
    h.shares.set(`${SHARED_PROJECT}|${COLLABORATOR}`, { access: 'read', rawData: false, expiresAt: null, user: { status: 'disabled' } })
    expect((await callAs(COLLABORATOR, PATH)).status).toBe(404)
  })

  test.each([
    ['the sharing switch off', () => setFlags({ identity: true, permissions: true, sharing: false })],
    ['the policy disabled', async () => { h.policy = {}; await setFlags({ identity: true, permissions: true, sharing: true }) }],
  ])('%s: the collaborator gets 404 and the owner the same answer as with it on', async (_state, turnOff) => {
    const before = await callAs(OWNER, PATH)
    await turnOff()
    const reader = await callAs(COLLABORATOR, PATH)
    expect(reader.status).toBe(404)
    expect(reader.queries).toEqual([])
    const owner = await callAs(OWNER, PATH)
    expect(owner.status).toBe(200)
    expect(owner.body).toEqual(before.body)
  })
})
