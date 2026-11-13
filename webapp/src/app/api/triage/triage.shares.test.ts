/**
 * The Priority Board on a shared project (step 4.8, SH-07): a read collaborator, with or without
 * Raw data & files (and a share stored as `write`, read as read while the write switch is off), and
 * an admin reaching the project by oversight, read the board, a finding, its evidence, the muted list,
 * the run preflight and the mute rules, all from the OWNER's graph (the tenant `triageCaller` hands the
 * agent is the project's owner, never the reader). Every triage write (a verdict, a mute or unmute,
 * Multi mute, the mute rules) answers 403 naming its permission, before the agent or the database is
 * touched. A review (MCP `submit_finding_review`) and a run (the `cypherfix-triage` ticket, MCP
 * `start_triage_run`) are refused at read where they are asked: `lib/mcp/triageWrites.shares.test.ts`
 * and `ws-ticket/route.shares.test.ts`.
 *
 * Real guard, can(), projectAccess(), sharing policy reader and capabilities; the session, Prisma
 * (sharedProjectDb), the agent and the graph-writer probe are doubles.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'
import type { SharedProjectDb } from '@/lib/authz/__testing__/sharedProjectDb'

const h = vi.hoisted(() => ({
  identity: null as unknown,
  db: { shares: new Map(), breakGlass: new Map(), policy: { enabled: true }, models: {}, writes: [] } as SharedProjectDb,
  agentCalls: [] as Array<Record<string, unknown>>,
}))
vi.mock('@/lib/session', async (orig) => ({
  ...(await orig<typeof import('@/lib/session')>()),
  ...(await import('@/lib/authz/__testing__/sharedProjectDb')).sessionOf(h),
}))
vi.mock('@/lib/prisma', async () => ({ default: (await import('@/lib/authz/__testing__/sharedProjectDb')).sharedProjectPrisma(h) }))
vi.mock('@/lib/authz/guards', async (orig) => {
  const real = await orig<typeof import('@/lib/authz/guards')>()
  return { ...real, requirePermission: vi.fn(real.requirePermission) }
})
vi.mock('@/lib/agentFetch', async (orig) => ({
  ...(await orig<typeof import('@/lib/agentFetch')>()),
  agentFetch: (_path: string, init: RequestInit) => agentAnswer(init),
}))
vi.mock('@/lib/graphWriters', async (orig) => ({
  ...(await orig<typeof import('@/lib/graphWriters')>()),
  describeLiveGraphWriters: async () => null,
}))

import { requirePermission, type PermissionContext } from '@/lib/authz/guards'
import { setFlagsForTests } from '@/lib/authz/flags'
import { clearSharingPolicyCacheForTests } from '@/lib/authz/sharingPolicy'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import { clearPrincipalCacheForTests } from '@/lib/authz/principal'
import { clearOversightMemoForTests } from '@/lib/authz/oversight'
import type { PermissionId } from '@/lib/authz/permissions'
import {
  COLLABORATOR, OVERSEER, OWNER, SHARED_PROJECT, STRANGER, identityOf, resetSharedProjectDb, shareWith,
} from '@/lib/authz/__testing__/sharedProjectDb'

/** What the agent answers each triage op; every call is recorded with its body. */
const AGENT_ANSWERS: Record<string, unknown> = {
  list_findings: { findings: [], total: 0 },
  triage_facets: { tiers: {} },
  finding_detail: { found: true, id: 'f-1' },
  finding_evidence: { found: true, evidence: '', evidence_hash: 'h' },
  list_muted: { findings: [], total: 0 },
  muted_facets: {},
  preflight: { in_scope: 0 },
}
async function agentAnswer(init: RequestInit | undefined): Promise<Response> {
  const body = JSON.parse(String(init?.body ?? '{}')) as Record<string, unknown>
  h.agentCalls.push(body)
  const answer = AGENT_ANSWERS[String(body.op)]
  return answer === undefined
    ? new Response(JSON.stringify({ error: 'not doubled' }), { status: 500 })
    : new Response(JSON.stringify(answer), { status: 200 })
}

type Handler = (request: NextRequest, context: never) => Promise<Response>
interface Case {
  route: string
  load: () => Promise<Record<string, unknown>>
  permission: PermissionId
  params?: Record<string, string>
  query?: Record<string, string>
  body?: unknown
  /** The agent ops this read asks, each for the owner's graph. */
  ops?: string[]
}

const FINDING = { findingId: 'f-1', label: 'Vulnerability' }
const onProject = { id: SHARED_PROJECT }

const READS: Case[] = [
  { route: 'GET /api/triage/findings', load: () => import('./findings/route'), permission: 'triage:read', query: {}, ops: ['list_findings', 'triage_facets'] },
  { route: 'GET /api/triage/finding', load: () => import('./finding/route'), permission: 'triage:read', query: FINDING, ops: ['finding_detail'] },
  { route: 'GET /api/triage/evidence', load: () => import('./evidence/route'), permission: 'triage:read', query: FINDING, ops: ['finding_evidence'] },
  { route: 'GET /api/triage/muted', load: () => import('./muted/route'), permission: 'triage:read', query: { facets: '1' }, ops: ['list_muted', 'muted_facets'] },
  { route: 'GET /api/triage/preflight', load: () => import('./preflight/route'), permission: 'triage:read', query: {}, ops: ['preflight'] },
  { route: 'GET /api/projects/[id]/node-filters', load: () => import('@/app/api/projects/[id]/node-filters/route'), permission: 'triage:read', params: onProject },
  { route: 'GET /api/projects/[id]/node-filters/apply', load: () => import('@/app/api/projects/[id]/node-filters/apply/route'), permission: 'triage:read', params: onProject },
  { route: 'GET /api/projects/[id]/node-filters/runs/[runId]', load: () => import('@/app/api/projects/[id]/node-filters/runs/[runId]/route'), permission: 'triage:read', params: { ...onProject, runId: 'run-1' } },
  { route: 'GET /api/projects/[id]/node-filters/status', load: () => import('@/app/api/projects/[id]/node-filters/status/route'), permission: 'triage:read', params: onProject },
]

const WRITES: Case[] = [
  { route: 'POST /api/triage/verdict', load: () => import('./verdict/route'), permission: 'triage:verdict', body: { nodeId: 'n-1', status: 'confirmed' } },
  { route: 'POST /api/triage/mute', load: () => import('./mute/route'), permission: 'triage:mute', body: { nodeId: 'n-1' } },
  { route: 'POST /api/triage/unmute', load: () => import('./unmute/route'), permission: 'triage:mute', body: { nodeId: 'n-1' } },
  { route: 'POST /api/triage/mute-by-graph-id', load: () => import('./mute-by-graph-id/route'), permission: 'triage:mute', body: { graphId: '4:abc:1' } },
  { route: 'POST /api/triage/multi-mute/apply', load: () => import('./multi-mute/apply/route'), permission: 'triage:mute', body: { batchId: 'multi-1', keys: ['k'] } },
  { route: 'POST /api/triage/multi-mute/suggest', load: () => import('./multi-mute/suggest/route'), permission: 'triage:mute', body: { nodeId: 'n-1' } },
  { route: 'PUT /api/projects/[id]/node-filters', load: () => import('@/app/api/projects/[id]/node-filters/route'), permission: 'node_filters:manage', params: onProject, body: { rules: [] } },
  { route: 'POST /api/projects/[id]/node-filters/apply', load: () => import('@/app/api/projects/[id]/node-filters/apply/route'), permission: 'node_filters:manage', params: onProject, body: {} },
  { route: 'POST /api/projects/[id]/node-filters/disarm', load: () => import('@/app/api/projects/[id]/node-filters/disarm/route'), permission: 'node_filters:manage', params: onProject, body: {} },
  { route: 'DELETE /api/projects/[id]/node-filters/exemptions', load: () => import('@/app/api/projects/[id]/node-filters/exemptions/route'), permission: 'node_filters:manage', params: onProject },
  { route: 'POST /api/projects/[id]/node-filters/preview', load: () => import('@/app/api/projects/[id]/node-filters/preview/route'), permission: 'node_filters:manage', params: onProject, body: { rules: [] } },
]

function requestFor(c: Case, projectId: string): NextRequest {
  const [method, path] = c.route.split(' ')
  const params: Record<string, string> = { ...c.params, ...(c.params?.id ? { id: projectId } : {}) }
  const query = c.query ? `?${new URLSearchParams({ projectId, ...c.query })}` : ''
  const url = 'http://localhost:3000' + path.replace(/\[(\w+)\]/g, (_m, k: string) => params[k] ?? k) + query
  const init: { method: string; headers?: Record<string, string>; body?: string } = { method }
  if (c.body !== undefined) {
    init.headers = { 'content-type': 'application/json', origin: 'http://localhost:3000' }
    init.body = JSON.stringify(c.params?.id ? c.body : { projectId, ...(c.body as object) })
  }
  return new NextRequest(url, init)
}

async function call(c: Case, who: string, projectId = SHARED_PROJECT): Promise<{ res: Response; guard: unknown }> {
  h.identity = identityOf(who)
  vi.mocked(requirePermission).mockClear()
  const handler = (await c.load())[c.route.split(' ')[0]] as Handler
  const params: Record<string, string> = { ...c.params, ...(c.params?.id ? { id: projectId } : {}) }
  const res = await handler(requestFor(c, projectId), { params: Promise.resolve(params) } as never)
  const first = vi.mocked(requirePermission).mock.results[0]
  return { res, guard: first ? await first.value : undefined }
}

/** The ways a person other than the owner reads the project, and the access each one is given. */
const READERS: Array<{ name: string; who: string; arrange: () => void; rawData: boolean; via: string }> = [
  { name: 'a read collaborator', who: COLLABORATOR, arrange: () => shareWith(h.db, COLLABORATOR), rawData: false, via: 'share' },
  { name: 'a read collaborator with Raw data & files', who: COLLABORATOR, arrange: () => shareWith(h.db, COLLABORATOR, { rawData: true }), rawData: true, via: 'share' },
  { name: 'a collaborator whose share is stored as write (read while the write switch is off)', who: COLLABORATOR, arrange: () => shareWith(h.db, COLLABORATOR, { access: 'write' }), rawData: false, via: 'share' },
  { name: 'an admin by oversight', who: OVERSEER, arrange: () => {}, rawData: false, via: 'oversight' },
]

/**
 * The one write an overseer's read makes: the day's `project.oversee` audit row, in its transaction
 * (step 4.14; this double records the transaction, not what runs in it). Nothing of the project.
 */
const OVERSIGHT_AUDIT = [{ model: '$client', method: '$transaction' }]

beforeEach(() => {
  resetSharedProjectDb(h.db)
  h.db.models.nodeFilterRun = { findFirst: () => ({ id: 'run-1', status: 'completed' }) }
  h.agentCalls.length = 0
  h.identity = null
  vi.stubGlobal('fetch', (_url: string, init?: RequestInit) => agentAnswer(init))
  setFlagsForTests({ identity: true, permissions: true, sharing: true })
  clearSharingPolicyCacheForTests()
  clearCapabilityCachesForTests()
  clearInstanceRootCacheForTests()
  clearPrincipalCacheForTests()
  clearOversightMemoForTests()
  vi.spyOn(console, 'error').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe.each(READERS)('$name reads the Priority Board from the owner\'s graph (step 4.8)', ({ who, arrange, rawData, via }) => {
  test.each(READS)('$route: 200, at read, the owner as the tenant', async (c) => {
    arrange()
    const { res, guard } = await call(c, who)
    expect(res.status).toBe(200)
    const auth = guard as PermissionContext
    expect(auth.permission).toBe(c.permission)
    expect(auth.access).toEqual({ project: { id: SHARED_PROJECT, userId: OWNER }, level: 'read', toggles: { rawData }, via })
    expect(h.agentCalls.map(b => b.op)).toEqual(expect.arrayContaining(c.ops ?? []))
    for (const sent of h.agentCalls) {
      expect([sent.op, sent.user_id, sent.project_id]).toEqual([sent.op, OWNER, SHARED_PROJECT])
    }
    expect(h.db.writes).toEqual(who === OVERSEER ? OVERSIGHT_AUDIT : [])
  })

  test.each(WRITES)('$route: 403 naming $permission, nothing reaches the agent or the database', async (c) => {
    arrange()
    const { res } = await call(c, who)
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'forbidden', permission: c.permission })
    expect(h.agentCalls).toEqual([])
    expect(h.db.writes).toEqual([])
  })
})

describe('who does not reach the board', () => {
  const board = READS[0]
  const verdict = WRITES[0]

  test('someone the project is not shared with: 404 on a read and on a write, the agent never called', async () => {
    for (const c of [board, verdict]) {
      const { res } = await call(c, STRANGER)
      expect([c.route, res.status]).toEqual([c.route, 404])
    }
    expect(h.agentCalls).toEqual([])
  })

  test('an expired share, or one whose collaborator is disabled: 404', async () => {
    shareWith(h.db, COLLABORATOR, { expiresAt: new Date(Date.now() - 1000) })
    expect((await call(board, COLLABORATOR)).res.status).toBe(404)
    shareWith(h.db, COLLABORATOR, { status: 'disabled' })
    expect((await call(board, COLLABORATOR)).res.status).toBe(404)
    expect(h.agentCalls).toEqual([])
  })

  test('with RBAC_SHARING_ENABLED off, or the instance policy disabled, a share gives nothing (404)', async () => {
    shareWith(h.db, COLLABORATOR, { rawData: true })
    setFlagsForTests({ identity: true, permissions: true, sharing: false })
    expect((await call(board, COLLABORATOR)).res.status).toBe(404)
    setFlagsForTests({ identity: true, permissions: true, sharing: true })
    h.db.policy = {}
    clearSharingPolicyCacheForTests()
    expect((await call(board, COLLABORATOR)).res.status).toBe(404)
    expect(h.agentCalls).toEqual([])
  })

  test('the owner reads the board as before, its own graph, at the owner level', async () => {
    const { res, guard } = await call(board, OWNER)
    expect(res.status).toBe(200)
    expect((guard as PermissionContext).access?.level).toBe('owner')
    expect(h.agentCalls.every(b => b.user_id === OWNER && b.project_id === SHARED_PROJECT)).toBe(true)
  })
})
