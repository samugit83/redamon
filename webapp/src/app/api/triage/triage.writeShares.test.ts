/**
 * Triage writes on a project shared at Read + Write (step 5.2; SH-24, SH-25, SH-27, SH-07 write part):
 * with write sharing in force an editor (no toggle) records verdicts, mutes, unmutes and Multi mute
 * applies at W, each sent to the OWNER's graph (the tenant) and attributed to the editor: `muted_by`,
 * `triage_verdict_by`, an unmute's exemption `createdBy` and every audit actor name the person, never
 * the owner. A collaborator's verdict therefore never trains the owner's detectors (they learn from
 * `triage_verdict_by = owner` only). The owner's requests are the ones sent before. A read share stays
 * refused (triage.shares.test.ts), and Manage-only and owner-only levels stay out of an editor's reach.
 *
 * Real guard, can(), projectAccess(), sharing policy reader and capabilities; the session, Prisma
 * (sharedProjectDb), the agent, the graph session and the audit writer are doubles.
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
  audits: [] as Array<Record<string, unknown>>,
}))
vi.mock('@/lib/session', async (orig) => ({
  ...(await orig<typeof import('@/lib/session')>()),
  ...(await import('@/lib/authz/__testing__/sharedProjectDb')).sessionOf(h),
}))
vi.mock('@/lib/prisma', async () => ({ default: (await import('@/lib/authz/__testing__/sharedProjectDb')).sharedProjectPrisma(h) }))
vi.mock('@/lib/agentFetch', async (orig) => ({
  ...(await orig<typeof import('@/lib/agentFetch')>()),
  agentFetch: (_path: string, init: RequestInit) => agentAnswer(init),
}))
vi.mock('@/lib/audit', async (orig) => ({
  ...(await orig<typeof import('@/lib/audit')>()),
  writeAudit: async (entry: Record<string, unknown>) => { h.audits.push(entry) },
}))
vi.mock('@/app/api/graph/neo4j', () => ({
  getGraphSession: () => ({
    run: async () => ({ records: [{ get: (k: string) => ({ labels: ['Vulnerability'], id: 'f-graph', findingId: null } as Record<string, unknown>)[k] }] }),
    close: async () => {},
  }),
}))

import '@/lib/authz/guards'
import { setFlagsForTests } from '@/lib/authz/flags'
import { clearSharingPolicyCacheForTests } from '@/lib/authz/sharingPolicy'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import { clearPrincipalCacheForTests } from '@/lib/authz/principal'
import { can } from '@/lib/authz/can'
import type { PermissionId } from '@/lib/authz/permissions'
import {
  COLLABORATOR, OWNER, SHARED_PROJECT, account, identityOf, resetSharedProjectDb, shareWith,
} from '@/lib/authz/__testing__/sharedProjectDb'

const AGENT_ANSWERS: Record<string, unknown> = {
  mute: { muted: true, label: 'Vulnerability' },
  human_verdict: { updated: true, label: 'Vulnerability', rescored: true, before: {}, after: {} },
  unmute_many: { items: [{ key: 'f-1', label: 'Vulnerability', muted_by: OWNER }] },
  mute_batch: { multi_mute: 1, items: [{ key: 'f-1', label: 'Vulnerability', outcome: 'muted' }] },
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
const ROUTES = {
  verdict: { load: () => import('./verdict/route'), body: { nodeId: 'f-1', status: 'confirmed', label: 'Vulnerability' } },
  mute: { load: () => import('./mute/route'), body: { nodeId: 'f-1', reason: 'noise' } },
  muteByGraphId: { load: () => import('./mute-by-graph-id/route'), body: { graphId: '42' } },
  unmute: { load: () => import('./unmute/route'), body: { nodeId: 'f-1' } },
  multiMuteApply: { load: () => import('./multi-mute/apply/route'), body: { batchId: 'mm-0123abcd', keys: ['f-1'], concept: 'same_problem' } },
} satisfies Record<string, { load: () => Promise<Record<string, unknown>>; body: Record<string, unknown> }>

async function post(name: keyof typeof ROUTES, who: string): Promise<Response> {
  h.identity = identityOf(who)
  const route = ROUTES[name]
  const handler = (await route.load()).POST as unknown as Handler
  return handler(new NextRequest('http://localhost:3000/api/triage/x', {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: 'http://localhost:3000' },
    body: JSON.stringify({ projectId: SHARED_PROJECT, ...route.body }),
  }), { params: Promise.resolve({}) } as never)
}

const WRITE_IN_FORCE = { identity: true, permissions: true, sharing: true, sharingWrite: true }

beforeEach(() => {
  resetSharedProjectDb(h.db)
  h.db.policy = { enabled: true, maxLevel: 'write' }
  h.db.models.nodeFilterRun = { findFirst: () => null }
  h.db.models.nodeFilterExemption = {
    findMany: () => [],
    createManyAndReturn: (args: unknown) => (args as { data: unknown[] }).data,
  }
  h.agentCalls.length = 0
  h.audits.length = 0
  h.identity = null
  vi.stubGlobal('fetch', (_url: string, init?: RequestInit) => agentAnswer(init))
  setFlagsForTests(WRITE_IN_FORCE)
  clearSharingPolicyCacheForTests()
  clearCapabilityCachesForTests()
  clearInstanceRootCacheForTests()
  clearPrincipalCacheForTests()
  vi.spyOn(console, 'error').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

/** Every agent call went to the owner's graph of the shared project. */
function expectOwnersGraph() {
  expect(h.agentCalls.length).toBeGreaterThan(0)
  for (const sent of h.agentCalls) expect([sent.op, sent.user_id, sent.project_id]).toEqual([sent.op, OWNER, SHARED_PROJECT])
}

describe("an editor's triage writes name the editor, the graph keeps the owner (step 5.2)", () => {
  beforeEach(() => shareWith(h.db, COLLABORATOR, { access: 'write' }))

  test("a collaborator's mute and verdict name the collaborator, the graph keeps the owner", async () => {
    expect((await post('mute', COLLABORATOR)).status).toBe(200)
    expectOwnersGraph()
    expect(h.agentCalls[0]).toMatchObject({ op: 'mute', muted_by: COLLABORATOR })
    expect(h.audits).toEqual([expect.objectContaining({ action: 'muted_nodes.muted', actorId: COLLABORATOR, targetId: SHARED_PROJECT })])
    expect(h.audits[0]).not.toHaveProperty('onBehalfOfUserId')

    h.agentCalls.length = 0
    h.audits.length = 0
    expect((await post('verdict', COLLABORATOR)).status).toBe(200)
    expectOwnersGraph()
    // triage_verdict_by is the collaborator: the owner's detector learning ignores it.
    expect(h.agentCalls[0]).toMatchObject({ op: 'human_verdict', verdict_by: COLLABORATOR, status: 'confirmed' })
    expect(h.audits).toEqual([expect.objectContaining({ action: 'triage.verdict', actorId: COLLABORATOR })])
    expect((h.audits[0].after as Record<string, unknown>).projectId).toBe(SHARED_PROJECT)
  })

  test('a mute by graph id names the collaborator', async () => {
    expect((await post('muteByGraphId', COLLABORATOR)).status).toBe(200)
    expectOwnersGraph()
    expect(h.agentCalls[0]).toMatchObject({ op: 'mute', muted_by: COLLABORATOR })
    expect(h.audits[0]).toMatchObject({ action: 'muted_nodes.muted', actorId: COLLABORATOR })
  })

  test("an unmute's exemption and audit name the collaborator", async () => {
    let created: Array<Record<string, unknown>> = []
    h.db.models.nodeFilterExemption.createManyAndReturn = (args: unknown) => {
      created = (args as { data: Array<Record<string, unknown>> }).data
      return created
    }
    expect((await post('unmute', COLLABORATOR)).status).toBe(200)
    expectOwnersGraph()
    expect(created.length).toBe(1)
    expect(created[0]).toMatchObject({ projectId: SHARED_PROJECT, createdBy: COLLABORATOR })
    expect(h.audits).toEqual([expect.objectContaining({ action: 'muted_nodes.unmuted', actorId: COLLABORATOR, targetId: SHARED_PROJECT })])
  })

  test('a Multi mute apply names the collaborator as muted_by and as the effective user', async () => {
    expect((await post('multiMuteApply', COLLABORATOR)).status).toBe(200)
    expectOwnersGraph()
    expect(h.agentCalls[0]).toMatchObject({ op: 'mute_batch', muted_by: COLLABORATOR })
    expect(h.audits[0]).toMatchObject({ action: 'muted_nodes.multi_muted', actorId: COLLABORATOR })
    expect((h.audits[0].after as Record<string, unknown>).effectiveUserId).toBe(COLLABORATOR)
  })
})

describe('owner unchanged', () => {
  test('the owner mutes and decides as before: muted_by the owner, no verdict_by sent, the owner as actor', async () => {
    expect((await post('mute', OWNER)).status).toBe(200)
    expect(h.agentCalls[0]).toMatchObject({ op: 'mute', muted_by: OWNER, user_id: OWNER })
    h.agentCalls.length = 0
    expect((await post('verdict', OWNER)).status).toBe(200)
    expect(h.agentCalls[0]).not.toHaveProperty('verdict_by')
    expect(h.audits.map(a => a.actorId)).toEqual([OWNER, OWNER])
  })

  test('with write sharing not in force the same write share is refused (read), the owner is not', async () => {
    shareWith(h.db, COLLABORATOR, { access: 'write', manage: true })
    setFlagsForTests({ identity: true, permissions: true, sharing: true })
    expect((await post('mute', COLLABORATOR)).status).toBe(403)
    expect(h.agentCalls).toEqual([])
    expect((await post('mute', OWNER)).status).toBe(200)
  })
})

describe('levels of a write share on the triage and graph families (step 5.2)', () => {
  const allowed = async (permission: PermissionId, who = account(COLLABORATOR)) =>
    (await can(who, permission, { projectId: SHARED_PROJECT })).allowed

  test('editor allowed at W, toggle required above it, Manage-only refused at W, owner-only refused at M', async () => {
    shareWith(h.db, COLLABORATOR, { access: 'write' })
    for (const p of ['triage:verdict', 'triage:mute', 'node_filters:manage', 'remediation:write', 'graph:views'] as const) {
      expect([p, await allowed(p)]).toEqual([p, true])
    }
    // triage:run is W+A (Use AI agent), closed for every collaborator until step 5.6 opens it.
    expect(await allowed('triage:run')).toBe(false)
    expect(await allowed('graph:edit')).toBe(false)
    shareWith(h.db, COLLABORATOR, { access: 'write', manage: true })
    expect(await allowed('graph:edit')).toBe(true)
    expect(await allowed('project:delete')).toBe(false)
  })

  test('capability required: a collaborator whose set lacks the permission is refused at any level', async () => {
    shareWith(h.db, COLLABORATOR, { access: 'write', manage: true })
    const narrowed = account(COLLABORATOR, { permissionOverrides: [{ permission: 'triage:mute', effect: 'deny', expiresAt: null, reason: null }] })
    expect(await allowed('triage:mute', narrowed)).toBe(false)
    expect(await allowed('triage:verdict', narrowed)).toBe(true)
  })
})
