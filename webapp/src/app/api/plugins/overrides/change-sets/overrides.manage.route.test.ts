/**
 * A project's plugin proposals are decided at Manage (step 5.10, SH-35, PE-25): approving, rejecting,
 * deleting and resetting a project-scope version needs the owner or a co-owner whose share holds
 * Manage. A collaborator below it, who can see the project, is told the level (403); oversight,
 * break-glass and strangers get the 404 of a scope that is not theirs; reading a set (the review
 * window, the summary, the versions) follows the same rule with 404 below it. An admin acting as a
 * collaborator reaches the share at read (D-22) and decides nothing. A user scope stays its owner's.
 *
 * The policy answer is doubled (its own tests prove how a share reads); the routes, the level table,
 * the override store and the review model are real.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextResponse } from 'next/server'

const h = vi.hoisted(() => ({
  db: null as unknown as Record<string, unknown>,
  session: null as unknown,
  effective: '',
  actingAs: null as null | { id: string },
  managed: new Set<string>(),
  agent: null as unknown as (path: string) => Promise<Response>,
  audits: [] as Record<string, unknown>[],
}))
vi.mock('@/lib/authz/guards', async (orig) => ({
  ...(await orig<typeof import('@/lib/authz/guards')>()),
  requirePermission: async (_request: Request, permission: string) =>
    h.effective
      ? { permission, actingAs: h.actingAs, effective: { userId: h.effective } }
      : NextResponse.json({ error: 'Unauthorized' }, { status: 401 }),
}))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => h.db[k as string] }) }))
vi.mock('@/lib/session', async () => {
  const { accountWriteDouble } = await import('@/lib/plugins/__testing__/accountWriteDouble')
  return {
    getSession: async () => h.session,
    getEffectiveUser: async () => (h.effective ? { userId: h.effective } : null),
    requireAccountWrite: accountWriteDouble(() => h),
  }
})
vi.mock('@/lib/agentFetch', () => {
  class AgentUnreachableError extends Error {}
  return { AgentUnreachableError, agentFetch: (path: string) => h.agent(path) }
})
vi.mock('@/lib/audit', () => ({ writeAudit: async (e: Record<string, unknown>) => void h.audits.push(e) }))
vi.mock('@/lib/authz/projectAccess', async (orig) => {
  const actual = await orig<typeof import('@/lib/authz/projectAccess')>()
  return { ...actual, projectAccess: vi.fn(actual.projectAccess) }
})

import { createFakePrisma, type FakePrisma } from '@/lib/plugins/__testing__/fakePrisma'
import { FACTORY, agentHandler, freshAgent, projectScope, seedProposal, seedWorld, sha256, userScope } from '@/lib/plugins/__testing__/reviewHarness'
import { clearSkillPartsCache } from '@/lib/plugins/skillPartsRegistry'
import * as ov from '@/lib/plugins/overrides'
import { buildSummaryModel } from '@/lib/plugins/summaryModel'
import { projectAccess, type ProjectAccess, type ProjectAccessToggles } from '@/lib/authz/projectAccess'
import { POST as approve } from './[id]/approve/route'
import { POST as reject } from './[id]/reject/route'
import { GET as read, DELETE as remove } from './[id]/route'
import { POST as reset } from '../reset/route'
import { GET as summary } from '../summary/route'

const policy = vi.mocked(projectAccess)
const access = (level: ProjectAccess['level'], toggles: Partial<ProjectAccessToggles> = {}, via: ProjectAccess['via'] = 'share'): ProjectAccess =>
  Object.freeze({
    project: Object.freeze({ id: 'p-alice', userId: 'alice' }),
    level,
    toggles: Object.freeze({ rawData: level !== 'read', ...toggles }),
    via,
  }) as ProjectAccess
const coOwner = () => access('write', { manage: true })
const editor = () => access('write', { runScans: true, useAgent: true, exploit: true })

let db: FakePrisma

const post = (data: Record<string, unknown> = {}) =>
  new Request('http://localhost:3000/api/plugins/overrides/x', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', origin: 'http://localhost:3000', host: 'localhost:3000' },
    body: JSON.stringify(data),
  }) as never
const del = () =>
  new Request('http://localhost:3000/api/plugins/overrides/change-sets/x', {
    method: 'DELETE',
    headers: { origin: 'http://localhost:3000', host: 'localhost:3000' },
  }) as never
const params = (id: string) => ({ params: Promise.resolve({ id }) })
const json = async (res: Response) => ({ status: res.status, body: await res.json() })

beforeEach(() => {
  db = createFakePrisma()
  h.db = db as unknown as Record<string, unknown>
  seedWorld(db)
  h.agent = agentHandler(freshAgent())
  h.session = { userId: 'bob', role: 'standard' }
  h.effective = 'bob'
  h.actingAs = null
  h.managed = new Set()
  h.audits = []
  policy.mockReset()
  clearSkillPartsCache()
})
afterEach(() => vi.unstubAllEnvs())

describe('a co-owner with Manage decides the project scope', () => {
  beforeEach(() => policy.mockResolvedValue(coOwner()))

  test('approves: the next revision, audited with the co-owner as the actor', async () => {
    const cs = await seedProposal(projectScope('p-alice'), { workflow: 'W2' })
    expect(await json(await approve(post({}), params(cs)))).toEqual({ status: 200, body: { revision: 2 } })
    expect(h.audits.at(-1)).toMatchObject({ action: 'plugin.override.approve', actorId: 'bob' })
    expect(policy).toHaveBeenCalledWith({ userId: 'bob' }, 'p-alice')
  })

  test('rejects, reads the review, deletes and resets', async () => {
    const cs = await seedProposal(projectScope('p-alice'), { workflow: 'W2' })
    expect((await read(new Request('http://localhost:3000/x') as never, params(cs))).status).toBe(200)
    expect(await json(await reject(post({}), params(cs)))).toEqual({ status: 200, body: { rejected: true } })
    expect(await json(await remove(del(), params(cs)))).toEqual({ status: 200, body: { deleted: true } })
    const active = await seedProposal(projectScope('p-alice'), { workflow: 'W3' })
    await ov.approve(active, 'alice', { 'ssrf/workflow': sha256(FACTORY.workflow) })
    const r = await json(await reset(post({ point: 'skill.text', group: 'ssrf', scopeType: 'project', projectId: 'p-alice' })))
    expect(r.status).toBe(200)
  })

  test('the project summary is theirs to see', async () => {
    expect(await buildSummaryModel('bob', 'p-alice')).toMatchObject({ projectId: 'p-alice' })
  })
})

describe('override approval needs Manage: a collaborator below it', () => {
  beforeEach(() => policy.mockResolvedValue(editor()))

  test('approve, reject, delete and reset answer 403 naming Manage; nothing changes', async () => {
    const cs = await seedProposal(projectScope('p-alice'), { workflow: 'W2' })
    const refused = {
      status: 403,
      body: { error: expect.stringMatching(/needs Manage/), code: 'forbidden', permission: 'plugins:approve_overrides', level: 'M' },
    }
    expect(await json(await approve(post({}), params(cs)))).toEqual(refused)
    expect(await json(await reject(post({}), params(cs)))).toEqual(refused)
    expect(await json(await remove(del(), params(cs)))).toEqual(refused)
    expect(await json(await reset(post({ point: 'skill.text', group: 'ssrf', scopeType: 'project', projectId: 'p-alice' })))).toEqual(refused)
    expect((await ov.getChangeSet(cs))!.status).toBe('proposed')
    expect(h.audits).toEqual([])
  })

  test('the review window and the summary are a 404 / nothing', async () => {
    const cs = await seedProposal(projectScope('p-alice'), { workflow: 'W2' })
    expect((await read(new Request('http://localhost:3000/x') as never, params(cs))).status).toBe(404)
    expect(await buildSummaryModel('bob', 'p-alice')).toBeNull()
  })

  test("the summary route names plugins:use and level M, which the Agent Skills section reads as no plugin facts", async () => {
    const r = await json(await summary(new Request('http://localhost:3000/api/plugins/overrides/summary?projectId=p-alice') as never))
    expect(r).toEqual({ status: 403, body: { error: expect.stringMatching(/needs Manage/), code: 'forbidden', permission: 'plugins:use', level: 'M' } })
    policy.mockResolvedValue(coOwner())
    expect((await summary(new Request('http://localhost:3000/api/plugins/overrides/summary?projectId=p-alice') as never)).status).toBe(200)
    policy.mockResolvedValue(access('read', {}, 'oversight'))
    expect((await summary(new Request('http://localhost:3000/api/plugins/overrides/summary?projectId=p-alice') as never)).status).toBe(404)
  })
})

describe('anyone who is no collaborator', () => {
  test.each([
    ['oversight', access('read', {}, 'oversight')],
    ['break-glass', access('read', { rawData: true }, 'break_glass')],
    ['no access', null],
  ])('%s: the 404 of a scope that is not theirs', async (_what, reached) => {
    policy.mockResolvedValue(reached)
    const cs = await seedProposal(projectScope('p-alice'), { workflow: 'W2' })
    expect((await reject(post({}), params(cs))).status).toBe(404)
    expect((await approve(post({}), params(cs))).status).toBe(404)
  })
})

describe('an admin acting as a co-owner', () => {
  test('reaches the share at read (D-22) and decides nothing', async () => {
    h.session = { userId: 'admin-1', role: 'admin' }
    h.actingAs = { id: 'bob' }
    policy.mockResolvedValue(access('read'))
    const cs = await seedProposal(projectScope('p-alice'), { workflow: 'W2' })
    expect((await reject(post({}), params(cs))).status).toBe(403)
    expect(policy).toHaveBeenCalledWith({ userId: 'bob' }, 'p-alice', { actingAs: true })
  })
})

describe('a user scope stays its owner\'s', () => {
  test("a co-owner of the owner's project never decides the owner's user scope", async () => {
    policy.mockResolvedValue(coOwner())
    const cs = await seedProposal(userScope('alice'), { workflow: 'W2' })
    expect((await reject(post({ scopeOwnerId: 'alice' }), params(cs))).status).toBe(404)
    expect(policy).not.toHaveBeenCalled()
  })
})
