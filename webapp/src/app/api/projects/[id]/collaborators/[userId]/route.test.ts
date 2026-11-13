/**
 * Changing and revoking a share (step 4.4; SH-10, SH-11 immediate part, OQ-34):
 * PATCH and DELETE /api/projects/[id]/collaborators/[userId].
 *
 * Real guard, can(), projectAccess(), sharing policy reader, capabilities, act-as refusal, audit
 * writer and socket close (closeAgentSockets); the session, Prisma (an in-memory store with
 * rollback), the agent's HTTP call (agentFetch) and the clock are doubles. "The next GET" is the
 * project's stale-access poll, GET /api/projects/[id]/my-access.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach, type Mock } from 'vitest'
import { NextRequest } from 'next/server'
import { createShareDb, shareAccount, type ShareAccount, type ShareDb } from '@/lib/authz/__testing__/shareDb'

const h = vi.hoisted(() => ({
  db: null as unknown as { client: Record<string | symbol, unknown> },
  identity: null as null | { session: { userId: string; role: string }; principal: unknown; actingAs: unknown },
  agentFetch: null as unknown as Mock<(...args: unknown[]) => Promise<Response>>,
  stopTriage: null as unknown as Mock<(...args: unknown[]) => Promise<{ stopped: boolean }>>,
}))
vi.mock('@/lib/prisma', () => {
  const client = new Proxy({}, { get: (_t, k) => h.db.client[k] })
  return { default: client, prisma: client }
})
// Whole-module double: importing the real session module first would bind the guards to it.
vi.mock('@/lib/session', () => ({
  getAuthzIdentity: async () => h.identity,
  getSession: async () => h.identity?.session ?? null,
  getEffectiveUser: async () => (h.identity ? { userId: ((h.identity.actingAs ?? h.identity.principal) as { id: string }).id } : null),
  mayActAs: async () => true,
  actAsInForce: async () => (h.identity?.actingAs ? { target: h.identity.actingAs, expiresAt: null } : null),
}))
vi.mock('@/lib/agentFetch', async (orig) => ({
  ...(await orig<typeof import('@/lib/agentFetch')>()),
  agentFetch: (...args: unknown[]) => h.agentFetch(...args),
}))
// The agent's triage stop (step 5.9 stops a live triage run the person started).
vi.mock('@/lib/triage/actions', () => ({ stopRun: (...args: unknown[]) => h.stopTriage(...args) }))

import { PATCH, DELETE } from './route'
import { GET as myAccess } from '../../my-access/route'
import { AgentUnreachableError } from '@/lib/agentFetch'
import { setFlagsForTests } from '@/lib/authz/flags'
import { setNowForTests } from '@/lib/authz/clock'
import { clearSharingPolicyCacheForTests } from '@/lib/authz/sharingPolicy'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import { clearPrincipalCacheForTests } from '@/lib/authz/principal'

const T0 = new Date('2026-11-13T12:00:00Z')
let db: ShareDb
const accounts: Record<string, ShareAccount> = {}

function add(account: ShareAccount) {
  accounts[account.id] = account
  db.addUser(account)
}

function signIn(id: string, actingAsId?: string) {
  const principal = accounts[id]
  h.identity = { session: { userId: id, role: principal.role }, principal, actingAs: actingAsId ? accounts[actingAsId] : null }
}

const ctx = (userId: string, id = 'P1') => ({ params: Promise.resolve({ id, userId }) })
const url = (userId: string, id = 'P1') => `http://localhost/api/projects/${id}/collaborators/${userId}`
const change = (userId: string, body: unknown, { id = 'P1', headers = {} as Record<string, string> } = {}) =>
  PATCH(new NextRequest(url(userId, id), { method: 'PATCH', headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body) }), ctx(userId, id))
const revoke = (userId: string, { id = 'P1', headers = {} as Record<string, string> } = {}) =>
  DELETE(new NextRequest(url(userId, id), { method: 'DELETE', headers }), ctx(userId, id))
const pollAs = async (id: string) => {
  signIn(id)
  return myAccess(new NextRequest('http://localhost/api/projects/P1/my-access'), { params: Promise.resolve({ id: 'P1' }) })
}

const agentClosed = () => new Response(JSON.stringify({ closed: 1, stopped_runs: 0, stopped: 1 }), { status: 200 })
const KINDS = ['agent', 'kali-terminal', 'cypherfix-triage', 'cypherfix-codefix']
const agentCalls = () => h.agentFetch.mock.calls.map(([path, init]) => [path, JSON.parse((init as { body: string }).body)])

beforeEach(() => {
  setNowForTests(() => T0)
  db = createShareDb(() => T0)
  h.db = db as never
  h.agentFetch = vi.fn(async () => agentClosed())
  h.stopTriage = vi.fn(async () => ({ stopped: true }))
  for (const k of Object.keys(accounts)) delete accounts[k]
  add(shareAccount('alice', { name: 'Alice Owner' }))
  add(shareAccount('bob'))
  add(shareAccount('carol'))
  add(shareAccount('admin-1', { role: 'admin' }))
  add(shareAccount('analyst', { permissionSets: ['builtin:read-only-analyst'] }))
  db.addProject('P1', 'alice')
  db.addProject('P-analyst', 'analyst')
  db.addShare({ projectId: 'P1', userId: 'bob', note: 'first note', grantedById: 'alice' })
  setFlagsForTests({ identity: true, permissions: true, sharing: true })
  clearSharingPolicyCacheForTests()
  clearCapabilityCachesForTests()
  clearInstanceRootCacheForTests()
  clearPrincipalCacheForTests()
  vi.spyOn(console, 'info').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
  h.identity = null
  vi.restoreAllMocks()
})

describe('PATCH: change a share (step 4.4, SH-10)', () => {
  test('update: Raw data, expiry and note change; audited with before and after (the note only as changed)', async () => {
    signIn('alice')
    const res = await change('bob', { rawData: true, expiresAt: '2026-12-31T00:00:00Z', note: 'second note' })
    expect(res.status).toBe(200)
    expect((await res.json()).collaborator).toMatchObject({ user: { id: 'bob' }, rawData: true, expiresAt: '2026-12-31T00:00:00.000Z', note: 'second note' })
    expect(db.share('P1', 'bob')).toMatchObject({ rawData: true, expiresAt: new Date('2026-12-31T00:00:00Z'), note: 'second note' })
    expect(db.audit()).toEqual([expect.objectContaining({
      action: 'project.share.update', actorId: 'alice', projectId: 'P1', targetId: 'bob', permission: 'project:share',
      before: expect.objectContaining({ rawData: false, expiresAt: null }),
      after: expect.objectContaining({ rawData: true, expiresAt: '2026-12-31T00:00:00.000Z', noteChanged: true }),
    })])
    expect(JSON.stringify(db.audit())).not.toContain('second note')
    // A wider share stops nothing (step 5.9).
    expect(h.agentFetch).not.toHaveBeenCalled()
  })

  test("narrowing a share stops the person's live work on the project (step 5.9, SH-12)", async () => {
    db.addShare({ projectId: 'P1', userId: 'carol', rawData: true })
    signIn('alice')
    expect((await change('carol', { rawData: false })).status).toBe(200)
    expect(db.share('P1', 'carol')?.rawData).toBe(false)
    expect(agentCalls()).toEqual([
      ['/agent-sessions/stop-for', { user_id: 'carol', project_ids: ['P1'] }],
      ['/ws/close', { user_id: 'carol', project_id: 'P1', kinds: KINDS, scope: 'access' }],
    ])
  })

  test('a narrowing whose audit row fails changes nothing and stops nothing', async () => {
    db.addShare({ projectId: 'P1', userId: 'carol', rawData: true })
    db.failAudit('project.share.update')
    vi.spyOn(console, 'error').mockImplementation(() => {})
    signIn('alice')
    expect((await change('carol', { rawData: false })).status).toBe(500)
    expect(db.share('P1', 'carol')?.rawData).toBe(true)
    expect(h.agentFetch).not.toHaveBeenCalled()
  })

  test('the answer names the person\'s account type and who granted the share (step 4.12, ID-31)', async () => {
    signIn('alice')
    const { collaborator } = await (await change('bob', { rawData: true })).json()
    expect(collaborator.user).toMatchObject({ id: 'bob', accountType: 'member' })
    expect(collaborator.grantedBy).toEqual({ id: 'alice', name: 'Alice Owner', email: 'alice@example.test', accountType: 'member' })
  })

  test('the expiry removed with null; the access kept at read', async () => {
    db.addShare({ projectId: 'P1', userId: 'carol', expiresAt: new Date('2026-12-01T00:00:00Z') })
    signIn('alice')
    expect((await change('carol', { access: 'read', expiresAt: null })).status).toBe(200)
    expect(db.share('P1', 'carol')?.expiresAt).toBeNull()
  })

  test('a change that changes nothing writes no audit row', async () => {
    signIn('alice')
    expect((await change('bob', { rawData: false, note: 'first note' })).status).toBe(200)
    expect(db.audit()).toEqual([])
  })

  test('to write: 409 write_sharing_off, the share unchanged', async () => {
    signIn('alice')
    const res = await change('bob', { access: 'write' })
    expect(res.status).toBe(409)
    expect(await res.json()).toMatchObject({ code: 'write_sharing_off' })
    expect(db.share('P1', 'bob')?.access).toBe('read')
  })

  test('a run toggle without the owner\'s consent (step 5.6): 409 owner_consent_required with write sharing in force, the share unchanged', async () => {
    setFlagsForTests({ identity: true, permissions: true, sharing: true, sharingWrite: true })
    db.setPolicy({ enabled: true, maxLevel: 'write' })
    signIn('alice')
    const res = await change('bob', { useAgent: true })
    expect(res.status).toBe(409)
    expect(await res.json()).toMatchObject({ code: 'owner_consent_required', toggles: ['useAgent'] })
    expect(db.share('P1', 'bob')?.access).toBe('read')
    expect(db.audit()).toEqual([])
  })

  test.each([
    ['an empty body', {}],
    ['rawData not a boolean', { rawData: 1 }],
    ['an expiry in the past', { expiresAt: '2026-01-01T00:00:00Z' }],
  ])('%s: 400', async (_what, body) => {
    signIn('alice')
    expect((await change('bob', body)).status).toBe(400)
    expect(db.audit()).toEqual([])
  })

  test('a person who holds no share: 404 no_such_share', async () => {
    signIn('alice')
    const res = await change('carol', { rawData: true })
    expect(res.status).toBe(404)
    expect(await res.json()).toMatchObject({ code: 'no_such_share' })
  })

  test('without project:share 403; the collaborator 403; a stranger 404', async () => {
    db.addShare({ projectId: 'P-analyst', userId: 'bob' })
    signIn('analyst')
    expect((await change('bob', { rawData: true }, { id: 'P-analyst' })).status).toBe(403)
    signIn('bob')
    expect((await change('bob', { rawData: true })).status).toBe(403)
    signIn('carol')
    expect((await change('bob', { rawData: true })).status).toBe(404)
    expect(db.share('P1', 'bob')?.rawData).toBe(false)
  })

  test('audit failure: no change', async () => {
    db.failAudit('project.share.update')
    vi.spyOn(console, 'error').mockImplementation(() => {})
    signIn('alice')
    expect((await change('bob', { rawData: true })).status).toBe(500)
    expect(db.share('P1', 'bob')?.rawData).toBe(false)
  })

  test('refused while acting as the owner', async () => {
    signIn('admin-1', 'alice')
    const res = await change('bob', { rawData: true })
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'not_while_acting_as', action: 'change_shares' })
    expect(db.share('P1', 'bob')?.rawData).toBe(false)
  })

  test('a page of another site: 403 cross_origin', async () => {
    signIn('alice')
    expect((await change('bob', { rawData: true }, { headers: { Origin: 'https://evil.example' } })).status).toBe(403)
    expect(db.share('P1', 'bob')?.rawData).toBe(false)
  })
})

describe('DELETE: revoke (step 4.4, SH-11)', () => {
  test('revoke -> the next GET of that person is 404; audited with the share as it was', async () => {
    expect((await pollAs('bob')).status).toBe(200)
    signIn('alice')
    const res = await revoke('bob')
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ revoked: { projectId: 'P1', userId: 'bob' }, socketsClosed: true })
    expect(db.share('P1', 'bob')).toBeUndefined()
    expect(db.audit()).toEqual([expect.objectContaining({
      action: 'project.share.revoke', actorId: 'alice', projectId: 'P1', targetId: 'bob', permission: 'project:share',
      before: expect.objectContaining({ access: 'read', rawData: false, grantedById: 'alice' }),
    })])
    expect((await pollAs('bob')).status).toBe(404)
  })

  test("revoke stops the person's runs on that project and closes every socket kind of theirs there, scope access (step 5.9)", async () => {
    signIn('alice')
    await revoke('bob')
    expect(agentCalls()).toEqual([
      ['/agent-sessions/stop-for', { user_id: 'bob', project_ids: ['P1'] }],
      ['/ws/close', { user_id: 'bob', project_id: 'P1', kinds: KINDS, scope: 'access' }],
    ])
  })

  test("revoke cancels the person's queued scans, pauses their schedules and stops their triage run; a running scan and the owner's work untouched (step 5.9)", async () => {
    db.addJob({ id: 'j-bob', projectId: 'P1', userId: 'bob' })
    db.addJob({ id: 'j-bob-running', projectId: 'P1', userId: 'bob', status: 'running' })
    db.addJob({ id: 'j-alice', projectId: 'P1', userId: 'alice' })
    db.addSchedule({ id: 's-bob', projectId: 'P1', userId: 'bob' })
    db.addSchedule({ id: 's-alice', projectId: 'P1', userId: 'alice' })
    db.addTriageRun({ id: 'run-bob', projectId: 'P1', actorUserId: 'bob' })
    signIn('alice')
    expect((await revoke('bob')).status).toBe(200)
    expect(db.job('j-bob')).toMatchObject({ status: 'canceled', blockedCode: 'actor_no_access' })
    expect(db.job('j-bob-running')?.status).toBe('running')
    expect(db.job('j-alice')?.status).toBe('queued')
    expect(db.schedule('s-bob')).toMatchObject({ enabled: false, pausedReason: 'actor_no_access' })
    expect(db.schedule('s-alice')).toMatchObject({ enabled: true, pausedReason: null })
    expect(h.stopTriage).toHaveBeenCalledWith({ userId: 'alice', projectId: 'P1' }, 'app')
    expect(db.audit().map((r) => [r.action, r.targetId])).toEqual([
      ['project.share.revoke', 'bob'], ['job_queue.cancelled', 'j-bob'], ['scan_schedule.paused', 's-bob'],
    ])
  })

  test('the agent unreachable: the revoke still succeeds and logs [rbac] socket-close failed', async () => {
    h.agentFetch = vi.fn(async (): Promise<Response> => { throw new AgentUnreachableError(new Error('ECONNREFUSED')) })
    const error = vi.spyOn(console, 'error').mockImplementation(() => {})
    signIn('alice')
    const res = await revoke('bob')
    expect(res.status).toBe(200)
    expect(await res.json()).toMatchObject({ socketsClosed: false })
    expect(db.share('P1', 'bob')).toBeUndefined()
    expect(error.mock.calls.map(c => String(c[0])).some(l => l.startsWith('[rbac] socket-close failed user=bob') && l.includes('project=P1') && l.endsWith('agent_unreachable'))).toBe(true)
    expect(error.mock.calls.map(c => String(c[0]))).toContain('[rbac] revocation step failed step=close_sockets reason=share_revoked user=bob project=P1: agent_unreachable')
  })

  test('double revoke: the second is 404 no_such_share, one audit row, one stop and one close', async () => {
    signIn('alice')
    expect((await revoke('bob')).status).toBe(200)
    const again = await revoke('bob')
    expect(again.status).toBe(404)
    expect(await again.json()).toMatchObject({ code: 'no_such_share' })
    expect(db.audit()).toHaveLength(1)
    expect(h.agentFetch.mock.calls.map((c) => c[0])).toEqual(['/agent-sessions/stop-for', '/ws/close'])
  })

  test('two revokes at once: one 200, one 404, one audit row', async () => {
    signIn('alice')
    const [a, b] = await Promise.all([revoke('bob'), revoke('bob')])
    expect([a.status, b.status].sort()).toEqual([200, 404])
    expect(db.audit().filter(r => r.action === 'project.share.revoke')).toHaveLength(1)
  })

  test('an expired share is revoked the same way', async () => {
    db.addShare({ projectId: 'P1', userId: 'carol', expiresAt: new Date(T0.getTime() - 1) })
    signIn('alice')
    expect((await revoke('carol')).status).toBe(200)
    expect(db.share('P1', 'carol')).toBeUndefined()
  })

  test('audit failure: no change, and no socket is closed', async () => {
    db.failAudit('project.share.revoke')
    vi.spyOn(console, 'error').mockImplementation(() => {})
    signIn('alice')
    expect((await revoke('bob')).status).toBe(500)
    expect(db.share('P1', 'bob')).toBeDefined()
    expect(h.agentFetch).not.toHaveBeenCalled()
  })

  test('refused while acting as the owner: 403, the share kept', async () => {
    signIn('admin-1', 'alice')
    const res = await revoke('bob')
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'not_while_acting_as' })
    expect(db.share('P1', 'bob')).toBeDefined()
    expect(h.agentFetch).not.toHaveBeenCalled()
  })

  test('without project:share 403; the collaborator 403 (they leave instead); a stranger 404', async () => {
    db.addShare({ projectId: 'P-analyst', userId: 'bob' })
    signIn('analyst')
    expect((await revoke('bob', { id: 'P-analyst' })).status).toBe(403)
    signIn('bob')
    expect((await revoke('bob')).status).toBe(403)
    signIn('carol')
    expect((await revoke('bob')).status).toBe(404)
    expect(db.share('P1', 'bob')).toBeDefined()
  })

  test('a page of another site: 403 cross_origin, the share kept', async () => {
    signIn('alice')
    expect((await revoke('bob', { headers: { Origin: 'https://evil.example' } })).status).toBe(403)
    expect(db.share('P1', 'bob')).toBeDefined()
  })
})

describe('switch off -> 404 (DV-30)', () => {
  test.each([
    ['every switch off', {}, { enabled: true }],
    ['identity + permissions on, sharing off', { identity: true, permissions: true }, { enabled: true }],
    ['the switch on, the policy disabled', { identity: true, permissions: true, sharing: true }, {}],
  ])('%s: PATCH and DELETE answer 404, the share untouched, no agent call', async (_what, flags, stored) => {
    setFlagsForTests(flags)
    db.setPolicy(stored)
    signIn('alice')
    expect((await change('bob', { rawData: true })).status).toBe(404)
    expect((await revoke('bob')).status).toBe(404)
    expect(db.share('P1', 'bob')).toMatchObject({ rawData: false })
    expect(db.audit()).toEqual([])
    expect(h.agentFetch).not.toHaveBeenCalled()
  })
})
