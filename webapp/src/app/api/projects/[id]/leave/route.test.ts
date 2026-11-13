/**
 * Leaving a share (step 4.4, SH-13): POST /api/projects/[id]/leave, the collaborator removing
 * their own share. Real act-as refusal, audit writer, socket close and projectAccess (through the
 * stale-access poll); the session, Prisma (an in-memory store with rollback), the agent's HTTP call
 * and the clock are doubles.
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

import { POST } from './route'
import { GET as myAccess } from '../my-access/route'
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

const leave = ({ id = 'P1', headers = {} as Record<string, string>, body = '{}' } = {}) =>
  POST(new NextRequest(`http://localhost/api/projects/${id}/leave`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body,
  }), { params: Promise.resolve({ id }) })
const poll = () => myAccess(new NextRequest('http://localhost/api/projects/P1/my-access'), { params: Promise.resolve({ id: 'P1' }) })

beforeEach(() => {
  setNowForTests(() => T0)
  db = createShareDb(() => T0)
  h.db = db as never
  h.agentFetch = vi.fn(async () => new Response(JSON.stringify({ closed: 0, stopped_runs: 0 }), { status: 200 }))
  for (const k of Object.keys(accounts)) delete accounts[k]
  add(shareAccount('alice'))
  add(shareAccount('bob'))
  add(shareAccount('carol'))
  add(shareAccount('admin-1', { role: 'admin' }))
  db.addProject('P1', 'alice')
  db.addShare({ projectId: 'P1', userId: 'bob', rawData: true })
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

describe('POST .../leave (step 4.4, SH-13)', () => {
  test('leave: the share goes, audited as the collaborator\'s own act; sockets closed; the next GET is 404', async () => {
    signIn('bob')
    expect((await poll()).status).toBe(200)
    const res = await leave()
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ left: { projectId: 'P1' }, socketsClosed: true })
    expect(db.share('P1', 'bob')).toBeUndefined()
    expect(db.audit()).toEqual([expect.objectContaining({
      action: 'project.share.leave', actorId: 'bob', projectId: 'P1', targetType: 'user', targetId: 'bob',
      before: expect.objectContaining({ access: 'read', rawData: true }),
    })])
    const [path, init] = h.agentFetch.mock.calls[0] as [string, { body: string }]
    expect(path).toBe('/ws/close')
    expect(JSON.parse(init.body)).toMatchObject({ user_id: 'bob', project_id: 'P1', scope: 'access' })
    expect((await poll()).status).toBe(404)
  })

  test('leave twice: the second is 404 no_such_share', async () => {
    signIn('bob')
    expect((await leave()).status).toBe(200)
    const again = await leave()
    expect(again.status).toBe(404)
    expect(await again.json()).toMatchObject({ code: 'no_such_share' })
    expect(db.audit()).toHaveLength(1)
  })

  test('the owner, or someone the project is not shared with: 404, nothing written', async () => {
    for (const id of ['alice', 'carol']) {
      signIn(id)
      expect((await leave()).status).toBe(404)
    }
    expect(db.share('P1', 'bob')).toBeDefined()
    expect(db.audit()).toEqual([])
  })

  test('the agent unreachable: the leave stands and logs [rbac] socket-close failed', async () => {
    h.agentFetch = vi.fn(async (): Promise<Response> => { throw new AgentUnreachableError(new Error('ECONNREFUSED')) })
    const error = vi.spyOn(console, 'error').mockImplementation(() => {})
    signIn('bob')
    const res = await leave()
    expect(res.status).toBe(200)
    expect(await res.json()).toMatchObject({ socketsClosed: false })
    expect(db.share('P1', 'bob')).toBeUndefined()
    expect(error.mock.calls.some(c => String(c[0]).startsWith('[rbac] socket-close failed user=bob'))).toBe(true)
  })

  test('audit failure: the share is kept', async () => {
    db.failAudit('project.share.leave')
    vi.spyOn(console, 'error').mockImplementation(() => {})
    signIn('bob')
    expect((await leave()).status).toBe(500)
    expect(db.share('P1', 'bob')).toBeDefined()
    expect(h.agentFetch).not.toHaveBeenCalled()
  })

  test('refused while acting as the collaborator: 403 not_while_acting_as', async () => {
    signIn('admin-1', 'bob')
    const res = await leave()
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'not_while_acting_as', action: 'change_shares' })
    expect(db.share('P1', 'bob')).toBeDefined()
  })

  test('a page of another site: 403; a body that is not JSON: 415', async () => {
    signIn('bob')
    expect((await leave({ headers: { Origin: 'https://evil.example' } })).status).toBe(403)
    expect((await leave({ headers: { 'Content-Type': 'text/plain' } })).status).toBe(415)
    expect(db.share('P1', 'bob')).toBeDefined()
  })

  test('signed out: 401', async () => {
    h.identity = null
    expect((await leave()).status).toBe(401)
  })

  test.each([
    ['every switch off', {}, { enabled: true }],
    ['identity + permissions on, sharing off', { identity: true, permissions: true }, { enabled: true }],
    ['the switch on, the policy disabled', { identity: true, permissions: true, sharing: true }, {}],
  ])('%s: 404, the share untouched', async (_what, flags, stored) => {
    setFlagsForTests(flags)
    db.setPolicy(stored)
    signIn('bob')
    expect((await leave()).status).toBe(404)
    expect(db.share('P1', 'bob')).toBeDefined()
    expect(db.audit()).toEqual([])
  })
})
