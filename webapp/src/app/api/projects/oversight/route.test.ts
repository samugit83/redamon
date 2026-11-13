/**
 * GET /api/projects/oversight (step 4.14, SH-47): the projects page's "All projects (oversight)".
 *
 * Real guard, can(), capabilities, policy reader and list reader; the session and Prisma (the share
 * routes' in-memory store) are doubles.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'
import { createShareDb, shareAccount, type ShareAccount, type ShareDb } from '@/lib/authz/__testing__/shareDb'

const h = vi.hoisted(() => ({
  client: null as unknown as Record<string | symbol, unknown>,
  identity: null as null | { session: { userId: string; role: string }; principal: unknown; actingAs: unknown },
}))
vi.mock('@/lib/prisma', () => {
  const client = new Proxy({}, { get: (_t, k) => h.client[k] })
  return { default: client, prisma: client }
})
vi.mock('@/lib/session', () => ({
  getAuthzIdentity: async () => h.identity,
  getSession: async () => h.identity?.session ?? null,
  mayActAs: async () => true,
  actAsInForce: async () => (h.identity?.actingAs ? { target: h.identity.actingAs, expiresAt: null } : null),
}))

import { GET } from './route'
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

const list = () => GET(new NextRequest('http://localhost/api/projects/oversight'))

beforeEach(() => {
  setNowForTests(() => T0)
  db = createShareDb(() => T0)
  h.client = db.client as Record<string | symbol, unknown>
  for (const k of Object.keys(accounts)) delete accounts[k]
  add(shareAccount('alice', { email: 'alice@example.test', name: 'Alice Owner' }))
  add(shareAccount('bob', { email: 'bob@example.test', name: 'Bob Reader' }))
  add(shareAccount('admin-1', { role: 'admin', email: 'admin1@example.test' }))
  add(shareAccount('auditor', { role: 'admin', adminProfileId: 'builtin:security-auditor' }))
  add(shareAccount('usermgr', { role: 'admin', adminProfileId: 'builtin:user-manager' }))
  db.addProject('P1', 'alice')
  db.addProject('P2', 'bob')
  db.addProject('P-admin', 'admin-1')
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

describe('GET /api/projects/oversight (step 4.14)', () => {
  test('a holder of projects:oversee lists every project with its owner and the access it has to each', async () => {
    db.addShare({ projectId: 'P2', userId: 'admin-1', rawData: true })
    signIn('admin-1')
    const res = await list()
    expect(res.status).toBe(200)
    expect(res.headers.get('Cache-Control')).toBe('no-store')
    const rows = await res.json() as Array<{ id: string; user: { email: string }; myAccess: { via: string; level: string; toggles: { rawData: boolean } } }>
    expect(Object.fromEntries(rows.map((r) => [r.id, [r.myAccess.via, r.myAccess.level, r.myAccess.toggles.rawData, r.user.email]]))).toEqual({
      P1: ['oversight', 'read', false, 'alice@example.test'],
      P2: ['share', 'read', true, 'bob@example.test'],
      'P-admin': ['owner', 'owner', true, 'admin1@example.test'],
    })
  })

  test('the Security auditor holds it too; listing writes no audit row (opening a project is the read)', async () => {
    signIn('auditor')
    expect((await list()).status).toBe(200)
    expect(db.audit()).toEqual([])
  })

  test('a member, and an admin whose profile lacks it, are refused naming it', async () => {
    for (const who of ['alice', 'usermgr']) {
      signIn(who)
      const res = await list()
      expect([who, res.status]).toEqual([who, 403])
      expect(await res.json()).toMatchObject({ code: 'forbidden', permission: 'projects:oversee' })
    }
  })

  test('never while acting as someone: 403 not_while_acting_as, with its act_as.refused row', async () => {
    signIn('admin-1', 'alice')
    const res = await list()
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'not_while_acting_as', action: 'oversight' })
    expect(db.audit()).toEqual([expect.objectContaining({ action: 'act_as.refused', onBehalfOfUserId: 'alice', after: { action: 'oversight' } })])
  })

  test('no session: 401', async () => {
    h.identity = null
    expect((await list()).status).toBe(401)
  })

  test.each([
    ['every switch off', {}, { enabled: true }],
    ['identity + permissions on, the sharing switch off', { identity: true, permissions: true }, { enabled: true }],
    ['the switch on, the policy disabled', { identity: true, permissions: true, sharing: true }, {}],
  ])('%s: the route does not exist (404), no project read', async (_what, flags, policy) => {
    setFlagsForTests(flags)
    db.setPolicy(policy)
    const projects = vi.spyOn(db.client.project, 'findMany')
    signIn('admin-1')
    expect((await list()).status).toBe(404)
    expect(projects).not.toHaveBeenCalled()
  })
})
