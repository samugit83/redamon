/**
 * Listing and granting shares (step 4.4; SH-04, SH-06, SH-09, SH-19, SH-20, SH-21, DV-05):
 * GET and POST /api/projects/[id]/collaborators.
 *
 * Real guard, can(), projectAccess(), sharing policy reader, capabilities, act-as refusal, audit
 * writer and lookup ceiling; the session, Prisma (an in-memory store with rollback) and the clock
 * are doubles.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { createHash } from 'node:crypto'
import { NextRequest } from 'next/server'
import { createShareDb, shareAccount, type ShareAccount, type ShareDb } from '@/lib/authz/__testing__/shareDb'

const h = vi.hoisted(() => ({
  db: null as unknown as { client: Record<string | symbol, unknown> },
  identity: null as null | { session: { userId: string; role: string }; principal: unknown; actingAs: unknown },
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

import { GET, POST } from './route'
import { setFlagsForTests } from '@/lib/authz/flags'
import { setNowForTests } from '@/lib/authz/clock'
import { clearSharingPolicyCacheForTests } from '@/lib/authz/sharingPolicy'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import { clearPrincipalCacheForTests } from '@/lib/authz/principal'
import { resetInviteLimitsForTests, SHARE_LOOKUPS_PER_MINUTE } from '@/lib/authz/inviteLimits'

const T0 = new Date('2026-11-13T12:00:00Z')
let clock = T0
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

const ctx = (id = 'P1') => ({ params: Promise.resolve({ id }) })
const list = (id = 'P1') => GET(new NextRequest(`http://localhost/api/projects/${id}/collaborators`), ctx(id))
const grant = (body: unknown, { id = 'P1', headers = {} as Record<string, string> } = {}) =>
  POST(new NextRequest(`http://localhost/api/projects/${id}/collaborators`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  }), ctx(id))

const sha = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex')

beforeEach(() => {
  clock = T0
  setNowForTests(() => clock)
  db = createShareDb(() => clock)
  h.db = db as never
  for (const k of Object.keys(accounts)) delete accounts[k]
  add(shareAccount('alice', { email: 'alice@example.test', name: 'Alice Owner' }))
  add(shareAccount('bob', { email: 'bob@example.test', name: 'Bob Reader' }))
  add(shareAccount('carol'))
  add(shareAccount('dave', { status: 'disabled' }))
  add(shareAccount('erin', { status: 'invited' }))
  add(shareAccount('admin-1', { role: 'admin' }))
  add(shareAccount('analyst', { permissionSets: ['builtin:read-only-analyst'] }))
  db.addProject('P1', 'alice')
  db.addProject('P-analyst', 'analyst')
  setFlagsForTests({ identity: true, permissions: true, sharing: true })
  clearSharingPolicyCacheForTests()
  clearCapabilityCachesForTests()
  clearInstanceRootCacheForTests()
  clearPrincipalCacheForTests()
  resetInviteLimitsForTests()
  vi.spyOn(console, 'info').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
  h.identity = null
  vi.restoreAllMocks()
})

describe('GET: who holds a share (step 4.4)', () => {
  test('the owner lists the shares with each collaborator\'s name and email, expired ones marked', async () => {
    db.addShare({ projectId: 'P1', userId: 'bob', rawData: true, note: 'until the engagement ends' })
    db.addShare({ projectId: 'P1', userId: 'carol', expiresAt: new Date(T0.getTime() - 1000) })
    signIn('alice')
    const res = await list()
    expect(res.status).toBe(200)
    const { collaborators } = await res.json()
    expect(collaborators).toEqual([
      expect.objectContaining({ user: { id: 'bob', name: 'Bob Reader', email: 'bob@example.test', status: 'active', accountType: 'member' }, access: 'read', rawData: true, expired: false, note: 'until the engagement ends', expiresAt: null }),
      expect.objectContaining({ user: expect.objectContaining({ id: 'carol' }), expired: true, expiresAt: new Date(T0.getTime() - 1000).toISOString() }),
    ])
  })

  test('each share names the person\'s account type and who granted it (step 4.12, ID-31)', async () => {
    add(shareAccount('root', { role: 'admin', name: 'Rita Root' }))
    db.setRoot('root', new Date('2026-10-01T00:00:00Z'))
    db.addShare({ projectId: 'P1', userId: 'bob', grantedById: 'alice' })
    db.addShare({ projectId: 'P1', userId: 'admin-1', grantedById: 'alice' })
    db.addShare({ projectId: 'P1', userId: 'root', grantedById: 'gone-account' })
    signIn('alice')
    const { collaborators } = await (await list()).json()
    expect(collaborators.map((c: { user: { id: string; accountType: string } }) => [c.user.id, c.user.accountType])).toEqual([
      ['bob', 'member'], ['admin-1', 'admin'], ['root', 'root'],
    ])
    expect(collaborators[0].grantedBy).toEqual({ id: 'alice', name: 'Alice Owner', email: 'alice@example.test', accountType: 'member' })
    // The account that granted it is gone: said as null, never guessed.
    expect(collaborators[2].grantedBy).toBeNull()
    expect(collaborators[2].grantedById).toBe('gone-account')
  })

  test('oversight read: an admin with projects:oversee lists them', async () => {
    db.addShare({ projectId: 'P1', userId: 'bob' })
    signIn('admin-1')
    const res = await list()
    expect(res.status).toBe(200)
    expect((await res.json()).collaborators).toHaveLength(1)
  })

  test('oversight read, with Root\'s policy hiding shares from admins: 403', async () => {
    db.setPolicy({ enabled: true, adminsSeeAllShares: false })
    signIn('admin-1')
    const res = await list()
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'forbidden', permission: 'project:share' })
  })

  test('Root\'s break-glass lists them whatever the policy says of admins', async () => {
    db.setPolicy({ enabled: true, adminsSeeAllShares: false })
    add(shareAccount('root', { role: 'admin' }))
    db.addBreakGlass('P1', 'root', new Date(T0.getTime() + 3_600_000))
    db.setRoot('root', new Date('2026-10-01T00:00:00Z'))
    signIn('root')
    expect((await list()).status).toBe(200)
  })

  test('a read collaborator sees the project but not who else holds it: 403', async () => {
    db.addShare({ projectId: 'P1', userId: 'bob' })
    signIn('bob')
    const res = await list()
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'forbidden', permission: 'project:share' })
  })

  test('someone the project is not shared with: 404', async () => {
    signIn('carol')
    expect((await list()).status).toBe(404)
  })

  test('an owner without project:share: 403', async () => {
    signIn('analyst')
    expect((await list('P-analyst')).status).toBe(403)
  })

  test('acting as the owner reads the list (a read changes nothing)', async () => {
    db.addShare({ projectId: 'P1', userId: 'bob' })
    signIn('admin-1', 'alice')
    expect((await list()).status).toBe(200)
  })

  test('signed out: 401', async () => {
    h.identity = null
    expect((await list()).status).toBe(401)
  })

  test('a failed share read answers a coded 500, never a list', async () => {
    db.failRead()
    vi.spyOn(console, 'error').mockImplementation(() => {})
    signIn('alice')
    const res = await list()
    expect(res.status).toBe(500)
    expect(await res.json()).toMatchObject({ error: "Could not list the project's shares", code: 'internal_error' })
  })
})

describe('POST: share at Read (step 4.4)', () => {
  test('grant by owner: 201 naming the recipient; the share binds the account id; lookup and grant audited', async () => {
    signIn('alice')
    const res = await grant({ email: 'bob@example.test', access: 'read' })
    expect(res.status).toBe(201)
    const { collaborator } = await res.json()
    expect(collaborator).toMatchObject({ user: { id: 'bob', name: 'Bob Reader', email: 'bob@example.test' }, access: 'read', rawData: false, expiresAt: null, expired: false })
    expect(db.share('P1', 'bob')).toMatchObject({ access: 'read', rawData: false, grantedById: 'alice', expiresAt: null })
    const actions = db.audit().map(r => r.action)
    expect(actions).toEqual(['project.share.lookup', 'project.share.grant'])
    expect(db.audit()[0]).toMatchObject({ actorId: 'alice', projectId: 'P1', targetId: 'bob', permission: 'project:share', after: { result: 'hit', emailSha256: sha('bob@example.test') } })
    expect(db.audit()[1]).toMatchObject({ actorId: 'alice', projectId: 'P1', targetType: 'user', targetId: 'bob', after: { access: 'read', rawData: false, expiresAt: null, grantedById: 'alice' } })
    expect(JSON.stringify(db.audit())).not.toContain('bob@example.test')
  })

  test('the grant names the recipient\'s account type and who granted it (step 4.12, ID-31, SH-20)', async () => {
    signIn('alice')
    const { collaborator } = await (await grant({ email: 'admin-1@example.test', access: 'read' })).json()
    expect(collaborator.user).toMatchObject({ id: 'admin-1', accountType: 'admin' })
    expect(collaborator.grantedBy).toEqual({ id: 'alice', name: 'Alice Owner', email: 'alice@example.test', accountType: 'member' })
  })

  test('the accounts unreadable after the grant committed: still 201, the type and granter null, logged', async () => {
    signIn('alice')
    const error = vi.spyOn(console, 'error').mockImplementation(() => {})
    const users = (db.client as unknown as { user: { findMany: () => Promise<unknown> } }).user
    vi.spyOn(users, 'findMany').mockRejectedValueOnce(Object.assign(new Error('connection lost'), { code: 'P1001' }))
    const res = await grant({ email: 'bob@example.test', access: 'read' })
    expect(res.status).toBe(201)
    const { collaborator } = await res.json()
    expect(collaborator.user).toMatchObject({ id: 'bob', name: 'Bob Reader', email: 'bob@example.test', accountType: null })
    expect(collaborator.grantedBy).toBeNull()
    expect(db.share('P1', 'bob')).toBeDefined()
    expect(error).toHaveBeenCalledWith("[rbac] could not read the share's accounts: P1001")
  })

  test('the email is exact but normalised: surrounding spaces and letter case are ignored', async () => {
    signIn('alice')
    expect((await grant({ email: '  BOB@Example.TEST ', access: 'read' })).status).toBe(201)
    expect(db.share('P1', 'bob')).toBeDefined()
  })

  test('Raw data & files and a note are kept; the note stays out of the audit row', async () => {
    signIn('alice')
    const res = await grant({ email: 'bob@example.test', access: 'read', rawData: true, note: '  Q4 pentest  ' })
    expect(res.status).toBe(201)
    expect(db.share('P1', 'bob')).toMatchObject({ rawData: true, note: 'Q4 pentest' })
    expect(JSON.stringify(db.audit())).not.toContain('Q4 pentest')
  })

  test('grant without project:share: 403, no lookup, nothing written', async () => {
    signIn('analyst')
    const res = await grant({ email: 'bob@example.test', access: 'read' }, { id: 'P-analyst' })
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'forbidden', permission: 'project:share' })
    expect(db.audit()).toEqual([])
    expect(db.shareCount()).toBe(0)
  })

  test('a read collaborator cannot share further: 403', async () => {
    db.addShare({ projectId: 'P1', userId: 'bob' })
    signIn('bob')
    expect((await grant({ email: 'carol@example.test', access: 'read' })).status).toBe(403)
    expect(db.share('P1', 'carol')).toBeUndefined()
  })

  test('someone the project is not shared with: 404', async () => {
    signIn('carol')
    expect((await grant({ email: 'bob@example.test', access: 'read' })).status).toBe(404)
    expect(db.audit()).toEqual([])
  })

  test('unknown email: 404 no_such_account, nothing held for it; the lookup audited with a hash on miss', async () => {
    signIn('alice')
    const res = await grant({ email: 'Nobody@Example.test', access: 'read' })
    expect(res.status).toBe(404)
    expect(await res.json()).toMatchObject({ code: 'no_such_account' })
    expect(db.shareCount()).toBe(0)
    expect(db.audit()).toEqual([expect.objectContaining({
      action: 'project.share.lookup', actorId: 'alice', projectId: 'P1', targetId: null,
      after: { result: 'miss', emailSha256: sha('nobody@example.test') },
    })])
    expect(JSON.stringify(db.audit()).toLowerCase()).not.toContain('nobody@')
  })

  test('two accounts whose emails differ only in case: 409 ambiguous_account, never a pick', async () => {
    add(shareAccount('m1', { email: 'mixed@example.test' }))
    add(shareAccount('m2', { email: 'Mixed@example.test' }))
    signIn('alice')
    const res = await grant({ email: 'mixed@example.test', access: 'read' })
    expect(res.status).toBe(409)
    expect(await res.json()).toMatchObject({ code: 'ambiguous_account' })
    expect(db.shareCount()).toBe(0)
    expect(db.audit()).toEqual([expect.objectContaining({ action: 'project.share.lookup', targetId: null, after: expect.objectContaining({ result: 'ambiguous' }) })])
  })

  test.each([['dave', 'disabled'], ['erin', 'invited']])('inactive account (%s, %s): 409 account_not_active', async (id) => {
    signIn('alice')
    const res = await grant({ email: `${id}@example.test`, access: 'read' })
    expect(res.status).toBe(409)
    expect(await res.json()).toMatchObject({ code: 'account_not_active' })
    expect(db.shareCount()).toBe(0)
  })

  test('self: 400', async () => {
    signIn('alice')
    const res = await grant({ email: 'alice@example.test', access: 'read' })
    expect(res.status).toBe(400)
    expect(await res.json()).toMatchObject({ code: 'share_with_self' })
    expect(db.shareCount()).toBe(0)
  })

  test.each([
    ['access write', { access: 'write' }],
    ['a Read + Write toggle', { access: 'read', runScans: true }],
    ['Manage', { access: 'read', manage: true }],
  ])('write refused while write sharing is off (%s): 409, no lookup', async (_what, extra) => {
    signIn('alice')
    const res = await grant({ email: 'bob@example.test', ...extra })
    expect(res.status).toBe(409)
    expect(await res.json()).toMatchObject({ code: 'write_sharing_off' })
    expect(db.audit()).toEqual([])
    expect(db.shareCount()).toBe(0)
  })

  test('max level enforced: with the write switch on and the policy at Read, a write share names the policy', async () => {
    setFlagsForTests({ identity: true, permissions: true, sharing: true, sharingWrite: true })
    db.setPolicy({ enabled: true, maxLevel: 'read' })
    signIn('alice')
    const res = await grant({ email: 'bob@example.test', access: 'write' })
    expect(res.status).toBe(409)
    expect(await res.json()).toMatchObject({ code: 'above_max_level', maxLevel: 'read' })
    // The policy at write still gets no write share in this phase.
    clearSharingPolicyCacheForTests()
    db.setPolicy({ enabled: true, maxLevel: 'write' })
    expect(await (await grant({ email: 'bob@example.test', access: 'write' })).json()).toMatchObject({ code: 'write_sharing_off' })
    expect(db.shareCount()).toBe(0)
  })

  test('default expiry applied from the policy; an explicit expiry or null wins', async () => {
    db.setPolicy({ enabled: true, defaultExpiryDays: 30 })
    signIn('alice')
    expect((await grant({ email: 'bob@example.test', access: 'read' })).status).toBe(201)
    expect(db.share('P1', 'bob')?.expiresAt).toEqual(new Date(T0.getTime() + 30 * 86_400_000))
    expect((await grant({ email: 'carol@example.test', access: 'read', expiresAt: null })).status).toBe(201)
    expect(db.share('P1', 'carol')?.expiresAt).toBeNull()
    add(shareAccount('frank'))
    expect((await grant({ email: 'frank@example.test', access: 'read', expiresAt: '2026-12-01T00:00:00Z' })).status).toBe(201)
    expect(db.share('P1', 'frank')?.expiresAt).toEqual(new Date('2026-12-01T00:00:00Z'))
  })

  test.each([
    ['no email', { access: 'read' }, 'email'],
    ['an email that is no address', { email: 'bob', access: 'read' }, 'email'],
    ['no access', { email: 'bob@example.test' }, 'access'],
    ['an unknown access', { email: 'bob@example.test', access: 'admin' }, 'access'],
    ['rawData not a boolean', { email: 'bob@example.test', access: 'read', rawData: 'yes' }, 'rawData'],
    ['an expiry in the past', { email: 'bob@example.test', access: 'read', expiresAt: '2026-11-13T11:59:59Z' }, 'expiresAt'],
    ['an expiry that is no date', { email: 'bob@example.test', access: 'read', expiresAt: 'soon' }, 'expiresAt'],
    ['an expiry past ten years', { email: 'bob@example.test', access: 'read', expiresAt: '2037-01-01T00:00:00Z' }, 'expiresAt'],
    ['a note too long', { email: 'bob@example.test', access: 'read', note: 'x'.repeat(501) }, 'note'],
  ])('%s: 400 invalid_field, no lookup', async (_what, body, field) => {
    signIn('alice')
    const res = await grant(body)
    expect(res.status).toBe(400)
    expect(await res.json()).toMatchObject({ code: 'invalid_field', field })
    expect(db.audit()).toEqual([])
  })

  test(`rate limit after ${SHARE_LOOKUPS_PER_MINUTE}: per person, sliding over a minute; a refusal is not a lookup`, async () => {
    signIn('alice')
    for (let i = 0; i < SHARE_LOOKUPS_PER_MINUTE; i++) {
      expect((await grant({ email: `nobody-${i}@example.test`, access: 'read' })).status, `lookup ${i + 1}`).toBe(404)
    }
    const refused = await grant({ email: 'bob@example.test', access: 'read' })
    expect(refused.status).toBe(429)
    expect(refused.headers.get('Retry-After')).toBe('60')
    expect(await refused.json()).toMatchObject({ code: 'rate_limited', retryAfterSeconds: 60 })
    expect(db.audit()).toHaveLength(SHARE_LOOKUPS_PER_MINUTE)
    expect(db.shareCount()).toBe(0)
    // Another person keeps their own ceiling.
    db.addProject('P-carol', 'carol')
    signIn('carol')
    expect((await grant({ email: 'bob@example.test', access: 'read' }, { id: 'P-carol' })).status).toBe(201)
    // A minute later the first person may look up again.
    clock = new Date(T0.getTime() + 60_000)
    signIn('alice')
    expect((await grant({ email: 'bob@example.test', access: 'read' })).status).toBe(201)
  })

  test('already shared: 409 already_shared, the share unchanged', async () => {
    db.addShare({ projectId: 'P1', userId: 'bob', rawData: true })
    signIn('alice')
    const res = await grant({ email: 'bob@example.test', access: 'read' })
    expect(res.status).toBe(409)
    expect(await res.json()).toMatchObject({ code: 'already_shared' })
    expect(db.share('P1', 'bob')?.rawData).toBe(true)
    expect(db.audit().map(r => r.action)).toEqual(['project.share.lookup'])
  })

  test('an expired share the sweep has not removed is replaced by a new grant, its old terms in the audit row', async () => {
    db.addShare({ projectId: 'P1', userId: 'bob', rawData: true, expiresAt: new Date(T0.getTime() - 1) })
    signIn('alice')
    expect((await grant({ email: 'bob@example.test', access: 'read' })).status).toBe(201)
    expect(db.share('P1', 'bob')).toMatchObject({ rawData: false, expiresAt: null })
    expect(db.audit()[1]).toMatchObject({ action: 'project.share.grant', before: expect.objectContaining({ rawData: true }), after: expect.objectContaining({ rawData: false }) })
  })

  test('two grants of the same person at once: one 201, one 409, one share and one grant row', async () => {
    signIn('alice')
    const [a, b] = await Promise.all([grant({ email: 'bob@example.test', access: 'read' }), grant({ email: 'bob@example.test', access: 'read' })])
    expect([a.status, b.status].sort()).toEqual([201, 409])
    expect(db.shareCount()).toBe(1)
    expect(db.audit().filter(r => r.action === 'project.share.grant')).toHaveLength(1)
  })

  test('another copy inserts the same share between the read and the write (P2002): 409, no grant row', async () => {
    db.raceCreate()
    signIn('alice')
    const res = await grant({ email: 'bob@example.test', access: 'read' })
    expect(res.status).toBe(409)
    expect(await res.json()).toMatchObject({ code: 'already_shared' })
    expect(db.audit().map(r => r.action)).toEqual(['project.share.lookup'])
  })

  test('audit failure: no change (the grant\'s row fails, the share is rolled back)', async () => {
    db.failAudit('project.share.grant')
    vi.spyOn(console, 'error').mockImplementation(() => {})
    signIn('alice')
    const res = await grant({ email: 'bob@example.test', access: 'read' })
    expect(res.status).toBe(500)
    expect(db.shareCount()).toBe(0)
  })

  test('audit failure of the lookup: nothing is said about the account, nothing written', async () => {
    db.failAudit('project.share.lookup')
    vi.spyOn(console, 'error').mockImplementation(() => {})
    signIn('alice')
    const res = await grant({ email: 'bob@example.test', access: 'read' })
    expect(res.status).toBe(500)
    expect(JSON.stringify(await res.json())).not.toContain('Bob')
    expect(db.shareCount()).toBe(0)
  })

  test('refused while acting as the owner: 403 not_while_acting_as, act_as.refused audited, no lookup', async () => {
    signIn('admin-1', 'alice')
    const res = await grant({ email: 'bob@example.test', access: 'read' })
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'not_while_acting_as', action: 'change_shares' })
    expect(db.shareCount()).toBe(0)
    expect(db.audit()).toEqual([expect.objectContaining({ action: 'act_as.refused', actorId: 'admin-1', onBehalfOfUserId: 'alice' })])
  })

  test('a page of another site: 403 cross_origin, nothing read', async () => {
    signIn('alice')
    const res = await grant({ email: 'bob@example.test', access: 'read' }, { headers: { Origin: 'https://evil.example' } })
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'cross_origin' })
    expect(db.audit()).toEqual([])
  })

  test('a body that is not JSON: 415', async () => {
    signIn('alice')
    const res = await POST(new NextRequest('http://localhost/api/projects/P1/collaborators', {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'email=bob@example.test&access=read',
    }), ctx())
    expect(res.status).toBe(415)
    expect(db.shareCount()).toBe(0)
  })
})

describe('switch off -> 404 (DV-30)', () => {
  test.each([
    ['every switch off', {}, { enabled: true }],
    ['identity + permissions on, sharing off', { identity: true, permissions: true }, { enabled: true }],
    ['the switch on, the policy disabled', { identity: true, permissions: true, sharing: true }, {}],
  ])('%s: GET and POST answer 404, no share read or written', async (_what, flags, stored) => {
    setFlagsForTests(flags)
    db.setPolicy(stored)
    db.addShare({ projectId: 'P1', userId: 'bob' })
    const findMany = vi.spyOn(db.client.projectCollaborator, 'findMany')
    signIn('alice')
    expect((await list()).status).toBe(404)
    expect((await grant({ email: 'carol@example.test', access: 'read' })).status).toBe(404)
    expect(findMany).not.toHaveBeenCalled()
    expect(db.share('P1', 'carol')).toBeUndefined()
    expect(db.audit()).toEqual([])
  })
})
