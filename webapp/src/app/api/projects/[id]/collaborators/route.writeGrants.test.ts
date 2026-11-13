/**
 * Read + Write grants through the share routes (step 5.14; SH-05, SH-09 "never more than held",
 * ID-25 exploit grant, feature document §6.1, §6.3, §6.5): with write sharing in force (the switch,
 * sharing and Root's `maxLevel: 'write'`) GET, POST and PATCH /api/projects/[id]/collaborators[/userId]
 * grant the write level and its toggles within Root's policy; a co-owner grants never more than they
 * hold; Exploitation & shells asks the granting person's password and, for a member, Root's
 * `membersMayGrantExploit`; the list says what the asker may grant. With write sharing not in force
 * every answer is Phase 4's (the collaborators route tests and sharingWrite.flags.off.test.ts pin it).
 *
 * Real guard, can(), projectAccess() (consent included), sharing policy reader, capabilities, audit
 * writer and revocation; Prisma is the share routes' in-memory store (shareDb.ts) plus the consent
 * table; the session, the step-up check and the agent are doubles.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'
import { createShareDb, shareAccount, type ShareAccount, type ShareDb } from '@/lib/authz/__testing__/shareDb'

type PolicyRow = { ownerCredentialConsentAt: Date | null; ownerCredentialConsentById: string | null }

const h = vi.hoisted(() => ({
  client: null as unknown as Record<string | symbol, unknown>,
  identity: null as null | { session: { userId: string; role: string }; principal: unknown; actingAs: unknown },
  agentFetch: vi.fn(),
  stepUp: vi.fn(),
}))
vi.mock('@/lib/prisma', () => {
  const client = new Proxy({}, { get: (_t, k) => h.client[k] })
  return { default: client, prisma: client }
})
// Whole-module double: importing the real session module first would bind the guards to it.
vi.mock('@/lib/session', () => ({
  getAuthzIdentity: async () => h.identity,
  getSession: async () => h.identity?.session ?? null,
  getEffectiveUser: async () => (h.identity ? { userId: (h.identity.principal as { id: string }).id } : null),
  mayActAs: async () => true,
  actAsInForce: async () => null,
}))
vi.mock('@/lib/authz/stepUp', () => ({ requireStepUp: (...a: unknown[]) => h.stepUp(...a) }))
vi.mock('@/lib/agentFetch', () => {
  class AgentUnreachableError extends Error {}
  return { agentFetch: (...a: unknown[]) => h.agentFetch(...a), AgentUnreachableError }
})
vi.mock('@/lib/triage/actions', () => ({ stopRun: async () => ({ stopped: false }) }))

import { GET, POST } from './route'
import { PATCH } from './[userId]/route'
import { setFlagsForTests } from '@/lib/authz/flags'
import { setNowForTests } from '@/lib/authz/clock'
import { clearSharingPolicyCacheForTests } from '@/lib/authz/sharingPolicy'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import { clearPrincipalCacheForTests } from '@/lib/authz/principal'
import { resetInviteLimitsForTests } from '@/lib/authz/inviteLimits'

const T0 = new Date('2026-11-13T12:00:00Z')
const PASSWORD = 'the-right-password'
let db: ShareDb
let consents: Map<string, PolicyRow>
const accounts: Record<string, ShareAccount> = {}

function add(account: ShareAccount) {
  accounts[account.id] = account
  db.addUser(account)
}

function signIn(id: string) {
  const principal = accounts[id]
  h.identity = { session: { userId: id, role: principal.role }, principal, actingAs: null }
}

const consent = (projectId = 'P1') => consents.set(projectId, { ownerCredentialConsentAt: T0, ownerCredentialConsentById: 'alice' })
const policy = (stored: Record<string, unknown>) => {
  db.setPolicy({ enabled: true, ...stored })
  clearSharingPolicyCacheForTests()
}

const list = async (id = 'P1') => {
  const res = await GET(new NextRequest(`http://localhost/api/projects/${id}/collaborators`), { params: Promise.resolve({ id }) })
  return { status: res.status, body: await res.json() }
}
const grant = async (body: Record<string, unknown>, id = 'P1') => {
  const res = await POST(new NextRequest(`http://localhost/api/projects/${id}/collaborators`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  }), { params: Promise.resolve({ id }) })
  return { status: res.status, body: await res.json() }
}
const change = async (userId: string, body: Record<string, unknown>, id = 'P1') => {
  const res = await PATCH(new NextRequest(`http://localhost/api/projects/${id}/collaborators/${userId}`, {
    method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  }), { params: Promise.resolve({ id, userId }) })
  return { status: res.status, body: await res.json() }
}
const auditOf = (action: string) => db.audit().filter((r) => r.action === action)
const NO_TOGGLES = { runScans: false, useAgent: false, exploit: false, manage: false }

beforeEach(() => {
  setNowForTests(() => T0)
  db = createShareDb(() => T0)
  consents = new Map()
  const consentTable = {
    findUnique: async ({ where }: { where: { projectId: string } }) => consents.get(where.projectId) ?? null,
    upsert: async ({ where, update }: { where: { projectId: string }; update: PolicyRow }) => {
      consents.set(where.projectId, update)
      return update
    },
  }
  h.client = { ...db.client, projectAccessPolicy: consentTable }
  for (const k of Object.keys(accounts)) delete accounts[k]
  add(shareAccount('alice', { email: 'alice@example.test', name: 'Alice Owner' }))
  add(shareAccount('bob', { email: 'bob@example.test', name: 'Bob Editor' }))
  add(shareAccount('carol', { email: 'carol@example.test', name: 'Carol Coowner' }))
  add(shareAccount('dan', { email: 'dan@example.test', name: 'Dan Coowner' }))
  add(shareAccount('root-admin', { role: 'admin', email: 'admin@example.test' }))
  db.addProject('P1', 'alice')
  db.addProject('P-admin', 'root-admin')
  db.addShare({ projectId: 'P1', userId: 'carol', access: 'write', rawData: true, manage: true, runScans: true })
  db.addShare({ projectId: 'P1', userId: 'dan', access: 'write', rawData: true, manage: true })
  setFlagsForTests({ identity: true, permissions: true, sharing: true, sharingWrite: true })
  policy({ maxLevel: 'write' })
  clearCapabilityCachesForTests()
  clearInstanceRootCacheForTests()
  clearPrincipalCacheForTests()
  resetInviteLimitsForTests()
  h.stepUp.mockReset().mockImplementation(async (_r: unknown, password: unknown) => (password === PASSWORD
    ? null
    : NextResponse.json({ error: 'Enter your password to confirm this action.', code: 'step_up_required' }, { status: 403 })))
  h.agentFetch.mockReset().mockImplementation(async (path: string) =>
    new Response(JSON.stringify(path === '/ws/close' ? { closed: 0, stopped_runs: 0 } : { stopped: 0 }), { status: 200 }))
  vi.spyOn(console, 'info').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
  h.identity = null
  vi.restoreAllMocks()
})

describe('GET: what the asker may grant (step 5.14)', () => {
  test('the owner: every toggle but Exploitation (a member, Root\'s policy keeps it to admins); no consent yet; each share\'s toggles listed', async () => {
    signIn('alice')
    const { status, body } = await list()
    expect(status).toBe(200)
    expect(body.grantable).toEqual({
      grantor: 'owner',
      ownerConsent: false,
      toggles: {
        runScans: { grantable: true },
        useAgent: { grantable: true },
        exploit: { grantable: false, code: 'exploit_admins_only', reason: expect.stringMatching(/only administrators/) },
        manage: { grantable: true },
      },
    })
    const carol = body.collaborators.find((c: { user: { id: string } }) => c.user.id === 'carol')
    expect(carol).toMatchObject({ access: 'write', rawData: true, runScans: true, useAgent: false, exploit: false, manage: true })
  })

  test("policy limits: membersMayGrantExploit opens Exploitation to a member owner; an admin owner always has it", async () => {
    policy({ maxLevel: 'write', membersMayGrantExploit: true })
    consent()
    signIn('alice')
    const owner = (await list()).body.grantable
    expect(owner.ownerConsent).toBe(true)
    expect(owner.toggles.exploit).toEqual({ grantable: true })

    policy({ maxLevel: 'write' })
    signIn('root-admin')
    expect((await list('P-admin')).body.grantable.toggles.exploit).toEqual({ grantable: true })
  })

  test('co-owner cap: a co-owner sees only what they hold; without the owner\'s consent no spend toggle', async () => {
    signIn('carol')
    const without = (await list()).body.grantable
    expect(without.grantor).toBe('co_owner')
    expect(without.toggles.runScans).toMatchObject({ grantable: false, code: 'owner_consent_required' })
    expect(without.toggles.useAgent).toMatchObject({ grantable: false, code: 'owner_consent_required' })
    expect(without.toggles.manage).toEqual({ grantable: true })

    consent()
    const withConsent = (await list()).body.grantable
    expect(withConsent.toggles.runScans).toEqual({ grantable: true })
    expect(withConsent.toggles.useAgent).toMatchObject({ grantable: false, code: 'not_held' })
    expect(withConsent.toggles.exploit).toMatchObject({ grantable: false, code: 'exploit_admins_only' })
  })

  test.each([
    ['the write switch off', { identity: true, permissions: true, sharing: true }, { maxLevel: 'write' }],
    ["Root's policy at Read", { identity: true, permissions: true, sharing: true, sharingWrite: true }, { maxLevel: 'read' }],
  ])('%s: the Phase 4 answer (no grantable, no write toggles, no consent read)', async (_what, flags, stored) => {
    setFlagsForTests(flags)
    policy(stored)
    const consentRead = vi.spyOn(h.client.projectAccessPolicy as { findUnique: () => unknown }, 'findUnique')
    signIn('alice')
    const { body } = await list()
    expect(Object.keys(body)).toEqual(['collaborators'])
    expect(Object.keys(body.collaborators[0]).sort()).toEqual([
      'access', 'createdAt', 'expired', 'expiresAt', 'grantedBy', 'grantedById', 'note', 'rawData', 'updatedAt', 'user',
    ])
    expect(consentRead).not.toHaveBeenCalled()
  })
})

describe('POST: Read + Write grants within the policy (step 5.14)', () => {
  test('presets: Editor is granted at write with no toggle, audited, answered with its toggles', async () => {
    signIn('alice')
    const { status, body } = await grant({ email: 'bob@example.test', access: 'write', rawData: true, ...NO_TOGGLES })
    expect(status).toBe(201)
    expect(body.collaborator).toMatchObject({ access: 'write', rawData: true, ...NO_TOGGLES })
    expect(db.share('P1', 'bob')).toMatchObject({ access: 'write', rawData: true, ...NO_TOGGLES, grantedById: 'alice' })
    expect(auditOf('project.share.grant')[0].after).toMatchObject({ access: 'write', ...NO_TOGGLES })
    expect(h.stepUp).not.toHaveBeenCalled()
  })

  test('consent prompt (server side): Operator needs the owner\'s consent, then grants Run scans and Use AI agent', async () => {
    signIn('alice')
    const operator = { email: 'bob@example.test', access: 'write', rawData: true, ...NO_TOGGLES, runScans: true, useAgent: true }
    const refused = await grant(operator)
    expect([refused.status, refused.body.code]).toEqual([409, 'owner_consent_required'])
    consent()
    const ok = await grant(operator)
    expect(ok.status).toBe(201)
    expect(db.share('P1', 'bob')).toMatchObject({ access: 'write', runScans: true, useAgent: true, exploit: false, manage: false })
  })

  test('a Read + Write toggle on a Read share is refused (400), nothing looked up', async () => {
    signIn('alice')
    const res = await grant({ email: 'bob@example.test', access: 'read', manage: true })
    expect([res.status, res.body.code, res.body.field]).toEqual([400, 'invalid_field', 'manage'])
    expect(db.audit()).toEqual([])
  })

  test('step-up for exploit: Red-teamer asks the password before any lookup; with it the share is granted', async () => {
    policy({ maxLevel: 'write', membersMayGrantExploit: true })
    consent()
    signIn('alice')
    const redTeamer = { email: 'bob@example.test', access: 'write', rawData: true, runScans: true, useAgent: true, exploit: true, manage: false }
    const asked = await grant(redTeamer)
    expect([asked.status, asked.body.code]).toEqual([403, 'step_up_required'])
    expect(db.audit()).toEqual([])
    const ok = await grant({ ...redTeamer, stepUpPassword: PASSWORD })
    expect(ok.status).toBe(201)
    expect(h.stepUp).toHaveBeenLastCalledWith(expect.anything(), PASSWORD)
    expect(db.share('P1', 'bob')).toMatchObject({ exploit: true })
    expect(JSON.stringify(db.audit())).not.toContain(PASSWORD)
  })

  test("policy limits: a member may not grant Exploitation while Root's policy keeps it to admins (409), no password asked; an admin may", async () => {
    consent()
    signIn('alice')
    const res = await grant({ email: 'bob@example.test', access: 'write', exploit: true, stepUpPassword: PASSWORD })
    expect([res.status, res.body.code]).toEqual([409, 'exploit_admins_only'])
    expect(h.stepUp).not.toHaveBeenCalled()
    expect(db.shareCount()).toBe(2)

    consent('P-admin')
    signIn('root-admin')
    const admin = await grant({ email: 'bob@example.test', access: 'write', exploit: true, stepUpPassword: PASSWORD }, 'P-admin')
    expect(admin.status).toBe(201)
  })

  test('co-owner cap: a co-owner grants what they hold (Run scans, Manage) and nothing more (403 grant_above_held)', async () => {
    consent()
    signIn('carol')
    const above = await grant({ email: 'bob@example.test', access: 'write', useAgent: true })
    expect(above.status).toBe(403)
    expect(above.body).toMatchObject({ code: 'grant_above_held', toggle: 'useAgent', permission: 'project:share' })
    expect(db.share('P1', 'bob')).toBeUndefined()
    const held = await grant({ email: 'bob@example.test', access: 'write', runScans: true, manage: true })
    expect(held.status).toBe(201)
    expect(db.share('P1', 'bob')).toMatchObject({ access: 'write', runScans: true, manage: true, grantedById: 'carol' })
  })

  test("max level enforced: Root's policy at Read still refuses a write grant (409 above_max_level)", async () => {
    policy({ maxLevel: 'read' })
    signIn('alice')
    const res = await grant({ email: 'bob@example.test', access: 'write' })
    expect([res.status, res.body.code]).toEqual([409, 'above_max_level'])
  })
})

describe('PATCH: changing the level and toggles (step 5.14)', () => {
  test('Viewer -> Editor -> Operator (consent) -> Viewer: toggles cleared with the level, live work stopped on the narrowing', async () => {
    db.addShare({ projectId: 'P1', userId: 'bob', access: 'read' })
    signIn('alice')
    expect((await change('bob', { access: 'write', rawData: true })).status).toBe(200)
    expect(db.share('P1', 'bob')).toMatchObject({ access: 'write', ...NO_TOGGLES })
    consent()
    const op = await change('bob', { runScans: true, useAgent: true })
    expect(op.status).toBe(200)
    expect(op.body.collaborator).toMatchObject({ access: 'write', runScans: true, useAgent: true })
    h.agentFetch.mockClear()
    const back = await change('bob', { access: 'read', rawData: false })
    expect(back.status).toBe(200)
    expect(db.share('P1', 'bob')).toMatchObject({ access: 'read', rawData: false, ...NO_TOGGLES })
    expect(auditOf('project.share.update').at(-1)!.after).toMatchObject({ access: 'read', ...NO_TOGGLES })
    expect(h.agentFetch).toHaveBeenCalled()
  })

  test('a toggle on a share that stays Read is refused (400), unchanged', async () => {
    db.addShare({ projectId: 'P1', userId: 'bob', access: 'read' })
    signIn('alice')
    const res = await change('bob', { manage: true })
    expect([res.status, res.body.code, res.body.field]).toEqual([400, 'invalid_field', 'manage'])
    expect(db.share('P1', 'bob')).toMatchObject({ access: 'read', manage: false })
  })

  test('turning Exploitation on asks the password; the policy refuses it to a member first', async () => {
    db.addShare({ projectId: 'P1', userId: 'bob', access: 'write', rawData: true })
    consent()
    signIn('alice')
    expect((await change('bob', { exploit: true, stepUpPassword: PASSWORD })).body.code).toBe('exploit_admins_only')
    policy({ maxLevel: 'write', membersMayGrantExploit: true })
    expect((await change('bob', { exploit: true })).body.code).toBe('step_up_required')
    expect(db.share('P1', 'bob')).toMatchObject({ exploit: false })
    expect((await change('bob', { exploit: true, stepUpPassword: PASSWORD })).status).toBe(200)
    expect(db.share('P1', 'bob')).toMatchObject({ exploit: true })
  })

  test('co-owner cap on a change; a co-owner never changes another co-owner (OQ-34)', async () => {
    db.addShare({ projectId: 'P1', userId: 'bob', access: 'write', rawData: true })
    consent()
    signIn('carol')
    const above = await change('bob', { useAgent: true })
    expect([above.status, above.body.code]).toEqual([403, 'grant_above_held'])
    expect((await change('bob', { runScans: true })).status).toBe(200)
    const coOwner = await change('dan', { manage: false })
    expect([coOwner.status, coOwner.body.code]).toEqual([403, 'owner_only'])
    expect(db.share('P1', 'dan')).toMatchObject({ manage: true })
  })
})
