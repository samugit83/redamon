/**
 * Root's break-glass (step 4.14; SH-18, SH-47): POST and DELETE /api/projects/[id]/breakglass.
 *
 * Real guard, can(), projectAccess(), sharing policy reader, capabilities, Root resolution, step-up
 * (bcrypt) and the break-glass writers; the session, Prisma (the share routes' in-memory store) and
 * the owner's notice writer are doubles.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import bcrypt from 'bcryptjs'
import { NextRequest, NextResponse } from 'next/server'
import { createShareDb, shareAccount, type ShareAccount, type ShareDb } from '@/lib/authz/__testing__/shareDb'

const h = vi.hoisted(() => ({
  client: null as unknown as Record<string | symbol, unknown>,
  identity: null as null | { session: { userId: string; role: string }; principal: unknown; actingAs: unknown },
  appendNotice: vi.fn(),
}))
vi.mock('@/lib/prisma', () => {
  const client = new Proxy({}, { get: (_t, k) => h.client[k] })
  return { default: client, prisma: client }
})
vi.mock('@/lib/session', () => ({
  getAuthzIdentity: async () => h.identity,
  getSession: async () => h.identity?.session ?? null,
  getEffectiveUser: async () => (h.identity ? { userId: ((h.identity.actingAs ?? h.identity.principal) as { id: string }).id } : null),
  mayActAs: async () => true,
  actAsInForce: async () => (h.identity?.actingAs ? { target: h.identity.actingAs, expiresAt: null } : null),
}))
vi.mock('@/lib/authz/accountNotices', async (orig) => ({
  ...(await orig<typeof import('@/lib/authz/accountNotices')>()),
  appendNotice: (...a: unknown[]) => h.appendNotice(...a),
}))

import { POST, DELETE } from './route'
import { setFlagsForTests } from '@/lib/authz/flags'
import { setNowForTests } from '@/lib/authz/clock'
import { clearSharingPolicyCacheForTests } from '@/lib/authz/sharingPolicy'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import { clearPrincipalCacheForTests } from '@/lib/authz/principal'
import { clearOversightMemoForTests } from '@/lib/authz/oversight'
import { requirePermission } from '@/lib/authz/guards'
import { __resetThrottle } from '@/lib/loginThrottle'
import { BREAKGLASS_MAX_MINUTES } from '@/lib/authz/breakGlass'

const T0 = new Date('2026-11-13T12:00:00Z')
const ROOT_PW = 'root-pass-0001-long'
const ROOT_HASH = bcrypt.hashSync(ROOT_PW, 4)
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
const ORIGIN = 'http://localhost'
const VALID = { reason: 'incident 7: leaked key', durationMinutes: 60, stepUpPassword: ROOT_PW }

function open(body: unknown, { id = 'P1', origin = ORIGIN, type = 'application/json' }: { id?: string; origin?: string; type?: string } = {}) {
  return POST(new NextRequest(`${ORIGIN}/api/projects/${id}/breakglass`, {
    method: 'POST',
    headers: { 'Content-Type': type, Origin: origin },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  }), ctx(id))
}

function close({ id = 'P1', origin = ORIGIN }: { id?: string; origin?: string } = {}) {
  return DELETE(new NextRequest(`${ORIGIN}/api/projects/${id}/breakglass`, { method: 'DELETE', headers: { Origin: origin } }), ctx(id))
}

async function codeOf(res: Response): Promise<string | undefined> {
  return ((await res.json()) as { code?: string }).code
}

/** What the real guard answers the signed-in person for a read of P1 at `permission`. */
async function reads(permission: 'recon:read' | 'traffic:read'): Promise<{ status: number; via?: string }> {
  clearCapabilityCachesForTests()
  const auth = await requirePermission(new Request(`${ORIGIN}/x`), permission, { projectId: 'P1' })
  return auth instanceof NextResponse ? { status: auth.status } : { status: 200, via: auth.access?.via }
}

beforeEach(() => {
  clock = T0
  setNowForTests(() => clock)
  db = createShareDb(() => clock)
  h.client = db.client as Record<string | symbol, unknown>
  for (const k of Object.keys(accounts)) delete accounts[k]
  add(shareAccount('alice', { email: 'alice@example.test', name: 'Alice Owner' }))
  add(shareAccount('admin-1', { role: 'admin', email: 'admin1@example.test', name: 'Ada Admin' }))
  add(shareAccount('root', { role: 'admin', email: 'root@example.test', name: 'Rita Root', password: ROOT_HASH }))
  db.addProject('P1', 'alice')
  db.addProject('P-root', 'root')
  db.setRoot('root', new Date('2026-10-01T00:00:00Z'))
  setFlagsForTests({ identity: true, permissions: true, sharing: true })
  clearSharingPolicyCacheForTests()
  clearCapabilityCachesForTests()
  clearInstanceRootCacheForTests()
  clearPrincipalCacheForTests()
  clearOversightMemoForTests()
  __resetThrottle()
  h.appendNotice.mockReset().mockResolvedValue(undefined)
  vi.spyOn(console, 'info').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
  h.identity = null
  vi.restoreAllMocks()
})

describe('break-glass needs Root, reason and step-up (step 4.14, SH-18)', () => {
  test('a member and an admin without projects:administer are refused naming it; nothing opened', async () => {
    for (const who of ['alice', 'admin-1']) {
      signIn(who)
      const res = await open(VALID)
      expect([who, res.status]).toEqual([who, 403])
      expect(await res.json()).toMatchObject({ code: 'forbidden', permission: 'projects:administer' })
    }
    expect(db.breakGlassRows()).toEqual([])
    expect(db.audit()).toEqual([])
  })

  test('the unconfirmed Root holds no Root-only permission until the host confirms it: 403 naming it, before any password', async () => {
    db.setRoot('root', null)
    signIn('root')
    const res = await open(VALID)
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'forbidden', permission: 'projects:administer' })
    expect(db.breakGlassRows()).toEqual([])
  })

  test('the confirmed Root without its password, or with a wrong one: step-up refused, nothing opened', async () => {
    signIn('root')
    expect(await codeOf(await open({ ...VALID, stepUpPassword: undefined }))).toBe('step_up_required')
    expect(await codeOf(await open({ ...VALID, stepUpPassword: 'wrong-password' }))).toBe('step_up_failed')
    expect(db.breakGlassRows()).toEqual([])
    expect(db.audit()).toEqual([])
  })

  test.each([
    ['no reason', { reason: undefined }, 'reason'],
    ['a blank reason', { reason: '   ' }, 'reason'],
    ['a reason over 500 characters', { reason: 'x'.repeat(501) }, 'reason'],
    ['no duration', { durationMinutes: undefined }, 'durationMinutes'],
    ['zero minutes', { durationMinutes: 0 }, 'durationMinutes'],
    [`more than ${BREAKGLASS_MAX_MINUTES} minutes`, { durationMinutes: BREAKGLASS_MAX_MINUTES + 1 }, 'durationMinutes'],
    ['a fraction of a minute', { durationMinutes: 1.5 }, 'durationMinutes'],
    ['minutes as text', { durationMinutes: '60' }, 'durationMinutes'],
  ])('%s: 400 naming the field, before the password is checked', async (_what, over, field) => {
    signIn('root')
    const res = await open({ ...VALID, ...over, stepUpPassword: 'wrong-password' })
    expect(res.status).toBe(400)
    expect(await res.json()).toMatchObject({ code: 'invalid_field', field })
    // The wrong password was never tried: the next good request is not locked or counted.
    expect((await open(VALID)).status).toBe(201)
  })

  test('Root with a reason and its password: 201, the row until the expiry, one project.breakglass row (fail closed)', async () => {
    signIn('root')
    const res = await open(VALID)
    expect(res.status).toBe(201)
    const expiresAt = new Date(T0.getTime() + 60 * 60_000).toISOString()
    expect(await res.json()).toEqual({ breakGlass: { id: expect.any(String), projectId: 'P1', expiresAt, durationMinutes: 60 } })
    expect(db.breakGlassRows()).toEqual([expect.objectContaining({ projectId: 'P1', userId: 'root', reason: 'incident 7: leaked key', expiresAt: new Date(expiresAt) })])
    expect(db.audit()).toEqual([expect.objectContaining({
      action: 'project.breakglass', actorId: 'root', actorEmail: 'root@example.test', projectId: 'P1', targetType: 'project',
      targetId: 'P1', permission: 'projects:administer', source: 'api',
      after: { breakGlassId: db.breakGlassRows()[0].id, reason: 'incident 7: leaked key', durationMinutes: 60, expiresAt },
    })])
    expect(JSON.stringify(db.audit())).not.toContain(ROOT_PW)
  })

  test('the audit row cannot be written: 500, no break-glass row (no row, no access)', async () => {
    db.failAudit('project.breakglass')
    vi.spyOn(console, 'error').mockImplementation(() => {})
    signIn('root')
    const res = await open(VALID)
    expect(res.status).toBe(500)
    expect(db.breakGlassRows()).toEqual([])
    expect(h.appendNotice).not.toHaveBeenCalled()
  })

  test("Root's own project: 400 own_project; a missing project 404; nothing opened", async () => {
    signIn('root')
    expect(await codeOf(await open(VALID, { id: 'P-root' }))).toBe('own_project')
    expect((await open(VALID, { id: 'P-missing' })).status).toBe(404)
    expect(db.breakGlassRows()).toEqual([])
  })

  test('same-origin JSON only: another site 403, a form 415', async () => {
    signIn('root')
    expect((await open(VALID, { origin: 'http://evil.test' })).status).toBe(403)
    expect((await open('reason=x', { type: 'application/x-www-form-urlencoded' })).status).toBe(415)
    expect(db.breakGlassRows()).toEqual([])
  })

  test('never while acting as someone: 403 not_while_acting_as with its act_as.refused row; nothing opened', async () => {
    signIn('root', 'alice')
    const res = await open(VALID)
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'not_while_acting_as', action: 'break_glass' })
    expect(db.audit()).toEqual([expect.objectContaining({ action: 'act_as.refused', actorId: 'root', onBehalfOfUserId: 'alice', after: { action: 'break_glass' } })])
    expect(db.breakGlassRows()).toEqual([])
    expect((await close()).status).toBe(403)
  })

  test('with sharing not in force the route does not exist: 404, no project read, nothing written', async () => {
    const findProject = vi.spyOn(db.client.project, 'findUnique')
    for (const [flags, policy] of [
      [{ identity: true, permissions: true }, { enabled: true }],
      [{}, { enabled: true }],
      [{ identity: true, permissions: true, sharing: true }, {}],
    ] as const) {
      setFlagsForTests(flags)
      db.setPolicy(policy)
      clearSharingPolicyCacheForTests()
      signIn('root')
      expect((await open(VALID)).status).toBe(404)
      expect((await close()).status).toBe(404)
    }
    expect(findProject).not.toHaveBeenCalled()
    expect(db.breakGlassRows()).toEqual([])
    expect(db.audit()).toEqual([])
  })
})

describe('what break-glass gives, and its end (step 4.14, SH-47)', () => {
  test('read with every read toggle, raw data included, until it expires; then Root reads by oversight again', async () => {
    signIn('root')
    expect(await reads('traffic:read')).toEqual({ status: 403 })
    expect(await reads('recon:read')).toEqual({ status: 200, via: 'oversight' })
    expect((await open({ ...VALID, durationMinutes: 30 })).status).toBe(201)
    expect(await reads('traffic:read')).toEqual({ status: 200, via: 'break_glass' })
    clock = new Date(T0.getTime() + 30 * 60_000 - 1)
    expect(await reads('traffic:read')).toEqual({ status: 200, via: 'break_glass' })
    clock = new Date(T0.getTime() + 30 * 60_000)
    expect(await reads('traffic:read')).toEqual({ status: 403 })
    expect(await reads('recon:read')).toEqual({ status: 200, via: 'oversight' })
  })

  test('a break-glass read writes no per-read row: its opening is the record', async () => {
    signIn('root')
    await open(VALID)
    const before = db.audit().length
    await reads('traffic:read')
    await reads('recon:read')
    expect(db.audit().length).toBe(before)
  })

  test('closing early: 200, every row of Root on the project gone, one project.breakglass.end row; no password asked', async () => {
    signIn('root')
    await open(VALID)
    const res = await close()
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ closed: 1 })
    expect(db.breakGlassRows()).toEqual([])
    expect(db.audit().map((r) => r.action)).toEqual(['project.breakglass', 'project.breakglass.end'])
    expect(db.audit()[1]).toMatchObject({
      actorId: 'root', projectId: 'P1', permission: 'projects:administer', after: { endedBy: 'closed' },
      before: { breakGlassIds: [expect.any(String)] },
    })
    expect(await reads('traffic:read')).toEqual({ status: 403 })
  })

  test('closing with nothing open: 404 no_break_glass, nothing written; an expired row is not "open"', async () => {
    signIn('root')
    expect(await codeOf(await close())).toBe('no_break_glass')
    db.addBreakGlass('P1', 'root', new Date(T0.getTime() - 1))
    expect(await codeOf(await close())).toBe('no_break_glass')
    expect(db.audit()).toEqual([])
  })

  test('closing needs projects:administer: a member and an admin get 403', async () => {
    for (const who of ['alice', 'admin-1']) {
      signIn(who)
      expect([who, (await close()).status]).toEqual([who, 403])
    }
  })
})

describe('owner notified (step 4.14, SH-18)', () => {
  test("the owner's notice names Root, the project, the reason and the time limit", async () => {
    signIn('root')
    await open(VALID)
    expect(h.appendNotice).toHaveBeenCalledTimes(1)
    expect(h.appendNotice).toHaveBeenCalledWith('alice', expect.objectContaining({
      type: 'break_glass', at: T0.toISOString(), by: { id: 'root', name: 'Rita Root', email: 'root@example.test' },
      reason: 'incident 7: leaked key', durationMinutes: 60, project: { id: 'P1', name: 'P1' },
    }))
  })

  test('a notice that cannot be written never undoes the break-glass: 201, logged with its code', async () => {
    h.appendNotice.mockRejectedValue(Object.assign(new Error('db down'), { code: 'P1001' }))
    const errors = vi.spyOn(console, 'error').mockImplementation(() => {})
    signIn('root')
    expect((await open(VALID)).status).toBe(201)
    expect(db.breakGlassRows()).toHaveLength(1)
    expect(errors.mock.calls.flat().join(' ')).toMatch(/\[rbac\] break-glass notice not written project=P1 code=P1001/)
  })
})
