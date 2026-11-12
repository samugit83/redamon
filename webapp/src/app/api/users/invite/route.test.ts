/**
 * The admin side of invite links (step 2.9, ID-14, ID-16, ID-36), identity switch on:
 *   - POST /api/users/invite {name, email} creates a MEMBER (whatever the body says) with
 *     status `invited` and no password, and answers its link once;
 *   - POST /api/users/[id]/invite/resend makes a new link and cancels the open one;
 *   - POST /api/users/[id]/invite/cancel removes an invited account that never signed in.
 * Each change, its link and its audit row commit together (`writeAuditTx`). With the switch off
 * the three routes do not exist (404 before any check).
 *
 * Real session helpers and tokens; the database is the in-memory accountDb (transactions roll
 * back); the clock is injected.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'
import { createHash } from 'node:crypto'

vi.stubEnv('AUTH_SECRET', 'f'.repeat(64))

const h = vi.hoisted(() => ({ db: null as unknown, jar: {} as { auth?: string; actAs?: string } }))
vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({
    get: (name: string) => {
      if (name === 'redamon-auth' && h.jar.auth) return { value: h.jar.auth }
      if (name === 'redamon-act-as' && h.jar.actAs) return { value: h.jar.actAs }
      return undefined
    },
    delete: () => {},
  })),
}))
vi.mock('@/lib/prisma', async () => {
  const { createAccountDb } = await import('@/lib/authz/__testing__/accountDb')
  h.db = createAccountDb()
  return { default: h.db, prisma: h.db }
})

import type { AccountDb } from '@/lib/authz/__testing__/accountDb'
import { createToken, createActAsToken } from '@/lib/auth'
import { setFlagsForTests } from '@/lib/authz/flags'
import { setNowForTests } from '@/lib/authz/clock'
import { clearPrincipalCacheForTests } from '@/lib/authz/principal'
import { createLink } from '@/lib/authz/invites'
import { POST as invite } from './route'
import { POST as resend } from '../[id]/invite/resend/route'
import { POST as cancel } from '../[id]/invite/cancel/route'

const db = () => h.db as AccountDb
const T0 = new Date('2026-11-12T10:00:00Z')
const sha256 = (s: string) => createHash('sha256').update(s).digest('hex')
const tokenOf = (link: string) => link.slice(link.lastIndexOf('/') + 1)
const LINK = /^https:\/\/redamon\.example\.com\/invite\/[A-Za-z0-9_-]{43}$/

function req(body: unknown = {}, opts: { origin?: string; contentType?: string; host?: string; cookie?: string } = {}): NextRequest {
  const headers: Record<string, string> = { host: opts.host ?? 'redamon.test', 'content-type': opts.contentType ?? 'application/json' }
  if (opts.origin !== undefined) headers.origin = opts.origin
  if (opts.cookie) headers.cookie = opts.cookie
  return new NextRequest('http://redamon.test/api/users/invite', {
    method: 'POST', headers, body: typeof body === 'string' ? body : JSON.stringify(body),
  })
}
const params = (id: string) => ({ params: Promise.resolve({ id }) })

async function signIn(userId: string, role = 'admin', actingAs?: string) {
  h.jar.auth = await createToken(userId, role, Number(db().account(userId)?.sessionVersion ?? 0))
  h.jar.actAs = actingAs ? await createActAsToken(userId, actingAs) : undefined
}

async function openInvite(userId: string) {
  return db().$transaction((tx) => createLink(tx as never, { userId, kind: 'invite', createdById: 'admin-1' }))
}

beforeEach(() => {
  db().reset()
  db().seedUsers([
    { id: 'admin-1', role: 'admin', email: 'ada@e2e.local' },
    { id: 'member-1', email: 'member-1@e2e.local' },
    { id: 'invited-1', status: 'invited', password: '', email: 'invited-1@e2e.local' },
  ])
  db().seedInstance({ inviteTtlHours: 168, resetTtlHours: 4, publicBaseUrl: 'https://redamon.example.com' })
  setFlagsForTests({ identity: true })
  setNowForTests(() => T0)
  clearPrincipalCacheForTests()
  vi.stubEnv('PLUGINS_ALLOWED_ORIGIN', '')
  vi.stubEnv('MCP_ALLOWED_ORIGIN', '')
  h.jar = {}
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
  vi.unstubAllEnvs()
  vi.stubEnv('AUTH_SECRET', 'f'.repeat(64))
})

describe('POST /api/users/invite', () => {
  test('creates a member, invited, without a password, and answers its link once', async () => {
    await signIn('admin-1')
    const res = await invite(req({ name: 'Nina', email: 'nina@e2e.local' }))
    expect(res.status).toBe(201)
    expect(res.headers.get('cache-control')).toBe('no-store')
    expect(res.headers.get('referrer-policy')).toBe('no-referrer')
    const body = await res.json()
    expect(body).toMatchObject({
      name: 'Nina', email: 'nina@e2e.local', role: 'standard', status: 'invited',
      expiresAt: new Date(T0.getTime() + 168 * 3600_000).toISOString(), localhostWarning: false,
    })
    expect(body.link).toMatch(LINK)
    expect(db().account(body.id)).toMatchObject({ role: 'standard', status: 'invited', password: '', mustChangePassword: false })
    const [row] = db().invites()
    expect(row).toMatchObject({ userId: body.id, kind: 'invite', createdById: 'admin-1', tokenHash: sha256(tokenOf(body.link)) })
  })

  test('invited account is a member even if the body says admin', async () => {
    await signIn('admin-1')
    const res = await invite(req({ name: 'Eve', email: 'eve@e2e.local', role: 'admin', password: 'x'.repeat(20) }))
    expect(res.status).toBe(201)
    const { id } = await res.json()
    expect(db().account(id)).toMatchObject({ role: 'standard', status: 'invited', password: '' })
  })

  test('an invite to an email that exists in another case → 409 email_taken', async () => {
    await signIn('admin-1')
    const res = await invite(req({ name: 'Copy', email: 'MEMBER-1@E2E.Local' }))
    expect(res.status).toBe(409)
    expect(await res.json()).toMatchObject({ code: 'email_taken' })
    expect(db().invites()).toEqual([])
    expect(db().audit()).toEqual([])
  })

  test('the address is stored lowercase', async () => {
    await signIn('admin-1')
    const { id } = await (await invite(req({ name: 'Nina', email: 'Nina@E2E.local' }))).json()
    expect(db().account(id)!.email).toBe('nina@e2e.local')
  })

  test('link uses publicBaseUrl not Host', async () => {
    await signIn('admin-1')
    const body = await (await invite(req({ name: 'Nina', email: 'nina@e2e.local' }, { host: 'attacker.example' }))).json()
    expect(body.link).toMatch(LINK)
    expect(body.link).not.toContain('attacker')
  })

  test('localhost warning when the instance has no public address', async () => {
    db().seedInstance({ publicBaseUrl: null })
    await signIn('admin-1')
    const body = await (await invite(req({ name: 'Nina', email: 'nina@e2e.local' }))).json()
    expect(body.link).toMatch(/^http:\/\/localhost:3000\/invite\//)
    expect(body.localhostWarning).toBe(true)
  })

  test('the account, the link and the audit row commit together; audit failure → nothing created', async () => {
    await signIn('admin-1')
    db().failAudit('user.invite')
    const res = await invite(req({ name: 'Nina', email: 'nina@e2e.local' }))
    expect(res.status).toBe(500)
    expect(db().account('user-4')).toBeUndefined()
    expect(db().invites()).toEqual([])
  })

  test('under act-as the real admin made it, for the member acted for', async () => {
    await signIn('admin-1', 'admin', 'member-1')
    // The audit reads the act-as cookie from the request, as the users routes' rows do.
    const cookie = `redamon-act-as=${h.jar.actAs}`
    const { id } = await (await invite(req({ name: 'Nina', email: 'nina@e2e.local' }, { cookie }))).json()
    expect(db().invites()[0].createdById).toBe('admin-1')
    expect(db().audit()[0]).toMatchObject({ actorId: 'admin-1', onBehalfOfUserId: 'member-1', action: 'user.invite', targetId: id })
  })

  test.each([
    [{ email: 'nina@e2e.local' }, 'name'],
    [{ name: '   ', email: 'nina@e2e.local' }, 'name'],
    [{ name: 'Nina' }, 'email'],
    [{ name: 'Nina', email: 'not-an-address' }, 'email'],
    [{ name: 'Nina', email: 42 }, 'email'],
    [{ name: 'x'.repeat(201), email: 'nina@e2e.local' }, 'name'],
  ])('a bad body %j → 400 invalid_field %s, nothing created', async (body, field) => {
    await signIn('admin-1')
    const res = await invite(req(body))
    expect(res.status).toBe(400)
    expect(await res.json()).toMatchObject({ code: 'invalid_field', field })
    expect(db().invites()).toEqual([])
  })

  test('refusals: member 403 coded, no session 401, cross-origin 403, not JSON 415', async () => {
    await signIn('member-1', 'standard')
    const member = await invite(req({ name: 'Nina', email: 'nina@e2e.local' }))
    expect(member.status).toBe(403)
    expect(await member.json()).toMatchObject({ code: 'forbidden', permission: 'users:create' })
    h.jar = {}
    expect((await invite(req({ name: 'Nina', email: 'nina@e2e.local' }))).status).toBe(401)
    await signIn('admin-1')
    expect((await invite(req({ name: 'Nina', email: 'nina@e2e.local' }, { origin: 'https://evil.example' }))).status).toBe(403)
    expect((await invite(req('name=Nina', { contentType: 'application/x-www-form-urlencoded' }))).status).toBe(415)
    expect(db().invites()).toEqual([])
  })

  test('switch off 404, before any check', async () => {
    setFlagsForTests({ identity: false })
    await signIn('admin-1')
    const res = await invite(req({ name: 'Nina', email: 'nina@e2e.local' }))
    expect(res.status).toBe(404)
    h.jar = {}
    expect((await invite(req({}))).status).toBe(404)
    expect(db().invites()).toEqual([])
  })
})

describe('POST /api/users/[id]/invite/resend', () => {
  test('resend cancels the old link and answers the new one', async () => {
    const first = await openInvite('invited-1')
    await signIn('admin-1')
    const res = await resend(req({}), params('invited-1'))
    expect(res.status).toBe(200)
    expect(res.headers.get('cache-control')).toBe('no-store')
    const body = await res.json()
    expect(body).toMatchObject({ id: 'invited-1', expiresAt: new Date(T0.getTime() + 168 * 3600_000).toISOString(), localhostWarning: false })
    expect(body.link).toMatch(LINK)
    expect(body.link).not.toBe(first.link)
    const rows = db().invites()
    expect(rows.find((r) => r.id === first.linkId)!.cancelledAt).toEqual(T0)
    expect(rows.filter((r) => !r.cancelledAt)).toHaveLength(1)
    expect(db().audit()).toEqual([expect.objectContaining({
      action: 'user.invite_resent', targetId: 'invited-1', actorId: 'admin-1', after: { expiresAt: body.expiresAt, cancelledLinks: 1 },
    })])
  })

  test('an account that is not invited → 409 not_invited, no link', async () => {
    await signIn('admin-1')
    const res = await resend(req({}), params('member-1'))
    expect(res.status).toBe(409)
    expect(await res.json()).toMatchObject({ code: 'not_invited' })
    expect(db().invites()).toEqual([])
  })

  test('unknown account 404; member 403; switch off 404; cross-origin 403', async () => {
    await signIn('admin-1')
    expect((await resend(req({}), params('nobody'))).status).toBe(404)
    expect((await resend(req({}, { origin: 'https://evil.example' }), params('invited-1'))).status).toBe(403)
    await signIn('member-1', 'standard')
    const member = await resend(req({}), params('invited-1'))
    expect(member.status).toBe(403)
    expect(await member.json()).toMatchObject({ code: 'forbidden', permission: 'users:create' })
    setFlagsForTests({ identity: false })
    await signIn('admin-1')
    expect((await resend(req({}), params('invited-1'))).status).toBe(404)
    expect(db().invites()).toEqual([])
  })

  test('audit failure → the old link stays open, no new one', async () => {
    const first = await openInvite('invited-1')
    await signIn('admin-1')
    db().failAudit('user.invite_resent')
    expect((await resend(req({}), params('invited-1'))).status).toBe(500)
    expect(db().invites()).toEqual([expect.objectContaining({ id: first.linkId, cancelledAt: null })])
  })
})

describe('POST /api/users/[id]/invite/cancel', () => {
  test('cancel removes the invited account and its links', async () => {
    await openInvite('invited-1')
    await signIn('admin-1')
    const res = await cancel(req({}), params('invited-1'))
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ id: 'invited-1', cancelled: true })
    expect(db().account('invited-1')).toBeUndefined()
    expect(db().invites()).toEqual([])
    expect(db().audit()).toEqual([expect.objectContaining({
      action: 'user.invite_cancelled', targetId: 'invited-1', actorId: 'admin-1', before: { email: 'invited-1@e2e.local', status: 'invited' },
    })])
  })

  test('the same cancel twice: the second finds nobody', async () => {
    await signIn('admin-1')
    expect((await cancel(req({}), params('invited-1'))).status).toBe(200)
    expect((await cancel(req({}), params('invited-1'))).status).toBe(404)
  })

  test('an active account, or one that signed in, is not removed (409 not_invited)', async () => {
    db().seedUsers([{ id: 'invited-2', status: 'invited', password: '', lastLoginAt: new Date(0) } as never])
    await signIn('admin-1')
    for (const id of ['member-1', 'invited-2']) {
      const res = await cancel(req({}), params(id))
      expect(res.status, id).toBe(409)
      expect(await res.json()).toMatchObject({ code: 'not_invited' })
      expect(db().account(id), id).toBeDefined()
    }
  })

  test('an invited account that owns projects is not removed here (409 has_projects)', async () => {
    db().seedProjects('invited-1', 2)
    await signIn('admin-1')
    const res = await cancel(req({}), params('invited-1'))
    expect(res.status).toBe(409)
    expect(await res.json()).toMatchObject({ code: 'has_projects' })
    expect(db().account('invited-1')).toBeDefined()
  })

  test('audit failure → the account stays', async () => {
    await openInvite('invited-1')
    await signIn('admin-1')
    db().failAudit('user.invite_cancelled')
    expect((await cancel(req({}), params('invited-1'))).status).toBe(500)
    expect(db().account('invited-1')).toBeDefined()
    expect(db().invites()).toHaveLength(1)
  })

  test('member 403; no session 401; switch off 404', async () => {
    await signIn('member-1', 'standard')
    expect((await cancel(req({}), params('invited-1'))).status).toBe(403)
    h.jar = {}
    expect((await cancel(req({}), params('invited-1'))).status).toBe(401)
    setFlagsForTests({ identity: false })
    await signIn('admin-1')
    expect((await cancel(req({}), params('invited-1'))).status).toBe(404)
    expect(db().account('invited-1')).toBeDefined()
  })
})
