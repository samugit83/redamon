/**
 * POST /api/users/invite with a set picker (step 3.13, ID-28: "permissions are chosen at
 * creation"): with the permissions switch on the invite may name member sets, which commit with
 * the account, its link and its `user.invite` row. The rules of assigning a set afterwards hold
 * (GET/PUT /api/users/[id]/permissions, step 3.11): `users:assign_permissions`, only sets whose
 * permissions the inviter holds, the inviter's password for a cross-tenant tool, an exploitation
 * approval, sessions or Kali exec. No set named: never assigned, so the account follows the
 * instance default set. With the switch off the key is ignored, as any unknown key was.
 *
 * Real session helpers, tokens, bcrypt, step-up, resolution and hierarchy; the database is the
 * in-memory accountDb (transactions roll back); the clock is injected.
 *
 * Run: npx vitest run --no-file-parallelism src/app/api/users/invite/route.sets.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'
import bcrypt from 'bcryptjs'

vi.stubEnv('AUTH_SECRET', 'f'.repeat(64))

const h = vi.hoisted(() => ({ db: null as unknown, jar: {} as { auth?: string } }))
vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({
    get: (name: string) => (name === 'redamon-auth' && h.jar.auth ? { value: h.jar.auth } : undefined),
    delete: () => {},
  })),
}))
vi.mock('@/lib/prisma', async () => {
  const { createAccountDb } = await import('@/lib/authz/__testing__/accountDb')
  h.db = createAccountDb()
  return { default: h.db, prisma: h.db }
})

import type { AccountDb } from '@/lib/authz/__testing__/accountDb'
import { createToken } from '@/lib/auth'
import { setFlagsForTests } from '@/lib/authz/flags'
import { setNowForTests } from '@/lib/authz/clock'
import { clearPrincipalCacheForTests, loadPrincipal } from '@/lib/authz/principal'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import { clearCapabilityCachesForTests, resolveCapabilities } from '@/lib/authz/capabilities'
import { builtinSet } from '@/lib/authz/builtinSets'
import { __resetThrottle } from '@/lib/loginThrottle'
import { POST as invite } from './route'

const db = () => h.db as AccountDb
const T0 = new Date('2026-11-12T10:00:00Z')
const ACCOUNTS = ['root-1', 'admin-1', 'admin-u', 'admin-c', 'admin-ro']
const pw = (id: string) => `${id}-own-passphrase-01`
const HASH = Object.fromEntries(ACCOUNTS.map((id) => [id, bcrypt.hashSync(pw(id), 4)]))

function req(body: unknown): NextRequest {
  return new NextRequest('http://redamon.test/api/users/invite', {
    method: 'POST',
    headers: { host: 'redamon.test', 'content-type': 'application/json' },
    body: JSON.stringify(body),
  })
}

async function send(actor: string, body: Record<string, unknown>) {
  const row = db().account(actor)!
  h.jar.auth = await createToken(actor, String(row.role), Number(row.sessionVersion ?? 0))
  const res = await invite(req({ name: 'Nina', email: 'nina@e2e.local', ...body }))
  return { res, body: await res.clone().json().catch(() => ({})) as Record<string, unknown> }
}

/** The set rows of accounts this file creates (admin-ro's own is seeded). */
const assignments = () => db().assignments().filter((a) => a.userId !== 'admin-ro')
/** Everything a refused invite could have written. */
const written = () => JSON.stringify({
  users: db().account('user-6') ?? null, invites: db().invites(), assignments: assignments(), audit: db().audit(),
})
const NOTHING = JSON.stringify({ users: null, invites: [], assignments: [], audit: [] })

beforeEach(() => {
  db().reset()
  db().seedUsers([
    { id: 'root-1', role: 'admin', password: HASH['root-1'] },
    { id: 'admin-1', role: 'admin', password: HASH['admin-1'] },
    // User manager: users:create and users:assign_permissions; member side Default member.
    { id: 'admin-u', role: 'admin', password: HASH['admin-u'], adminProfileId: 'builtin:user-manager' },
    // Invites, assigns nothing.
    { id: 'admin-c', role: 'admin', password: HASH['admin-c'], adminProfileId: 'set-inviter' },
    // User manager whose own member side is Read-only analyst: holds no scan.
    { id: 'admin-ro', role: 'admin', password: HASH['admin-ro'], adminProfileId: 'builtin:user-manager' },
  ])
  db().seedSet({ id: 'set-inviter', kind: 'admin', name: 'Inviter', permissions: ['users:read', 'users:create'] })
  db().seedSet({ id: 'set-recon', kind: 'member', name: 'Recon team', permissions: [...builtinSet('builtin:recon-operator')!.permissions] })
  db().seedSet({ id: 'set-profile', kind: 'admin', name: 'Some profile', permissions: ['users:read'] })
  db().seedAssignment('admin-ro', 'builtin:read-only-analyst')
  db().seedInstance({
    rootUserId: 'root-1', rootAssignedBy: 'host', rootConfirmedAt: new Date('2026-11-12T08:00:00Z'),
    inviteTtlHours: 168, resetTtlHours: 4, publicBaseUrl: 'https://redamon.example.com',
  })
  setFlagsForTests({ identity: true, permissions: true })
  setNowForTests(() => T0)
  clearPrincipalCacheForTests()
  clearInstanceRootCacheForTests()
  clearCapabilityCachesForTests()
  __resetThrottle()
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

describe('invite sends the chosen set (ID-28)', () => {
  test('the account starts with the set, written with the account, its link and the audit row', async () => {
    const { res, body } = await send('admin-u', { sets: ['builtin:read-only-analyst'] })
    expect(res.status).toBe(201)
    const id = String(body.id)
    expect(assignments().map((a) => [a.userId, a.setId])).toEqual([[id, 'builtin:read-only-analyst']])
    expect(db().invites()).toHaveLength(1)
    const [row] = db().audit()
    expect(row).toMatchObject({ action: 'user.invite', actorId: 'admin-u', targetId: id })
    expect(row.after).toMatchObject({ role: 'standard', status: 'invited', sets: ['builtin:read-only-analyst'] })
    // Once the invite is accepted, the set decides.
    await db().user.update({ where: { id }, data: { status: 'active' } })
    clearPrincipalCacheForTests()
    const caps = await resolveCapabilities((await loadPrincipal(id, { fresh: true }))!, { fresh: true })
    expect(caps.sets.map((s) => [s.id, s.via])).toEqual([['builtin:read-only-analyst', 'assigned']])
    expect(caps.has('recon:scan')).toBe(false)
  })

  test('a custom set and two sets at once', async () => {
    const { res, body } = await send('admin-u', { sets: ['set-recon', 'builtin:read-only-analyst'] })
    expect(res.status).toBe(201)
    expect(assignments().map((a) => a.setId).sort()).toEqual(['builtin:read-only-analyst', 'set-recon'])
    expect(db().audit()[0].after).toMatchObject({ sets: ['set-recon', 'builtin:read-only-analyst'] })
    expect(assignments().every((a) => a.userId === body.id)).toBe(true)
  })

  test.each([[{}], [{ sets: [] }]])('no set named (%j): never assigned, the account follows the instance default set', async (extra) => {
    const { res } = await send('admin-c', extra)
    expect(res.status).toBe(201)
    expect(assignments()).toEqual([])
    expect(db().audit()[0].after).not.toHaveProperty('sets')
  })

  test('choosing a set needs users:assign_permissions: 403 naming it, nothing written', async () => {
    const { res, body } = await send('admin-c', { sets: ['builtin:read-only-analyst'] })
    expect(res.status).toBe(403)
    expect(body).toMatchObject({ code: 'forbidden', permission: 'users:assign_permissions' })
    expect(written()).toBe(NOTHING)
  })

  test('only sets whose permissions the inviter holds: 403 not_held, nothing written', async () => {
    const { res, body } = await send('admin-ro', { sets: ['set-recon'] })
    expect(res.status).toBe(403)
    expect(body.code).toBe('not_held')
    expect(body.permissions).toEqual(expect.arrayContaining(['recon:scan', 'agent:chat']))
    expect(written()).toBe(NOTHING)
    // What it holds itself it may give.
    expect((await send('admin-ro', { sets: ['builtin:read-only-analyst'] })).res.status).toBe(201)
  })

  test('a set holding Kali exec or an exploitation approval takes the inviter\'s password (ID-25)', async () => {
    const missing = await send('admin-u', { sets: ['builtin:red-team-operator'] })
    expect([missing.res.status, missing.body.code]).toEqual([403, 'step_up_required'])
    const wrong = await send('admin-u', { sets: ['builtin:red-team-operator'], stepUpPassword: 'not-it' })
    expect([wrong.res.status, wrong.body.code]).toEqual([403, 'step_up_failed'])
    expect(written()).toBe(NOTHING)
    const ok = await send('admin-u', { sets: ['builtin:red-team-operator'], stepUpPassword: pw('admin-u') })
    expect(ok.res.status).toBe(201)
    expect(assignments().map((a) => a.setId)).toEqual(['builtin:red-team-operator'])
  })

  test.each([
    [{ sets: 'builtin:read-only-analyst' }, 'invalid_sets'],
    [{ sets: [''] }, 'invalid_sets'],
    [{ sets: [42] }, 'invalid_sets'],
    [{ sets: ['builtin:read-only-analyst', 'builtin:read-only-analyst'] }, 'invalid_sets'],
    [{ sets: Array.from({ length: 51 }, (_, i) => `set-${i}`) }, 'invalid_sets'],
    [{ sets: ['set-gone'] }, 'unknown_set'],
    [{ sets: ['set-profile'] }, 'unknown_set'],
    [{ sets: ['builtin:full-admin'] }, 'unknown_set'],
  ])('a bad set list %j → 400 %s, nothing written', async (extra, code) => {
    const { res, body } = await send('admin-u', extra)
    expect(res.status).toBe(400)
    expect(body.code).toBe(code)
    expect(written()).toBe(NOTHING)
  })

  test('audit failure → no account, no link, no set row', async () => {
    db().failAudit('user.invite')
    const { res } = await send('admin-u', { sets: ['builtin:read-only-analyst'] })
    expect(res.status).toBe(500)
    expect(written()).toBe(NOTHING)
  })

  test('a set deleted while the invite ran → 409 permissions_changed, nothing written', async () => {
    const real = db().permissionSet.findUnique
    let reads = 0
    const spy = vi.spyOn(db().permissionSet, 'findUnique').mockImplementation(async (a) => {
      reads += 1
      // The check outside the transaction sees the set; the re-check under the lock does not.
      return reads === 1 ? real(a) : null
    })
    const { res, body } = await send('admin-u', { sets: ['set-recon'] })
    spy.mockRestore()
    expect([res.status, body.code]).toEqual([409, 'permissions_changed'])
    expect(written()).toBe(NOTHING)
  })

  test('the permissions lock is taken in the transaction that writes the set', async () => {
    await send('admin-u', { sets: ['builtin:read-only-analyst'] })
    expect(db().rawCalls.some((sql) => sql.includes('pg_advisory_xact_lock'))).toBe(true)
    expect(db().rawValues.flat()).toContain('rbac.permissions')
  })

  test('switch off: the key is ignored as any unknown key was; the account follows the default', async () => {
    setFlagsForTests({ identity: true, permissions: false })
    const { res } = await send('admin-c', { sets: ['builtin:no-access'] })
    expect(res.status).toBe(201)
    expect(assignments()).toEqual([])
    expect(db().audit()[0].after).not.toHaveProperty('sets')
  })
})
