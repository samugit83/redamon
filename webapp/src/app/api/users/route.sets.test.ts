/**
 * POST /api/users with a set picker (step 3.13, ID-28): with the permissions switch on, the
 * "Create with a temporary password" and passwordless create modals may name member sets, which
 * commit with the account and its `user.create` row (one transaction: no row, no account). The
 * rules of the invite's picker and of assigning a set afterwards hold: `users:assign_permissions`,
 * only held permissions, the creator's password for a cross-tenant tool, an exploitation approval,
 * sessions or Kali exec (Root creating an admin already gave it). With the switch off the key is
 * ignored, as any unknown key was, and the Phase 1 path writes the account alone.
 *
 * Real session helpers, tokens, bcrypt, step-up, resolution and hierarchy; the database is the
 * in-memory accountDb (transactions roll back).
 *
 * Run: npx vitest run --no-file-parallelism src/app/api/users/route.sets.test.ts
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
import { clearPrincipalCacheForTests } from '@/lib/authz/principal'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { __resetThrottle } from '@/lib/loginThrottle'
import { POST } from './route'

const db = () => h.db as AccountDb
const ACCOUNTS = ['root-1', 'admin-u', 'admin-c']
const pw = (id: string) => `${id}-own-passphrase-01`
const HASH = Object.fromEntries(ACCOUNTS.map((id) => [id, bcrypt.hashSync(pw(id), 4)]))

async function create(actor: string, body: Record<string, unknown>) {
  const row = db().account(actor)!
  h.jar.auth = await createToken(actor, String(row.role), Number(row.sessionVersion ?? 0))
  const res = await POST(new NextRequest('http://redamon.test/api/users', {
    method: 'POST',
    headers: { host: 'redamon.test', 'content-type': 'application/json' },
    body: JSON.stringify({ name: 'Nina', email: 'nina@e2e.local', ...body }),
  }))
  return { res, body: await res.clone().json().catch(() => ({})) as Record<string, unknown> }
}

const written = () => JSON.stringify({ user: db().account('user-4') ?? null, assignments: db().assignments(), audit: db().audit() })
const NOTHING = JSON.stringify({ user: null, assignments: [], audit: [] })

beforeEach(() => {
  db().reset()
  db().seedUsers([
    { id: 'root-1', role: 'admin', password: HASH['root-1'] },
    { id: 'admin-u', role: 'admin', password: HASH['admin-u'], adminProfileId: 'builtin:user-manager' },
    { id: 'admin-c', role: 'admin', password: HASH['admin-c'], adminProfileId: 'set-creator' },
  ])
  db().seedSet({ id: 'set-creator', kind: 'admin', name: 'Creator', permissions: ['users:read', 'users:create'] })
  db().seedInstance({ rootUserId: 'root-1', rootAssignedBy: 'host', rootConfirmedAt: new Date('2026-11-12T08:00:00Z') })
  setFlagsForTests({ identity: true, permissions: true })
  clearPrincipalCacheForTests()
  clearInstanceRootCacheForTests()
  clearCapabilityCachesForTests()
  __resetThrottle()
  h.jar = {}
})
afterEach(() => {
  setFlagsForTests(null)
})

describe('a created account starts with the chosen set (ID-28)', () => {
  test('passwordless member with a set: the account, its set and the audit row', async () => {
    const { res, body } = await create('admin-u', { sets: ['builtin:read-only-analyst'] })
    expect(res.status).toBe(201)
    expect(body.id).toBe('user-4')
    expect(db().assignments().map((a) => [a.userId, a.setId])).toEqual([['user-4', 'builtin:read-only-analyst']])
    expect(db().audit()).toHaveLength(1)
    expect(db().audit()[0]).toMatchObject({ action: 'user.create', actorId: 'admin-u', targetId: 'user-4' })
    expect(db().audit()[0].after).toMatchObject({ role: 'standard', passwordless: true, sets: ['builtin:read-only-analyst'] })
  })

  test('no set named: no row, the account follows the instance default set; the row names no sets', async () => {
    const { res } = await create('admin-c', {})
    expect(res.status).toBe(201)
    expect(db().assignments()).toEqual([])
    expect(db().audit()[0].after).not.toHaveProperty('sets')
  })

  test('choosing a set needs users:assign_permissions: 403 naming it, nothing written', async () => {
    const { res, body } = await create('admin-c', { sets: ['builtin:read-only-analyst'] })
    expect(res.status).toBe(403)
    expect(body).toMatchObject({ code: 'forbidden', permission: 'users:assign_permissions' })
    expect(written()).toBe(NOTHING)
  })

  test('a set with Kali exec takes the creator\'s password; Root creating an admin already gave it', async () => {
    const missing = await create('admin-u', { sets: ['builtin:red-team-operator'] })
    expect([missing.res.status, missing.body.code]).toEqual([403, 'step_up_required'])
    expect(written()).toBe(NOTHING)
    expect((await create('admin-u', { sets: ['builtin:red-team-operator'], stepUpPassword: pw('admin-u') })).res.status).toBe(201)
    expect(db().assignments().map((a) => a.setId)).toEqual(['builtin:red-team-operator'])

    const admin = await create('root-1', {
      email: 'adam@e2e.local', role: 'admin', sets: ['builtin:red-team-operator'], stepUpPassword: pw('root-1'),
    })
    expect(admin.res.status).toBe(201)
    expect(db().assignments().filter((a) => a.userId === admin.body.id).map((a) => a.setId)).toEqual(['builtin:red-team-operator'])
  })

  test('an unknown set → 400 unknown_set, nothing written', async () => {
    const { res, body } = await create('admin-u', { sets: ['builtin:full-admin'] })
    expect([res.status, body.code]).toEqual([400, 'unknown_set'])
    expect(written()).toBe(NOTHING)
  })

  test('audit failure → no account, no set row', async () => {
    db().failAudit('user.create')
    const { res } = await create('admin-u', { sets: ['builtin:read-only-analyst'] })
    expect(res.status).toBe(500)
    expect(written()).toBe(NOTHING)
  })

  test('switch off: the key is ignored; the account is created as before, with no set row', async () => {
    setFlagsForTests({ identity: true, permissions: false })
    const { res } = await create('admin-u', { sets: ['builtin:no-access'] })
    expect(res.status).toBe(201)
    expect(db().assignments()).toEqual([])
    expect(db().audit()[0].after).not.toHaveProperty('sets')
  })
})
