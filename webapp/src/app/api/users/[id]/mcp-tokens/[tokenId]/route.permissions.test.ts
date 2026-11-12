/**
 * Narrowing or deleting another account's MCP token is revoking its MCP access: the registry's
 * `users:revoke_sessions` ("Sign a member out everywhere and revoke their MCP tokens", §5.1), not
 * the directory read. With RBAC_PERMISSIONS_ENABLED on, a profile holding only `users:read` (the
 * Security auditor, which changes nothing) is refused 403 naming `users:revoke_sessions` before
 * anything changes, and a profile holding `users:revoke_sessions` without `users:read` passes. The
 * account's own tokens need neither. With the switch off every admin answers as before.
 *
 * Real routes, session helpers, tokens and capability resolution; the database is the in-memory
 * accountDb.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'

vi.stubEnv('AUTH_SECRET', 'f'.repeat(64))
vi.stubEnv('INTERNAL_API_KEY', 'ik-test-master-0001')

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
import { PATCH as editToken, DELETE as deleteToken } from './route'

const db = () => h.db as AccountDb

function req(method: string, body?: unknown): NextRequest {
  return new NextRequest('http://redamon.test/api/x', {
    method,
    headers: { host: 'redamon.test', 'content-type': 'application/json' },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  })
}
const token = (id: string, tokenId: string) => ({ params: Promise.resolve({ id, tokenId }) })

async function as(userId: string) {
  const row = db().account(userId)!
  h.jar.auth = await createToken(userId, String(row.role), Number(row.sessionVersion ?? 0))
}

const tokenRow = (id: string, userId: string) => ({
  id, userId, name: `${id} name`, tokenPrefix: `rdm_${id}`, scopes: ['recon:read', 'recon:scan'], profile: null,
  lastUsedAt: null, expiresAt: null, revokedAt: null, createdAt: new Date('2026-11-01T00:00:00Z'),
})

const NARROW = { scopes: ['recon:read'] }
const memberToken = () => db().tokens().find((t) => t.id === 'tok-member')

beforeEach(() => {
  db().reset()
  db().seedUsers([
    { id: 'root-1', role: 'admin' },
    { id: 'admin-audit', role: 'admin', adminProfileId: 'builtin:security-auditor' },
    { id: 'admin-um', role: 'admin', adminProfileId: 'builtin:user-manager' },
    { id: 'admin-revoker', role: 'admin', adminProfileId: 'prof-revoker' },
    { id: 'member-1' },
    { id: 'member-2' },
  ])
  db().seedSet({ id: 'prof-revoker', kind: 'admin', name: 'Revoker', permissions: ['users:revoke_sessions'] })
  db().seedInstance({ rootUserId: 'root-1', rootAssignedBy: 'host', rootConfirmedAt: new Date('2026-11-12T08:00:00Z') })
  db().seedToken(tokenRow('tok-member', 'member-1'))
  db().seedToken(tokenRow('tok-audit', 'admin-audit'))
  setFlagsForTests({ identity: true, permissions: true })
  clearPrincipalCacheForTests()
  clearInstanceRootCacheForTests()
  clearCapabilityCachesForTests()
  h.jar = {}
})
afterEach(() => {
  setFlagsForTests(null)
})

describe("another account's token: users:revoke_sessions (permissions switch on)", () => {
  test('a Security auditor (users:read only) cannot narrow it: 403 naming users:revoke_sessions, nothing changed', async () => {
    await as('admin-audit')
    const res = await editToken(req('PATCH', NARROW), token('member-1', 'tok-member'))
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'forbidden', permission: 'users:revoke_sessions' })
    expect(memberToken()).toMatchObject({ scopes: ['recon:read', 'recon:scan'] })
    expect(db().audit()).toEqual([])
  })

  test('nor expire it now', async () => {
    await as('admin-audit')
    const res = await editToken(req('PATCH', { expiry: 'now' }), token('member-1', 'tok-member'))
    expect(res.status).toBe(403)
    expect(memberToken()?.expiresAt).toBeNull()
  })

  test('nor delete it', async () => {
    await as('admin-audit')
    const res = await deleteToken(req('DELETE'), token('member-1', 'tok-member'))
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'forbidden', permission: 'users:revoke_sessions' })
    expect(memberToken()).toBeDefined()
    expect(db().audit()).toEqual([])
  })

  test('a profile holding users:revoke_sessions without users:read narrows and deletes it', async () => {
    await as('admin-revoker')
    expect((await editToken(req('PATCH', NARROW), token('member-1', 'tok-member'))).status).toBe(200)
    expect(memberToken()).toMatchObject({ scopes: ['recon:read'] })
    expect((await deleteToken(req('DELETE'), token('member-1', 'tok-member'))).status).toBe(200)
    expect(memberToken()).toBeUndefined()
    expect(db().audit().map((r) => [r.action, r.actorId])).toEqual([
      ['mcp-token.update', 'admin-revoker'],
      ['mcp-token.delete', 'admin-revoker'],
    ])
  })

  test('a User manager (both) narrows and deletes it', async () => {
    await as('admin-um')
    expect((await editToken(req('PATCH', NARROW), token('member-1', 'tok-member'))).status).toBe(200)
    expect((await deleteToken(req('DELETE'), token('member-1', 'tok-member'))).status).toBe(200)
  })

  test('the permission only reaches it to take power away: a rename stays the account write rule', async () => {
    await as('admin-revoker')
    const res = await editToken(req('PATCH', { name: 'renamed' }), token('member-1', 'tok-member'))
    expect(res.status).toBe(403)
    expect(memberToken()?.name).toBe('tok-member name')
  })

  test('a member never reaches another member\'s token', async () => {
    await as('member-2')
    expect((await editToken(req('PATCH', NARROW), token('member-1', 'tok-member'))).status).toBe(403)
    expect((await deleteToken(req('DELETE'), token('member-1', 'tok-member'))).status).toBe(403)
    expect(memberToken()).toMatchObject({ scopes: ['recon:read', 'recon:scan'] })
  })
})

describe('own tokens need no administration permission', () => {
  test('a member narrows and deletes its own token', async () => {
    await as('member-1')
    expect((await editToken(req('PATCH', NARROW), token('member-1', 'tok-member'))).status).toBe(200)
    expect((await deleteToken(req('DELETE'), token('member-1', 'tok-member'))).status).toBe(200)
  })

  test('a Security auditor narrows and deletes its own token', async () => {
    await as('admin-audit')
    expect((await editToken(req('PATCH', NARROW), token('admin-audit', 'tok-audit'))).status).toBe(200)
    expect((await deleteToken(req('DELETE'), token('admin-audit', 'tok-audit'))).status).toBe(200)
  })
})

describe('switch off: every admin as before', () => {
  test.each(['admin-audit', 'admin-revoker'])('%s narrows and deletes a member\'s token', async (admin) => {
    setFlagsForTests({ identity: true, permissions: false })
    await as(admin)
    expect((await editToken(req('PATCH', NARROW), token('member-1', 'tok-member'))).status).toBe(200)
    expect((await deleteToken(req('DELETE'), token('member-1', 'tok-member'))).status).toBe(200)
  })

  test('a member is refused on another member\'s token', async () => {
    setFlagsForTests({ identity: true, permissions: false })
    await as('member-2')
    expect((await deleteToken(req('DELETE'), token('member-1', 'tok-member'))).status).toBe(403)
  })
})
