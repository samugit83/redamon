/**
 * Root's MCP tokens are Root's (review of step 2.5, finding B; feature document §4.3, Root is
 * "untouchable by anyone else in the app"): with the identity switch on, no other admin lists,
 * narrows, expires or deletes them; each attempt answers 403 `root_protected` and writes a
 * `rbac.root_protected_refused` row, as the other Root protections do. Root itself keeps full
 * control of its own tokens, the internal key (a service) still lists them, and another
 * account's tokens keep HD-23's incident exception: an admin may list, narrow and delete them.
 * With the switch off the Phase 1 answers hold and the instance row is never read.
 *
 * Real session helpers and tokens; the database is the in-memory accountDb.
 *
 * Run: npx vitest run --no-file-parallelism "src/app/api/users/[id]/mcp-tokens/rootTokens.test.ts"
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'

vi.stubEnv('AUTH_SECRET', 'f'.repeat(64))
vi.stubEnv('INTERNAL_API_KEY', 'ik-test-master-0001')

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
import { clearPrincipalCacheForTests } from '@/lib/authz/principal'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import { GET as listTokens } from './route'
import { PATCH as editToken, DELETE as deleteToken } from './[tokenId]/route'

const db = () => h.db as AccountDb
const ROOT = 'root-1'
const REFUSED = 'rbac.root_protected_refused'

function req(method: string, body?: unknown, headers: Record<string, string> = {}): NextRequest {
  const all: Record<string, string> = { host: 'redamon.test', 'content-type': 'application/json', ...headers }
  if (h.jar.actAs) all.cookie = `redamon-act-as=${h.jar.actAs}`
  return new NextRequest('http://redamon.test/api/x', {
    method, headers: all, ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  })
}
const owner = (id: string) => ({ params: Promise.resolve({ id }) })
const token = (id: string, tokenId: string) => ({ params: Promise.resolve({ id, tokenId }) })

async function signIn(userId: string, actingAs?: string) {
  const row = db().account(userId)!
  h.jar.auth = await createToken(userId, String(row.role), Number(row.sessionVersion ?? 0))
  h.jar.actAs = actingAs ? await createActAsToken(userId, actingAs) : undefined
}

const tokenRow = (id: string, userId: string) => ({
  id, userId, name: `${id} name`, tokenPrefix: `rdm_${id}`, scopes: ['recon:read', 'recon:scan'], profile: null,
  lastUsedAt: null, expiresAt: null, revokedAt: null, createdAt: new Date('2026-11-01T00:00:00Z'),
})

type Attempt = { name: string; attempted: string; call: (owner: string, tokenId: string) => Promise<Response> }
const ATTEMPTS: Attempt[] = [
  { name: 'list', attempted: 'list_mcp_tokens', call: (o) => listTokens(req('GET'), owner(o)) },
  { name: 'narrow (drop a scope)', attempted: 'edit_mcp_token', call: (o, t) => editToken(req('PATCH', { scopes: ['recon:read'] }), token(o, t)) },
  { name: 'expire now', attempted: 'edit_mcp_token', call: (o, t) => editToken(req('PATCH', { expiry: 'now' }), token(o, t)) },
  { name: 'delete', attempted: 'delete_mcp_token', call: (o, t) => deleteToken(req('DELETE'), token(o, t)) },
]

beforeEach(() => {
  db().reset()
  db().seedUsers([
    { id: ROOT, name: 'Root', role: 'admin', email: 'root@e2e.local' },
    { id: 'admin-2', role: 'admin', email: 'adm2@e2e.local' },
    { id: 'member-1' },
  ])
  db().seedToken(tokenRow('tok-root', ROOT))
  db().seedToken(tokenRow('tok-member', 'member-1'))
  db().seedInstance({ rootUserId: ROOT, rootAssignedBy: 'automatic' })
  setFlagsForTests({ identity: true })
  clearPrincipalCacheForTests()
  clearInstanceRootCacheForTests()
  h.jar = {}
})
afterEach(() => {
  setFlagsForTests(null)
  vi.restoreAllMocks()
})

const rootToken = () => db().tokens().find((t) => t.id === 'tok-root')

describe("another admin on Root's MCP tokens: root_protected, nothing changed", () => {
  for (const a of ATTEMPTS) {
    test(`${a.name}: an admin`, async () => {
      await signIn('admin-2')
      const res = await a.call(ROOT, 'tok-root')
      expect(res.status).toBe(403)
      const body = await res.json()
      expect(body.code).toBe('root_protected')
      expect(body).not.toHaveProperty('tokens')
      expect(rootToken()).toMatchObject({ scopes: ['recon:read', 'recon:scan'], expiresAt: null, revokedAt: null })
      expect(db().audit()).toMatchObject([{ action: REFUSED, actorId: 'admin-2', targetId: ROOT, after: { attempted: a.attempted } }])
    })

    test(`${a.name}: an admin acting as a member`, async () => {
      await signIn('admin-2', 'member-1')
      const res = await a.call(ROOT, 'tok-root')
      expect(res.status).toBe(403)
      expect(db().audit()).toMatchObject([{ action: REFUSED, actorId: 'admin-2', onBehalfOfUserId: 'member-1' }])
      expect(rootToken()).toBeDefined()
    })
  }

  test('an unconfirmed Root is protected too (the boot chose it)', async () => {
    await signIn('admin-2')
    expect((await listTokens(req('GET'), owner(ROOT))).status).toBe(403)
  })
})

describe('what still works', () => {
  test('Root lists, narrows and deletes its own tokens', async () => {
    await signIn(ROOT)
    expect((await listTokens(req('GET'), owner(ROOT))).status).toBe(200)
    expect((await editToken(req('PATCH', { scopes: ['recon:read'] }), token(ROOT, 'tok-root'))).status).toBe(200)
    expect((await deleteToken(req('DELETE'), token(ROOT, 'tok-root'))).status).toBe(200)
    expect(rootToken()).toBeUndefined()
    expect(db().audit().filter((r) => r.action === REFUSED)).toEqual([])
  })

  test("an admin keeps HD-23's incident exception on a member's tokens", async () => {
    await signIn('admin-2')
    expect((await listTokens(req('GET'), owner('member-1'))).status).toBe(200)
    expect((await editToken(req('PATCH', { expiry: 'now' }), token('member-1', 'tok-member'))).status).toBe(200)
    expect((await deleteToken(req('DELETE'), token('member-1', 'tok-member'))).status).toBe(200)
    expect(db().audit().filter((r) => r.action === REFUSED)).toEqual([])
  })

  test('the internal key (a service, no person) still lists them', async () => {
    const res = await listTokens(req('GET', undefined, { 'x-internal-key': 'ik-test-master-0001' }), owner(ROOT))
    expect(res.status).toBe(200)
    expect((await res.json()).tokens.map((t: { id: string }) => t.id)).toEqual(['tok-root'])
  })

  test('a dangling Root id protects nobody', async () => {
    db().seedInstance({ rootUserId: 'gone', rootAssignedBy: 'automatic' })
    await signIn('admin-2')
    expect((await listTokens(req('GET'), owner(ROOT))).status).toBe(200)
  })
})

describe('switch off: Phase 1, the instance row never read', () => {
  test('an admin lists, narrows and deletes the tokens of the account the row names', async () => {
    setFlagsForTests({ identity: false })
    const read = vi.spyOn(db().instanceSettings, 'findUnique')
    await signIn('admin-2')
    expect((await listTokens(req('GET'), owner(ROOT))).status).toBe(200)
    expect((await editToken(req('PATCH', { expiry: 'now' }), token(ROOT, 'tok-root'))).status).toBe(200)
    expect((await deleteToken(req('DELETE'), token(ROOT, 'tok-root'))).status).toBe(200)
    expect(read).not.toHaveBeenCalled()
    expect(db().audit().filter((r) => r.action === REFUSED)).toEqual([])
  })
})
