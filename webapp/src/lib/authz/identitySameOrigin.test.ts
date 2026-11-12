/**
 * Same-origin JSON on the identity routes Phase 1 changed (step 2.12, ID-26, T14): creating an
 * account, editing or deleting one, setting a password, acting as someone, and minting, editing
 * or deleting an MCP token. A request whose Origin is another site is refused with 403
 * `cross_origin` and changes nothing; a write whose body is not JSON is refused with 415 (an HTML
 * form can only send urlencoded, multipart or text/plain). The session check still answers first,
 * so a caller without a session gets the answer it got after Phase 1. A request without an Origin
 * (a script, a server-side caller) and one from this host pass on to the route's own checks. A
 * DELETE carries no body (a member's deletion, stopping act-as, revoking a token) and needs none.
 *
 * The check is a security fix of Phase 1 routes, so it runs whatever RBAC_IDENTITY_ENABLED says:
 * every case runs with the switch off and on.
 *
 * Real session helpers and tokens; the database is the in-memory accountDb; the project teardown
 * is a double that must not run.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/authz/identitySameOrigin.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'

vi.stubEnv('AUTH_SECRET', 'f'.repeat(64))
vi.stubEnv('INTERNAL_API_KEY', 'ik-test-master-0001')
vi.stubEnv('AGENT_API_URL', 'http://agent.test:8080')
vi.stubEnv('PLUGINS_ALLOWED_ORIGIN', '')

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
vi.mock('@/lib/projectTeardown', () => ({
  teardownProject: async () => { throw new Error('no project is torn down here') },
}))

import type { AccountDb } from '@/lib/authz/__testing__/accountDb'
import { createToken, createActAsToken } from '@/lib/auth'
import { setFlagsForTests } from './flags'
import { clearPrincipalCacheForTests } from './principal'
import { POST as createUser } from '@/app/api/users/route'
import { PUT as editUser, DELETE as deleteUser } from '@/app/api/users/[id]/route'
import { PUT as setPassword } from '@/app/api/users/[id]/password/route'
import { POST as startActAs, DELETE as stopActAs } from '@/app/api/auth/act-as/route'
import { POST as mintToken } from '@/app/api/users/[id]/mcp-tokens/route'
import { PATCH as editToken, DELETE as deleteToken } from '@/app/api/users/[id]/mcp-tokens/[tokenId]/route'

const db = () => h.db as AccountDb
const HOST = 'redamon.test'
const FOREIGN = 'https://evil.example'

interface Send { origin?: string | null; contentType?: string | null; body?: string }

function req(method: string, path: string, send: Send = {}): NextRequest {
  const headers: Record<string, string> = { host: HOST }
  if (send.origin) headers.origin = send.origin
  if (send.contentType) headers['content-type'] = send.contentType
  if (h.jar.actAs) headers.cookie = `redamon-act-as=${h.jar.actAs}`
  return new NextRequest(`http://${HOST}${path}`, { method, headers, ...(send.body === undefined ? {} : { body: send.body }) })
}
const one = (id: string) => ({ params: Promise.resolve({ id }) })
const two = (id: string, tokenId: string) => ({ params: Promise.resolve({ id, tokenId }) })

async function signIn(userId: string, actingAs?: string) {
  const row = db().account(userId)!
  h.jar.auth = await createToken(userId, String(row.role), Number(row.sessionVersion ?? 0))
  h.jar.actAs = actingAs ? await createActAsToken(userId, actingAs) : undefined
}

/** Everything a refused request could have changed. */
function state() {
  return JSON.stringify({
    users: ['admin-1', 'admin-2', 'member-1'].map((id) => db().account(id)),
    tokens: db().tokens(),
    audit: db().audit(),
    actAs: db().actAs(),
  })
}

interface Route {
  name: string
  method: 'POST' | 'PUT' | 'PATCH' | 'DELETE'
  path: string
  /** Who sends it: a session the route admits. */
  actor: string
  actingAs?: string
  /** A body the route refuses after its own checks, so passing the origin check changes nothing. */
  probe?: Record<string, unknown>
  /** The answer to the probe (or to the bodiless request) once the origin check lets it through. */
  passes: { status: number; has?: string }
  /** The answer without any session, as after Phase 1. */
  anonymous: number
  call: (r: NextRequest) => Promise<Response>
}

const ROUTES: Route[] = [
  {
    name: 'POST /api/users', method: 'POST', path: '/api/users', actor: 'admin-1',
    probe: {}, passes: { status: 400, has: 'Name and email are required' }, anonymous: 403,
    call: (r) => createUser(r),
  },
  {
    name: 'PUT /api/users/[id]', method: 'PUT', path: '/api/users/member-1', actor: 'admin-1',
    probe: { defaultAgentModel: 'loop/mcp' }, passes: { status: 400, has: 'loop_model_not_allowed' }, anonymous: 401,
    call: (r) => editUser(r, one('member-1')),
  },
  {
    name: 'PUT /api/users/[id]/password', method: 'PUT', path: '/api/users/member-1/password', actor: 'admin-1',
    probe: { newPassword: 'short' }, passes: { status: 400, has: 'password_too_short' }, anonymous: 401,
    call: (r) => setPassword(r, one('member-1')),
  },
  {
    name: 'POST /api/auth/act-as', method: 'POST', path: '/api/auth/act-as', actor: 'admin-1',
    probe: {}, passes: { status: 400, has: 'targetUserId is required' }, anonymous: 401,
    call: (r) => startActAs(r),
  },
  {
    name: 'POST /api/users/[id]/mcp-tokens', method: 'POST', path: '/api/users/member-1/mcp-tokens', actor: 'member-1',
    probe: {}, passes: { status: 400, has: 'A token name is required' }, anonymous: 401,
    call: (r) => mintToken(r, one('member-1')),
  },
  {
    name: 'PATCH /api/users/[id]/mcp-tokens/[tokenId]', method: 'PATCH', path: '/api/users/member-1/mcp-tokens/tok-1',
    actor: 'member-1', probe: {}, passes: { status: 400, has: 'Nothing to change' }, anonymous: 401,
    call: (r) => editToken(r, two('member-1', 'tok-1')),
  },
  {
    // The own account: refused after the origin check, so nothing is deleted when it passes.
    name: 'DELETE /api/users/[id]', method: 'DELETE', path: '/api/users/admin-1', actor: 'admin-1',
    passes: { status: 400, has: 'Cannot delete your own account' }, anonymous: 403,
    call: (r) => deleteUser(r, one('admin-1')),
  },
  {
    // No act-as cookie: stopping writes no row, so passing changes nothing.
    name: 'DELETE /api/auth/act-as', method: 'DELETE', path: '/api/auth/act-as', actor: 'admin-1',
    passes: { status: 200, has: '"actingAs":null' }, anonymous: 401,
    call: (r) => stopActAs(r),
  },
  {
    name: 'DELETE /api/users/[id]/mcp-tokens/[tokenId]', method: 'DELETE', path: '/api/users/member-1/mcp-tokens/tok-none',
    actor: 'member-1', passes: { status: 404 }, anonymous: 401,
    call: (r) => deleteToken(r, two('member-1', 'tok-none')),
  },
]

function send(route: Route, over: Send): NextRequest {
  const body = route.probe === undefined ? undefined : JSON.stringify(route.probe)
  return req(route.method, route.path, {
    contentType: route.probe === undefined ? null : 'application/json',
    body,
    ...over,
  })
}

beforeEach(() => {
  db().reset()
  db().seedUsers([
    { id: 'admin-1', role: 'admin', email: 'ada@e2e.local' },
    { id: 'admin-2', role: 'admin' },
    { id: 'member-1' },
  ])
  db().seedToken({ id: 'tok-1', userId: 'member-1', name: 'ci', scopes: ['recon:read'] })
  clearPrincipalCacheForTests()
  h.jar = {}
})
afterEach(() => {
  setFlagsForTests(null)
  vi.restoreAllMocks()
})

for (const identity of [false, true]) {
  const mode = identity ? 'switch on' : 'switch off'

  describe(`identity routes accept only same-origin JSON (${mode})`, () => {
    beforeEach(() => setFlagsForTests({ identity }))

    for (const route of ROUTES) {
      test(`${route.name}: cross-origin refused, nothing changed`, async () => {
        await signIn(route.actor, route.actingAs)
        const before = state()
        const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
        const res = await route.call(send(route, { origin: FOREIGN }))
        expect(res.status).toBe(403)
        expect(await res.json()).toMatchObject({ code: 'cross_origin' })
        expect(state()).toBe(before)
        expect(res.headers.get('set-cookie')).toBeNull()
        expect(warn.mock.calls.flat().join(' ')).toContain('evil.example')
      })

      test(`${route.name}: from this host and without an Origin it reaches the route's own checks`, async () => {
        await signIn(route.actor, route.actingAs)
        for (const origin of [`http://${HOST}`, null]) {
          const res = await route.call(send(route, { origin }))
          expect(res.status).toBe(route.passes.status)
          if (route.passes.has) expect(await res.text()).toContain(route.passes.has)
        }
      })

      test(`${route.name}: without a session the Phase 1 answer comes first`, async () => {
        const res = await route.call(send(route, { origin: FOREIGN }))
        expect(res.status).toBe(route.anonymous)
        expect(JSON.stringify(await res.json())).not.toContain('cross_origin')
      })

      if (route.probe !== undefined) {
        test(`${route.name}: a body that is not JSON 415, nothing changed`, async () => {
          await signIn(route.actor, route.actingAs)
          const before = state()
          for (const [contentType, body] of [
            ['text/plain', JSON.stringify(route.probe)],
            ['application/x-www-form-urlencoded', 'name=x'],
            [null, JSON.stringify(route.probe)],
          ] as const) {
            const res = await route.call(send(route, { origin: `http://${HOST}`, contentType, body }))
            expect(res.status).toBe(415)
          }
          expect(state()).toBe(before)
        })

        test(`${route.name}: JSON that does not parse 400`, async () => {
          await signIn(route.actor, route.actingAs)
          const res = await route.call(send(route, { origin: `http://${HOST}`, body: '{"name":' }))
          expect(res.status).toBe(400)
        })
      }
    }
  })
}

describe('a DELETE needs no body (switch off and on)', () => {
  for (const identity of [false, true]) {
    test(`a member is deleted with a bodiless same-origin DELETE (${identity ? 'on' : 'off'})`, async () => {
      setFlagsForTests({ identity })
      await signIn('admin-1')
      const res = await deleteUser(req('DELETE', '/api/users/member-1', { origin: `http://${HOST}` }), one('member-1'))
      expect(res.status).toBe(200)
      expect(db().account('member-1')).toBeUndefined()
    })
  }

  test('stopping act-as with the cookie, from this host, clears it and names the target', async () => {
    setFlagsForTests({ identity: false })
    await signIn('admin-1', 'member-1')
    const res = await stopActAs(req('DELETE', '/api/auth/act-as', { origin: `http://${HOST}` }))
    expect(res.status).toBe(200)
    expect(res.headers.get('set-cookie') || '').toMatch(/redamon-act-as=;.*Max-Age=0/i)
    expect(db().actAs()).toMatchObject([{ adminId: 'admin-1', targetUserId: 'member-1', event: 'end' }])
  })
})
