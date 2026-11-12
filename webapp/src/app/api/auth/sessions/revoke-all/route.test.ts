/**
 * POST /api/auth/sessions/revoke-all (step 2.3, ID-21): "sign out everywhere" for the
 * signed-in account. Every login cookie of it ends (this browser's is also cleared in the
 * answer), its MCP tokens are revoked and its sockets close. The account is the real
 * signed-in one: an admin acting as a member signs the admin out, never the member.
 * Identity switch only.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'

vi.stubEnv('AUTH_SECRET', 'f'.repeat(64))
vi.stubEnv('INTERNAL_API_KEY', 'ik-test-master-0001')
vi.stubEnv('AGENT_API_URL', 'http://agent.test:8080')

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
import { getSession } from '@/lib/session'
import { POST } from './route'

const db = () => h.db as AccountDb
const fetchMock = vi.fn()

function req(body: unknown = {}, opts: { origin?: string; contentType?: string; cookie?: string } = {}): NextRequest {
  const headers: Record<string, string> = { host: 'redamon.test', 'content-type': opts.contentType ?? 'application/json' }
  if (opts.origin !== undefined) headers.origin = opts.origin
  if (opts.cookie) headers.cookie = opts.cookie
  return new NextRequest('http://redamon.test/api/auth/sessions/revoke-all', {
    method: 'POST', headers, body: typeof body === 'string' ? body : JSON.stringify(body),
  })
}
const cookieOf = async (userId: string, role = 'standard') =>
  createToken(userId, role, Number(db().account(userId)?.sessionVersion ?? 0))

beforeEach(() => {
  db().reset()
  db().seedUsers([{ id: 'admin-1', role: 'admin' }, { id: 'member-1' }, { id: 'member-2' }])
  db().seedToken({ id: 'tok-1', userId: 'member-1' })
  db().seedToken({ id: 'tok-2', userId: 'member-2' })
  setFlagsForTests({ identity: true })
  clearPrincipalCacheForTests()
  h.jar = {}
  fetchMock.mockReset()
  fetchMock.mockImplementation(async () => new Response(JSON.stringify({ closed: 0, stopped_runs: 0, by_kind: {} }), { status: 200 }))
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  setFlagsForTests(null)
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('sign out everywhere', () => {
  test('every cookie of the account ends, this one is cleared, its tokens are revoked', async () => {
    const otherBrowser = await cookieOf('member-1')
    h.jar = { auth: await cookieOf('member-1') }
    const res = await POST(req())
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ id: 'member-1', revoked: true, tokensRevoked: 1, agent: { sockets: { closed: 0 } } })
    const cleared = res.headers.getSetCookie()
    expect(cleared.some((c) => /^redamon-auth=;/.test(c) && /Max-Age=0/i.test(c))).toBe(true)
    expect(cleared.some((c) => /^redamon-act-as=;/.test(c) && /Max-Age=0/i.test(c))).toBe(true)
    h.jar = { auth: otherBrowser }
    expect(await getSession()).toBeNull()
    expect(db().account('member-1')!.sessionVersion).toBe(1)
    expect(db().tokens().map((t) => t.revokedAt instanceof Date)).toEqual([true, false])
    expect(db().account('member-2')!.sessionVersion).toBe(0)
    expect(db().audit()).toEqual([expect.objectContaining({
      actorId: 'member-1', action: 'user.sessions_revoked', targetId: 'member-1', after: { sessionVersion: 1, tokensRevoked: 1 },
    })])
  })

  test('the sockets of the account close, scope account', async () => {
    h.jar = { auth: await cookieOf('member-1') }
    await POST(req())
    expect(JSON.parse(String(fetchMock.mock.calls[0][1].body))).toEqual({
      user_id: 'member-1', kinds: ['agent', 'kali-terminal', 'cypherfix-triage', 'cypherfix-codefix'], scope: 'account',
    })
  })

  test('an admin acting as a member signs the admin out, not the member', async () => {
    h.jar = { auth: await cookieOf('admin-1', 'admin'), actAs: await createActAsToken('admin-1', 'member-1') }
    const res = await POST(req({}, { cookie: `redamon-act-as=${h.jar.actAs}` }))
    expect(res.status).toBe(200)
    expect(db().account('admin-1')!.sessionVersion).toBe(1)
    expect(db().account('member-1')!.sessionVersion).toBe(0)
    expect(db().audit()[0]).toMatchObject({ actorId: 'admin-1', targetId: 'admin-1', onBehalfOfUserId: 'member-1' })
  })

  test('an admin signs itself out (no Root needed for one\'s own account)', async () => {
    h.jar = { auth: await cookieOf('admin-1', 'admin') }
    expect((await POST(req())).status).toBe(200)
    expect(db().account('admin-1')!.sessionVersion).toBe(1)
  })

  test('audit failure → nothing changed, the cookie kept', async () => {
    db().failAudit('user.sessions_revoked')
    vi.spyOn(console, 'error').mockImplementation(() => {})
    h.jar = { auth: await cookieOf('member-1') }
    const res = await POST(req())
    expect(res.status).toBe(500)
    expect(res.headers.getSetCookie()).toEqual([])
    expect(db().account('member-1')!.sessionVersion).toBe(0)
  })
})

describe('refusals', () => {
  afterEach(() => expect(db().account('member-1')!.sessionVersion).toBe(0))

  test('no session 401', async () => {
    expect((await POST(req())).status).toBe(401)
  })

  test('cross-origin refused', async () => {
    h.jar = { auth: await cookieOf('member-1') }
    const res = await POST(req({}, { origin: 'https://evil.example' }))
    expect(res.status).toBe(403)
    expect((await res.json()).code).toBe('cross_origin')
  })

  test('a body that is not JSON 415', async () => {
    h.jar = { auth: await cookieOf('member-1') }
    expect((await POST(req('x', { contentType: 'text/plain' }))).status).toBe(415)
  })

  test('switch off 404', async () => {
    setFlagsForTests({ identity: false })
    h.jar = { auth: await cookieOf('member-1') }
    expect((await POST(req())).status).toBe(404)
  })
})
