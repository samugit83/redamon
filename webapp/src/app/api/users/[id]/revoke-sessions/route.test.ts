/**
 * POST /api/users/[id]/revoke-sessions (step 2.3, ID-21): an admin signs a member out
 * everywhere. The session version is raised and every MCP token revoked, with the
 * `user.sessions_revoked` row, in one transaction; then the member's sockets close
 * (`scope: 'account'`). The account stays active and signs in again normally. Identity
 * switch only.
 *
 * Real session helpers and tokens; the database is the in-memory accountDb; the agent is a
 * fetch double.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'

vi.stubEnv('AUTH_SECRET', 'f'.repeat(64))
vi.stubEnv('INTERNAL_API_KEY', 'ik-test-master-0001')
vi.stubEnv('AGENT_API_URL', 'http://agent.test:8080')

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
import { getSession } from '@/lib/session'
import { POST } from './route'

const db = () => h.db as AccountDb
const fetchMock = vi.fn()

function req(body: unknown = {}, opts: { origin?: string; contentType?: string } = {}): NextRequest {
  const headers: Record<string, string> = { host: 'redamon.test', 'content-type': opts.contentType ?? 'application/json' }
  if (opts.origin !== undefined) headers.origin = opts.origin
  return new NextRequest('http://redamon.test/api/users/x/revoke-sessions', {
    method: 'POST', headers, body: typeof body === 'string' ? body : JSON.stringify(body),
  })
}
const params = (id: string) => ({ params: Promise.resolve({ id }) })
const cookieOf = async (userId: string, role = 'standard') =>
  createToken(userId, role, Number(db().account(userId)?.sessionVersion ?? 0))
async function signIn(userId: string, role = 'admin') {
  h.jar.auth = await cookieOf(userId, role)
}

beforeEach(() => {
  db().reset()
  db().seedUsers([{ id: 'admin-1', role: 'admin' }, { id: 'admin-2', role: 'admin' }, { id: 'member-1' }, { id: 'member-2' }])
  db().seedToken({ id: 'tok-1', userId: 'member-1' })
  db().seedToken({ id: 'tok-2', userId: 'member-2' })
  setFlagsForTests({ identity: true })
  clearPrincipalCacheForTests()
  h.jar = {}
  fetchMock.mockReset()
  fetchMock.mockImplementation(async () => new Response(JSON.stringify({ closed: 1, stopped_runs: 0, by_kind: {} }), { status: 200 }))
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  setFlagsForTests(null)
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('sign a member out everywhere', () => {
  test('old cookie refused after; a new sign-in works', async () => {
    const old = await cookieOf('member-1')
    await signIn('admin-1')
    const res = await POST(req(), params('member-1'))
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ id: 'member-1', revoked: true, tokensRevoked: 1, agent: { sockets: { closed: 1 } } })
    h.jar = { auth: old }
    expect(await getSession()).toBeNull()
    h.jar = { auth: await cookieOf('member-1') }
    expect(await getSession()).toEqual({ userId: 'member-1', role: 'standard' })
  })

  test('version raised, tokens revoked, the row in the same transaction; the account stays active', async () => {
    await signIn('admin-1')
    await POST(req(), params('member-1'))
    expect(db().account('member-1')).toMatchObject({ status: 'active', sessionVersion: 1 })
    expect(db().tokens().map((t) => [t.id, t.revokedAt instanceof Date])).toEqual([['tok-1', true], ['tok-2', false]])
    expect(db().audit()).toEqual([expect.objectContaining({
      actorId: 'admin-1', action: 'user.sessions_revoked', targetType: 'user', targetId: 'member-1',
      after: { sessionVersion: 1, tokensRevoked: 1 },
    })])
    expect(db().transactions).toBe(1)
  })

  test('every socket of the four kinds closes, the acting ones too; no run is stopped by name', async () => {
    await signIn('admin-1')
    await POST(req(), params('member-1'))
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(String(fetchMock.mock.calls[0][0])).toBe('http://agent.test:8080/ws/close')
    expect(JSON.parse(String(fetchMock.mock.calls[0][1].body))).toEqual({
      user_id: 'member-1', kinds: ['agent', 'kali-terminal', 'cypherfix-triage', 'cypherfix-codefix'], scope: 'account',
    })
  })

  test('the same revoke twice raises the version twice and writes two rows', async () => {
    await signIn('admin-1')
    await POST(req(), params('member-1'))
    const second = await POST(req(), params('member-1'))
    expect((await second.json()).tokensRevoked).toBe(0)
    expect(db().account('member-1')!.sessionVersion).toBe(2)
    expect(db().audit()).toHaveLength(2)
  })

  test('agent unreachable: still revoked, the failure reported and logged', async () => {
    fetchMock.mockImplementation(async () => { throw new TypeError('fetch failed') })
    const err = vi.spyOn(console, 'error').mockImplementation(() => {})
    await signIn('admin-1')
    const res = await POST(req(), params('member-1'))
    expect(res.status).toBe(200)
    expect((await res.json()).agent).toEqual({ sockets: { error: 'agent_unreachable' } })
    expect(db().account('member-1')!.sessionVersion).toBe(1)
    expect(err.mock.calls.some((c) => String(c[0]).startsWith('[rbac] socket-close failed user=member-1 '))).toBe(true)
  })

  test('audit failure → nothing changed', async () => {
    db().failAudit('user.sessions_revoked')
    vi.spyOn(console, 'error').mockImplementation(() => {})
    await signIn('admin-1')
    expect((await POST(req(), params('member-1'))).status).toBe(500)
    expect(db().account('member-1')!.sessionVersion).toBe(0)
    expect(db().tokens()[0].revokedAt).toBeNull()
    expect(fetchMock).not.toHaveBeenCalled()
  })
})

describe('refusals: nothing is written', () => {
  afterEach(() => {
    expect(db().account('member-1')!.sessionVersion).toBe(0)
    expect(db().audit()).toEqual([])
    expect(fetchMock).not.toHaveBeenCalled()
  })

  test('admin target 403 root_only', async () => {
    await signIn('admin-1')
    const res = await POST(req(), params('admin-2'))
    expect(res.status).toBe(403)
    expect((await res.json()).code).toBe('root_only')
    expect(db().account('admin-2')!.sessionVersion).toBe(0)
  })

  test('own account 400, pointing to revoke-all', async () => {
    await signIn('admin-1')
    const res = await POST(req(), params('admin-1'))
    expect(res.status).toBe(400)
    expect(await res.json()).toMatchObject({ code: 'own_account', error: expect.stringContaining('/api/auth/sessions/revoke-all') })
  })

  test('a member 403, coded with the permission', async () => {
    await signIn('member-2', 'standard')
    const res = await POST(req(), params('member-1'))
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'forbidden', permission: 'users:revoke_sessions' })
  })

  test('no session 401', async () => {
    expect((await POST(req(), params('member-1'))).status).toBe(401)
  })

  test('cross-origin refused', async () => {
    await signIn('admin-1')
    expect((await POST(req({}, { origin: 'https://evil.example' }), params('member-1'))).status).toBe(403)
  })

  test('a body that is not JSON 415', async () => {
    await signIn('admin-1')
    expect((await POST(req('x', { contentType: 'text/plain' }), params('member-1'))).status).toBe(415)
  })

  test('unknown account 404', async () => {
    await signIn('admin-1')
    expect((await (await POST(req(), params('nobody'))).json()).code).toBe('user_not_found')
  })

  test('switch off 404', async () => {
    setFlagsForTests({ identity: false })
    await signIn('admin-1')
    expect((await POST(req(), params('member-1'))).status).toBe(404)
  })
})
