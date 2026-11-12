/**
 * POST /api/users/[id]/disable (step 2.3, ID-13, ID-21, UP-05): an admin disables a member.
 * In one transaction: status `disabled`, the password on hold and emptied, the session
 * version raised, every MCP token revoked and the `user.disable` row; a failed audit write
 * leaves all of it undone. Then the member's agent runs stop and its sockets close
 * (`scope: 'account'`), best effort: an unreachable agent leaves the account disabled and
 * logs `[rbac] socket-close failed`. With the identity switch off the route does not exist.
 *
 * Real session helpers and tokens; the database is the in-memory accountDb (transactions
 * roll back); the agent is a fetch double.
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
const HELD = '$2a$12$hash-of-member-1'

function req(body: unknown = {}, opts: { origin?: string; contentType?: string; cookie?: string } = {}): NextRequest {
  const headers: Record<string, string> = { host: 'redamon.test', 'content-type': opts.contentType ?? 'application/json' }
  if (opts.origin !== undefined) headers.origin = opts.origin
  if (opts.cookie) headers.cookie = opts.cookie
  return new NextRequest('http://redamon.test/api/users/x/disable', {
    method: 'POST', headers, body: typeof body === 'string' ? body : JSON.stringify(body),
  })
}
const params = (id: string) => ({ params: Promise.resolve({ id }) })

async function signIn(userId: string, role = 'admin', actingAs?: string) {
  h.jar.auth = await createToken(userId, role, Number(db().account(userId)?.sessionVersion ?? 0))
  h.jar.actAs = actingAs ? await createActAsToken(userId, actingAs) : undefined
}

const agentCalls = (path: string) => fetchMock.mock.calls.filter((c) => String(c[0]).endsWith(path))
const agentBody = (path: string) => JSON.parse(String(agentCalls(path)[0][1].body))

beforeEach(() => {
  db().reset()
  db().seedUsers([
    { id: 'admin-1', role: 'admin', email: 'ada@e2e.local' },
    { id: 'admin-2', role: 'admin' },
    { id: 'member-1' },
    { id: 'member-2' },
  ])
  db().seedToken({ id: 'tok-1', userId: 'member-1' })
  db().seedToken({ id: 'tok-2', userId: 'member-1', revokedAt: new Date('2026-01-01T00:00:00Z') })
  db().seedToken({ id: 'tok-3', userId: 'member-2' })
  setFlagsForTests({ identity: true })
  clearPrincipalCacheForTests()
  h.jar = {}
  fetchMock.mockReset()
  fetchMock.mockImplementation(async (url: string) => new Response(
    JSON.stringify(String(url).endsWith('/ws/close') ? { closed: 2, stopped_runs: 1, by_kind: {} } : { stopped: 1 }),
    { status: 200 },
  ))
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  setFlagsForTests(null)
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('disable a member', () => {
  test('member disabled: status, password on hold, sv bumped, tokens revoked, audit in the same transaction', async () => {
    await signIn('admin-1')
    const res = await POST(req(), params('member-1'))
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({
      id: 'member-1', status: 'disabled', changed: true, tokensRevoked: 1,
      agent: { runs: { stopped: 1 }, sockets: { closed: 2 } },
    })
    expect(db().account('member-1')).toMatchObject({
      status: 'disabled', password: '', passwordOnHold: HELD, sessionVersion: 1,
    })
    const tokens = db().tokens()
    expect(tokens.find((t) => t.id === 'tok-1')!.revokedAt).toBeInstanceOf(Date)
    expect(tokens.find((t) => t.id === 'tok-2')!.revokedAt).toEqual(new Date('2026-01-01T00:00:00Z'))
    expect(tokens.find((t) => t.id === 'tok-3')!.revokedAt).toBeNull()
    expect(db().audit()).toEqual([{
      actorId: 'admin-1', actorEmail: 'ada@e2e.local', action: 'user.disable', targetType: 'user', targetId: 'member-1',
      before: { status: 'active' }, after: { status: 'disabled', sessionVersion: 1, tokensRevoked: 1 }, source: 'api',
    }])
    expect(JSON.stringify(db().audit())).not.toContain('$2a$')
    // One transaction held the change and its row, under the admin-set lock.
    expect(db().transactions).toBe(1)
    expect(db().rawCalls.some((s) => s.includes('pg_advisory_xact_lock'))).toBe(true)
    expect(db().account('member-2')).toMatchObject({ status: 'active', sessionVersion: 0 })
  })

  test('its runs stop and every socket of the four kinds closes, the acting ones too', async () => {
    await signIn('admin-1')
    await POST(req(), params('member-1'))
    expect(agentBody('/agent-sessions/stop-for')).toEqual({ user_id: 'member-1' })
    expect(agentBody('/ws/close')).toEqual({
      user_id: 'member-1', kinds: ['agent', 'kali-terminal', 'cypherfix-triage', 'cypherfix-codefix'], scope: 'account',
    })
    for (const path of ['/agent-sessions/stop-for', '/ws/close']) {
      expect(String(agentCalls(path)[0][0])).toBe(`http://agent.test:8080${path}`)
    }
  })

  test('the member\'s login cookie is refused at once', async () => {
    const memberCookie = await createToken('member-1', 'standard', 0)
    await signIn('admin-1')
    await POST(req(), params('member-1'))
    h.jar = { auth: memberCookie }
    expect(await getSession()).toBeNull()
  })

  test('audit failure → nothing changed', async () => {
    db().failAudit('user.disable')
    const err = vi.spyOn(console, 'error').mockImplementation(() => {})
    await signIn('admin-1')
    const res = await POST(req(), params('member-1'))
    expect(res.status).toBe(500)
    expect(db().account('member-1')).toMatchObject({ status: 'active', password: HELD, passwordOnHold: '', sessionVersion: 0 })
    expect(db().tokens().find((t) => t.id === 'tok-1')!.revokedAt).toBeNull()
    expect(db().audit()).toEqual([])
    expect(fetchMock).not.toHaveBeenCalled()
    expect(err.mock.calls.some((c) => String(c[0]).includes('[audit] failed to persist user.disable'))).toBe(true)
  })

  test('agent unreachable → still disabled and logged', async () => {
    fetchMock.mockImplementation(async () => { throw Object.assign(new TypeError('fetch failed'), { cause: { code: 'ECONNREFUSED' } }) })
    const err = vi.spyOn(console, 'error').mockImplementation(() => {})
    await signIn('admin-1')
    const res = await POST(req(), params('member-1'))
    expect(res.status).toBe(200)
    expect((await res.json()).agent).toEqual({ runs: { error: 'agent_unreachable' }, sockets: { error: 'agent_unreachable' } })
    expect(db().account('member-1')!.status).toBe('disabled')
    expect(db().audit()).toHaveLength(1)
    const lines = err.mock.calls.map((c) => String(c[0]))
    expect(lines).toContain('[rbac] agent-stop failed user=member-1: agent_unreachable')
    expect(lines.some((l) => l.startsWith('[rbac] socket-close failed user=member-1 '))).toBe(true)
  })

  test('the agent refusing the close is reported, the account stays disabled', async () => {
    fetchMock.mockImplementation(async () => new Response('{}', { status: 503 }))
    vi.spyOn(console, 'error').mockImplementation(() => {})
    await signIn('admin-1')
    const res = await POST(req(), params('member-1'))
    expect((await res.json()).agent).toEqual({ runs: { error: 'agent_http_503' }, sockets: { error: 'agent_http_503' } })
    expect(db().account('member-1')!.status).toBe('disabled')
  })

  test('the same disable twice: the second changes nothing and writes no row', async () => {
    await signIn('admin-1')
    await POST(req(), params('member-1'))
    fetchMock.mockClear()
    const res = await POST(req(), params('member-1'))
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ id: 'member-1', status: 'disabled', changed: false })
    expect(db().account('member-1')).toMatchObject({ passwordOnHold: HELD, password: '', sessionVersion: 1 })
    expect(db().audit()).toHaveLength(1)
    expect(fetchMock).not.toHaveBeenCalled()
  })

  test('two disables at once: one disables, the other finds it done, the password stays on hold', async () => {
    await signIn('admin-1')
    const [a, b] = await Promise.all([POST(req(), params('member-1')), POST(req(), params('member-1'))])
    const answers = [await a.json(), await b.json()].map((x) => x.changed).sort()
    expect(answers).toEqual([false, true])
    expect(db().account('member-1')).toMatchObject({ passwordOnHold: HELD, sessionVersion: 1 })
    expect(db().audit()).toHaveLength(1)
  })

  test('under act-as the row names the admin and the account acted for', async () => {
    await signIn('admin-1', 'admin', 'member-2')
    const cookie = `redamon-act-as=${h.jar.actAs}`
    await POST(req({}, { cookie }), params('member-1'))
    expect(db().audit()[0]).toMatchObject({
      actorId: 'admin-1', onBehalfOfUserId: 'member-2', after: { actingAsUserId: 'member-2' },
    })
  })

  test('a passwordless managed account is disabled with nothing on hold', async () => {
    db().seedUsers([{ id: 'managed-1', password: '' }])
    await signIn('admin-1')
    expect((await POST(req(), params('managed-1'))).status).toBe(200)
    expect(db().account('managed-1')).toMatchObject({ status: 'disabled', password: '', passwordOnHold: '', sessionVersion: 1 })
  })
})

describe('refusals: nothing is written', () => {
  afterEach(() => {
    expect(db().account('member-1')).toMatchObject({ status: 'active', sessionVersion: 0 })
    expect(db().audit()).toEqual([])
  })

  test('admin target 403 root_only', async () => {
    await signIn('admin-1')
    const res = await POST(req(), params('admin-2'))
    expect(res.status).toBe(403)
    expect(await res.json()).toEqual({ error: 'Only Root can disable, enable or sign out an admin account.', code: 'root_only' })
    expect(db().account('admin-2')).toMatchObject({ status: 'active', sessionVersion: 0 })
    expect(fetchMock).not.toHaveBeenCalled()
  })

  test('own account 400', async () => {
    await signIn('admin-1')
    const res = await POST(req(), params('admin-1'))
    expect(res.status).toBe(400)
    expect((await res.json()).code).toBe('own_account')
  })

  test('unknown account 404', async () => {
    await signIn('admin-1')
    const res = await POST(req(), params('nobody'))
    expect(res.status).toBe(404)
    expect((await res.json()).code).toBe('user_not_found')
  })

  test('a member 403, coded with the permission', async () => {
    await signIn('member-2', 'standard')
    const res = await POST(req(), params('member-1'))
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'forbidden', permission: 'users:disable' })
  })

  test('a member whose token still says admin 403: the role is read from the database', async () => {
    await signIn('member-2', 'admin')
    expect((await POST(req(), params('member-1'))).status).toBe(403)
  })

  test('no session 401', async () => {
    expect((await POST(req(), params('member-1'))).status).toBe(401)
  })

  test('cross-origin refused', async () => {
    await signIn('admin-1')
    const res = await POST(req({}, { origin: 'https://evil.example' }), params('member-1'))
    expect(res.status).toBe(403)
    expect((await res.json()).code).toBe('cross_origin')
  })

  test('a body that is not JSON 415', async () => {
    await signIn('admin-1')
    expect((await POST(req('a=1', { contentType: 'application/x-www-form-urlencoded' }), params('member-1'))).status).toBe(415)
  })

  test('switch off 404, before any check', async () => {
    setFlagsForTests({ identity: false })
    await signIn('admin-1')
    const res = await POST(req(), params('member-1'))
    expect(res.status).toBe(404)
    h.jar = {}
    expect((await POST(req(), params('member-1'))).status).toBe(404)
  })
})
