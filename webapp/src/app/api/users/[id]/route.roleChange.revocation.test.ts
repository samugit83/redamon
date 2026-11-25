/**
 * A role change ends the account's open sockets (step 5.13, the pending item of step 5.9; SH-12): with
 * the identity switch on a role change raises the account's session version in its transaction, which
 * ends every cookie signed for the old role, but a socket is checked only when it opens. Once the change
 * has committed the revocation path closes every socket of the account (scope `account`): a promotion
 * plays `role_promoted` (nothing lost, the person's runs and Kali sandbox go on); a demotion plays
 * `capability_removed`, since it takes the admin-only permissions away (its runs stop, its sandboxes
 * stop), and turns off a tunnel the demoted admin may still have up (G-03). An edit that changes no
 * role asks the agent nothing; a refused role change neither. With the agent down the role change
 * still lands and the failed close is logged.
 *
 * Real session helpers, tokens, bcrypt, step-up, Root re-check and revocation path; the database is the
 * in-memory accountDb; the agent is a double that records what it was asked.
 *
 * Run: npx vitest run --no-file-parallelism 'src/app/api/users/[id]/route.roleChange.revocation.test.ts'
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'
import bcrypt from 'bcryptjs'

vi.stubEnv('AUTH_SECRET', 'f'.repeat(64))

const h = vi.hoisted(() => ({
  db: null as unknown,
  jar: {} as { auth?: string },
  agent: [] as Array<{ path: string; body: Record<string, unknown> }>,
  agentDown: false,
  enforceTunnel: vi.fn(async (_userId: string) => ({ turnedOff: false, warning: null })),
}))
vi.mock('@/lib/sharedSettingsEffects', async (orig) => ({
  ...(await orig<typeof import('@/lib/sharedSettingsEffects')>()),
  enforceTunnelPermission: (userId: string) => h.enforceTunnel(userId),
}))
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
vi.mock('@/lib/agentFetch', async (orig) => {
  const actual = await orig<typeof import('@/lib/agentFetch')>()
  return {
    ...actual,
    agentFetch: async (path: string, init: { body?: string } = {}) => {
      h.agent.push({ path, body: init.body ? JSON.parse(init.body) : {} })
      if (h.agentDown) throw new actual.AgentUnreachableError('connect ECONNREFUSED')
      return new Response(JSON.stringify({ closed: 1 }), { status: 200 })
    },
  }
})

import type { AccountDb } from '@/lib/authz/__testing__/accountDb'
import { createToken } from '@/lib/auth'
import { setFlagsForTests } from '@/lib/authz/flags'
import { clearPrincipalCacheForTests } from '@/lib/authz/principal'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import { setNowForTests } from '@/lib/authz/clock'
import { __resetThrottle } from '@/lib/loginThrottle'
import { PUT as editUser } from './route'

const db = () => h.db as AccountDb
const ROOT = 'root-1'
const ROOT_PW = 'root-own-passphrase-0001'

function req(body: unknown): NextRequest {
  return new NextRequest('http://redamon.test/api/users/x', {
    method: 'PUT', headers: { host: 'redamon.test', 'content-type': 'application/json' }, body: JSON.stringify(body),
  })
}
const params = (id: string) => ({ params: Promise.resolve({ id }) })

beforeEach(async () => {
  db().reset()
  db().seedUsers([
    { id: ROOT, name: 'Root', role: 'admin', email: 'root@e2e.local', password: bcrypt.hashSync(ROOT_PW, 4) },
    { id: 'admin-2', name: 'Pia', role: 'admin', email: 'adm2@e2e.local', password: bcrypt.hashSync('admin-two-passphrase-0002', 4) },
    { id: 'member-1', name: 'Marco', email: 'mem1@e2e.local', password: bcrypt.hashSync('member-one-passphrase-0003', 4) },
  ])
  db().seedInstance({ rootUserId: ROOT, rootAssignedBy: 'host', rootConfirmedAt: new Date('2026-11-12T08:00:00Z') })
  setFlagsForTests({ identity: true })
  setNowForTests(() => new Date('2026-11-13T12:00:00Z'))
  clearPrincipalCacheForTests()
  clearInstanceRootCacheForTests()
  __resetThrottle()
  h.agent = []
  h.agentDown = false
  h.enforceTunnel.mockClear()
  const row = db().account(ROOT)!
  h.jar.auth = await createToken(ROOT, String(row.role), Number(row.sessionVersion ?? 0))
  vi.spyOn(console, 'info').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
  vi.restoreAllMocks()
})

const closes = () => h.agent.filter((c) => c.path === '/ws/close').map((c) => c.body)

describe('a role change closes the account\'s open sockets once it has committed', () => {
  test('a promotion: the session version rose and every socket of the account closes, scope account', async () => {
    const before = Number(db().account('member-1')!.sessionVersion ?? 0)
    const res = await editUser(req({ role: 'admin', stepUpPassword: ROOT_PW }), params('member-1'))
    expect(res.status).toBe(200)
    expect(Number(db().account('member-1')!.sessionVersion)).toBe(before + 1)
    expect(closes()).toEqual([{ user_id: 'member-1', kinds: expect.arrayContaining(['agent']), scope: 'account' }])
    // A session plan stops no run: the person signs in again and goes on (step 5.9's SESSIONS plan).
    expect(h.agent.map((c) => c.path)).toEqual(['/ws/close'])
    expect(h.enforceTunnel).not.toHaveBeenCalled()
  })

  test('a demotion by Root, under the last-admin guard: the capability plan (runs stop), the same close, the tunnel turned off', async () => {
    const res = await editUser(req({ role: 'standard', stepUpPassword: ROOT_PW }), params('admin-2'))
    expect(res.status).toBe(200)
    expect(closes()).toEqual([{ user_id: 'admin-2', kinds: expect.any(Array), scope: 'account' }])
    expect(h.agent.filter((c) => c.path === '/agent-sessions/stop-for').map((c) => c.body)).toEqual([{ user_id: 'admin-2' }])
    expect(h.enforceTunnel.mock.calls).toEqual([['admin-2']])
  })

  test('a demotion whose tunnel turn-off throws still lands, and says so', async () => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => {})
    h.enforceTunnel.mockRejectedValueOnce(new Error('db down'))
    const res = await editUser(req({ role: 'standard', stepUpPassword: ROOT_PW }), params('admin-2'))
    expect(res.status).toBe(200)
    expect(db().account('admin-2')!.role).toBe('standard')
    expect(error.mock.calls.map((c) => String(c[0]))).toContain('[rbac] tunnel turn-off after a demotion failed user=admin-2: internal_error')
  })

  test('an edit that changes no role, or sets the role it has, asks the agent nothing', async () => {
    expect((await editUser(req({ name: 'Marco R.' }), params('member-1'))).status).toBe(200)
    expect((await editUser(req({ role: 'standard' }), params('member-1'))).status).toBe(200)
    expect(h.agent).toEqual([])
  })

  test('a refused role change (no password) closes nothing', async () => {
    expect((await editUser(req({ role: 'admin' }), params('member-1'))).status).toBe(403)
    expect(h.agent).toEqual([])
  })

  test('the agent down: the role change still lands and the failed close is logged', async () => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => {})
    h.agentDown = true
    const res = await editUser(req({ role: 'admin', stepUpPassword: ROOT_PW }), params('member-1'))
    expect(res.status).toBe(200)
    expect(db().account('member-1')!.role).toBe('admin')
    const lines = error.mock.calls.map((c) => String(c[0]))
    expect(lines.some((l) => l.startsWith('[rbac] socket-close failed user=member-1'))).toBe(true)
    expect(lines.some((l) => l.startsWith('[rbac] revocation step failed step=close_sockets reason=role_promoted user=member-1'))).toBe(true)
  })
})
