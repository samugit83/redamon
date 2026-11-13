/**
 * POST /api/internal/rbac/sweep (step 4.15; SH-14, DV-09, T19): the RBAC expiry sweep. Expiry is
 * judged lazily wherever access is read; the sweep writes the `.expired` audit rows and removes
 * what is dead: expired shares (`project.share.expired`, then the collaborator's live work on that
 * project stops: step 5.9's onAccessReduced, its runs and sockets through the agent), expired overrides (`user.override_expired`), expired break-glass rows
 * and expired unused invite and reset links. The orchestrator's reaper loop calls it.
 *
 * The internal key is the only way in (the real isInternalRequest and middleware). Prisma is an
 * in-memory double whose deleteMany is atomic, like a Postgres DELETE; lib/audit.ts,
 * lib/agentSockets.ts, the switches, the sharing policy reader and the invite link reader are the
 * real ones; the agent (agentFetch) and the clock are doubles.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'

const KEY = 'internal-key-for-test'
vi.stubEnv('INTERNAL_API_KEY', KEY)
vi.stubEnv('AUTH_SECRET', 'b'.repeat(64))

type Row = Record<string, unknown>

const h = vi.hoisted(() => {
  const s = {
    collaborators: [] as Row[],
    breakGlass: [] as Row[],
    overrides: [] as Row[],
    invites: [] as Row[],
    sessions: [] as Row[],
    audit: [] as Row[],
    instance: null as Row | null,
    /** Every table a call read or wrote. */
    touched: new Set<string>(),
    auditFails: false,
    /** Runs after a findMany of expired shares answered: another request acting in between. */
    afterShareRead: null as null | (() => void),
  }
  const matches = (row: Row, where: Row = {}): boolean => Object.entries(where).every(([k, v]) => {
    const value = row[k]
    if (v === null) return value === null || value === undefined
    if (v instanceof Date) return value instanceof Date && value.getTime() === v.getTime()
    if (v && typeof v === 'object' && 'lte' in v) {
      return value instanceof Date && value.getTime() <= (v as { lte: Date }).lte.getTime()
    }
    return value === v
  })
  const table = (name: string, rows: () => Row[], set: (r: Row[]) => void) => ({
    findMany: async (a: { where?: Row; orderBy?: Record<string, 'asc'>; take?: number } = {}) => {
      s.touched.add(name)
      await Promise.resolve()
      let out = rows().filter((r) => matches(r, a.where)).map((r) => ({ ...r }))
      if (a.orderBy?.expiresAt) out.sort((x, y) => (x.expiresAt as Date).getTime() - (y.expiresAt as Date).getTime())
      if (a.take !== undefined) out = out.slice(0, a.take)
      if (name === 'projectCollaborator' && s.afterShareRead) {
        const hook = s.afterShareRead
        s.afterShareRead = null
        hook()
      }
      return out
    },
    deleteMany: async (a: { where?: Row } = {}) => {
      s.touched.add(name)
      const before = rows().length
      set(rows().filter((r) => !matches(r, a.where)))
      return { count: before - rows().length }
    },
    findUnique: async (a: { where: Row }) => {
      s.touched.add(name)
      const row = rows().find((r) => matches(r, a.where))
      if (!row) return null
      // The invite link reader selects the account with the link.
      return name === 'userInvite'
        ? { ...row, user: { id: row.userId, name: 'Nina', email: 'nina@e2e.local', role: 'standard', status: row.kind === 'invite' ? 'invited' : 'active', sessionVersion: 0 } }
        : { ...row }
    },
  })
  const client: Row = {
    projectCollaborator: table('projectCollaborator', () => s.collaborators, (r) => { s.collaborators = r }),
    projectBreakGlass: table('projectBreakGlass', () => s.breakGlass, (r) => { s.breakGlass = r }),
    userPermissionOverride: table('userPermissionOverride', () => s.overrides, (r) => { s.overrides = r }),
    userInvite: table('userInvite', () => s.invites, (r) => { s.invites = r }),
    userSession: table('userSession', () => s.sessions, (r) => { s.sessions = r }),
    // What an ended share's revocation reads (step 5.9): nothing queued, scheduled or running here.
    jobQueue: table('jobQueue', () => [], () => {}),
    scanSchedule: table('scanSchedule', () => [], () => {}),
    triageRun: table('triageRun', () => [], () => {}),
    auditLog: {
      create: async ({ data }: { data: Row }) => {
        s.touched.add('auditLog')
        if (s.auditFails) throw Object.assign(new Error('audit insert failed'), { code: 'P1001' })
        s.audit.push(data)
        return { id: `audit-${s.audit.length}` }
      },
    },
    instanceSettings: {
      findUnique: async () => {
        s.touched.add('instanceSettings')
        return s.instance ? { ...s.instance } : null
      },
    },
    // Rolls back what the callback wrote when it throws, as a Postgres transaction does.
    $transaction: async (fn: (tx: Row) => Promise<unknown>) => {
      const snapshot = { collaborators: s.collaborators, overrides: s.overrides, audit: [...s.audit] }
      try {
        return await fn(client)
      } catch (err) {
        s.collaborators = snapshot.collaborators
        s.overrides = snapshot.overrides
        s.audit = snapshot.audit
        throw err
      }
    },
  }
  return { s, client, agentFetch: vi.fn() }
})

vi.mock('@/lib/prisma', () => ({ default: h.client, prisma: h.client }))
vi.mock('@/lib/agentFetch', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/agentFetch')>()),
  agentFetch: (...a: unknown[]) => h.agentFetch(...a),
}))

import { AgentUnreachableError } from '@/lib/agentFetch'
import { setFlagsForTests, type RbacFlags } from '@/lib/authz/flags'
import { setNowForTests } from '@/lib/authz/clock'
import { clearSharingPolicyCacheForTests } from '@/lib/authz/sharingPolicy'
import { INVITE_COOKIE_NAME, signInviteCookie } from '@/lib/authz/invites'
import { WS_SOCKETS } from '@/lib/wsTicket'
import { GET as inviteState } from '@/app/api/invite/state/route'
import { POST } from './route'

const PATH = '/api/internal/rbac/sweep'
const T0 = new Date('2026-11-13T12:00:00Z')
const ago = (minutes: number) => new Date(T0.getTime() - minutes * 60_000)
const later = (minutes: number) => new Date(T0.getTime() + minutes * 60_000)
const ALL_ON: Partial<RbacFlags> = { identity: true, permissions: true, sharing: true }

function req(headers: Record<string, string> = { 'x-internal-key': KEY }, method = 'POST'): NextRequest {
  return new NextRequest(`http://localhost:3000${PATH}`, { method, headers: { 'Content-Type': 'application/json', ...headers }, body: '{}' })
}

const share = (projectId: string, userId: string, expiresAt: Date | null, extra: Row = {}): Row => ({
  projectId, userId, access: 'read', runScans: false, useAgent: false, exploit: false, rawData: false, manage: false,
  expiresAt, note: 'kept out of the audit row', grantedById: 'owner-1', createdAt: ago(10_000), updatedAt: ago(10_000), ...extra,
})
const override = (userId: string, permission: string, expiresAt: Date | null, effect = 'grant'): Row => ({
  userId, permission, effect, expiresAt, reason: 'temporary access', grantedById: 'admin-1', createdAt: ago(10_000),
})
const link = (id: string, kind: 'invite' | 'reset', expiresAt: Date, extra: Row = {}): Row => ({
  id, userId: `user-of-${id}`, kind, tokenHash: `hash-${id}`, expiresAt, usedAt: null, cancelledAt: null,
  createdById: 'admin-1', reason: null, createdAt: ago(10_000), ...extra,
})
const breakGlass = (id: string, expiresAt: Date): Row => ({
  id, projectId: 'proj-1', userId: 'root-1', reason: 'incident 42', expiresAt, createdAt: ago(300),
})

const agentAnswers = () => h.agentFetch.mockImplementation(async () => new Response(JSON.stringify({ closed: 1, stopped_runs: 0 }), { status: 200 }))
const closeCalls = () => h.agentFetch.mock.calls.map(([path, init]) => ({ path, body: JSON.parse((init as RequestInit).body as string) }))
const sweep = async () => {
  const res = await POST(req())
  return { status: res.status, body: await res.json() }
}

beforeEach(() => {
  Object.assign(h.s, {
    collaborators: [], breakGlass: [], overrides: [], invites: [], sessions: [], audit: [],
    instance: { id: 'instance', sharingPolicy: { enabled: true }, passwordMinLength: 12, passwordAskChangeIfShort: false },
    auditFails: false, afterShareRead: null,
  })
  h.s.touched.clear()
  h.agentFetch.mockReset()
  agentAnswers()
  setFlagsForTests(ALL_ON)
  setNowForTests(() => T0)
  clearSharingPolicyCacheForTests()
  vi.spyOn(console, 'info').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
  vi.restoreAllMocks()
})

describe('internal key only', () => {
  test('no key, a wrong key or the scanner key: 401, nothing read or removed', async () => {
    vi.stubEnv('SCANNER_API_KEY', 'scanner-key-for-test')
    h.s.collaborators = [share('proj-1', 'viewer-1', ago(5))]
    for (const headers of [{}, { 'x-internal-key': 'nope' }, { 'x-internal-key': 'scanner-key-for-test' }] as Record<string, string>[]) {
      expect((await POST(req(headers))).status).toBe(401)
    }
    expect(h.s.touched.size).toBe(0)
    expect(h.s.collaborators).toHaveLength(1)
    expect(h.agentFetch).not.toHaveBeenCalled()
  })

  test('a signed-in browser has no way in: a session cookie without the key is 401', async () => {
    expect((await POST(req({ cookie: 'redamon-auth=whatever' }))).status).toBe(401)
    expect(h.s.touched.size).toBe(0)
  })
})

describe('allowed with the allowlist enforced', () => {
  test('the middleware lets the orchestrator through with INTERNAL_KEY_ALLOWLIST_ENFORCE=true, POST only', async () => {
    vi.stubEnv('INTERNAL_KEY_ALLOWLIST_ENFORCE', 'true')
    vi.resetModules()
    const { middleware, internalKeyRouteAllowed, scannerKeyRouteAllowed } = await import('@/middleware')
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    expect(internalKeyRouteAllowed('POST', PATH)).toBe(true)
    const passed = await middleware(req())
    expect(passed.status).toBe(200)
    expect(passed.headers.get('x-middleware-next')).toBe('1')
    // Only POST, only this path, never the scanner key.
    expect(internalKeyRouteAllowed('GET', PATH)).toBe(false)
    expect(internalKeyRouteAllowed('POST', `${PATH}/x`)).toBe(false)
    expect(internalKeyRouteAllowed('POST', '/api/internal/rbac')).toBe(false)
    expect(scannerKeyRouteAllowed('POST', PATH)).toBe(false)
    const refused = await middleware(new NextRequest(`http://localhost:3000${PATH}`, { method: 'GET', headers: { 'x-internal-key': KEY } }))
    expect(refused.status).toBe(401)
  })
})

describe('expired rows audited and removed', () => {
  test('an expired share: removed, audited project.share.expired by the system, then its sockets on that project closed', async () => {
    h.s.collaborators = [share('proj-1', 'viewer-1', ago(5), { rawData: true })]
    const { status, body } = await sweep()
    expect(status).toBe(200)
    expect(h.s.collaborators).toEqual([])
    expect(h.s.audit).toEqual([{
      actorId: null,
      projectId: 'proj-1',
      action: 'project.share.expired',
      targetType: 'user',
      targetId: 'viewer-1',
      before: {
        access: 'read', rawData: true, runScans: false, useAgent: false, exploit: false, manage: false,
        expiresAt: ago(5).toISOString(), grantedById: 'owner-1',
      },
      source: 'system',
    }])
    expect(closeCalls()).toEqual([
      { path: '/agent-sessions/stop-for', body: { user_id: 'viewer-1', project_ids: ['proj-1'] } },
      { path: '/ws/close', body: { user_id: 'viewer-1', project_id: 'proj-1', kinds: [...WS_SOCKETS], scope: 'access' } },
    ])
    expect(body).toMatchObject({ at: T0.toISOString(), removed: { shares: 1 }, socketCloseFailed: 0, failed: [] })
  })

  test('an expired override: removed and audited user.override_expired, nothing closed', async () => {
    h.s.overrides = [override('member-1', 'recon:run', ago(1)), override('member-2', 'agent:chat', ago(60), 'deny')]
    const { status, body } = await sweep()
    expect(status).toBe(200)
    expect(h.s.overrides).toEqual([])
    expect(h.s.audit).toEqual([
      {
        actorId: null, action: 'user.override_expired', targetType: 'user', targetId: 'member-2',
        before: { permission: 'agent:chat', effect: 'deny', expiresAt: ago(60).toISOString(), reason: 'temporary access' },
        source: 'system',
      },
      {
        actorId: null, action: 'user.override_expired', targetType: 'user', targetId: 'member-1',
        before: { permission: 'recon:run', effect: 'grant', expiresAt: ago(1).toISOString(), reason: 'temporary access' },
        source: 'system',
      },
    ])
    expect(body.removed.overrides).toBe(2)
    expect(h.agentFetch).not.toHaveBeenCalled()
  })

  test('expired break-glass rows and expired unused links of both kinds: removed, no audit row', async () => {
    h.s.breakGlass = [breakGlass('bg-1', ago(1)), breakGlass('bg-2', ago(500))]
    h.s.invites = [
      link('inv-1', 'invite', ago(1)),
      link('rst-1', 'reset', ago(90)),
      link('inv-cancelled', 'invite', ago(30), { cancelledAt: ago(60) }),
    ]
    const { body } = await sweep()
    expect(h.s.breakGlass).toEqual([])
    expect(h.s.invites).toEqual([])
    expect(h.s.audit).toEqual([])
    expect(body.removed).toEqual({ shares: 0, breakGlass: 2, overrides: 0, links: 3 })
  })

  test('a used link is kept even once expired: it is the record of how the account was set up', async () => {
    h.s.invites = [link('inv-used', 'invite', ago(60), { usedAt: ago(120) })]
    await sweep()
    expect(h.s.invites.map((r) => r.id)).toEqual(['inv-used'])
  })

  test('a row expiring exactly now is expired, as every access check reads it', async () => {
    h.s.collaborators = [share('proj-1', 'viewer-1', T0)]
    h.s.overrides = [override('member-1', 'recon:run', T0)]
    h.s.breakGlass = [breakGlass('bg-1', T0)]
    h.s.invites = [link('inv-1', 'invite', T0)]
    const { body } = await sweep()
    expect(body.removed).toEqual({ shares: 1, breakGlass: 1, overrides: 1, links: 1 })
  })

  test('the /invite page answers a swept link exactly as an expired one: {valid: false}', async () => {
    h.s.invites = [link('inv-live', 'invite', later(60)), link('inv-old', 'invite', ago(1))]
    const page = async (id: string) => {
      const cookie = `${INVITE_COOKIE_NAME}=${await signInviteCookie(id)}`
      const res = await inviteState(new NextRequest('http://redamon.test/api/invite/state', { headers: { cookie } }))
      return { status: res.status, body: await res.json() }
    }
    // A live link answers who it is for, so the cookie and the reader work.
    expect(await page('inv-live')).toMatchObject({ status: 200, body: { valid: true, kind: 'invite' } })
    const expired = await page('inv-old')
    expect(expired).toEqual({ status: 200, body: { valid: false } })
    await sweep()
    expect(h.s.invites.map((r) => r.id)).toEqual(['inv-live'])
    expect(await page('inv-old')).toEqual(expired)
  })
})

describe('live rows kept', () => {
  test('shares, overrides, break-glass rows and links with no expiry or a later one stay; nothing audited or closed', async () => {
    h.s.collaborators = [share('proj-1', 'viewer-1', null), share('proj-1', 'viewer-2', later(1))]
    h.s.overrides = [override('member-1', 'recon:run', null), override('member-1', 'agent:chat', later(60))]
    h.s.breakGlass = [breakGlass('bg-1', later(30))]
    h.s.invites = [link('inv-1', 'invite', later(1)), link('rst-1', 'reset', later(30))]
    const { status, body } = await sweep()
    expect(status).toBe(200)
    expect(h.s.collaborators).toHaveLength(2)
    expect(h.s.overrides).toHaveLength(2)
    expect(h.s.breakGlass).toHaveLength(1)
    expect(h.s.invites).toHaveLength(2)
    expect(h.s.audit).toEqual([])
    expect(h.agentFetch).not.toHaveBeenCalled()
    expect(body.removed).toEqual({ shares: 0, breakGlass: 0, overrides: 0, links: 0 })
  })

  test('only the expired share of a project goes; the live one beside it stays', async () => {
    h.s.collaborators = [share('proj-1', 'viewer-1', ago(1)), share('proj-1', 'viewer-2', later(1))]
    await sweep()
    expect(h.s.collaborators.map((r) => r.userId)).toEqual(['viewer-2'])
    expect(h.s.audit.map((r) => r.targetId)).toEqual(['viewer-1'])
  })
})

describe('idempotent', () => {
  test('the same expiry swept twice: one audit row, one stop and one socket close; the second sweep finds nothing', async () => {
    h.s.collaborators = [share('proj-1', 'viewer-1', ago(5))]
    h.s.overrides = [override('member-1', 'recon:run', ago(5))]
    h.s.invites = [link('inv-1', 'invite', ago(5))]
    expect((await sweep()).body.removed).toEqual({ shares: 1, breakGlass: 0, overrides: 1, links: 1 })
    const second = await sweep()
    expect(second.status).toBe(200)
    expect(second.body.removed).toEqual({ shares: 0, breakGlass: 0, overrides: 0, links: 0 })
    expect(h.s.audit.map((r) => r.action)).toEqual(['user.override_expired', 'project.share.expired'])
    expect(closeCalls().map((c) => c.path)).toEqual(['/agent-sessions/stop-for', '/ws/close'])
  })

  test('two sweeps at once (two webapp copies): both read the same rows, each expiry is audited and closed once', async () => {
    h.s.collaborators = [share('proj-1', 'viewer-1', ago(5)), share('proj-2', 'viewer-1', ago(3))]
    h.s.overrides = [override('member-1', 'recon:run', ago(5))]
    const [a, b] = await Promise.all([sweep(), sweep()])
    expect([a.status, b.status]).toEqual([200, 200])
    expect(a.body.removed.shares + b.body.removed.shares).toBe(2)
    expect(a.body.removed.overrides + b.body.removed.overrides).toBe(1)
    expect(h.s.audit.filter((r) => r.action === 'project.share.expired').map((r) => r.projectId).sort()).toEqual(['proj-1', 'proj-2'])
    expect(h.s.audit.filter((r) => r.action === 'user.override_expired')).toHaveLength(1)
    expect(closeCalls().filter((c) => c.path === '/ws/close').map((c) => c.body.project_id).sort()).toEqual(['proj-1', 'proj-2'])
  })

  test('a share renewed between the read and the delete is kept and not audited', async () => {
    h.s.collaborators = [share('proj-1', 'viewer-1', ago(5))]
    h.s.afterShareRead = () => { h.s.collaborators = [share('proj-1', 'viewer-1', later(60 * 24))] }
    const { body } = await sweep()
    expect(body.removed.shares).toBe(0)
    expect(h.s.collaborators).toHaveLength(1)
    expect(h.s.audit).toEqual([])
    expect(h.agentFetch).not.toHaveBeenCalled()
  })

  test('the audit row cannot be written: the share stays, the answer is 500 sweep_incomplete, the other parts still run', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    h.s.collaborators = [share('proj-1', 'viewer-1', ago(5))]
    h.s.invites = [link('inv-1', 'invite', ago(5))]
    h.s.breakGlass = [breakGlass('bg-1', ago(5))]
    h.s.auditFails = true
    const { status, body } = await sweep()
    expect(status).toBe(500)
    expect(body).toMatchObject({ code: 'sweep_incomplete', failed: ['shares'] })
    expect(h.s.collaborators).toHaveLength(1)
    expect(h.agentFetch).not.toHaveBeenCalled()
    expect(h.s.invites).toEqual([])
    expect(h.s.breakGlass).toEqual([])
    expect(String(vi.mocked(console.error).mock.calls.map((c) => c.join(' ')))).toMatch(/\[rbac\] sweep failed part=shares/)
    // The next sweep, with the database back, audits it then.
    h.s.auditFails = false
    expect((await sweep()).body.removed.shares).toBe(1)
    expect(h.s.audit.map((r) => r.action)).toEqual(['project.share.expired'])
  })
})

describe('the agent unreachable when a socket must close', () => {
  test('the expiry still lands and logs [rbac] socket-close failed', async () => {
    const errors = vi.spyOn(console, 'error').mockImplementation(() => {})
    h.agentFetch.mockRejectedValue(new AgentUnreachableError('agent down'))
    h.s.collaborators = [share('proj-1', 'viewer-1', ago(5))]
    const { status, body } = await sweep()
    expect(status).toBe(200)
    expect(h.s.collaborators).toEqual([])
    expect(h.s.audit.map((r) => r.action)).toEqual(['project.share.expired'])
    expect(body).toMatchObject({ removed: { shares: 1 }, socketCloseFailed: 1, failed: [] })
    expect(errors.mock.calls.map((c) => String(c[0]))).toContainEqual(
      expect.stringContaining('[rbac] socket-close failed user=viewer-1 project=proj-1'),
    )
    expect(errors.mock.calls.map((c) => String(c[0])).join('\n')).toContain('agent_unreachable')
  })

  test('an agent answering an error counts as a failed close too', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    h.agentFetch.mockResolvedValue(new Response('{}', { status: 503 }))
    h.s.collaborators = [share('proj-1', 'viewer-1', ago(5))]
    const { status, body } = await sweep()
    expect(status).toBe(200)
    expect(body.socketCloseFailed).toBe(1)
  })

  test('the agent down with many expiries: one batch is tried, the rest counted, every expiry still lands', async () => {
    const errors = vi.spyOn(console, 'error').mockImplementation(() => {})
    h.agentFetch.mockRejectedValue(new AgentUnreachableError('agent down'))
    h.s.collaborators = Array.from({ length: 20 }, (_, i) => share(`proj-${i}`, 'viewer-1', ago(5 + i)))
    const { status, body } = await sweep()
    expect(status).toBe(200)
    expect(h.s.collaborators).toEqual([])
    expect(h.s.audit).toHaveLength(20)
    // One batch of 8 expiries, each a stop and a close (step 5.9); the other 12 are not tried.
    expect(h.agentFetch).toHaveBeenCalledTimes(16)
    expect(body.socketCloseFailed).toBe(20)
    expect(errors.mock.calls.map((c) => String(c[0])).filter((l) => /^\[rbac\] revocation step failed step=close_sockets reason=share_expired user=viewer-1 project=proj-\d+: agent_unreachable$/.test(l))).toHaveLength(8)
    expect(errors.mock.calls.map((c) => String(c[0]))).toContainEqual('[rbac] socket-close failed for 12 more expired share(s): the agent did not answer')
  })
})

describe('each part only with its switch on (DV-30)', () => {
  const everyKind = () => {
    h.s.collaborators = [share('proj-1', 'viewer-1', ago(5))]
    h.s.breakGlass = [breakGlass('bg-1', ago(5))]
    h.s.overrides = [override('member-1', 'recon:run', ago(5))]
    h.s.invites = [link('inv-1', 'invite', ago(5))]
  }

  test('every switch off: 200, nothing read, nothing removed, nothing audited', async () => {
    setFlagsForTests({})
    everyKind()
    const { status, body } = await sweep()
    expect(status).toBe(200)
    expect(body.removed).toEqual({ shares: null, breakGlass: null, overrides: null, links: null })
    expect([...h.s.touched]).toEqual([])
    expect([h.s.collaborators, h.s.breakGlass, h.s.overrides, h.s.invites].map((t) => t.length)).toEqual([1, 1, 1, 1])
  })

  test('identity on only: the links are swept; overrides and the sharing tables are not read', async () => {
    setFlagsForTests({ identity: true })
    everyKind()
    const { body } = await sweep()
    expect(body.removed).toEqual({ shares: null, breakGlass: null, overrides: null, links: 1 })
    expect([...h.s.touched].sort()).toEqual(['userInvite'])
  })

  test('permissions on, sharing off: overrides and links are swept; no sharing table and no policy is read', async () => {
    setFlagsForTests({ identity: true, permissions: true })
    everyKind()
    const { body } = await sweep()
    expect(body.removed).toEqual({ shares: null, breakGlass: null, overrides: 1, links: 1 })
    expect([...h.s.touched].sort()).toEqual(['auditLog', 'userInvite', 'userPermissionOverride'])
  })

  test('sharing switched on but the instance policy disabled (the stored {}): no collaborator or break-glass row is read', async () => {
    h.s.instance = { id: 'instance', sharingPolicy: {} }
    everyKind()
    const { body } = await sweep()
    expect(body.removed).toEqual({ shares: null, breakGlass: null, overrides: 1, links: 1 })
    expect(h.s.touched.has('projectCollaborator')).toBe(false)
    expect(h.s.touched.has('projectBreakGlass')).toBe(false)
    expect(h.s.collaborators).toHaveLength(1)
    expect(h.agentFetch).not.toHaveBeenCalled()
  })

  test('the policy cannot be read: the two sharing parts fail (500), the others run', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    everyKind()
    h.client.instanceSettings = { findUnique: async () => { throw Object.assign(new Error('db down'), { code: 'P1001' }) } }
    try {
      const { status, body } = await sweep()
      expect(status).toBe(500)
      expect(body.failed).toEqual(['shares', 'breakGlass'])
      expect(body.removed).toMatchObject({ overrides: 1, links: 1, shares: null, breakGlass: null })
      expect(h.s.collaborators).toHaveLength(1)
    } finally {
      h.client.instanceSettings = { findUnique: async () => ({ ...h.s.instance }) }
    }
  })
})

// Step 6.10: device sessions are kept 30 days after they ended (revoked, signed out or expired), with
// the address and browser they hold, then removed without an audit row; only with the governance switch.
describe('device sessions (step 6.10)', () => {
  const GOVERNANCE: Partial<RbacFlags> = { ...ALL_ON, governance: true }
  const DAY = 24 * 60
  const deviceRow = (id: string, extra: Row): Row => ({
    id, userId: 'member-1', sessionVersion: 0, createdAt: ago(60 * DAY), lastSeenAt: ago(40 * DAY), expiresAt: later(DAY),
    ip: '192.0.2.1', ipTrusted: false, userAgent: 'Firefox', revokedAt: null, revokedById: null, endedBy: null, ...extra,
  })

  test('governance on: a row revoked or expired 30 days ago or more is removed, a younger or live one stays, no audit row', async () => {
    setFlagsForTests(GOVERNANCE)
    h.s.sessions = [
      deviceRow('revoked-31d', { revokedAt: ago(31 * DAY), endedBy: 'admin' }),
      deviceRow('signed-out-30d', { revokedAt: ago(30 * DAY), endedBy: 'sign_out' }),
      deviceRow('expired-45d', { expiresAt: ago(45 * DAY) }),
      deviceRow('revoked-29d', { revokedAt: ago(29 * DAY), endedBy: 'self' }),
      deviceRow('expired-2d', { expiresAt: ago(2 * DAY) }),
      deviceRow('live', {}),
    ]
    const { status, body } = await sweep()
    expect(status).toBe(200)
    expect(body.removed).toEqual({ shares: 0, breakGlass: 0, overrides: 0, links: 0, devices: 3 })
    expect(h.s.sessions.map((r) => r.id).sort()).toEqual(['expired-2d', 'live', 'revoked-29d'])
    expect(h.s.audit).toEqual([])
    expect((await sweep()).body.removed.devices).toBe(0)
  })

  test('governance off (the other switches on): no device session is read, and the answer has no devices key', async () => {
    h.s.sessions = [deviceRow('revoked-31d', { revokedAt: ago(31 * DAY) })]
    const { body } = await sweep()
    expect(body.removed).toEqual({ shares: 0, breakGlass: 0, overrides: 0, links: 0 })
    expect(h.s.touched.has('userSession')).toBe(false)
    expect(h.s.sessions).toHaveLength(1)
  })

  test('the part fails: 500 sweep_incomplete naming it, the other parts still ran', async () => {
    setFlagsForTests(GOVERNANCE)
    vi.spyOn(console, 'error').mockImplementation(() => {})
    const client = h.client as { userSession: { deleteMany: (...a: unknown[]) => Promise<unknown> } }
    vi.spyOn(client.userSession, 'deleteMany').mockRejectedValueOnce(Object.assign(new Error('db down'), { code: 'P1001' }))
    h.s.overrides = [override('member-1', 'agent:chat', ago(1))]
    const { status, body } = await sweep()
    expect(status).toBe(500)
    expect(body).toMatchObject({ code: 'sweep_incomplete', failed: ['devices'], removed: { overrides: 1, devices: null } })
  })
})
