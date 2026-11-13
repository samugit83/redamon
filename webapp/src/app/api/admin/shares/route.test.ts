/**
 * GET /api/admin/shares and DELETE /api/admin/shares/[projectId]/[userId] (step 6.4; GV-05, GV-20,
 * SH-18): the admin console's shares overview and Root's force-revoke. With RBAC_GOVERNANCE_ENABLED
 * off both are 404 having read nothing; with sharing not in force both are 404 having read no share;
 * the list needs users:read and Root's policy letting administrators see every share (403
 * `shares_hidden` otherwise, Root included); the force-revoke is the confirmed Root's with its
 * password, removes the share and writes `project.share.revoke` with `after.forced` in one
 * transaction (no row, no change), then closes the collaborator's sockets, best effort.
 *
 * The routes, lib/authz/adminShares.ts, projectShares.ts's policy gate, rootPowers.ts and the audit
 * writers are real; the session, the permission answers, the Root, the step-up check, the act-as
 * reader, the sharing policy, the agent's socket close and Prisma are doubles (inline, with a
 * transaction that rolls back what it wrote when it throws).
 *
 * Run: npx vitest run --no-file-parallelism src/app/api/admin/shares/route.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

interface Share {
  projectId: string; userId: string; access: string; rawData: boolean; runScans: boolean; useAgent: boolean
  exploit: boolean; manage: boolean; expiresAt: Date | null; grantedById: string; createdAt: Date
}

const h = vi.hoisted(() => ({
  session: { userId: 'adm-a', role: 'admin' } as { userId: string; role: string } | null,
  held: new Set<string>(),
  root: { userId: 'root-1', confirmed: true } as { userId: string; confirmed: boolean } | null,
  actingAs: null as string | null,
  password: 'root-pass',
  policy: null as null | { enabled: boolean; adminsSeeAllShares: boolean },
  touched: [] as string[],
  shares: [] as Share[],
  audit: [] as Record<string, unknown>[],
  failAudit: false,
  db: { findMany: vi.fn(), count: vi.fn() },
  close: vi.fn(),
}))

vi.mock('@/lib/prisma', () => {
  const key = (w: { projectId?: string; userId?: string; projectId_userId?: { projectId: string; userId: string } }) =>
    w.projectId_userId ?? { projectId: w.projectId!, userId: w.userId! }
  const tables = (shares: Share[], audit: Record<string, unknown>[]) => ({
    projectCollaborator: {
      findMany: h.db.findMany,
      count: h.db.count,
      findUnique: vi.fn(async ({ where }: { where: never }) => {
        const k = key(where)
        return shares.find((s) => s.projectId === k.projectId && s.userId === k.userId) ?? null
      }),
      deleteMany: vi.fn(async ({ where }: { where: never }) => {
        const k = key(where)
        const i = shares.findIndex((s) => s.projectId === k.projectId && s.userId === k.userId)
        if (i < 0) return { count: 0 }
        shares.splice(i, 1)
        return { count: 1 }
      }),
    },
    auditLog: {
      create: vi.fn(async ({ data }: { data: Record<string, unknown> }) => {
        if (h.failAudit) throw Object.assign(new Error('audit down'), { code: 'P1001' })
        audit.push(data)
        return { id: `al-${audit.length}`, ...data }
      }),
    },
  })
  const client = {
    ...tables(h.shares, h.audit),
    // Serialised, and rolled back when the callback throws: work on copies, commit on success.
    $transaction: vi.fn(async (fn: (tx: unknown) => Promise<unknown>) => {
      const shares = h.shares.map((s) => ({ ...s }))
      const audit = [...h.audit]
      const out = await fn(tables(shares, audit))
      h.shares.splice(0, h.shares.length, ...shares)
      h.audit.splice(0, h.audit.length, ...audit)
      return out
    }),
  }
  return { default: client, prisma: client }
})
vi.mock('@/lib/session', () => ({
  requireSession: vi.fn(async () => { h.touched.push('session'); return h.session ?? NextResponse.json({ error: 'Unauthorized' }, { status: 401 }) }),
}))
vi.mock('@/lib/authz/adminPermission', async () => {
  const { forbiddenResponse } = await import('@/lib/authz/guards')
  return {
    sessionHolds: vi.fn(async (_s: unknown, p: string) => h.held.has(p)),
    requireSessionPermission: vi.fn(async (_s: unknown, p: Parameters<typeof forbiddenResponse>[0]) => (h.held.has(p) ? null : forbiddenResponse(p))),
  }
})
vi.mock('@/lib/authz/root', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/authz/root')>()),
  loadInstanceRoot: vi.fn(async () => h.root),
}))
vi.mock('@/lib/authz/stepUp', async () => {
  const { NextResponse: R } = await import('next/server')
  return {
    requireStepUp: vi.fn(async (_r: unknown, password: unknown) => {
      h.touched.push('step-up')
      if (!password) return R.json({ error: 'Enter your password to confirm this action.', code: 'step_up_required' }, { status: 403 })
      return password === h.password ? null : R.json({ error: 'Password is incorrect', code: 'step_up_failed' }, { status: 403 })
    }),
  }
})
vi.mock('@/lib/userAudit', () => ({ actingAsUserId: vi.fn(async () => h.actingAs) }))
vi.mock('@/lib/authz/sharingPolicy', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/authz/sharingPolicy')>()),
  sharingPolicyInForce: vi.fn(async () => { h.touched.push('policy'); return h.policy }),
}))
vi.mock('@/lib/agentSockets', () => ({ closeAgentSockets: h.close }))

import { setFlagsForTests } from '@/lib/authz/flags'
import { setNowForTests } from '@/lib/authz/clock'
import { encodeShareCursor } from '@/lib/authz/adminShares'
import { GET as listShares } from './route'
import { DELETE as revokeShare } from './[projectId]/[userId]/route'

const NOW = new Date('2026-11-13T12:00:00.000Z')
const GOV = { identity: true, permissions: true, governance: true }
const SHARING = { ...GOV, sharing: true }
const VISIBLE = { enabled: true, adminsSeeAllShares: true }

function record(over: Record<string, unknown> = {}) {
  return {
    projectId: 'p-1', userId: 'mem-b', access: 'read', rawData: true, runScans: false, useAgent: false, exploit: false,
    manage: false, expiresAt: null, createdAt: new Date('2026-11-10T08:00:00.000Z'),
    user: { id: 'mem-b', name: 'Member B', email: 'mem-b@e2e.local', status: 'active' },
    project: { id: 'p-1', name: 'Lab', user: { id: 'mem-a', name: 'Member A', email: 'mem-a@e2e.local' } },
    ...over,
  }
}

function share(over: Partial<Share> = {}): Share {
  return {
    projectId: 'p-1', userId: 'mem-b', access: 'read', rawData: true, runScans: false, useAgent: false, exploit: false,
    manage: false, expiresAt: null, grantedById: 'mem-a', createdAt: new Date('2026-11-10T08:00:00.000Z'), ...over,
  }
}

const list = (qs = '') => listShares(new NextRequest(`http://redamon.test/api/admin/shares${qs ? `?${qs}` : ''}`))
function revoke(projectId = 'p-1', userId = 'mem-b', payload: unknown = { stepUpPassword: h.password }, headers: Record<string, string> = {}) {
  return revokeShare(new NextRequest(`http://redamon.test/api/admin/shares/${projectId}/${userId}`, {
    method: 'DELETE',
    headers: { 'content-type': 'application/json', host: 'redamon.test', origin: 'http://redamon.test', ...headers },
    body: typeof payload === 'string' ? payload : JSON.stringify(payload),
  }), { params: Promise.resolve({ projectId, userId }) })
}
const body = async (res: Response) => res.json() as Promise<Record<string, any>>
const findManyArg = () => h.db.findMany.mock.calls[0][0]

beforeEach(() => {
  setFlagsForTests(SHARING)
  setNowForTests(() => NOW)
  h.session = { userId: 'adm-a', role: 'admin' }
  h.held = new Set(['users:read'])
  h.root = { userId: 'root-1', confirmed: true }
  h.actingAs = null
  h.policy = VISIBLE
  h.touched = []
  h.shares.splice(0)
  h.audit.splice(0)
  h.failAudit = false
  h.db.findMany.mockReset().mockResolvedValue([])
  h.db.count.mockReset().mockResolvedValue(0)
  h.close.mockReset().mockResolvedValue({ ok: true, closed: 1, stoppedRuns: 0 })
  vi.spyOn(console, 'info').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
  vi.restoreAllMocks()
})

describe('with RBAC_GOVERNANCE_ENABLED off', () => {
  test.each([
    ['every switch off', {}],
    ['identity, permissions and sharing on', { identity: true, permissions: true, sharing: true }],
  ])('%s: the list and the revoke are 404 and read nothing', async (_what, flags) => {
    setFlagsForTests(flags)
    h.shares.push(share())
    expect((await list()).status).toBe(404)
    expect((await revoke()).status).toBe(404)
    expect(h.touched).toEqual([])
    expect(h.db.findMany).not.toHaveBeenCalled()
    expect(h.shares).toHaveLength(1)
  })
})

describe('GET /api/admin/shares', () => {
  test('401 without a session; 403 naming users:read without it, no share read', async () => {
    h.session = null
    expect((await list()).status).toBe(401)
    h.session = { userId: 'aud-a', role: 'admin' }
    h.held = new Set(['projects:oversee'])
    const res = await list()
    expect(res.status).toBe(403)
    expect(await body(res)).toMatchObject({ code: 'forbidden', permission: 'users:read' })
    expect(h.db.findMany).not.toHaveBeenCalled()
  })

  test.each([
    ['the sharing switch off', GOV, VISIBLE, false],
    ['the switch on, the policy disabled', SHARING, { enabled: false, adminsSeeAllShares: true }, true],
  ])('%s: 404, no share read', async (_what, flags, policy, policyRead) => {
    setFlagsForTests(flags)
    h.policy = policy
    expect((await list()).status).toBe(404)
    expect(h.db.findMany).not.toHaveBeenCalled()
    expect(h.touched.includes('policy')).toBe(policyRead)
  })

  test('shares list hidden when the policy says so: 403 shares_hidden for an admin and for Root, no share read', async () => {
    h.policy = { enabled: true, adminsSeeAllShares: false }
    const res = await list()
    expect(res.status).toBe(403)
    expect(await body(res)).toMatchObject({ code: 'shares_hidden' })
    h.session = { userId: 'root-1', role: 'admin' }
    expect((await body(await list())).code).toBe('shares_hidden')
    expect(h.db.findMany).not.toHaveBeenCalled()
  })

  test('every share with owner, collaborator, level, toggles and expiry; expired marked; no revoke for an admin', async () => {
    h.db.findMany.mockResolvedValue([
      record(),
      record({
        projectId: 'p-2', userId: 'mem-c', rawData: false, expiresAt: new Date('2026-11-12T00:00:00.000Z'),
        user: { id: 'mem-c', name: 'Member C', email: 'mem-c@e2e.local', status: 'disabled' },
        project: { id: 'p-2', name: 'Range', user: { id: 'mem-a', name: 'Member A', email: 'mem-a@e2e.local' } },
      }),
    ])
    h.db.count.mockResolvedValue(2)
    const page = await body(await list())
    expect(page).toMatchObject({ total: 2, nextCursor: null, actions: { revoke: false } })
    expect(page.shares).toEqual([
      {
        project: { id: 'p-1', name: 'Lab' }, owner: { id: 'mem-a', name: 'Member A', email: 'mem-a@e2e.local' },
        collaborator: { id: 'mem-b', name: 'Member B', email: 'mem-b@e2e.local', status: 'active' },
        access: 'read', toggles: { rawData: true, runScans: false, useAgent: false, exploit: false, manage: false },
        expiresAt: null, expired: false, createdAt: '2026-11-10T08:00:00.000Z',
      },
      expect.objectContaining({
        project: { id: 'p-2', name: 'Range' }, collaborator: expect.objectContaining({ status: 'disabled' }),
        expiresAt: '2026-11-12T00:00:00.000Z', expired: true,
      }),
    ])
    const arg = findManyArg()
    expect(arg.where).toEqual({})
    expect(arg.orderBy).toEqual([{ createdAt: 'desc' }, { projectId: 'desc' }, { userId: 'desc' }])
    expect(arg.take).toBe(51)
    // Never the note nor who granted it: the overview shows terms, not free text.
    expect(arg.select.note).toBeUndefined()
  })

  test('the confirmed Root is offered the force-revoke; an unconfirmed Root is not', async () => {
    h.session = { userId: 'root-1', role: 'admin' }
    expect((await body(await list())).actions).toEqual({ revoke: true })
    h.root = { userId: 'root-1', confirmed: false }
    expect((await body(await list())).actions).toEqual({ revoke: false })
  })

  test('filters and pagination: q, project, user, a cursor and the next one; the total ignores the cursor', async () => {
    const rows = [record({ userId: 'u-3' }), record({ userId: 'u-2' }), record({ userId: 'u-1' })]
    h.db.findMany.mockResolvedValue(rows)
    h.db.count.mockResolvedValue(9)
    const cursor = encodeShareCursor({ createdAt: new Date('2026-11-11T08:00:00.000Z'), projectId: 'p-9', userId: 'u-9' })
    const page = await body(await list(`q=lab&project=p-1&user=mem-a&limit=2&cursor=${cursor}`))
    const like = { contains: 'lab', mode: 'insensitive' }
    const where = {
      AND: [
        { OR: [{ project: { name: like } }, { user: { name: like } }, { user: { email: like } },
          { project: { user: { name: like } } }, { project: { user: { email: like } } }] },
        { projectId: 'p-1' },
        { OR: [{ userId: 'mem-a' }, { project: { userId: 'mem-a' } }] },
      ],
    }
    const at = new Date('2026-11-11T08:00:00.000Z')
    expect(findManyArg().where).toEqual({
      AND: [where, { OR: [
        { createdAt: { lt: at } }, { createdAt: at, projectId: { lt: 'p-9' } }, { createdAt: at, projectId: 'p-9', userId: { lt: 'u-9' } },
      ] }],
    })
    expect(h.db.count).toHaveBeenCalledWith({ where })
    expect(page.shares).toHaveLength(2)
    expect(page.nextCursor).toBe(encodeShareCursor({ createdAt: rows[1].createdAt, projectId: 'p-1', userId: 'u-2' }))
  })

  test.each([['limit=0', 'limit'], ['cursor=bm9wZQ', 'cursor'], [`project=${'p'.repeat(201)}`, 'project']])(
    '%s: 400 invalid_filter naming %s', async (qs, field) => {
      const res = await list(qs)
      expect(res.status).toBe(400)
      expect(await body(res)).toMatchObject({ code: 'invalid_filter', field })
      expect(h.db.findMany).not.toHaveBeenCalled()
    })
})

describe("DELETE /api/admin/shares/[projectId]/[userId]: Root's force-revoke", () => {
  beforeEach(() => {
    h.session = { userId: 'root-1', role: 'admin' }
    h.shares.push(share({ manage: true, rawData: false }))
  })

  test('actions need their permission: an admin gets 403 root_only before any password, the share stays', async () => {
    h.session = { userId: 'adm-a', role: 'admin' }
    const res = await revoke()
    expect(res.status).toBe(403)
    expect(await body(res)).toMatchObject({ code: 'root_only' })
    expect(h.touched).not.toContain('step-up')
    expect(h.shares).toHaveLength(1)
    expect(h.close).not.toHaveBeenCalled()
  })

  test('a wrong or missing password, cross-origin and non-JSON are refused; the share stays', async () => {
    expect((await body(await revoke('p-1', 'mem-b', { stepUpPassword: 'wrong' }))).code).toBe('step_up_failed')
    expect((await body(await revoke('p-1', 'mem-b', {}))).code).toBe('step_up_required')
    expect((await body(await revoke('p-1', 'mem-b', undefined, { origin: 'https://evil.example' }))).code).toBe('cross_origin')
    expect((await revoke('p-1', 'mem-b', 'x', { 'content-type': 'text/plain' })).status).toBe(415)
    expect(h.shares).toHaveLength(1)
    expect(h.audit).toEqual([])
  })

  test('sharing not in force: 404 before any password is checked, no share read', async () => {
    h.policy = { enabled: false, adminsSeeAllShares: true }
    expect((await revoke()).status).toBe(404)
    expect(h.touched).not.toContain('step-up')
    expect(h.shares).toHaveLength(1)
  })

  test('force-revoke audited and runs the revocation: row gone, project.share.revoke with after.forced, sockets closed', async () => {
    const res = await revoke()
    expect(res.status).toBe(200)
    expect(await body(res)).toEqual({ revoked: { projectId: 'p-1', userId: 'mem-b' }, forced: true, socketsClosed: true })
    expect(h.shares).toEqual([])
    expect(h.audit).toEqual([expect.objectContaining({
      actorId: 'root-1', action: 'project.share.revoke', projectId: 'p-1', permission: 'projects:administer',
      targetType: 'user', targetId: 'mem-b', source: 'api',
      before: { access: 'read', rawData: false, runScans: false, useAgent: false, exploit: false, manage: true, expiresAt: null, grantedById: 'mem-a' },
      after: { forced: true },
    })])
    const { WS_SOCKETS } = await import('@/lib/wsTicket')
    expect(h.close).toHaveBeenCalledWith({ userId: 'mem-b', projectId: 'p-1', kinds: [...WS_SOCKETS], scope: 'access' })
  })

  test('under act-as the row names the account acted as beside Root', async () => {
    h.actingAs = 'mem-z'
    await revoke()
    expect(h.audit[0]).toMatchObject({ actorId: 'root-1', onBehalfOfUserId: 'mem-z', after: { forced: true } })
  })

  test('the agent down: the revoke stands and the answer says the sockets were not closed', async () => {
    h.close.mockResolvedValueOnce({ ok: false, reason: 'agent_unreachable' })
    const answer = await body(await revoke())
    expect(answer).toMatchObject({ forced: true, socketsClosed: false })
    expect(h.shares).toEqual([])
    expect(h.audit).toHaveLength(1)
  })

  test('audit failure: no row, no change, no socket closed (coded 500)', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    h.failAudit = true
    const res = await revoke()
    expect(res.status).toBe(500)
    expect((await body(res)).code).toBe('P1001')
    expect(h.shares).toHaveLength(1)
    expect(h.close).not.toHaveBeenCalled()
  })

  test('no such share, and twice: one revoke, one 404 no_such_share, one row', async () => {
    expect(await body(await revoke('p-1', 'mem-q'))).toMatchObject({ code: 'no_such_share' })
    const [first, second] = [await revoke(), await revoke()]
    expect(first.status).toBe(200)
    expect(second.status).toBe(404)
    expect((await body(second)).code).toBe('no_such_share')
    expect(h.audit).toHaveLength(1)
    expect(h.close).toHaveBeenCalledTimes(1)
  })

  test("Root's policy hiding others' shares does not limit the force-revoke", async () => {
    h.policy = { enabled: true, adminsSeeAllShares: false }
    expect((await revoke()).status).toBe(200)
    expect(h.shares).toEqual([])
  })
})
