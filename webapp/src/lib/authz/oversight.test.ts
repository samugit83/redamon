/**
 * Oversight reads (step 4.14; SH-47, DV-24, OQ-03): an admin holding `projects:oversee` reads any
 * project at Read, without Raw data & files and without anyone's private conversations; each read
 * through the route guard (and the feed and share list) writes one `project.oversee` row per admin,
 * project and day, in a transaction holding the day's advisory lock; the owner's feed shows it.
 *
 * Real guard, can(), projectAccess(), capabilities, policy reader, audit writers and the activity
 * feed; the session and Prisma (the share routes' in-memory store, plus an audit list the feed's
 * query reads) are doubles.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'
import { createShareDb, shareAccount, type ShareAccount, type ShareDb } from './__testing__/shareDb'

const h = vi.hoisted(() => ({
  client: null as unknown as Record<string | symbol, unknown>,
  identity: null as null | { session: { userId: string; role: string }; principal: unknown; actingAs: unknown },
}))
vi.mock('@/lib/prisma', () => {
  const client = new Proxy({}, { get: (_t, k) => h.client[k] })
  return { default: client, prisma: client }
})
vi.mock('@/lib/session', () => ({
  getAuthzIdentity: async () => h.identity,
  getSession: async () => h.identity?.session ?? null,
  getEffectiveUser: async () => (h.identity ? { userId: ((h.identity.actingAs ?? h.identity.principal) as { id: string }).id } : null),
  mayActAs: async () => true,
  actAsInForce: async () => (h.identity?.actingAs ? { target: h.identity.actingAs, expiresAt: null } : null),
}))

import { requirePermission } from './guards'
import { setFlagsForTests } from './flags'
import { setNowForTests } from './clock'
import { clearSharingPolicyCacheForTests } from './sharingPolicy'
import { clearCapabilityCachesForTests } from './capabilities'
import { clearInstanceRootCacheForTests } from './root'
import { clearPrincipalCacheForTests } from './principal'
import { projectAccess } from './projectAccess'
import {
  OVERSEE_ACTION, auditOversightRead, clearOversightMemoForTests, oversightDay, oversightLockKey, oversightProjects,
  recordOversightRead,
} from './oversight'
import type { PermissionId } from './permissions'
import { GET as feedGET } from '@/app/api/projects/[id]/activity/route'

const T0 = new Date('2026-11-13T12:00:00Z')
let clock = T0
let db: ShareDb
let transactions = 0
const accounts: Record<string, ShareAccount> = {}

function add(account: ShareAccount) {
  accounts[account.id] = account
  db.addUser(account)
}

function signIn(id: string, actingAsId?: string) {
  const principal = accounts[id]
  h.identity = { session: { userId: id, role: principal.role }, principal, actingAs: actingAsId ? accounts[actingAsId] : null }
}

type Where = Record<string, unknown>
function feedMatches(row: Record<string, unknown>, where: Where): boolean {
  return Object.entries(where).every(([k, cond]) => {
    if (k === 'AND') return (cond as Where[]).every((w) => feedMatches(row, w))
    if (k === 'OR') return (cond as Where[]).some((w) => feedMatches(row, w))
    if (k === 'NOT') return !feedMatches(row, cond as Where)
    const v = row[k]
    if (cond && typeof cond === 'object' && !(cond instanceof Date)) {
      const c = cond as { in?: unknown[]; startsWith?: string; not?: unknown; lt?: Date }
      if ('in' in c) return c.in!.includes(v)
      if ('startsWith' in c) return typeof v === 'string' && v.startsWith(c.startsWith!)
      if ('not' in c) return c.not === null ? v !== null && v !== undefined : v !== c.not
      if ('lt' in c) return v instanceof Date && v.getTime() < c.lt!.getTime()
    }
    return (v ?? null) === cond
  })
}

function client(): Record<string | symbol, unknown> {
  const base = db.client as Record<string | symbol, unknown>
  return {
    ...base,
    user: {
      ...(base.user as object),
      findMany: async ({ where }: { where: { id: { in: string[] } } }) =>
        where.id.in.map((id) => accounts[id]).filter(Boolean).map((u) => ({ id: u.id, name: u.name, email: u.email, role: u.role })),
    },
    auditLog: {
      ...(base.auditLog as object),
      findMany: async ({ where, take }: { where: Where; take: number }) => db.audit()
        .map((r, i) => ({ id: `r${i}`, targetType: 'project', targetId: null, onBehalfOfUserId: null, actorEmail: null, source: 'api', ...r }))
        .filter((r) => feedMatches(r as never, where)).reverse().slice(0, take),
    },
    $transaction: (fn: (tx: unknown) => Promise<unknown>) => {
      transactions += 1
      return (base.$transaction as (f: typeof fn) => Promise<unknown>)(fn)
    },
  }
}

const oversee = () => db.audit().filter((r) => r.action === OVERSEE_ACTION)

async function guarded(permission: PermissionId, projectId = 'P1'): Promise<number> {
  const auth = await requirePermission(new Request('http://localhost/x'), permission, { projectId })
  return auth instanceof NextResponse ? auth.status : 200
}

beforeEach(() => {
  clock = T0
  transactions = 0
  setNowForTests(() => clock)
  db = createShareDb(() => clock)
  h.client = client()
  for (const k of Object.keys(accounts)) delete accounts[k]
  add(shareAccount('alice', { email: 'alice@example.test', name: 'Alice Owner' }))
  add(shareAccount('bob', { email: 'bob@example.test', name: 'Bob Reader' }))
  add(shareAccount('admin-1', { role: 'admin', email: 'admin1@example.test', name: 'Ada Admin' }))
  add(shareAccount('admin-2', { role: 'admin', email: 'admin2@example.test', name: 'Ugo Users', adminProfileId: 'builtin:user-manager' }))
  add(shareAccount('auditor', { role: 'admin', email: 'auditor@example.test', adminProfileId: 'builtin:security-auditor' }))
  add(shareAccount('root', { role: 'admin', email: 'root@example.test', name: 'Rita Root' }))
  db.addProject('P1', 'alice')
  db.addProject('P2', 'bob')
  db.addProject('P-admin', 'admin-1')
  db.setRoot('root', new Date('2026-10-01T00:00:00Z'))
  setFlagsForTests({ identity: true, permissions: true, sharing: true })
  clearSharingPolicyCacheForTests()
  clearCapabilityCachesForTests()
  clearInstanceRootCacheForTests()
  clearPrincipalCacheForTests()
  clearOversightMemoForTests()
  vi.spyOn(console, 'info').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
  h.identity = null
  vi.restoreAllMocks()
})

describe('oversight reads without raw (step 4.14, SH-47)', () => {
  test('Full admin and Security auditor read any project at R; raw data, writes and the owner\'s level stay refused', async () => {
    for (const who of ['admin-1', 'auditor']) {
      signIn(who)
      expect([who, await guarded('recon:read')]).toEqual([who, 200])
      expect([who, await guarded('graph:read')]).toEqual([who, 200])
      for (const p of ['traffic:read', 'workspace:read', 'recon:scan', 'project:settings', 'agent:chat'] as PermissionId[]) {
        expect([who, p, await guarded(p)]).toEqual([who, p, 403])
      }
    }
  })

  test('an admin without projects:oversee (User manager) cannot see the project: 404, no row', async () => {
    signIn('admin-2')
    expect(await guarded('recon:read')).toBe(404)
    expect(oversee()).toEqual([])
  })

  test('no private conversations: oversight opens the project, never another author\'s conversation', async () => {
    const { requireConversationAccess } = await import('@/lib/access')
    h.client = { ...client(), conversation: { findUnique: async () => ({ id: 'c1', userId: 'alice', projectId: 'P1' }) } }
    signIn('admin-1')
    const res = await requireConversationAccess({ userId: 'admin-1' }, 'c1')
    expect(res instanceof NextResponse && res.status).toBe(404)
  })

  test('a refused read writes no row: only an allowed oversight read is audited', async () => {
    signIn('admin-1')
    expect(await guarded('traffic:read')).toBe(403)
    expect(await guarded('recon:scan')).toBe(403)
    expect(oversee()).toEqual([])
  })

  test('the owner, a collaborator and Root\'s break-glass read without a per-read row', async () => {
    db.addShare({ projectId: 'P1', userId: 'bob' })
    db.addBreakGlass('P1', 'root', new Date(T0.getTime() + 3_600_000))
    for (const who of ['alice', 'bob', 'root']) {
      signIn(who)
      expect([who, await guarded('recon:read')]).toEqual([who, 200])
    }
    expect(oversee()).toEqual([])
  })
})

describe('one audit row per day (step 4.14, DV-24)', () => {
  test('the first oversight read of the day writes the row in its locked transaction; the next ones nothing', async () => {
    signIn('admin-1')
    expect(await guarded('recon:read')).toBe(200)
    expect(oversee()).toEqual([expect.objectContaining({
      action: 'project.oversee', actorId: 'admin-1', actorEmail: 'admin1@example.test', projectId: 'P1', targetType: 'project',
      targetId: 'P1', permission: 'projects:oversee', after: { day: '2026-11-13', read: 'recon:read' }, source: 'api',
    })])
    expect(db.locks()).toEqual(['oversee:admin-1:P1:2026-11-13'])
    for (const p of ['graph:read', 'recon:read', 'triage:read'] as PermissionId[]) expect(await guarded(p)).toBe(200)
    expect(oversee()).toHaveLength(1)
    expect(transactions).toBe(1)
  })

  test('another project, another admin and the next UTC day each get their own row', async () => {
    signIn('admin-1')
    await guarded('recon:read', 'P1')
    await guarded('recon:read', 'P2')
    signIn('auditor')
    await guarded('recon:read', 'P1')
    signIn('admin-1')
    clock = new Date('2026-11-13T23:59:59.999Z')
    await guarded('recon:read', 'P1')
    clock = new Date('2026-11-14T00:00:00.000Z')
    await guarded('recon:read', 'P1')
    expect(oversee().map((r) => `${r.actorId}:${r.projectId}:${(r.after as { day: string }).day}`)).toEqual([
      'admin-1:P1:2026-11-13', 'admin-1:P2:2026-11-13', 'auditor:P1:2026-11-13', 'admin-1:P1:2026-11-14',
    ])
  })

  test('another copy already wrote the day\'s row: this one finds it under the lock and writes nothing', async () => {
    await db.client.auditLog.create({ data: { action: OVERSEE_ACTION, actorId: 'admin-1', projectId: 'P1', after: { day: '2026-11-13' } } })
    clock = new Date(T0.getTime() + 60_000)
    signIn('admin-1')
    expect(await guarded('recon:read')).toBe(200)
    expect(oversee()).toHaveLength(1)
    expect(db.locks()).toEqual(['oversee:admin-1:P1:2026-11-13'])
  })

  test('two reads at once write one row (the lock serialises them, the second finds the first\'s row)', async () => {
    signIn('admin-1')
    expect(await Promise.all([guarded('recon:read'), guarded('graph:read')])).toEqual([200, 200])
    expect(oversee()).toHaveLength(1)
  })

  test('the row cannot be written: a coded 500, never an unaudited read; the next read tries again', async () => {
    db.failAudit(OVERSEE_ACTION)
    vi.spyOn(console, 'error').mockImplementation(() => {})
    signIn('admin-1')
    const auth = await requirePermission(new Request('http://localhost/x'), 'recon:read', { projectId: 'P1' })
    expect(auth).toBeInstanceOf(NextResponse)
    expect((auth as NextResponse).status).toBe(500)
    expect(await (auth as NextResponse).json()).toMatchObject({ error: 'Could not record the oversight read' })
    expect(oversee()).toEqual([])
    expect(await guarded('recon:read')).toBe(500)
  })

  test('the day and lock key: UTC, per admin, project and day', () => {
    expect(oversightDay(new Date('2026-11-13T23:30:00-02:00'))).toBe('2026-11-14')
    expect(oversightLockKey('a', 'p', '2026-11-13')).toBe('oversee:a:p:2026-11-13')
  })

  test('auditOversightRead writes for an oversight access only, never while acting as someone', async () => {
    const access = (via: 'owner' | 'share' | 'break_glass' | 'oversight') =>
      Object.freeze({ project: { id: 'P1', userId: 'alice' }, level: 'read' as const, toggles: { rawData: false }, via })
    for (const via of ['owner', 'share', 'break_glass'] as const) {
      await auditOversightRead({ principal: { id: 'admin-1' }, actingAs: null }, access(via), 'recon:read')
    }
    await auditOversightRead({ principal: { id: 'admin-1' }, actingAs: { id: 'alice' } }, access('oversight'), 'recon:read')
    await auditOversightRead({ principal: { id: 'admin-1' }, actingAs: null }, null, 'recon:read')
    expect(oversee()).toEqual([])
    await recordOversightRead({ id: 'admin-1' }, 'P1', 'recon:read', 'api')
    expect(oversee()).toHaveLength(1)
  })
})

describe('never while acting as someone (step 4.14, D-22)', () => {
  test("Root acting as an admin with oversight cannot reach a third person's project through it: 404, no row", async () => {
    signIn('root', 'admin-1')
    expect(await guarded('recon:read', 'P1')).toBe(404)
    // The admin's own project stays theirs to read while acted as.
    expect(await guarded('recon:read', 'P-admin')).toBe(200)
    expect(oversee()).toEqual([])
  })

  test("nor through the acted-as account's break-glass (were it Root's): 404", async () => {
    db.addBreakGlass('P1', 'admin-1', new Date(T0.getTime() + 3_600_000))
    signIn('root', 'admin-1')
    expect(await guarded('recon:read', 'P1')).toBe(404)
  })
})

describe('owner feed shows it (step 4.14, AU-09)', () => {
  test('the owner reads the oversight row in the project activity feed, with the admin named', async () => {
    signIn('admin-1')
    await guarded('recon:read')
    signIn('alice')
    const res = await feedGET(new NextRequest('http://localhost/api/projects/P1/activity'), { params: Promise.resolve({ id: 'P1' }) })
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.events).toEqual([expect.objectContaining({
      action: 'project.oversee', label: 'Read the project by oversight', group: 'oversight',
      actor: expect.objectContaining({ email: 'admin1@example.test', accountType: 'admin' }),
    })])
  })

  test('an overseer reading the feed itself writes the day\'s row too (the feed is an oversight read)', async () => {
    signIn('admin-1')
    const res = await feedGET(new NextRequest('http://localhost/api/projects/P1/activity'), { params: Promise.resolve({ id: 'P1' }) })
    expect(res.status).toBe(200)
    expect(oversee()).toEqual([expect.objectContaining({ actorId: 'admin-1', projectId: 'P1', after: { day: '2026-11-13', read: 'project:share' } })])
  })
})

describe('the "All projects (oversight)" list (step 4.14)', () => {
  test('every project with its owner and the holder\'s own access, as projectAccess() answers it', async () => {
    db.addShare({ projectId: 'P2', userId: 'root', rawData: false })
    db.addBreakGlass('P1', 'root', new Date(T0.getTime() + 3_600_000))
    db.addProject('P-root', 'root')
    const { resolveCapabilities } = await import('./capabilities')
    const { loadPrincipal } = await import('./principal')
    const caps = await resolveCapabilities((await loadPrincipal('root'))!)
    const rows = await oversightProjects('root', caps)
    const byId = Object.fromEntries(rows.map((r) => [r.id, r.myAccess]))
    expect(byId).toEqual({
      P1: { level: 'read', toggles: { rawData: true }, via: 'break_glass', owner: { name: 'Alice Owner', email: 'alice@example.test' } },
      P2: { level: 'read', toggles: { rawData: false }, via: 'share', owner: { name: 'Bob Reader', email: 'bob@example.test' } },
      'P-admin': { level: 'read', toggles: { rawData: false }, via: 'oversight', owner: expect.objectContaining({ email: 'admin1@example.test' }) },
      'P-root': { level: 'owner', toggles: { rawData: true }, via: 'owner', owner: expect.objectContaining({ email: 'root@example.test' }) },
    })
    for (const row of rows) {
      const access = await projectAccess({ userId: 'root' }, row.id)
      expect([row.id, row.myAccess.via, row.myAccess.toggles.rawData]).toEqual([row.id, access?.via, access?.toggles.rawData])
    }
    expect(oversee()).toEqual([])
  })

  test('break-glass counts only for a holder of projects:administer, an expired one not at all', async () => {
    db.addBreakGlass('P1', 'admin-1', new Date(T0.getTime() + 3_600_000))
    db.addBreakGlass('P2', 'root', new Date(T0.getTime() - 1))
    const { resolveCapabilities } = await import('./capabilities')
    const { loadPrincipal } = await import('./principal')
    const admin = await oversightProjects('admin-1', await resolveCapabilities((await loadPrincipal('admin-1'))!))
    expect(admin.find((r) => r.id === 'P1')?.myAccess.via).toBe('oversight')
    const root = await oversightProjects('root', await resolveCapabilities((await loadPrincipal('root'))!))
    expect(root.find((r) => r.id === 'P2')?.myAccess.via).toBe('oversight')
  })
})
