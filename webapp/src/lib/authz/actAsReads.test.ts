/**
 * Reads made while acting as an account (IM-07, D-22; the gap step 4.16 found): an admin acting as a
 * collaborator reads the collaborator's shared project read-only, and the owner's activity feed names
 * the admin for it. Each read the route guard allows through the account's share while acting writes
 * one `project.read_acting` row per admin, account acted as, project and UTC day, in a transaction
 * holding that day's advisory lock; the owner's own reads, a collaborator's own reads, oversight
 * (its own row) and the switch-off path write none.
 *
 * Real guard, can(), projectAccess(), capabilities, policy reader, audit writers and the activity
 * feed; the session and Prisma (the share routes' in-memory store, plus an audit list the feed's
 * query reads) are doubles, as in oversight.test.ts.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/authz/actAsReads.test.ts
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
import { OVERSEE_ACTION, clearOversightMemoForTests } from './oversight'
import { ACT_AS_READ_ACTION, actAsReadLockKey, auditActAsRead, clearActAsReadMemoForTests } from './actAsReads'
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

const actingReads = () => db.audit().filter((r) => r.action === ACT_AS_READ_ACTION)

async function guarded(permission: PermissionId, projectId = 'P1'): Promise<number> {
  const auth = await requirePermission(new Request('http://localhost/x'), permission, { projectId })
  return auth instanceof NextResponse ? auth.status : 200
}

async function feed(projectId = 'P1', query = '') {
  const res = await feedGET(new NextRequest(`http://localhost/api/projects/${projectId}/activity${query}`), { params: Promise.resolve({ id: projectId }) })
  return { status: res.status, body: await res.json() }
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
  add(shareAccount('carol', { email: 'carol@example.test', name: 'Carol Reader' }))
  add(shareAccount('admin-1', { role: 'admin', email: 'admin1@example.test', name: 'Ada Admin' }))
  add(shareAccount('admin-2', { role: 'admin', email: 'admin2@example.test', name: 'Ugo Admin' }))
  add(shareAccount('root', { role: 'admin', email: 'root@example.test', name: 'Rita Root' }))
  db.addProject('P1', 'alice')
  db.addProject('P2', 'alice')
  db.addShare({ projectId: 'P1', userId: 'bob' })
  db.addShare({ projectId: 'P2', userId: 'bob' })
  db.addShare({ projectId: 'P1', userId: 'carol' })
  db.setRoot('root', new Date('2026-10-01T00:00:00Z'))
  setFlagsForTests({ identity: true, permissions: true, sharing: true })
  clearSharingPolicyCacheForTests()
  clearCapabilityCachesForTests()
  clearInstanceRootCacheForTests()
  clearPrincipalCacheForTests()
  clearOversightMemoForTests()
  clearActAsReadMemoForTests()
  vi.spyOn(console, 'info').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
  h.identity = null
  vi.restoreAllMocks()
})

describe('a read through a share while acting writes one row per day (IM-07, D-22)', () => {
  test('the first read of the day writes the row in its locked transaction; the next reads write nothing', async () => {
    signIn('admin-1', 'bob')
    expect(await guarded('recon:read')).toBe(200)
    expect(actingReads()).toEqual([expect.objectContaining({
      action: 'project.read_acting', actorId: 'admin-1', actorEmail: 'admin1@example.test', onBehalfOfUserId: 'bob',
      projectId: 'P1', targetType: 'project', targetId: 'P1', permission: 'users:impersonate',
      after: { day: '2026-11-13', read: 'recon:read' }, source: 'api',
    })])
    expect(db.locks()).toEqual(['act_as_read:admin-1:bob:P1:2026-11-13'])
    for (const p of ['graph:read', 'recon:read', 'triage:read', 'recon:read'] as PermissionId[]) expect(await guarded(p)).toBe(200)
    expect(actingReads()).toHaveLength(1)
    expect(transactions).toBe(1)
  })

  test('another project, another account acted as, another admin and the next UTC day each get their own row', async () => {
    signIn('admin-1', 'bob')
    await guarded('recon:read', 'P1')
    await guarded('recon:read', 'P2')
    signIn('admin-1', 'carol')
    await guarded('recon:read', 'P1')
    signIn('admin-2', 'bob')
    await guarded('recon:read', 'P1')
    signIn('admin-1', 'bob')
    clock = new Date('2026-11-13T23:59:59.999Z')
    await guarded('recon:read', 'P1')
    clock = new Date('2026-11-14T00:00:00.000Z')
    await guarded('recon:read', 'P1')
    expect(actingReads().map((r) => `${r.actorId}:${r.onBehalfOfUserId}:${r.projectId}:${(r.after as { day: string }).day}`)).toEqual([
      'admin-1:bob:P1:2026-11-13', 'admin-1:bob:P2:2026-11-13', 'admin-1:carol:P1:2026-11-13', 'admin-2:bob:P1:2026-11-13',
      'admin-1:bob:P1:2026-11-14',
    ])
  })

  test("another copy already wrote the day's row: this one finds it under the lock and writes nothing", async () => {
    await db.client.auditLog.create({
      data: { action: ACT_AS_READ_ACTION, actorId: 'admin-1', onBehalfOfUserId: 'bob', projectId: 'P1', after: { day: '2026-11-13' } },
    })
    clock = new Date(T0.getTime() + 60_000)
    signIn('admin-1', 'bob')
    expect(await guarded('recon:read')).toBe(200)
    expect(actingReads()).toHaveLength(1)
    expect(db.locks()).toEqual(['act_as_read:admin-1:bob:P1:2026-11-13'])
  })

  test('two reads at once write one row (the lock serialises them, the second finds the first\'s row)', async () => {
    signIn('admin-1', 'bob')
    expect(await Promise.all([guarded('recon:read'), guarded('graph:read')])).toEqual([200, 200])
    expect(actingReads()).toHaveLength(1)
  })

  test('the row cannot be written: a coded 500, never an unrecorded read; the next read tries again', async () => {
    db.failAudit(ACT_AS_READ_ACTION)
    vi.spyOn(console, 'error').mockImplementation(() => {})
    signIn('admin-1', 'bob')
    const auth = await requirePermission(new Request('http://localhost/x'), 'recon:read', { projectId: 'P1' })
    expect(auth).toBeInstanceOf(NextResponse)
    expect((auth as NextResponse).status).toBe(500)
    expect(await (auth as NextResponse).json()).toMatchObject({ error: 'Could not record the read made while acting as an account' })
    expect(actingReads()).toEqual([])
    expect(await guarded('recon:read')).toBe(500)
  })

  test('a refused request writes no row: a write through the share stays refused while acting (D-22)', async () => {
    db.addShare({ projectId: 'P1', userId: 'bob', access: 'write', runScans: true })
    signIn('admin-1', 'bob')
    expect(await guarded('recon:scan')).toBe(403)
    expect(await guarded('project:settings')).toBe(403)
    expect(actingReads()).toEqual([])
  })

  test('the lock key: per admin, account acted as, project and UTC day', () => {
    expect(actAsReadLockKey('a', 't', 'p', '2026-11-13')).toBe('act_as_read:a:t:p:2026-11-13')
  })
})

describe('no row for any other read (DV-30: the owner, oversight and switch-off paths unchanged)', () => {
  test('the owner and a collaborator reading as themselves write no row', async () => {
    for (const who of ['alice', 'bob']) {
      signIn(who)
      expect([who, await guarded('recon:read')]).toEqual([who, 200])
    }
    expect(db.audit()).toEqual([])
    expect(db.locks()).toEqual([])
  })

  test('an admin acting as the owner reads the owner\'s project with no row (the owner is the account acted as)', async () => {
    signIn('admin-1', 'alice')
    expect(await guarded('recon:read')).toBe(200)
    expect(db.audit()).toEqual([])
  })

  test('oversight keeps its own row and no acting row; acting, the admin\'s oversight still does not apply (404)', async () => {
    signIn('admin-1')
    expect(await guarded('recon:read')).toBe(200)
    expect(db.audit().map((r) => r.action)).toEqual([OVERSEE_ACTION])
    signIn('admin-1', 'root')
    expect(await guarded('recon:read')).toBe(404)
    expect(actingReads()).toEqual([])
  })

  test('sharing switched off: the share is not read, the project is not found, no row', async () => {
    setFlagsForTests({ identity: true, permissions: true, sharing: false })
    signIn('admin-1', 'bob')
    expect(await guarded('recon:read')).toBe(404)
    expect(db.audit()).toEqual([])
    expect(db.locks()).toEqual([])
  })

  test('auditActAsRead writes for a share access while acting only', async () => {
    const access = (via: 'owner' | 'share' | 'break_glass' | 'oversight') =>
      Object.freeze({ project: { id: 'P1', userId: 'alice' }, level: 'read' as const, toggles: { rawData: false }, via })
    for (const via of ['owner', 'break_glass', 'oversight'] as const) {
      await auditActAsRead({ principal: { id: 'admin-1' }, actingAs: { id: 'bob' } }, access(via), 'recon:read')
    }
    await auditActAsRead({ principal: { id: 'bob' }, actingAs: null }, access('share'), 'recon:read')
    await auditActAsRead({ principal: { id: 'admin-1' }, actingAs: { id: 'bob' } }, null, 'recon:read')
    expect(actingReads()).toEqual([])
    await auditActAsRead({ principal: { id: 'admin-1' }, actingAs: { id: 'bob' } }, access('share'), 'recon:read')
    expect(actingReads()).toEqual([expect.objectContaining({ actorId: 'admin-1', onBehalfOfUserId: 'bob', projectId: 'P1' })])
  })
})

describe("the owner's activity feed names the admin (IM-07, AU-09)", () => {
  test('the owner reads "Opened the project", by the admin, acting as the collaborator, in the Acting as group', async () => {
    signIn('admin-1', 'bob')
    await guarded('recon:read')
    await guarded('graph:read')
    signIn('alice')
    const all = await feed()
    expect(all.status).toBe(200)
    expect(all.body.events).toEqual([expect.objectContaining({
      action: 'project.read_acting', label: 'Opened the project', group: 'acting',
      actor: expect.objectContaining({ name: 'Ada Admin', email: 'admin1@example.test', accountType: 'admin' }),
      onBehalfOf: expect.objectContaining({ name: 'Bob Reader', email: 'bob@example.test', accountType: 'member' }),
    })])
    const acting = await feed('P1', '?group=acting')
    expect(acting.body.events.map((e: { action: string }) => e.action)).toEqual(['project.read_acting'])
  })

  test("another owner's feed does not show it", async () => {
    db.addProject('P3', 'carol')
    signIn('admin-1', 'bob')
    await guarded('recon:read', 'P1')
    signIn('carol')
    const other = await feed('P3')
    expect(other.status).toBe(200)
    expect(other.body.events).toEqual([])
  })
})
