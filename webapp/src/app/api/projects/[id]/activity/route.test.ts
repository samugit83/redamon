/**
 * The project activity feed (step 4.13; UI-08, AU-07, AU-09, IM-07): GET /api/projects/[id]/activity.
 *
 * Real guard, can(), projectAccess(), sharing policy reader, capabilities, labels and feed reader; the
 * session and Prisma (the share routes' in-memory store, plus an audit log that answers the feed's
 * query: AND / OR / NOT, equality, in, startsWith, not null, lt, ordered and limited) are doubles.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'
import { createShareDb, shareAccount, type ShareAccount, type ShareDb } from '@/lib/authz/__testing__/shareDb'

interface Row {
  id: string
  action: string
  createdAt: Date
  actorId: string | null
  actorEmail: string | null
  onBehalfOfUserId: string | null
  targetType: string
  targetId: string | null
  projectId: string | null
  permission: string | null
  source: string
  before: unknown
  after: unknown
}

type Where = Record<string, unknown>

function cmp(a: unknown, b: unknown): number {
  if (a instanceof Date && b instanceof Date) return a.getTime() - b.getTime()
  return String(a) < String(b) ? -1 : String(a) > String(b) ? 1 : 0
}

function matches(row: Record<string, unknown>, where: Where): boolean {
  return Object.entries(where).every(([k, cond]) => {
    if (k === 'AND') return (cond as Where[]).every(w => matches(row, w))
    if (k === 'OR') return (cond as Where[]).some(w => matches(row, w))
    if (k === 'NOT') return !matches(row, cond as Where)
    const v = row[k]
    if (cond === null) return v === null
    if (cond instanceof Date) return v instanceof Date && v.getTime() === cond.getTime()
    if (typeof cond === 'object') {
      const c = cond as { in?: unknown[]; startsWith?: string; not?: unknown; lt?: unknown }
      if ('in' in c) return c.in!.includes(v)
      if ('startsWith' in c) return typeof v === 'string' && v.startsWith(c.startsWith!)
      if ('not' in c) return c.not === null ? v !== null && v !== undefined : v !== c.not
      if ('lt' in c) return v !== null && v !== undefined && cmp(v, c.lt) < 0
      throw new Error(`the double does not know ${JSON.stringify(cond)}`)
    }
    return v === cond
  })
}

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

import { GET } from './route'
import { setFlagsForTests } from '@/lib/authz/flags'
import { setNowForTests } from '@/lib/authz/clock'
import { clearSharingPolicyCacheForTests } from '@/lib/authz/sharingPolicy'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import { clearPrincipalCacheForTests } from '@/lib/authz/principal'
import { ACTIVITY_PAGE_SIZE } from '@/lib/authz/projectActivity'

const T0 = new Date('2026-11-13T12:00:00Z')
let db: ShareDb
let audit: Row[] = []
let auditReads = 0
let failAuditRead = false
const accounts: Record<string, ShareAccount> = {}

function add(account: ShareAccount) {
  accounts[account.id] = account
  db.addUser(account)
}

function signIn(id: string, actingAsId?: string) {
  const principal = accounts[id]
  h.identity = { session: { userId: id, role: principal.role }, principal, actingAs: actingAsId ? accounts[actingAsId] : null }
}

let seq = 0
function row(over: Partial<Row> & { action: string }): Row {
  seq += 1
  const r: Row = {
    id: `a${String(seq).padStart(4, '0')}`, createdAt: new Date(T0.getTime() - 3_600_000 + seq * 1000),
    actorId: 'alice', actorEmail: 'alice@example.test', onBehalfOfUserId: null, targetType: 'project', targetId: 'P1',
    projectId: 'P1', permission: null, source: 'api', before: null, after: null, ...over,
  }
  audit.push(r)
  return r
}

function client(): Record<string | symbol, unknown> {
  const base = db.client as Record<string | symbol, unknown>
  return {
    ...base,
    user: {
      ...(base.user as object),
      findMany: async ({ where }: { where: { id: { in: string[] } } }) =>
        where.id.in.map(id => accounts[id]).filter(Boolean).map(u => ({ id: u.id, name: u.name, email: u.email, role: u.role })),
    },
    auditLog: {
      ...(base.auditLog as object),
      findMany: async ({ where, orderBy, take }: { where: Where; orderBy: Array<Record<string, 'asc' | 'desc'>>; take: number }) => {
        auditReads += 1
        if (failAuditRead) throw Object.assign(new Error('connection lost'), { code: 'P1001' })
        expect(orderBy).toEqual([{ createdAt: 'desc' }, { id: 'desc' }])
        return audit.filter(r => matches(r as never, where))
          .sort((a, b) => cmp(b.createdAt, a.createdAt) || cmp(b.id, a.id))
          .slice(0, take)
      },
    },
  }
}

const ctx = (id = 'P1') => ({ params: Promise.resolve({ id }) })
async function feed(query = '', id = 'P1') {
  return GET(new NextRequest(`http://localhost/api/projects/${id}/activity${query ? `?${query}` : ''}`), ctx(id))
}
async function feedJson(query = '', id = 'P1') {
  const res = await feed(query, id)
  expect(res.status).toBe(200)
  return res.json()
}

beforeEach(() => {
  seq = 0
  audit = []
  auditReads = 0
  failAuditRead = false
  setNowForTests(() => T0)
  db = createShareDb(() => T0)
  h.client = client()
  for (const k of Object.keys(accounts)) delete accounts[k]
  add(shareAccount('alice', { email: 'alice@example.test', name: 'Alice Owner' }))
  add(shareAccount('bob', { email: 'bob@example.test', name: 'Bob Reader' }))
  add(shareAccount('carol'))
  add(shareAccount('admin-1', { role: 'admin', email: 'admin1@example.test', name: 'Ada Admin' }))
  add(shareAccount('root', { role: 'admin', email: 'root@example.test', name: 'Rita Root' }))
  add(shareAccount('analyst', { permissionSets: ['builtin:read-only-analyst'] }))
  db.addProject('P1', 'alice')
  db.addProject('P2', 'carol')
  db.addProject('P-analyst', 'analyst')
  db.addShare({ projectId: 'P1', userId: 'bob' })
  setFlagsForTests({ identity: true, permissions: true, sharing: true })
  clearSharingPolicyCacheForTests()
  clearCapabilityCachesForTests()
  clearInstanceRootCacheForTests()
  clearPrincipalCacheForTests()
  vi.spyOn(console, 'info').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
  h.identity = null
  vi.restoreAllMocks()
})

describe('who reads the feed (step 4.13, AU-09)', () => {
  test('owner sees the feed: the project\'s rows and the rows written about it before step 2.1, newest first', async () => {
    const grant = row({ action: 'project.share.grant', targetType: 'user', targetId: 'bob', permission: 'project:share' })
    const legacy = row({ action: 'scan-version.activate', projectId: null, targetType: 'project', targetId: 'P1' })
    row({ action: 'project.update', projectId: 'P2', targetId: 'P2', actorId: 'carol' })
    row({ action: 'user.update', projectId: null, targetType: 'user', targetId: 'P1' })
    row({ action: 'scan-version.activate', projectId: null, targetType: 'version', targetId: 'P1' })
    const mcp = row({ action: 'mcp.list_findings', projectId: null, targetType: 'project', targetId: 'P1', source: 'mcp' })
    signIn('alice')
    const body = await feedJson()
    expect(body.events.map((e: { id: string }) => e.id)).toEqual([mcp.id, legacy.id, grant.id])
    expect(body.project).toEqual({ name: 'P1' })
    expect(body.nextCursor).toBeNull()
    expect(body.sharesHidden).toBe(false)
    expect(body.events[2]).toMatchObject({
      action: 'project.share.grant', label: 'Shared the project', group: 'sharing', source: 'api', at: grant.createdAt.toISOString(),
    })
    expect(body.events[0]).toMatchObject({ label: 'MCP tool call: list findings', group: 'mcp', source: 'mcp' })
  })

  test('read collaborator 403: a share shows the project, not who did what on it', async () => {
    row({ action: 'project.share.grant', targetType: 'user', targetId: 'bob' })
    signIn('bob')
    const res = await feed()
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'forbidden', permission: 'project:share' })
    expect(auditReads).toBe(0)
  })

  test('a stranger 404, a signed-out caller 401, a missing project 404; nothing read', async () => {
    signIn('carol')
    expect((await feed()).status).toBe(404)
    signIn('alice')
    expect((await feed('', 'P-missing')).status).toBe(404)
    h.identity = null
    expect((await feed()).status).toBe(401)
    expect(auditReads).toBe(0)
  })

  test('an owner whose set lacks project:share is refused like any account without it', async () => {
    signIn('analyst')
    const res = await feed('', 'P-analyst')
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ permission: 'project:share' })
  })

  test('oversight read: an admin with projects:oversee reads the whole feed', async () => {
    row({ action: 'project.share.grant', targetType: 'user', targetId: 'bob' })
    row({ action: 'project.update' })
    signIn('admin-1')
    const body = await feedJson()
    expect(body.events.map((e: { action: string }) => e.action)).toEqual(['project.update', 'project.share.grant'])
    expect(body.sharesHidden).toBe(false)
  })

  test("oversight with Root's policy hiding shares from admins: the feed without the share rows, and it says so", async () => {
    db.setPolicy({ enabled: true, adminsSeeAllShares: false })
    row({ action: 'project.share.grant', targetType: 'user', targetId: 'bob' })
    row({ action: 'project.share.lookup', targetType: 'user', targetId: 'bob' })
    row({ action: 'project.update' })
    signIn('admin-1')
    const body = await feedJson()
    expect(body.events.map((e: { action: string }) => e.action)).toEqual(['project.update'])
    expect(body.sharesHidden).toBe(true)
    expect(JSON.stringify(body)).not.toContain('bob@example.test')
    const sharing = await feedJson('group=sharing')
    expect(sharing).toMatchObject({ events: [], sharesHidden: true })
  })

  test("Root's break-glass reads every row whatever the policy says of admins", async () => {
    db.setPolicy({ enabled: true, adminsSeeAllShares: false })
    db.addBreakGlass('P1', 'root', new Date(T0.getTime() + 3_600_000))
    db.setRoot('root', new Date('2026-10-01T00:00:00Z'))
    row({ action: 'project.share.grant', targetType: 'user', targetId: 'bob' })
    signIn('root')
    const body = await feedJson()
    expect(body.events).toHaveLength(1)
    expect(body.sharesHidden).toBe(false)
  })

  test('acting as the owner reads the owner\'s feed; acting as a read collaborator is refused, oversight or not (D-22)', async () => {
    row({ action: 'project.update' })
    signIn('admin-1', 'alice')
    expect((await feed()).status).toBe(200)
    signIn('admin-1', 'bob')
    const res = await feed()
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ permission: 'project:share' })
  })
})

describe('what a row says (AU-07, IM-07, master plan §9.8)', () => {
  test('identity shows email and type: Root, admin and member, the deleted account by its recorded email, the system as nobody', async () => {
    db.setRoot('root', new Date('2026-10-01T00:00:00Z'))
    row({ action: 'project.update', actorId: 'root', actorEmail: 'root@example.test' })
    row({ action: 'project.update', actorId: 'admin-1', actorEmail: 'admin1@example.test' })
    row({ action: 'project.update', actorId: 'alice', actorEmail: 'old-alice@example.test' })
    row({ action: 'project.update', actorId: 'gone', actorEmail: 'gone@example.test' })
    row({ action: 'project.share.expired', actorId: null, actorEmail: null, source: 'system', targetType: 'user', targetId: 'bob' })
    signIn('alice')
    const actors = (await feedJson()).events.map((e: { actor: unknown }) => e.actor)
    expect(actors).toEqual([
      null,
      { name: '', email: 'gone@example.test', accountType: null, deleted: true },
      { name: 'Alice Owner', email: 'alice@example.test', accountType: 'member', deleted: false },
      { name: 'Ada Admin', email: 'admin1@example.test', accountType: 'admin', deleted: false },
      { name: 'Rita Root', email: 'root@example.test', accountType: 'root', deleted: false },
    ])
  })

  test('an action done while acting as the owner names the admin and the account acted as (IM-07)', async () => {
    row({ action: 'project.update', actorId: 'admin-1', actorEmail: 'admin1@example.test', onBehalfOfUserId: 'alice' })
    row({ action: 'project.update', actorId: 'admin-1', actorEmail: 'admin1@example.test', onBehalfOfUserId: 'gone' })
    signIn('alice')
    const [gone, acting] = (await feedJson()).events
    expect(acting.actor).toMatchObject({ email: 'admin1@example.test', accountType: 'admin' })
    expect(acting.onBehalfOf).toEqual({ name: 'Alice Owner', email: 'alice@example.test', accountType: 'member', deleted: false })
    expect(gone.onBehalfOf).toEqual({ name: '', email: null, accountType: null, deleted: true })
  })

  test('a share row names the collaborator it changed; a non-account target names nobody', async () => {
    row({ action: 'project.share.grant', targetType: 'user', targetId: 'bob' })
    row({ action: 'scan-version.activate', targetType: 'version', targetId: 'v1' })
    signIn('alice')
    const [version, grant] = (await feedJson()).events
    expect(grant.target).toEqual({ name: 'Bob Reader', email: 'bob@example.test', accountType: 'member', deleted: false })
    expect(version.target).toBeNull()
  })

  test('never a token, a hash, a lookup email, an account id, or the row\'s before and after', async () => {
    row({ action: 'project.share.lookup', targetType: 'user', targetId: null, after: { result: 'miss', emailSha256: 'f'.repeat(64) } })
    row({ action: 'project.share.update', targetType: 'user', targetId: 'bob', before: { note: 'secret-note' }, after: { rawData: true } })
    row({ action: 'mcp.kali_exec', source: 'mcp', after: { tokenId: 'tok-1', tokenPrefix: 'rdm_abcd', command: 'id' } })
    signIn('alice')
    const text = JSON.stringify(await feedJson())
    for (const leak of ['emailSha256', 'f'.repeat(64), 'secret-note', 'tok-1', 'rdm_abcd', '"before"', '"after"', '"bob"', '"alice"']) {
      expect(text, leak).not.toContain(leak)
    }
  })

  test('an action no label knows keeps its stored name, with no group', async () => {
    row({ action: 'future.thing' })
    signIn('alice')
    expect((await feedJson()).events[0]).toMatchObject({ action: 'future.thing', label: 'future.thing', group: null })
  })
})

describe('pagination and filters', () => {
  test('pagination: pages of 50, newest first, each row once, rows of the same instant split by id', async () => {
    // 70 rows share one instant, ordered between the others, so both page ends fall inside them.
    const instant = new Date(T0.getTime() - 3_600_000 + 75_000)
    for (let i = 0; i < 120; i += 1) row({ action: 'project.update', ...(i >= 40 && i < 110 ? { createdAt: instant } : {}) })
    signIn('alice')
    const seen: string[] = []
    let cursor: string | null = null
    const sizes: number[] = []
    do {
      const body: { events: Array<{ id: string; at: string }>; nextCursor: string | null } =
        await feedJson(cursor ? `cursor=${encodeURIComponent(cursor)}` : '')
      sizes.push(body.events.length)
      seen.push(...body.events.map(e => e.id))
      cursor = body.nextCursor
    } while (cursor)
    expect(ACTIVITY_PAGE_SIZE).toBe(50)
    expect(sizes).toEqual([50, 50, 20])
    expect(new Set(seen).size).toBe(120)
    const expected = [...audit].sort((a, b) => cmp(b.createdAt, a.createdAt) || cmp(b.id, a.id)).map(r => r.id)
    expect(seen).toEqual(expected)
  })

  test('exactly one page: no next cursor', async () => {
    for (let i = 0; i < ACTIVITY_PAGE_SIZE; i += 1) row({ action: 'project.update' })
    signIn('alice')
    const body = await feedJson()
    expect(body.events).toHaveLength(ACTIVITY_PAGE_SIZE)
    expect(body.nextCursor).toBeNull()
  })

  test('group filters: sharing, acting as (any action done while acting, and act_as rows), MCP with its family', async () => {
    row({ action: 'project.share.grant', targetType: 'user', targetId: 'bob' })
    row({ action: 'project.share.expired', actorId: null, source: 'system' })
    row({ action: 'project.update', actorId: 'admin-1', onBehalfOfUserId: 'alice' })
    row({ action: 'act_as.refused', actorId: 'admin-1', onBehalfOfUserId: 'alice' })
    row({ action: 'project.update' })
    row({ action: 'mcp.list_findings', projectId: null, source: 'mcp' })
    row({ action: 'mcp.kali_exec', projectId: null, source: 'mcp' })
    signIn('alice')
    const actions = async (group: string) => (await feedJson(`group=${group}`)).events.map((e: { action: string }) => e.action)
    expect(await actions('sharing')).toEqual(['project.share.expired', 'project.share.grant'])
    expect(await actions('acting')).toEqual(['act_as.refused', 'project.update'])
    expect(await actions('mcp')).toEqual(['mcp.kali_exec', 'mcp.list_findings'])
    expect(await actions('oversight')).toEqual([])
  })

  test('a bad cursor or an unknown group: 400 naming the field, nothing read', async () => {
    signIn('alice')
    for (const [query, field] of [
      ['cursor=not-a-cursor', 'cursor'],
      [`cursor=${Buffer.from(JSON.stringify({ t: 'yesterday', i: 'a1' })).toString('base64url')}`, 'cursor'],
      [`cursor=${Buffer.from(JSON.stringify({ t: T0.toISOString(), i: 'a b' })).toString('base64url')}`, 'cursor'],
      ['group=everything', 'group'],
      ['group=__proto__', 'group'],
    ]) {
      const res = await feed(query)
      expect([query, res.status]).toEqual([query, 400])
      expect(await res.json()).toMatchObject({ code: 'invalid_field', field })
    }
    expect(auditReads).toBe(0)
  })

  test('a failed read answers a coded 500, never the error text', async () => {
    failAuditRead = true
    vi.spyOn(console, 'error').mockImplementation(() => {})
    signIn('alice')
    const res = await feed()
    expect(res.status).toBe(500)
    const body = await res.json()
    expect(body.code).toBe('P1001')
    expect(JSON.stringify(body)).not.toContain('connection lost')
  })
})

describe('sharing not in force: the feed does not exist (DV-30)', () => {
  const OFF: Array<[string, Parameters<typeof setFlagsForTests>[0], unknown]> = [
    ['every switch off', {}, { enabled: true }],
    ['identity + permissions on, the sharing switch off', { identity: true, permissions: true }, { enabled: true }],
    ['the switch on, the policy disabled (the stored {})', { identity: true, permissions: true, sharing: true }, {}],
  ]
  test.each(OFF)('%s: 404 for the owner and an admin, no audit row read', async (_what, flags, stored) => {
    setFlagsForTests(flags)
    db.setPolicy(stored)
    row({ action: 'project.update' })
    for (const who of ['alice', 'admin-1']) {
      signIn(who)
      const res = await feed()
      expect([who, res.status]).toEqual([who, 404])
    }
    expect(auditReads).toBe(0)
  })
})
