/**
 * The audit viewer and its export (step 6.6; GV-07, AU-04, AU-07): GET /api/admin/audit (audit:read),
 * GET /api/admin/audit/[id] (audit:read) and GET /api/admin/audit/export (audit:export). With
 * RBAC_GOVERNANCE_ENABLED off all three are 404 having read nothing. The list filters and pages the
 * three audit tables, names every account by email and type (a deleted actor by the email its row
 * recorded) and never carries `before`/`after`; the details route does, secrets withheld. The export
 * streams CSV or JSON a batch at a time, stops at 100 000 rows and says so, and writes its own
 * `audit.exported` row before the first byte, fail-closed.
 *
 * The routes, lib/authz/auditReader.ts and lib/authz/auditExport.ts are real; the session, the
 * permission answers, the Root, the actor and Prisma are doubles. Prisma is an in-memory double that
 * evaluates each `where` (__testing__/auditRowsDb.ts), so a filter asked wrongly finds the wrong rows.
 *
 * Run: npx vitest run --no-file-parallelism src/app/api/admin/audit/route.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import path from 'node:path'
import { auditRowsDb, emptyAuditRowsState, type Row } from '@/lib/authz/__testing__/auditRowsDb'

const h = vi.hoisted(() => ({
  session: { userId: 'aud-1', role: 'admin' } as { userId: string; role: string } | null,
  held: new Set<string>(),
  root: { userId: 'root-1', email: 'root@e2e.local', confirmed: true, assignedBy: 'host' } as unknown,
  state: null as unknown as import('@/lib/authz/__testing__/auditRowsDb').AuditRowsState,
  db: null as unknown as Record<string, unknown>,
  sessionReads: 0,
}))

vi.mock('@/lib/prisma', () => {
  const client = new Proxy({}, { get: (_t, name) => (h.db as Record<string | symbol, unknown>)[name] })
  return { default: client, prisma: client }
})
vi.mock('@/lib/session', () => ({
  requireSession: vi.fn(async () => {
    h.sessionReads += 1
    return h.session ?? NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }),
  getSession: vi.fn(async () => h.session),
  getEffectiveUser: vi.fn(async () => (h.session ? { userId: h.session.userId } : null)),
}))
vi.mock('@/lib/auditActor', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/auditActor')>()),
  auditActor: vi.fn(async () => ({ actorId: h.session?.userId ?? null, onBehalfOfUserId: null, actorEmail: 'auditor@e2e.local' })),
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

import { setFlagsForTests } from '@/lib/authz/flags'
import { setNowForTests } from '@/lib/authz/clock'
import { ROUTE_MANIFEST } from '@/lib/authz/routeManifest'
import { AUDIT_EXPORT_MAX_ROWS } from '@/lib/authz/auditExport'
import { WITHHELD } from '@/lib/authz/auditReader'
import { GET as listAudit } from './route'
import { GET as auditRow } from './[id]/route'
import { GET as exportAudit } from './export/route'

const NOW = new Date('2026-11-13T12:00:00.000Z')
const GOV = { identity: true, permissions: true, governance: true }
const at = (iso: string) => new Date(iso)
const minutesAgo = (m: number) => new Date(NOW.getTime() - m * 60_000)

let seq = 0
function auditRow_(over: Row = {}): Row {
  seq += 1
  return {
    id: `al-${String(seq).padStart(4, '0')}`, actorId: null, actorEmail: null, onBehalfOfUserId: null, action: 'user.update',
    targetType: 'user', targetId: null, projectId: null, permission: null, before: null, after: null, source: 'api',
    createdAt: minutesAgo(seq), ...over,
  }
}

const list = (qs = '') => listAudit(new NextRequest(`http://redamon.test/api/admin/audit${qs ? `?${qs}` : ''}`))
const detail = (id: string) => auditRow(new NextRequest(`http://redamon.test/api/admin/audit/${id}`), { params: Promise.resolve({ id }) })
const exportOf = (qs = '') => exportAudit(new NextRequest(`http://redamon.test/api/admin/audit/export${qs ? `?${qs}` : ''}`))
const json = async (res: Response) => res.json() as Promise<Record<string, any>>
const ids = async (res: Response) => ((await json(res)).entries as Array<{ id: string }>).map((e) => e.id)

beforeEach(() => {
  seq = 0
  setFlagsForTests(GOV)
  setNowForTests(() => NOW)
  h.session = { userId: 'aud-1', role: 'admin' }
  h.held = new Set(['audit:read', 'audit:export'])
  h.root = { userId: 'root-1', email: 'root@e2e.local', confirmed: true, assignedBy: 'host' }
  h.state = emptyAuditRowsState()
  h.state.users = [
    { id: 'root-1', name: 'Rhea', email: 'root@e2e.local', role: 'admin' },
    { id: 'adm-a', name: 'Ada', email: 'ada@e2e.local', role: 'admin' },
    { id: 'mem-a', name: 'Mona', email: 'mona@e2e.local', role: 'standard' },
    { id: 'aud-1', name: 'Audrey', email: 'auditor@e2e.local', role: 'admin' },
  ]
  h.state.projects = [{ id: 'proj-1', name: 'Alpha' }, { id: 'proj-2', name: 'Beta' }]
  h.db = auditRowsDb(h.state, () => NOW) as unknown as Record<string, unknown>
  h.sessionReads = 0
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
    ['identity and permissions on', { identity: true, permissions: true }],
  ])('%s: the three routes are 404 and read neither the session nor the database', async (_what, flags) => {
    setFlagsForTests(flags)
    h.state.audit = [auditRow_()]
    expect((await list()).status).toBe(404)
    expect((await detail('al-0001')).status).toBe(404)
    expect((await exportOf()).status).toBe(404)
    expect(h.sessionReads).toBe(0)
    expect(h.state.calls).toEqual([])
  })
})

describe('who may read and export', () => {
  test('no session: 401 on each route', async () => {
    h.session = null
    for (const res of [await list(), await detail('al-0001'), await exportOf()]) expect(res.status).toBe(401)
  })

  test('without audit:read the list and the details are 403 naming it, before anything is read', async () => {
    h.held = new Set(['users:read', 'audit:export'])
    for (const res of [await list(), await detail('al-0001')]) {
      expect(res.status).toBe(403)
      expect(await json(res)).toMatchObject({ code: 'forbidden', permission: 'audit:read' })
    }
    expect(h.state.calls).toEqual([])
  })

  test('without audit:export the export is 403 naming it and writes no audit row; audit:export alone exports', async () => {
    h.held = new Set(['audit:read'])
    const refused = await exportOf()
    expect(refused.status).toBe(403)
    expect(await json(refused)).toMatchObject({ code: 'forbidden', permission: 'audit:export' })
    expect(h.state.audit).toEqual([])
    h.held = new Set(['audit:export'])
    expect((await exportOf()).status).toBe(200)
  })
})

describe('filters', () => {
  beforeEach(() => {
    h.state.audit = [
      auditRow_({ id: 'a-root', actorId: 'root-1', actorEmail: 'root@e2e.local', action: 'instance.settings_changed', targetType: 'instance', targetId: 'instance' }),
      auditRow_({ id: 'a-share', actorId: 'mem-a', actorEmail: 'mona@e2e.local', action: 'project.share.grant', targetType: 'user', targetId: 'adm-a', projectId: 'proj-1', permission: 'project:share' }),
      auditRow_({ id: 'a-acting', actorId: 'adm-a', actorEmail: 'ada@e2e.local', onBehalfOfUserId: 'mem-a', action: 'project.update', targetType: 'project', targetId: 'proj-2', projectId: 'proj-2' }),
      auditRow_({ id: 'a-legacy', actorId: 'mem-a', action: 'project.update', targetType: 'project', targetId: 'proj-1' }),
      auditRow_({ id: 'a-gone', actorId: 'del-9', actorEmail: 'Gone@E2E.local', action: 'mcp-token.create', targetType: 'mcpAccessToken', targetId: 'tok-1' }),
      auditRow_({ id: 'a-mcp', actorId: 'mem-a', actorEmail: 'mona@e2e.local', action: 'mcp.list_projects', targetType: 'mcp', targetId: null }),
      auditRow_({ id: 'a-old', actorId: 'adm-a', action: 'user.update', targetType: 'user', targetId: 'mem-a', createdAt: at('2026-10-01T23:59:59.000Z') }),
      auditRow_({ id: 'a-older', actorId: 'adm-a', action: 'user.update', targetType: 'user', targetId: 'mem-a', createdAt: at('2026-09-30T08:00:00.000Z') }),
    ]
  })

  test('no filter: every row, newest first, each with its label and group', async () => {
    const res = await list()
    expect(res.status).toBe(200)
    expect(res.headers.get('cache-control')).toBe('no-store')
    const body = await json(res)
    expect(body.table).toBe('audit')
    expect(body.entries.map((e: { id: string }) => e.id)).toEqual(['a-root', 'a-share', 'a-acting', 'a-legacy', 'a-gone', 'a-mcp', 'a-old', 'a-older'])
    expect(body.entries[1]).toMatchObject({ kind: 'audit', action: 'project.share.grant', label: 'Shared the project', group: 'sharing' })
    expect(body.entries[5]).toMatchObject({ label: 'MCP tool call: list projects', group: 'mcp' })
  })

  test('actor by id, and by email: the live account by id and a deleted one by the email its rows recorded (any case)', async () => {
    expect(await ids(await list('actor=mem-a'))).toEqual(['a-share', 'a-legacy', 'a-mcp'])
    expect(await ids(await list('actor=MONA%40e2e.local'))).toEqual(['a-share', 'a-legacy', 'a-mcp'])
    expect(await ids(await list('actor=gone%40e2e.local'))).toEqual(['a-gone'])
    expect(await ids(await list('actor=nobody%40e2e.local'))).toEqual([])
  })

  test('on behalf of, target (id or email), target type', async () => {
    expect(await ids(await list('onBehalfOf=mem-a'))).toEqual(['a-acting'])
    expect(await ids(await list('target=mem-a'))).toEqual(['a-old', 'a-older'])
    expect(await ids(await list('target=ada%40e2e.local'))).toEqual(['a-share'])
    expect(await ids(await list('targetType=mcpAccessToken'))).toEqual(['a-gone'])
  })

  test('project: its rows, and the rows written about it before projectId existed', async () => {
    expect(await ids(await list('project=proj-1'))).toEqual(['a-share', 'a-legacy'])
    expect(await ids(await list('project=proj-2'))).toEqual(['a-acting'])
  })

  test('action exact or as a prefix; group by the label table (acting also matches rows written on behalf)', async () => {
    expect(await ids(await list('action=project.update'))).toEqual(['a-acting', 'a-legacy'])
    expect(await ids(await list('action=project.*'))).toEqual(['a-share', 'a-acting', 'a-legacy'])
    expect(await ids(await list('group=sharing'))).toEqual(['a-share'])
    expect(await ids(await list('group=mcp'))).toEqual(['a-mcp'])
    expect(await ids(await list('group=accounts&targetType=mcpAccessToken'))).toEqual(['a-gone'])
    expect(await ids(await list('group=acting'))).toEqual(['a-acting'])
  })

  test('from and to: a bare date covers its whole day; combined with other filters', async () => {
    expect(await ids(await list('from=2026-09-30&to=2026-10-01'))).toEqual(['a-old', 'a-older'])
    expect(await ids(await list('to=2026-09-30'))).toEqual(['a-older'])
    expect(await ids(await list('from=2026-10-01T00:00:00.000Z&to=2026-10-31'))).toEqual(['a-old'])
    expect(await ids(await list('actor=adm-a&target=mem-a&from=2026-10-01'))).toEqual(['a-old'])
  })

  test.each([
    ['table=users', 'table'],
    ['actor=not%20an%20id', 'actor'],
    ['project=a%2Fb', 'project'],
    ['action=*', 'action'],
    ['action=project.*.x', 'action'],
    ['group=everything', 'group'],
    ['from=yesterday', 'from'],
    ['to=2026-02-30', 'to'],
    ['from=2026-11-02&to=2026-11-01', 'to'],
    ['cursor=not-one-of-ours', 'cursor'],
    ['limit=0', 'limit'],
    ['limit=101', 'limit'],
    ['table=act_as&project=proj-1', 'project'],
    ['table=fireteam&target=mem-a', 'target'],
    ['table=act_as&group=acting', 'group'],
  ])('%s: 400 invalid_filter naming %s, nothing read', async (qs, field) => {
    const res = await list(qs)
    expect(res.status).toBe(400)
    expect(await json(res)).toMatchObject({ code: 'invalid_filter', field })
    expect(h.state.calls.filter((c) => !c.startsWith('user.'))).toEqual([])
  })
})

describe('pagination', () => {
  test('120 rows, 70 of them at one instant: following nextCursor returns each row once, newest first', async () => {
    const same = minutesAgo(30)
    h.state.audit = Array.from({ length: 120 }, (_, i) => auditRow_({
      id: `p-${String(i).padStart(3, '0')}`, createdAt: i < 70 ? same : minutesAgo(31 + i),
    }))
    const seen: string[] = []
    let cursor: string | null = null
    let pages = 0
    do {
      const body = await json(await list(`limit=50${cursor ? `&cursor=${cursor}` : ''}`))
      seen.push(...body.entries.map((e: { id: string }) => e.id))
      cursor = body.nextCursor
      pages += 1
    } while (cursor && pages < 10)
    expect(pages).toBe(3)
    expect(seen).toHaveLength(120)
    expect(new Set(seen).size).toBe(120)
    const expected = [...h.state.audit].sort((a, b) =>
      (b.createdAt as Date).getTime() - (a.createdAt as Date).getTime() || ((a.id as string) < (b.id as string) ? 1 : -1)).map((r) => r.id)
    expect(seen).toEqual(expected)
  })

  test('an exact page: no nextCursor', async () => {
    h.state.audit = Array.from({ length: 50 }, () => auditRow_())
    const body = await json(await list())
    expect(body.entries).toHaveLength(50)
    expect(body.nextCursor).toBeNull()
  })
})

describe('identity of deleted actors and the other people a row names', () => {
  test('Root, admin and member by name, email and type; a deleted actor by its recorded email; the system as nobody', async () => {
    h.state.audit = [
      auditRow_({ id: 'r1', actorId: 'root-1', actorEmail: 'root@e2e.local' }),
      auditRow_({ id: 'r2', actorId: 'adm-a', actorEmail: 'old-ada@e2e.local', onBehalfOfUserId: 'mem-a', targetType: 'user', targetId: 'mem-a' }),
      auditRow_({ id: 'r3', actorId: 'del-9', actorEmail: 'gone@e2e.local' }),
      auditRow_({ id: 'r4', actorId: null, actorEmail: null, source: 'system' }),
      auditRow_({ id: 'r5', actorId: 'del-8', actorEmail: null }),
    ]
    const entries = (await json(await list())).entries as Array<Record<string, any>>
    expect(entries[0].actor).toEqual({ id: 'root-1', name: 'Rhea', email: 'root@e2e.local', accountType: 'root', deleted: false })
    // The current email of a live account; the account acted as and the target named too.
    expect(entries[1].actor).toEqual({ id: 'adm-a', name: 'Ada', email: 'ada@e2e.local', accountType: 'admin', deleted: false })
    expect(entries[1].onBehalfOf).toEqual({ id: 'mem-a', name: 'Mona', email: 'mona@e2e.local', accountType: 'member', deleted: false })
    expect(entries[1].target).toMatchObject({ type: 'user', id: 'mem-a', account: { id: 'mem-a', accountType: 'member' } })
    expect(entries[2].actor).toEqual({ id: 'del-9', name: '', email: 'gone@e2e.local', accountType: null, deleted: true })
    expect(entries[3].actor).toBeNull()
    expect(entries[4].actor).toEqual({ id: 'del-8', name: '', email: null, accountType: null, deleted: true })
  })

  test('the project a row names by id and name; a deleted project by id', async () => {
    h.state.audit = [auditRow_({ id: 'p1', projectId: 'proj-1' }), auditRow_({ id: 'p2', projectId: 'proj-gone' })]
    const entries = (await json(await list())).entries as Array<Record<string, any>>
    expect(entries[0].project).toEqual({ id: 'proj-1', name: 'Alpha' })
    expect(entries[1].project).toEqual({ id: 'proj-gone', name: null })
  })
})

describe('the list never carries before or after; the details route does, secrets withheld', () => {
  const recorded = {
    before: { scopes: ['read'], tokenPrefix: 'rdm_abcd', nested: { stepUpPassword: 'hunter2' } },
    after: { result: 'hit', emailSha256: 'deadbeef', name: 'ci token', list: [{ apiKey: 'sk-1', label: 'x' }], expiresAt: null },
  }

  test('list: no before, after or recorded payload, whatever the row holds', async () => {
    h.state.audit = [auditRow_({ id: 'd1', ...recorded })]
    const text = JSON.stringify(await json(await list()))
    expect(text).not.toMatch(/before|after|rdm_abcd|hunter2|deadbeef|sk-1/)
  })

  test('details: before and after with every credential, token, hash and step-up field withheld', async () => {
    h.state.audit = [auditRow_({ id: 'd1', actorId: 'del-9', actorEmail: 'gone@e2e.local', action: 'mcp-token.create', ...recorded })]
    const res = await detail('d1')
    expect(res.status).toBe(200)
    expect(res.headers.get('cache-control')).toBe('no-store')
    const { row } = await json(res)
    expect(row).toMatchObject({ id: 'd1', label: 'Created an MCP token', actorEmailRecorded: 'gone@e2e.local', actor: { deleted: true } })
    expect(row.before).toEqual({ scopes: ['read'], tokenPrefix: WITHHELD, nested: { stepUpPassword: WITHHELD } })
    expect(row.after).toEqual({ result: 'hit', emailSha256: WITHHELD, name: 'ci token', list: [{ apiKey: WITHHELD, label: 'x' }], expiresAt: null })
    expect(JSON.stringify(row)).not.toMatch(/rdm_abcd|hunter2|deadbeef|sk-1/)
  })

  test('details: an unknown id, or one no row could have, is 404', async () => {
    expect((await detail('al-missing')).status).toBe(404)
    expect((await detail('..%2F..')).status).toBe(404)
  })
})

describe('the act-as and Fireteam tables', () => {
  beforeEach(() => {
    h.state.actAs = [
      { id: 'x1', adminId: 'adm-a', targetUserId: 'mem-a', event: 'start', source: 'api', createdAt: minutesAgo(10), reason: 'ticket 42', durationMinutes: 30, endedBy: null },
      { id: 'x2', adminId: 'adm-a', targetUserId: 'mem-a', event: 'end', source: 'api', createdAt: minutesAgo(5), reason: null, durationMinutes: null, endedBy: 'admin' },
      { id: 'x3', adminId: 'root-1', targetUserId: 'adm-a', event: 'start', source: 'api', createdAt: minutesAgo(2), reason: null, durationMinutes: 15, endedBy: null },
    ]
    h.state.fireteam = [
      { id: 'f1', projectId: 'proj-1', userId: 'mem-a', field: 'fireteamEnabled', oldValue: false, newValue: true, source: 'ui', createdAt: minutesAgo(9) },
      { id: 'f2', projectId: 'proj-2', userId: 'del-7', field: 'fireteamMaxConcurrent', oldValue: 2, newValue: 4, source: 'api', createdAt: minutesAgo(3) },
    ]
  })

  test('act_as: rows with both people, reason and duration; actor, target and event filters', async () => {
    const body = await json(await list('table=act_as'))
    expect(body.table).toBe('act_as')
    expect(body.entries.map((e: { id: string }) => e.id)).toEqual(['x3', 'x2', 'x1'])
    expect(body.entries[2]).toMatchObject({
      kind: 'act_as', event: 'start', label: 'Started acting as an account', reason: 'ticket 42', durationMinutes: 30,
      admin: { email: 'ada@e2e.local', accountType: 'admin' }, target: { email: 'mona@e2e.local', accountType: 'member' },
    })
    expect(await ids(await list('table=act_as&actor=adm-a'))).toEqual(['x2', 'x1'])
    expect(await ids(await list('table=act_as&target=ada%40e2e.local'))).toEqual(['x3'])
    expect(await ids(await list('table=act_as&action=end'))).toEqual(['x2'])
  })

  test('fireteam: the field, old and new values, the project and the person; project, actor and field filters', async () => {
    const body = await json(await list('table=fireteam'))
    expect(body.entries[0]).toMatchObject({
      kind: 'fireteam', field: 'fireteamMaxConcurrent', oldValue: 2, newValue: 4, project: { id: 'proj-2', name: 'Beta' },
      user: { id: 'del-7', deleted: true },
    })
    expect(await ids(await list('table=fireteam&project=proj-1'))).toEqual(['f1'])
    expect(await ids(await list('table=fireteam&actor=mona%40e2e.local'))).toEqual(['f1'])
    expect(await ids(await list('table=fireteam&action=fireteamMax*'))).toEqual(['f2'])
  })
})

/** Reads a streamed body chunk by chunk. */
async function chunksOf(res: Response): Promise<string[]> {
  const reader = res.body!.getReader()
  const decoder = new TextDecoder()
  const out: string[] = []
  for (;;) {
    const { done, value } = await reader.read()
    if (done) return out
    out.push(decoder.decode(value))
  }
}

describe('export streams and caps', () => {
  test('CSV: a file download with the header line and one line per row, read a batch at a time', async () => {
    h.state.audit = Array.from({ length: 2_500 }, (_, i) => auditRow_({ actorId: i % 2 ? 'adm-a' : 'mem-a', action: 'project.update' }))
    const res = await exportOf('action=project.update')
    expect(res.status).toBe(200)
    expect(res.headers.get('content-type')).toBe('text/csv; charset=utf-8')
    expect(res.headers.get('content-disposition')).toBe('attachment; filename="redamon-audit-audit-20261113T120000Z.csv"')
    expect(res.headers.get('cache-control')).toBe('no-store')
    expect(res.headers.get('x-audit-export-total')).toBe('2500')
    expect(res.headers.get('x-audit-export-truncated')).toBe('false')
    const reads = h.state.calls.filter((c) => c === 'auditLog.findMany').length
    expect(reads, 'no row read before the body is').toBe(0)
    const chunks = await chunksOf(res)
    expect(chunks.length).toBeGreaterThanOrEqual(4)
    expect(h.state.calls.filter((c) => c === 'auditLog.findMany')).toHaveLength(3)
    const lines = chunks.join('').split('\r\n').filter(Boolean)
    expect(lines[0]).toBe('id,at,action,label,actor_id,actor_email,actor_type,on_behalf_of_id,on_behalf_of_email,target_type,target_id,target_email,project_id,project_name,permission,source,before,after')
    expect(lines).toHaveLength(2_501)
    expect(new Set(lines.slice(1).map((l) => l.split(',')[0])).size).toBe(2_500)
  })

  test(`at most ${AUDIT_EXPORT_MAX_ROWS} rows: the file stops there and the headers say how many matched`, async () => {
    const total = AUDIT_EXPORT_MAX_ROWS + 20_000
    let offset = 0
    const base = NOW.getTime()
    h.db = {
      ...h.db,
      auditLog: {
        ...(h.db.auditLog as object),
        count: async () => total,
        // Rows made as they are asked for, newest first: each read starts after the rows already kept.
        findMany: async ({ take }: { take: number }) => {
          h.state.calls.push('auditLog.findMany')
          const rows = Array.from({ length: Math.min(take, total - offset) }, (_, i) => {
            const n = offset + i
            return {
              id: `big-${String(n).padStart(6, '0')}`, action: 'user.update', createdAt: new Date(base - n * 1000), actorId: null,
              actorEmail: null, onBehalfOfUserId: null, targetType: 'user', targetId: null, projectId: null, permission: null,
              source: 'api', before: null, after: null,
            }
          })
          offset += take - 1
          return rows
        },
      },
    }
    const res = await exportOf()
    expect(res.headers.get('x-audit-export-total')).toBe(String(total))
    expect(res.headers.get('x-audit-export-rows')).toBe(String(AUDIT_EXPORT_MAX_ROWS))
    expect(res.headers.get('x-audit-export-truncated')).toBe('true')
    const lines = (await chunksOf(res)).join('').split('\r\n').filter(Boolean)
    expect(lines).toHaveLength(AUDIT_EXPORT_MAX_ROWS + 1)
    expect(lines[AUDIT_EXPORT_MAX_ROWS].startsWith(`big-${String(AUDIT_EXPORT_MAX_ROWS - 1).padStart(6, '0')},`)).toBe(true)
  }, 60_000)

  test('JSON: the head (table, time, total, truncated) and the rows, before/after with secrets withheld', async () => {
    h.state.audit = [
      auditRow_({ id: 'j1', actorId: 'mem-a', actorEmail: 'mona@e2e.local', action: 'project.share.lookup', projectId: 'proj-1',
        targetType: 'user', targetId: 'adm-a', after: { result: 'hit', emailSha256: 'deadbeef' } }),
      auditRow_({ id: 'j2', actorId: 'del-9', actorEmail: 'gone@e2e.local', action: 'mcp-token.create',
        after: { tokenPrefix: 'rdm_abcd', name: 'ci' } }),
    ]
    const res = await exportOf('format=json')
    expect(res.headers.get('content-type')).toBe('application/json; charset=utf-8')
    expect(res.headers.get('content-disposition')).toContain('.json"')
    const text = (await chunksOf(res)).join('')
    const file = JSON.parse(text)
    expect(file).toMatchObject({ table: 'audit', exportedAt: NOW.toISOString(), total: 2, truncated: false })
    expect(file.rows).toHaveLength(2)
    expect(file.rows[0]).toMatchObject({
      id: 'j1', action: 'project.share.lookup', actor_email: 'mona@e2e.local', actor_type: 'member', target_email: 'ada@e2e.local',
      project_name: 'Alpha', after: { result: 'hit', emailSha256: WITHHELD },
    })
    expect(file.rows[1]).toMatchObject({ actor_id: 'del-9', actor_email: 'gone@e2e.local', actor_type: 'deleted', after: { tokenPrefix: WITHHELD, name: 'ci' } })
    expect(text).not.toMatch(/deadbeef|rdm_abcd/)
  })

  test('an empty selection is a valid file in both formats', async () => {
    expect((await chunksOf(await exportOf('actor=nobody'))).join('').split('\r\n').filter(Boolean)).toHaveLength(1)
    expect(JSON.parse((await chunksOf(await exportOf('format=json&actor=nobody'))).join(''))).toMatchObject({ total: 0, rows: [] })
  })

  test('a CSV cell a spreadsheet would run as a formula is quoted', async () => {
    h.state.audit = [auditRow_({ id: 'c1', targetType: 'user', targetId: '=HYPERLINK("http://x")', action: 'user.update' })]
    const line = (await chunksOf(await exportOf())).join('').split('\r\n')[1]
    expect(line).toContain(`"'=HYPERLINK(""http://x"")"`)
  })

  test('the act-as table exports its own columns', async () => {
    h.state.actAs = [{ id: 'x1', adminId: 'adm-a', targetUserId: 'mem-a', event: 'start', source: 'api', createdAt: minutesAgo(1), reason: 'ticket, 42', durationMinutes: 30, endedBy: null }]
    const lines = (await chunksOf(await exportOf('table=act_as'))).join('').split('\r\n').filter(Boolean)
    expect(lines).toEqual([
      'id,at,event,admin_id,admin_email,target_id,target_email,source,reason,duration_minutes,ended_by',
      `x1,${minutesAgo(1).toISOString()},start,adm-a,ada@e2e.local,mem-a,mona@e2e.local,api,"ticket, 42",30,`,
    ])
  })

  test.each([
    ['cursor=abc', 'cursor'],
    ['limit=10', 'limit'],
    ['format=xlsx', 'format'],
    ['table=fireteam&onBehalfOf=mem-a', 'onBehalfOf'],
  ])('%s: 400 naming %s, no audit row, nothing exported', async (qs, field) => {
    const res = await exportOf(qs)
    expect(res.status).toBe(400)
    expect(await json(res)).toMatchObject({ code: 'invalid_filter', field })
    expect(h.state.audit).toEqual([])
  })
})

describe('export audited', () => {
  test('one audit.exported row, written before the first byte: who, the permission, the table, format, filters and counts', async () => {
    h.state.audit = [auditRow_({ id: 'e1', action: 'project.update', projectId: 'proj-1' }), auditRow_({ id: 'e2', action: 'user.update' })]
    const res = await exportOf('format=json&project=proj-1&from=2026-11-01&limit=')
    const written = h.state.audit.filter((r) => r.action === 'audit.exported')
    expect(written).toHaveLength(1)
    expect(written[0]).toMatchObject({
      actorId: 'aud-1', actorEmail: 'auditor@e2e.local', action: 'audit.exported', targetType: 'audit', targetId: 'audit',
      permission: 'audit:export', source: 'api',
      after: { table: 'audit', format: 'json', filters: { project: 'proj-1', from: '2026-11-01' }, total: 1, rows: 1, truncated: false },
    })
    // The export's own row is written after the export started, so the file holds the rows asked for only.
    expect(JSON.parse((await chunksOf(res)).join('')).rows.map((r: { id: string }) => r.id)).toEqual(['e1'])
  })

  test('fail-closed: when the audit row cannot be written the export is refused (500) and nothing is streamed', async () => {
    h.state.audit = [auditRow_({ id: 'e1' })]
    h.state.failAudit = true
    const err = vi.spyOn(console, 'error').mockImplementation(() => {})
    const res = await exportOf()
    expect(res.status).toBe(500)
    expect(res.headers.get('content-disposition')).toBeNull()
    expect(await json(res)).toMatchObject({ code: 'P1001' })
    expect(h.state.calls.filter((c) => c === 'auditLog.findMany')).toEqual([])
    err.mockRestore()
  })
})

describe('no delete route exists', () => {
  const WEBAPP = path.resolve(__dirname, '../../../../..')

  test('the audit routes answer GET only, in their files and in the route manifest', () => {
    const files = ['route.ts', '[id]/route.ts', 'export/route.ts'].map((f) => readFileSync(path.join(__dirname, f), 'utf8'))
    for (const source of files) {
      const handlers = [...source.matchAll(/export\s+(?:const|async\s+function|function)\s+(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)\b/g)].map((m) => m[1])
      expect(handlers).toEqual(['GET'])
    }
    for (const e of ROUTE_MANIFEST.filter((r) => r.path.startsWith('/api/admin/audit'))) expect(e.methods, e.path).toEqual(['GET'])
  })

  test('no route deletes audit rows', () => {
    const deletes = /\b(auditLog|actAsAudit|fireteamSettingsAudit)\s*\.\s*delete(Many)?\b|DELETE\s+FROM\s+"?(audit_log|act_as_audit|fireteam_settings_audit)\b/i
    const offenders: string[] = []
    const walk = (dir: string): void => {
      for (const name of readdirSync(dir)) {
        const full = path.join(dir, name)
        if (statSync(full).isDirectory()) walk(full)
        else if (/\.(ts|tsx)$/.test(name) && !/\.test\.(ts|tsx)$/.test(name) && deletes.test(readFileSync(full, 'utf8'))) {
          offenders.push(path.relative(WEBAPP, full))
        }
      }
    }
    walk(path.join(WEBAPP, 'src', 'app'))
    expect(offenders).toEqual([])
  })
})
